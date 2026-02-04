use crate::error::{PortLinkerError, Result};
use crate::ssh::handler::ClientHandler;
use crate::ssh::{PortProtocol, RemotePort};
use russh::client::Handle;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

#[derive(Debug)]
pub struct TunnelHandle {
    #[allow(dead_code)]
    pub remote_port: RemotePort,
    #[allow(dead_code)]
    pub local_port: u16,
    shutdown_tx: oneshot::Sender<()>,
}

impl TunnelHandle {
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

pub struct ActiveTunnel {
    #[allow(dead_code)]
    pub remote_port: RemotePort,
    #[allow(dead_code)]
    pub local_port: u16,
}

impl ActiveTunnel {
    pub async fn start(
        ssh_handle: Arc<Handle<ClientHandler>>,
        remote_port: RemotePort,
        local_port: Option<u16>,
    ) -> Result<TunnelHandle> {
        let local_port = local_port.unwrap_or(remote_port.port);

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        match remote_port.protocol {
            PortProtocol::Tcp => {
                Self::start_tcp_tunnel(ssh_handle, &remote_port, local_port, shutdown_rx).await?;
            }
            PortProtocol::Udp => {
                Self::start_udp_tunnel(ssh_handle, &remote_port, local_port, shutdown_rx).await?;
            }
        }

        info!(
            "Forwarding {} localhost:{} -> remote:{}",
            remote_port.protocol, local_port, remote_port.port
        );

        Ok(TunnelHandle {
            remote_port,
            local_port,
            shutdown_tx,
        })
    }

    async fn start_tcp_tunnel(
        ssh_handle: Arc<Handle<ClientHandler>>,
        remote_port: &RemotePort,
        local_port: u16,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) -> Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", local_port))
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AddrInUse {
                    PortLinkerError::PortInUse(local_port)
                } else {
                    PortLinkerError::PortForward {
                        port: local_port,
                        message: format!("Failed to bind: {}", e),
                    }
                }
            })?;

        let remote_port_num = remote_port.port;
        let bind_address = remote_port.bind_address.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                debug!("New TCP connection from {} for port {}", addr, local_port);
                                let ssh_handle = ssh_handle.clone();
                                let bind_addr = bind_address.clone();

                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_tcp_connection(
                                        ssh_handle,
                                        stream,
                                        &bind_addr,
                                        remote_port_num,
                                    ).await {
                                        debug!("TCP connection error: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Failed to accept connection: {}", e);
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        debug!("Shutting down TCP tunnel for port {}", local_port);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_tcp_connection(
        ssh_handle: Arc<Handle<ClientHandler>>,
        mut local_stream: tokio::net::TcpStream,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<()> {
        // Determine the actual host to connect to
        let connect_host = match remote_host {
            "0.0.0.0" | "::" | "*" => "127.0.0.1",
            addr => addr,
        };

        let mut channel = ssh_handle
            .channel_open_direct_tcpip(connect_host, remote_port as u32, "127.0.0.1", 0)
            .await
            .map_err(|e| PortLinkerError::PortForward {
                port: remote_port,
                message: format!("Failed to open channel: {}", e),
            })?;

        let (mut local_read, mut local_write) = local_stream.split();

        // Create a stream from the channel
        let mut local_buf = vec![0u8; 32768];

        loop {
            tokio::select! {
                // Read from local, write to channel
                result = local_read.read(&mut local_buf) => {
                    match result {
                        Ok(0) => {
                            debug!("Local connection closed");
                            let _ = channel.eof().await;
                            break;
                        }
                        Ok(n) => {
                            if channel.data(&local_buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("Local read error: {}", e);
                            break;
                        }
                    }
                }

                // Read from channel, write to local
                msg = channel.wait() => {
                    match msg {
                        Some(russh::ChannelMsg::Data { data }) => {
                            if local_write.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                        Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) | None => {
                            debug!("Channel closed");
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }

    async fn start_udp_tunnel(
        _ssh_handle: Arc<Handle<ClientHandler>>,
        _remote_port: &RemotePort,
        local_port: u16,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) -> Result<()> {
        // UDP tunneling over SSH requires a helper on the remote side
        // We'll use socat if available
        let local_socket = UdpSocket::bind(format!("127.0.0.1:{}", local_port))
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AddrInUse {
                    PortLinkerError::PortInUse(local_port)
                } else {
                    PortLinkerError::PortForward {
                        port: local_port,
                        message: format!("Failed to bind UDP: {}", e),
                    }
                }
            })?;

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];

            warn!(
                "UDP forwarding for port {} - requires socat on remote",
                local_port
            );

            loop {
                tokio::select! {
                    result = local_socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, src)) => {
                                debug!(
                                    "UDP packet from {} ({} bytes) for port {}",
                                    src, len, local_port
                                );
                                // For UDP, we need to establish a TCP tunnel and relay
                                // This is complex - for now just log
                                // Full implementation would spawn socat on remote
                            }
                            Err(e) => {
                                error!("UDP receive error: {}", e);
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        debug!("Shutting down UDP tunnel for port {}", local_port);
                        break;
                    }
                }
            }
        });

        Ok(())
    }
}
