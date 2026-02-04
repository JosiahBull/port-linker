//! Common test utilities and helpers
#![allow(dead_code)]

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Find an available TCP port for testing
pub fn find_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to random port");
    listener.local_addr().unwrap().port()
}

/// Get the path to a test fixture file
pub fn fixture_path(relative_path: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures");
    path.push(relative_path);
    path
}

/// Read a fixture file as a string
pub fn read_fixture(relative_path: &str) -> String {
    std::fs::read_to_string(fixture_path(relative_path))
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", relative_path, e))
}

/// Simple echo TCP server for tunnel testing
pub struct EchoServer {
    pub port: u16,
    shutdown: Arc<Mutex<bool>>,
}

impl EchoServer {
    pub async fn start() -> Self {
        let port = find_available_port();
        let shutdown = Arc::new(Mutex::new(false));
        let shutdown_clone = shutdown.clone();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
                .await
                .expect("Failed to bind echo server");

            loop {
                tokio::select! {
                    result = listener.accept() => {
                        if let Ok((mut socket, _)) = result {
                            tokio::spawn(async move {
                                let (mut reader, mut writer) = socket.split();
                                let _ = tokio::io::copy(&mut reader, &mut writer).await;
                            });
                        }
                    }
                    _ = async {
                        loop {
                            if *shutdown_clone.lock().await {
                                break;
                            }
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        }
                    } => {
                        break;
                    }
                }
            }
        });

        // Give the server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        Self { port, shutdown }
    }

    pub async fn stop(&self) {
        *self.shutdown.lock().await = true;
    }
}

/// A simple TCP server that records received data and sends a fixed response
pub struct RecordingServer {
    pub port: u16,
    pub received: Arc<Mutex<Vec<u8>>>,
    response: Vec<u8>,
    shutdown: Arc<Mutex<bool>>,
}

impl RecordingServer {
    pub async fn start(response: Vec<u8>) -> Self {
        let port = find_available_port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(Mutex::new(false));

        let received_clone = received.clone();
        let shutdown_clone = shutdown.clone();
        let response_clone = response.clone();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
                .await
                .expect("Failed to bind recording server");

            loop {
                tokio::select! {
                    result = listener.accept() => {
                        if let Ok((mut socket, _)) = result {
                            let received = received_clone.clone();
                            let response = response_clone.clone();

                            tokio::spawn(async move {
                                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                                let mut buf = vec![0u8; 4096];
                                if let Ok(n) = socket.read(&mut buf).await {
                                    received.lock().await.extend_from_slice(&buf[..n]);
                                }
                                let _ = socket.write_all(&response).await;
                            });
                        }
                    }
                    _ = async {
                        loop {
                            if *shutdown_clone.lock().await {
                                break;
                            }
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        }
                    } => {
                        break;
                    }
                }
            }
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        Self {
            port,
            received,
            response,
            shutdown,
        }
    }

    pub async fn get_received(&self) -> Vec<u8> {
        self.received.lock().await.clone()
    }

    pub async fn stop(&self) {
        *self.shutdown.lock().await = true;
    }
}

/// Check if a port is in use
pub fn is_port_in_use(port: u16) -> bool {
    TcpListener::bind(format!("127.0.0.1:{}", port)).is_err()
}

/// Wait for a condition to be true, with timeout
pub async fn wait_for<F>(mut condition: F, timeout_ms: u64) -> bool
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(timeout_ms);

    while start.elapsed() < timeout {
        if condition() {
            return true;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    false
}
