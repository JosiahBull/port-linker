//! Windows platform: IP Helper API scanner, process lookup/kill, notifications, username.

use std::collections::HashSet;

use super::{Listener, ScanError};

// ---------------------------------------------------------------------------
// Process lookup and kill: GetExtendedTcpTable, OpenProcess, TerminateProcess
// ---------------------------------------------------------------------------

pub mod process {
    use crate::process::{ProcessInfo, TransportProto};

    pub fn find_listener(port: u16, proto: TransportProto) -> Option<ProcessInfo> {
        let port_ne = port as u32;
        match proto {
            TransportProto::Tcp => find_tcp_listener(port_ne),
            TransportProto::Udp => find_udp_listener(port_ne),
        }
    }

    fn find_tcp_listener(port: u32) -> Option<ProcessInfo> {
        use windows::Win32::NetworkManagement::IpHelper::*;
        use windows::Win32::Networking::WinSock::AF_INET;

        let mut size: u32 = 0;
        // First call: get required buffer size.
        unsafe {
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_CLASS(5), // TCP_TABLE_OWNER_PID_LISTENER
                0,
            );
        }
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        // Second call: fill the buffer.
        let ret = unsafe {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_CLASS(5),
                0,
            )
        };
        if ret != 0 {
            return None;
        }

        let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let rows = unsafe {
            std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
        };
        for row in rows {
            // dwLocalPort is stored in network byte order (big-endian) in the low 16 bits.
            let row_port = u16::from_be(row.dwLocalPort as u16) as u32;
            if row_port == port {
                return pid_to_process_info(row.dwOwningPid);
            }
        }
        None
    }

    fn find_udp_listener(port: u32) -> Option<ProcessInfo> {
        use windows::Win32::NetworkManagement::IpHelper::*;
        use windows::Win32::Networking::WinSock::AF_INET;

        let mut size: u32 = 0;
        unsafe {
            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_CLASS(1), // UDP_TABLE_OWNER_PID
                0,
            );
        }
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_CLASS(1),
                0,
            )
        };
        if ret != 0 {
            return None;
        }

        let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let rows = unsafe {
            std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
        };
        for row in rows {
            let row_port = u16::from_be(row.dwLocalPort as u16) as u32;
            if row_port == port {
                return pid_to_process_info(row.dwOwningPid);
            }
        }
        None
    }

    fn pid_to_process_info(pid: u32) -> Option<ProcessInfo> {
        // For now, return just the PID; process name lookup requires
        // CreateToolhelp32Snapshot which needs additional features.
        // A PID-only result is still useful for kill operations.
        Some(ProcessInfo {
            pid,
            name: format!("PID:{pid}"),
        })
    }

    pub fn kill_process(pid: u32) -> Result<(), String> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
                .map_err(|e| format!("OpenProcess failed for PID {pid}: {e}"))?;
            let result = TerminateProcess(handle, 1);
            let _ = CloseHandle(handle);
            result.map_err(|e| format!("TerminateProcess failed for PID {pid}: {e}"))?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Port scanner: IP Helper API
// ---------------------------------------------------------------------------

/// Port scanner using Windows IP Helper API (GetExtendedTcpTable / GetExtendedUdpTable).
pub struct IpHelperScanner;

impl IpHelperScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IpHelperScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl super::PortScanner for IpHelperScanner {
    fn scan(&self) -> Result<HashSet<Listener>, ScanError> {
        use windows::Win32::NetworkManagement::IpHelper::*;
        use windows::Win32::Networking::WinSock::AF_INET;

        let mut listeners = HashSet::new();

        // TCP listeners
        let mut size: u32 = 0;
        unsafe {
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_CLASS(5), // TCP_TABLE_OWNER_PID_LISTENER
                0,
            );
        }
        if size > 0 {
            let mut buf = vec![0u8; size as usize];
            let ret = unsafe {
                GetExtendedTcpTable(
                    Some(buf.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    TCP_TABLE_CLASS(5),
                    0,
                )
            };
            if ret == 0 {
                let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
                let rows = unsafe {
                    std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
                };
                for row in rows {
                    let port = u16::from_be(row.dwLocalPort as u16);
                    listeners.insert((port, protocol::Protocol::Tcp));
                }
            }
        }

        // UDP listeners
        size = 0;
        unsafe {
            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_CLASS(1), // UDP_TABLE_OWNER_PID
                0,
            );
        }
        if size > 0 {
            let mut buf = vec![0u8; size as usize];
            let ret = unsafe {
                GetExtendedUdpTable(
                    Some(buf.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    UDP_TABLE_CLASS(1),
                    0,
                )
            };
            if ret == 0 {
                let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
                let rows = unsafe {
                    std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
                };
                for row in rows {
                    let port = u16::from_be(row.dwLocalPort as u16);
                    listeners.insert((port, protocol::Protocol::Udp));
                }
            }
        }

        Ok(listeners)
    }
}

// ---------------------------------------------------------------------------
// Desktop notifications: notify-rust (cross-platform crate)
// ---------------------------------------------------------------------------

/// Windows notifier using `notify-rust` which wraps Windows toast notifications.
pub struct ToastNotifier;

impl Default for ToastNotifier {
    fn default() -> Self {
        Self
    }
}

impl super::Notifier for ToastNotifier {
    fn show(
        &self,
        title: &str,
        body: &str,
        _is_error: bool,
        _with_sound: bool,
        _icon: Option<&std::path::Path>,
    ) -> Result<(), String> {
        use notify_rust::Notification;
        Notification::new()
            .summary(title)
            .body(body)
            .appname("port-linker")
            .show()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Username
// ---------------------------------------------------------------------------

pub fn username() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "Administrator".to_string())
}
