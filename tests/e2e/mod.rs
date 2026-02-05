//! End-to-end integration tests for port-linker
//!
//! These tests require the Docker test environment to be running.
//! Run `./tests/docker/setup-test-env.sh` first.
//!
//! The tests verify that port-linker can:
//! - Connect to a remote host via SSH
//! - Discover listening ports on the remote
//! - Forward those ports to localhost
//! - Handle dynamic port changes
//! - Handle connection drops and reconnection
//!
//! ## Port Isolation Strategy
//!
//! Tests are organized to allow maximum parallelism while avoiding port conflicts:
//!
//! 1. **No-port tests**: Tests like `test_help_output` don't use ports and run freely in parallel.
//!
//! 2. **Dynamic port tests**: Tests that create their own remote services use unique port ranges
//!    allocated per-test, allowing them to run in parallel.
//!
//! 3. **Fixed port tests**: Tests that use the Docker container's pre-configured services
//!    (8080, 3000, 5432 for TCP; 5353, 9999 for UDP) use per-port locks to serialize only
//!    tests that would conflict.
//!
//! Note: These tests only run on Unix systems as they require Docker and Unix-specific APIs.

#![cfg(unix)]

mod tcp;
mod udp;

use ntest::timeout;
use wait_timeout::ChildExt;

#[allow(deprecated)]
use assert_cmd::cargo::cargo_bin;
use assert_cmd::prelude::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

/// Get the path to the port-linker binary
#[allow(deprecated)]
fn bin_path() -> std::path::PathBuf {
    cargo_bin("port-linker")
}

// ============================================================================
// PORT ISOLATION INFRASTRUCTURE
// ============================================================================

/// Maximum time to wait for a port lock before giving up (2 minutes)
const PORT_LOCK_TIMEOUT_SECS: u64 = 120;

/// Base port for dynamically allocated test ports
const DYNAMIC_PORT_BASE: u16 = 10000;

/// Counter for allocating unique dynamic ports across tests
static DYNAMIC_PORT_COUNTER: AtomicU16 = AtomicU16::new(0);

/// Guard that holds a file lock for a specific port.
/// Multiple tests using different ports can run in parallel.
pub struct PortLock {
    _files: Vec<File>,
}

impl PortLock {
    /// Acquire locks for the specified ports. Tests using different ports can run in parallel.
    pub fn acquire(ports: &[u16]) -> Self {
        let mut files = Vec::new();

        for &port in ports {
            let lock_path =
                std::env::temp_dir().join(format!("port-linker-e2e-port-{}.lock", port));
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(&lock_path)
                .expect("Failed to open port lock file");

            // Use non-blocking lock with timeout
            let start = std::time::Instant::now();
            let timeout = Duration::from_secs(PORT_LOCK_TIMEOUT_SECS);

            loop {
                let result =
                    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                if result == 0 {
                    break;
                }

                if start.elapsed() > timeout {
                    panic!(
                        "Timeout after {}s waiting to acquire lock for port {}. \
                         Another test may be hung. Try removing: {:?}",
                        PORT_LOCK_TIMEOUT_SECS, port, lock_path
                    );
                }

                std::thread::sleep(Duration::from_millis(100));
            }

            files.push(file);
        }

        PortLock { _files: files }
    }
}

impl Drop for PortLock {
    fn drop(&mut self) {
        // File locks are automatically released when the file is closed
        // The _file field being dropped handles this
    }
}

/// Allocate a unique port for a test. Each call returns a different port.
/// Ports are allocated from a high range (10000+) to avoid conflicts with
/// the Docker container's fixed services.
pub fn allocate_test_port() -> u16 {
    let offset = DYNAMIC_PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    DYNAMIC_PORT_BASE + offset
}

// ============================================================================
// TEST CONFIGURATION
// ============================================================================

/// Test configuration - matches docker compose setup
const SSH_HOST: &str = "localhost";
const SSH_PORT: u16 = 2222;
const SSH_USER: &str = "testuser";

/// Fixed ports in the Docker container (TCP)
pub const DOCKER_TCP_PORT_HTTP: u16 = 8080;
pub const DOCKER_TCP_PORT_ECHO: u16 = 3000;
pub const DOCKER_TCP_PORT_POSTGRES: u16 = 5432;

/// Fixed ports in the Docker container (UDP)
/// Note: Port 9999 is bound to 127.0.0.1, used only for localhost-bound test
pub const DOCKER_UDP_PORT_ECHO_LOCALHOST: u16 = 9999;

/// Get healthcheck wait time from environment variable or use default.
/// Set E2E_HEALTHCHECK_WAIT_SECS to a lower value (e.g., 5) for faster testing.
pub fn get_healthcheck_wait_secs() -> u64 {
    std::env::var("E2E_HEALTHCHECK_WAIT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

/// Get long healthcheck wait time (for traffic pause test).
/// Set E2E_HEALTHCHECK_LONG_WAIT_SECS to a lower value (e.g., 10) for faster testing.
pub fn get_healthcheck_long_wait_secs() -> u64 {
    std::env::var("E2E_HEALTHCHECK_LONG_WAIT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(45)
}

/// Get the path to the test SSH key
fn test_key_path() -> PathBuf {
    // CARGO_MANIFEST_DIR points to crates/port-linker/, but tests are at workspace root
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent() // crates/
        .unwrap()
        .parent() // workspace root
        .unwrap()
        .join("tests")
        .join("docker")
        .join("test_key")
}

/// Check if the Docker test environment is running
pub fn is_test_env_running() -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", SSH_PORT).parse().unwrap(),
        Duration::from_secs(1),
    )
    .is_ok()
}

/// Start port-linker as a background process
pub fn start_port_linker(extra_args: &[&str]) -> std::io::Result<Child> {
    let key_path = test_key_path();

    std::process::Command::new(bin_path())
        .arg(format!("{}@{}", SSH_USER, SSH_HOST))
        .arg("-P")
        .arg(SSH_PORT.to_string())
        .arg("-i")
        .arg(&key_path)
        .arg("--no-notifications")
        .arg("--log-level")
        .arg("debug")
        // Auto-kill conflicting local processes to prevent hangs when
        // orphaned processes from previous test runs are still bound to ports
        .arg("--auto-kill")
        .args(extra_args)
        // Use null for stdout/stderr to prevent buffer blocking.
        // When piped, if the buffer fills up and isn't read, the process blocks.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// Maximum time to wait for port-linker process to exit after kill (seconds)
const PROCESS_EXIT_TIMEOUT_SECS: u64 = 10;

/// Stop port-linker and wait for cleanup
#[track_caller]
pub fn stop_port_linker(mut child: Child, ports: &[u16]) {
    child.kill().ok();

    // Wait for process to exit with a timeout to prevent hanging
    match child.wait_timeout(Duration::from_secs(PROCESS_EXIT_TIMEOUT_SECS)) {
        Ok(Some(_status)) => {
            // Process exited normally
        }
        Ok(None) => {
            // Timeout - process didn't exit, try SIGKILL
            eprintln!(
                "Warning: port-linker process did not exit within {}s after SIGTERM, sending SIGKILL",
                PROCESS_EXIT_TIMEOUT_SECS
            );
            unsafe {
                libc::kill(child.id() as i32, libc::SIGKILL);
            }
            // Wait a bit more after SIGKILL
            let _ = child.wait_timeout(Duration::from_secs(5));
        }
        Err(e) => {
            eprintln!("Warning: error waiting for port-linker process: {}", e);
        }
    }

    // Wait for ports to be released
    for &port in ports {
        assert!(
            wait_for_port_closed(port, Duration::from_secs(5)),
            "Port {} did not close within timeout after stopping port-linker",
            port
        );
    }
}

/// Wait for a local port to become available (listening)
pub fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", port).parse().unwrap(),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Wait for a local port to become unavailable (closed)
pub fn wait_for_port_closed(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", port).parse().unwrap(),
            Duration::from_millis(100),
        )
        .is_err()
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Check if a port is currently listening
pub fn is_port_open(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", port).parse().unwrap(),
        Duration::from_millis(500),
    )
    .is_ok()
}

/// Run a command on the remote host via SSH
/// Includes connection and keepalive timeouts to prevent indefinite hangs
pub fn ssh_exec(command: &str) -> std::io::Result<std::process::Output> {
    std::process::Command::new("ssh")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("ServerAliveInterval=5")
        .arg("-o")
        .arg("ServerAliveCountMax=2")
        .arg("-i")
        .arg(test_key_path())
        .arg("-p")
        .arg(SSH_PORT.to_string())
        .arg(format!("{}@{}", SSH_USER, SSH_HOST))
        .arg(command)
        .output()
}

/// Start a TCP service on the remote host (returns the PID)
pub fn start_remote_service(port: u16) -> Option<u32> {
    // Start a simple netcat listener in the background
    let output = ssh_exec(&format!(
        "nohup sh -c 'while true; do echo \"test response\" | nc -l -p {} 2>/dev/null; done' > /dev/null 2>&1 & echo $!",
        port
    ))
    .ok()?;

    let pid_str = String::from_utf8_lossy(&output.stdout);
    pid_str.trim().parse().ok()
}

/// Stop a service on the remote host by PID
pub fn stop_remote_service(pid: u32) {
    let _ = ssh_exec(&format!("kill {} 2>/dev/null", pid));
}

/// Send data through a forwarded port and get response
pub fn send_and_receive(port: u16, data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(data)?;
    stream.flush()?;

    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    match stream.read(&mut buf) {
        Ok(n) => response.extend_from_slice(&buf[..n]),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e),
    }
    Ok(response)
}

// ============================================================================
// UDP HELPER FUNCTIONS
// ============================================================================

/// Send UDP data through a forwarded port and get response
pub fn udp_send_and_receive(port: u16, data: &[u8]) -> std::io::Result<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.connect(format!("127.0.0.1:{}", port))?;
    socket.send(data)?;

    let mut buf = [0u8; 65535];
    match socket.recv(&mut buf) {
        Ok(n) => Ok(buf[..n].to_vec()),
        Err(e) => Err(e),
    }
}

/// Check if a UDP port responds (by sending a test packet and waiting for response)
pub fn is_udp_port_responding(port: u16) -> bool {
    let socket = match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(_) => return false,
    };
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok();
    if socket.connect(format!("127.0.0.1:{}", port)).is_err() {
        return false;
    }
    if socket.send(b"ping").is_err() {
        return false;
    }

    let mut buf = [0u8; 1024];
    socket.recv(&mut buf).is_ok()
}

/// Wait for a UDP port to become responsive
pub fn wait_for_udp_port(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if is_udp_port_responding(port) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

/// Start a UDP service on the remote host (returns the PID)
pub fn start_remote_udp_service(port: u16) -> Option<u32> {
    // Start a socat UDP echo server in the background
    let output = ssh_exec(&format!(
        "nohup socat UDP4-LISTEN:{},fork EXEC:'/bin/cat' > /dev/null 2>&1 & echo $!",
        port
    ))
    .ok()?;

    let pid_str = String::from_utf8_lossy(&output.stdout);
    pid_str.trim().parse().ok()
}

// ============================================================================
// TEST HELPERS
// ============================================================================

/// Skip tests if Docker environment is not running
macro_rules! require_test_env {
    () => {
        if !$crate::is_test_env_running() {
            eprintln!("SKIPPED: Docker test environment not running");
            eprintln!("Run: ./tests/docker/setup-test-env.sh");
            panic!();
        }
    };
}

pub(crate) use require_test_env;

// ============================================================================
// TESTS - NO PORT USAGE (can run fully in parallel)
// ============================================================================

#[test]
#[timeout(30000)]
fn test_invalid_ssh_host() {
    // This should fail quickly with connection error - no port locks needed
    Command::new(bin_path())
        .arg("testuser@nonexistent.invalid")
        .arg("-i")
        .arg(test_key_path())
        .arg("--no-notifications")
        .assert()
        .failure();
}

#[test]
#[timeout(30000)]
fn test_invalid_ssh_key() {
    require_test_env!();

    // Use a non-existent key - no port locks needed
    Command::new(bin_path())
        .arg(format!("{}@{}", SSH_USER, SSH_HOST))
        .arg("-P")
        .arg(SSH_PORT.to_string())
        .arg("-i")
        .arg("/nonexistent/key")
        .arg("--no-notifications")
        .assert()
        .failure();
}

#[test]
#[timeout(10000)]
fn test_help_output() {
    let output = Command::new(bin_path())
        .arg("--help")
        .output()
        .expect("Failed to run port-linker --help");

    assert!(output.status.success());
    insta::assert_snapshot!(String::from_utf8_lossy(&output.stdout));
}

#[test]
#[timeout(10000)]
fn test_version_output() {
    let output = Command::new(bin_path())
        .arg("--version")
        .output()
        .expect("Failed to run port-linker --version");

    assert!(output.status.success());
    insta::assert_snapshot!(String::from_utf8_lossy(&output.stdout));
}
