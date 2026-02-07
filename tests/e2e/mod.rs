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
use std::sync::OnceLock;
use std::time::Duration;

// ============================================================================
// SSH CONNECTION MULTIPLEXING
// ============================================================================
// Uses SSH ControlMaster to share a single connection across all test processes,
// dramatically reducing connection overhead.

/// Path to the SSH control socket (lazily initialized)
static SSH_CONTROL_SOCKET: OnceLock<PathBuf> = OnceLock::new();

/// Get or create the SSH control socket path
fn get_ssh_control_socket() -> &'static PathBuf {
    SSH_CONTROL_SOCKET.get_or_init(|| {
        let socket_path = std::env::temp_dir().join(format!(
            "port-linker-e2e-ssh-{}.sock",
            std::process::id()
        ));

        // Start the master connection
        let _ = std::process::Command::new("ssh")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg("-o")
            .arg("ControlMaster=yes")
            .arg("-o")
            .arg(format!("ControlPath={}", socket_path.display()))
            .arg("-o")
            .arg("ControlPersist=60")
            .arg("-i")
            .arg(test_key_path())
            .arg("-p")
            .arg(SSH_PORT.to_string())
            .arg("-fN") // Background, no command
            .arg(format!("{}@{}", SSH_USER, SSH_HOST))
            .status();

        // Wait for the control socket to be ready
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(5) && !socket_path.exists() {
            std::thread::sleep(Duration::from_millis(5));
        }

        socket_path
    })
}

// ============================================================================
// PRE-TEST CLEANUP
// ============================================================================
// Kills orphaned agent and socat processes from previous test runs.
// Without this, successive test runs degrade as zombie processes accumulate
// in the Docker container, consuming SSH slots and ports.

/// One-time test environment initialization
static TEST_INIT: OnceLock<()> = OnceLock::new();

/// Clean up orphaned processes from prior test runs.
///
/// When a test times out (via ntest), `stop_port_linker` never runs, leaving:
/// - Local port-linker processes bound to forwarded ports
/// - Remote agent processes consuming SSH slots
///
/// This function kills both. It matches test port-linker instances by their
/// `testuser@localhost` argument (which is unique to E2E tests) to avoid
/// killing the user's real port-linker instances.
///
/// Does NOT kill socat — the Docker container has pre-configured socat services
/// (ports 5353, 9999) that must stay alive.
fn init_test_env() {
    TEST_INIT.get_or_init(|| {
        // Kill orphaned local port-linker processes from prior test runs.
        // Match on "testuser@localhost" to only kill test instances.
        let _ = std::process::Command::new("pkill")
            .args(["-9", "-f", "port-linker.*testuser@localhost"])
            .status();
        // Kill orphaned remote agent processes
        let _ = ssh_exec("pkill -9 -f '/tmp/port-linker-agent' 2>/dev/null; true");
        // Let ports release after killing processes
        std::thread::sleep(Duration::from_millis(500));
    });
}

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

                std::thread::sleep(Duration::from_millis(10));
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

/// Virtual port used as a lock key for tests that kill all remote agents (`pkill -f port-linker-agent`)
/// or depend on agent stability during long idle periods. Tests holding this lock are
/// serialized to prevent `pkill -f port-linker-agent` from breaking concurrent tests' agents.
pub const AGENT_STABILITY_LOCK: u16 = 1;

/// Get healthcheck wait time from environment variable or use default.
/// Default is 1 second (fast). Set E2E_HEALTHCHECK_WAIT_SECS higher for thorough testing.
pub fn get_healthcheck_wait_secs() -> u64 {
    std::env::var("E2E_HEALTHCHECK_WAIT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
}

/// Get long healthcheck wait time (for traffic pause test).
/// Default is 1.5 seconds (fast). Set E2E_HEALTHCHECK_LONG_WAIT_SECS higher for thorough testing.
pub fn get_healthcheck_long_wait_secs() -> u64 {
    std::env::var("E2E_HEALTHCHECK_LONG_WAIT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2)
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

/// Start port-linker as a background process and wait for it to be ready.
/// Returns immediately after detecting the "Starting port monitoring" log message.
pub fn start_port_linker(extra_args: &[&str]) -> std::io::Result<Child> {
    let key_path = test_key_path();

    let mut child = std::process::Command::new(bin_path())
        .arg(format!("{}@{}", SSH_USER, SSH_HOST))
        .arg("-P")
        .arg(SSH_PORT.to_string())
        .arg("-i")
        .arg(&key_path)
        .arg("--no-notifications")
        .arg("--log-level")
        .arg("info")
        // Auto-kill conflicting local processes to prevent hangs when
        // orphaned processes from previous test runs are still bound to ports
        .arg("--auto-kill")
        .args(extra_args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    // Wait for the "Starting port monitoring" message indicating readiness
    let stderr = child.stderr.take().expect("stderr should be piped");
    let ready_signal = b"Starting port monitoring";
    let timeout = Duration::from_secs(5);

    // Channel to signal when ready
    let (tx, rx) = std::sync::mpsc::channel::<bool>();

    // Spawn a thread to read stderr and detect readiness
    std::thread::spawn(move || {
        let mut stderr = stderr;
        let mut buffer = Vec::with_capacity(4096);
        let mut temp = [0u8; 256];
        let mut found = false;

        loop {
            match stderr.read(&mut temp) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    buffer.extend_from_slice(&temp[..n]);
                    if !found && buffer.windows(ready_signal.len()).any(|w| w == ready_signal) {
                        found = true;
                        let _ = tx.send(true);
                    }
                    // Keep buffer bounded
                    if buffer.len() > 8192 {
                        buffer.drain(..4096);
                    }
                }
                Err(_) => break,
            }
        }
        if !found {
            let _ = tx.send(false);
        }
    });

    // Wait for ready signal or timeout
    match rx.recv_timeout(timeout) {
        Ok(true) => Ok(child),
        Ok(false) => {
            child.kill().ok();
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "port-linker exited before becoming ready",
            ))
        }
        Err(_) => {
            child.kill().ok();
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Timeout waiting for port-linker to start",
            ))
        }
    }
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
            Duration::from_millis(50),
        )
        .is_ok()
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

/// Wait for a local port to become unavailable (closed)
pub fn wait_for_port_closed(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", port).parse().unwrap(),
            Duration::from_millis(50),
        )
        .is_err()
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
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
/// Uses ControlMaster connection multiplexing for faster execution
pub fn ssh_exec(command: &str) -> std::io::Result<std::process::Output> {
    let control_socket = get_ssh_control_socket();

    std::process::Command::new("ssh")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg(format!("ControlPath={}", control_socket.display()))
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg("-i")
        .arg(test_key_path())
        .arg("-p")
        .arg(SSH_PORT.to_string())
        .arg(format!("{}@{}", SSH_USER, SSH_HOST))
        .arg(command)
        .output()
}

/// Start a TCP service on the remote host and wait for it to be listening.
/// Returns the PID of the service.
pub fn start_remote_service(port: u16) -> Option<u32> {
    // Start a socat TCP echo server (more reliable than nc in a loop)
    let output = ssh_exec(&format!(
        "nohup socat TCP-LISTEN:{},fork,reuseaddr EXEC:'/bin/cat' > /dev/null 2>&1 & echo $!",
        port
    ))
    .ok()?;

    let pid_str = String::from_utf8_lossy(&output.stdout);
    let pid: u32 = pid_str.trim().parse().ok()?;

    // Wait for the service to be listening (deterministic)
    wait_for_remote_port_listening(port, Duration::from_secs(5));

    Some(pid)
}

/// Wait for a port to be listening on the remote host
fn wait_for_remote_port_listening(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        // Check if port is listening using netstat
        let output = ssh_exec(&format!(
            "netstat -tln 2>/dev/null | grep -q ':{} ' && echo yes || echo no",
            port
        ));
        if let Ok(o) = output {
            if String::from_utf8_lossy(&o.stdout).trim() == "yes" {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

/// Wait for a port to NOT be listening on the remote host
pub fn wait_for_remote_port_closed(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        // Check if port is NOT listening using netstat
        let output = ssh_exec(&format!(
            "netstat -tln 2>/dev/null | grep -q ':{} ' && echo yes || echo no",
            port
        ));
        if let Ok(o) = output {
            if String::from_utf8_lossy(&o.stdout).trim() == "no" {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

/// Stop a service on the remote host by PID and wait for it to die.
pub fn stop_remote_service(pid: u32) {
    // Kill the specific PID and all its children (fork'd socat processes)
    let _ = ssh_exec(&format!(
        "kill {} 2>/dev/null; pkill -P {} 2>/dev/null; sleep 0.05; kill -9 {} 2>/dev/null; pkill -9 -P {} 2>/dev/null",
        pid, pid, pid, pid
    ));
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
    socket.set_read_timeout(Some(Duration::from_millis(500))).ok();
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
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// Start a UDP service on the remote host and wait for it to be listening.
/// Returns the PID of the service.
pub fn start_remote_udp_service(port: u16) -> Option<u32> {
    // Start a socat UDP echo server in the background
    let output = ssh_exec(&format!(
        "nohup socat UDP4-LISTEN:{},fork EXEC:'/bin/cat' > /dev/null 2>&1 & echo $!",
        port
    ))
    .ok()?;

    let pid_str = String::from_utf8_lossy(&output.stdout);
    let pid: u32 = pid_str.trim().parse().ok()?;

    // Wait for the service to be listening (deterministic)
    wait_for_remote_udp_port_listening(port, Duration::from_secs(5));

    Some(pid)
}

/// Wait for a UDP port to be listening on the remote host
fn wait_for_remote_udp_port_listening(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        // Check if UDP port is listening using netstat
        let output = ssh_exec(&format!(
            "netstat -uln 2>/dev/null | grep -q ':{} ' && echo yes || echo no",
            port
        ));
        if let Ok(o) = output {
            if String::from_utf8_lossy(&o.stdout).trim() == "yes" {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

// ============================================================================
// TEST HELPERS
// ============================================================================

/// Skip tests if Docker environment is not running.
/// Also performs one-time cleanup of orphaned processes from prior runs.
macro_rules! require_test_env {
    () => {
        if !$crate::is_test_env_running() {
            eprintln!("SKIPPED: Docker test environment not running");
            eprintln!("Run: ./tests/docker/setup-test-env.sh");
            panic!();
        }
        $crate::init_test_env();
    };
}

pub(crate) use require_test_env;

// ============================================================================
// TESTS - NO PORT USAGE (can run fully in parallel)
// ============================================================================

#[test]
#[timeout(20000)]
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
#[timeout(20000)]
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
#[timeout(5000)]
fn test_help_output() {
    let output = Command::new(bin_path())
        .arg("--help")
        .output()
        .expect("Failed to run port-linker --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Verify key elements of help output
    assert!(stdout.contains("Usage: port-linker"), "Missing usage line");
    assert!(stdout.contains("--ports"), "Missing --ports option");
    assert!(stdout.contains("--exclude"), "Missing --exclude option");
    assert!(stdout.contains("--identity"), "Missing --identity option");
    assert!(stdout.contains("--help"), "Missing --help option");
}

#[test]
#[timeout(5000)]
fn test_version_output() {
    let output = Command::new(bin_path())
        .arg("--version")
        .output()
        .expect("Failed to run port-linker --version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("port-linker"), "Missing program name");
}
