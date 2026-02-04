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

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Test configuration - matches docker-compose setup
const SSH_HOST: &str = "localhost";
const SSH_PORT: u16 = 2222;
const SSH_USER: &str = "testuser";

/// Get the path to the test SSH key
fn test_key_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("tests")
        .join("docker")
        .join("test_key")
}

/// Get the path to the port-linker binary
fn binary_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("target")
        .join("debug")
        .join("port-linker")
}

/// Check if the Docker test environment is running
fn is_test_env_running() -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", SSH_PORT).parse().unwrap(),
        Duration::from_secs(1),
    )
    .is_ok()
}

/// Start port-linker as a background process
fn start_port_linker(extra_args: &[&str]) -> std::io::Result<Child> {
    let key_path = test_key_path();

    let mut cmd = Command::new(binary_path());
    cmd.arg(format!("{}@{}", SSH_USER, SSH_HOST))
        .arg("-P")
        .arg(SSH_PORT.to_string())
        .arg("-i")
        .arg(&key_path)
        .arg("--no-notifications")
        .arg("--log-level")
        .arg("debug")
        .args(extra_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    cmd.spawn()
}

/// Stop port-linker and wait for cleanup
fn stop_port_linker(mut child: Child, ports: &[u16]) {
    child.kill().ok();
    let _ = child.wait();

    // Wait for ports to be released
    for &port in ports {
        wait_for_port_closed(port, Duration::from_secs(5));
    }
}

/// Wait for a local port to become available
fn wait_for_port(port: u16, timeout: Duration) -> bool {
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

/// Wait for a local port to become unavailable
fn wait_for_port_closed(port: u16, timeout: Duration) -> bool {
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
fn is_port_open(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", port).parse().unwrap(),
        Duration::from_millis(500),
    )
    .is_ok()
}

/// Send data through a forwarded port and get response
fn send_and_receive(port: u16, data: &[u8]) -> std::io::Result<Vec<u8>> {
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
// TESTS
// ============================================================================

/// Skip tests if Docker environment is not running
macro_rules! require_test_env {
    () => {
        if !is_test_env_running() {
            eprintln!("SKIPPED: Docker test environment not running");
            eprintln!("Run: ./tests/docker/setup-test-env.sh");
            return;
        }
    };
}

#[test]
fn test_binary_exists() {
    let path = binary_path();
    assert!(
        path.exists(),
        "port-linker binary not found at {:?}. Run `cargo build` first.",
        path
    );
}

#[test]
#[ignore] // Requires Docker environment setup
fn test_ssh_key_exists() {
    let path = test_key_path();
    assert!(
        path.exists(),
        "Test SSH key not found at {:?}. Run `./tests/docker/setup-test-env.sh` first.",
        path
    );
}

#[test]
#[ignore] // Requires Docker environment
fn test_connects_and_discovers_ports() {
    require_test_env!();

    let child = start_port_linker(&["--scan-interval", "1"]).expect("Failed to start port-linker");

    // Wait for ports to be forwarded
    let port_8080_ready = wait_for_port(8080, Duration::from_secs(15));

    // Stop port-linker and wait for cleanup
    stop_port_linker(child, &[8080]);

    assert!(
        port_8080_ready,
        "Port 8080 was not forwarded within timeout"
    );
}

#[test]
#[ignore] // Requires Docker environment
fn test_forwards_http_traffic() {
    require_test_env!();

    let child = start_port_linker(&["--scan-interval", "1", "-p", "8080"])
        .expect("Failed to start port-linker");

    // Wait for port 8080 to be forwarded
    assert!(
        wait_for_port(8080, Duration::from_secs(15)),
        "Port 8080 was not forwarded"
    );

    // Make HTTP request through forwarded port
    let response = send_and_receive(8080, b"GET / HTTP/1.0\r\n\r\n");

    // Stop port-linker and wait for cleanup
    stop_port_linker(child, &[8080]);

    assert!(
        response.is_ok(),
        "Failed to connect through forwarded port: {:?}",
        response.err()
    );
    let response_data = response.unwrap();
    assert!(
        !response_data.is_empty(),
        "Got empty response from forwarded port"
    );
}

#[test]
#[ignore] // Requires Docker environment
fn test_port_whitelist() {
    require_test_env!();

    // Only forward port 8080
    let child = start_port_linker(&["--scan-interval", "1", "-p", "8080"])
        .expect("Failed to start port-linker");

    // Wait for port 8080 to be forwarded
    assert!(
        wait_for_port(8080, Duration::from_secs(15)),
        "Port 8080 was not forwarded"
    );

    // Give it a moment to forward other ports (if it incorrectly would)
    std::thread::sleep(Duration::from_secs(3));

    // Port 5432 should NOT be forwarded (not in whitelist)
    let port_5432_open = is_port_open(5432);

    // Stop port-linker and wait for cleanup
    stop_port_linker(child, &[8080]);

    assert!(
        !port_5432_open,
        "Port 5432 was forwarded despite not being in whitelist"
    );
}

#[test]
#[ignore] // Requires Docker environment
fn test_port_exclusion() {
    require_test_env!();

    // Exclude port 8080
    let child = start_port_linker(&[
        "--scan-interval",
        "1",
        "-x",
        "8080",
        "--no-default-excludes",
    ])
    .expect("Failed to start port-linker");

    // Wait for port 5432 to be forwarded (should be forwarded)
    let port_5432_ready = wait_for_port(5432, Duration::from_secs(15));

    // Give time for 8080 to potentially be forwarded
    std::thread::sleep(Duration::from_secs(2));

    // Port 8080 should NOT be forwarded (excluded)
    let port_8080_open = is_port_open(8080);

    // Stop port-linker and wait for cleanup
    stop_port_linker(child, &[3000, 5432]);

    assert!(port_5432_ready, "Port 5432 was not forwarded");
    assert!(
        !port_8080_open,
        "Port 8080 was forwarded despite being excluded"
    );
}

#[test]
#[ignore] // Requires Docker environment
fn test_clean_shutdown() {
    require_test_env!();

    let mut child = start_port_linker(&["--scan-interval", "1", "-p", "8080"])
        .expect("Failed to start port-linker");

    // Wait for port to be forwarded
    assert!(
        wait_for_port(8080, Duration::from_secs(15)),
        "Port 8080 was not forwarded"
    );

    // Send SIGTERM for graceful shutdown
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }

    // Wait for process to exit
    let status = child.wait().expect("Failed to wait for process");

    // Port should be closed after shutdown
    assert!(
        wait_for_port_closed(8080, Duration::from_secs(5)),
        "Port 8080 still open after shutdown"
    );

    // Process should have exited cleanly (or with SIGTERM)
    assert!(
        status.success() || status.code() == Some(130) || status.code().is_none(),
        "Process exited with unexpected status: {:?}",
        status
    );
}

#[test]
#[ignore] // Requires Docker environment
fn test_multiple_ports() {
    require_test_env!();

    let child = start_port_linker(&[
        "--scan-interval",
        "1",
        "-p",
        "8080,5432",
        "--no-default-excludes",
    ])
    .expect("Failed to start port-linker");

    // Wait for both ports
    let port_8080_ready = wait_for_port(8080, Duration::from_secs(15));
    let port_5432_ready = wait_for_port(5432, Duration::from_secs(5));

    // Stop port-linker and wait for cleanup
    stop_port_linker(child, &[8080, 5432]);

    assert!(port_8080_ready, "Port 8080 was not forwarded");
    assert!(port_5432_ready, "Port 5432 was not forwarded");
}

#[test]
#[ignore] // Requires Docker environment
fn test_localhost_bound_port() {
    require_test_env!();

    // Port 3000 is bound to 127.0.0.1 on the remote
    let child = start_port_linker(&["--scan-interval", "1", "-p", "3000"])
        .expect("Failed to start port-linker");

    // Wait for port to be forwarded
    let port_ready = wait_for_port(3000, Duration::from_secs(15));

    // Stop port-linker and wait for cleanup
    stop_port_linker(child, &[3000]);

    assert!(
        port_ready,
        "Port 3000 (bound to 127.0.0.1 on remote) was not forwarded"
    );
}

#[test]
#[ignore] // Requires Docker environment
fn test_invalid_ssh_host() {
    // This should fail quickly with connection error
    let key_path = test_key_path();

    let output = Command::new(binary_path())
        .arg("testuser@nonexistent.invalid")
        .arg("-i")
        .arg(&key_path)
        .arg("--no-notifications")
        .output()
        .expect("Failed to run port-linker");

    assert!(
        !output.status.success(),
        "port-linker should fail with invalid host"
    );
}

#[test]
#[ignore] // Requires Docker environment
fn test_invalid_ssh_key() {
    require_test_env!();

    // Use a non-existent key
    let output = Command::new(binary_path())
        .arg(format!("{}@{}", SSH_USER, SSH_HOST))
        .arg("-P")
        .arg(SSH_PORT.to_string())
        .arg("-i")
        .arg("/nonexistent/key")
        .arg("--no-notifications")
        .output()
        .expect("Failed to run port-linker");

    assert!(
        !output.status.success(),
        "port-linker should fail with invalid key"
    );
}
