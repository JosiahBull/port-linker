//! UDP-specific end-to-end tests for port-linker

use super::*;
use ntest::timeout;
use std::time::Duration;

// ============================================================================
// UDP TESTS - USING DYNAMIC PORTS (can run in parallel)
// ============================================================================
// These tests start their own UDP services on dynamic ports, allowing them
// to run in parallel with each other and with other tests.

#[test]
#[timeout(20000)]
fn test_udp_discovers_ports() {
    let dynamic_port = allocate_test_port();
    let _lock = PortLock::acquire(&[dynamic_port]);
    require_test_env!();

    // Start our own UDP echo service on the dynamic port
    let service_pid = start_remote_udp_service(dynamic_port).expect("Failed to start UDP service");

    // Give socat time to start
    std::thread::sleep(Duration::from_millis(500));

    // Start port-linker with UDP protocol
    let child = start_port_linker(&[
        "--scan-interval",
        "1",
        "--protocol",
        "udp",
        "-p",
        &dynamic_port.to_string(),
        "--no-default-excludes",
    ])
    .expect("Failed to start port-linker");

    // Wait for UDP port to be forwarded and responding
    let port_ready = wait_for_udp_port(dynamic_port, Duration::from_secs(10));

    // Cleanup
    stop_port_linker(child, &[]);
    stop_remote_service(service_pid);

    assert!(
        port_ready,
        "UDP port {} was not forwarded or not responding within timeout",
        dynamic_port
    );
}

#[test]
#[timeout(20000)]
fn test_udp_echo_traffic() {
    let dynamic_port = allocate_test_port();
    let _lock = PortLock::acquire(&[dynamic_port]);
    require_test_env!();

    // Start our own UDP echo service
    let service_pid = start_remote_udp_service(dynamic_port).expect("Failed to start UDP service");
    std::thread::sleep(Duration::from_millis(500));

    // Start port-linker with UDP protocol
    let child = start_port_linker(&[
        "--scan-interval",
        "1",
        "--protocol",
        "udp",
        "-p",
        &dynamic_port.to_string(),
        "--no-default-excludes",
    ])
    .expect("Failed to start port-linker");

    // Wait for UDP port to be forwarded
    assert!(
        wait_for_udp_port(dynamic_port, Duration::from_secs(10)),
        "UDP port {} was not forwarded",
        dynamic_port
    );

    // Send test data through the UDP tunnel
    let test_data = b"Hello UDP World!";
    let response = udp_send_and_receive(dynamic_port, test_data);

    // Cleanup
    stop_port_linker(child, &[]);
    stop_remote_service(service_pid);

    assert!(
        response.is_ok(),
        "Failed to send/receive UDP data: {:?}",
        response.err()
    );
    let response_data = response.unwrap();
    assert_eq!(
        response_data,
        test_data,
        "UDP echo response mismatch: got {:?}, expected {:?}",
        String::from_utf8_lossy(&response_data),
        String::from_utf8_lossy(test_data)
    );
}

#[test]
#[timeout(20000)]
fn test_udp_multiple_packets() {
    let dynamic_port = allocate_test_port();
    let _lock = PortLock::acquire(&[dynamic_port]);
    require_test_env!();

    // Start our own UDP echo service
    let service_pid = start_remote_udp_service(dynamic_port).expect("Failed to start UDP service");
    std::thread::sleep(Duration::from_millis(500));

    // Start port-linker with UDP protocol
    let child = start_port_linker(&[
        "--scan-interval",
        "1",
        "--protocol",
        "udp",
        "-p",
        &dynamic_port.to_string(),
        "--no-default-excludes",
    ])
    .expect("Failed to start port-linker");

    // Wait for UDP port to be forwarded
    assert!(
        wait_for_udp_port(dynamic_port, Duration::from_secs(10)),
        "UDP port {} was not forwarded",
        dynamic_port
    );

    // Send multiple packets and verify responses
    let test_messages = [
        b"First packet".to_vec(),
        b"Second packet".to_vec(),
        b"Third packet with more data".to_vec(),
    ];

    let mut all_passed = true;
    for msg in &test_messages {
        match udp_send_and_receive(dynamic_port, msg) {
            Ok(response) => {
                if response != *msg {
                    eprintln!(
                        "Mismatch: sent {:?}, got {:?}",
                        String::from_utf8_lossy(msg),
                        String::from_utf8_lossy(&response)
                    );
                    all_passed = false;
                }
            }
            Err(e) => {
                eprintln!("Failed to send/receive: {}", e);
                all_passed = false;
            }
        }
        // Small delay between packets
        std::thread::sleep(Duration::from_millis(100));
    }

    // Cleanup
    stop_port_linker(child, &[]);
    stop_remote_service(service_pid);

    assert!(all_passed, "Not all UDP packets were echoed correctly");
}

// ============================================================================
// UDP TESTS - LOCALHOST-BOUND PORT (requires Docker's port 9999)
// ============================================================================
// This test specifically verifies that localhost-bound ports are forwarded.
// Port 9999 in Docker is bound to 127.0.0.1, not 0.0.0.0.

#[test]
#[timeout(20000)]
fn test_udp_localhost_bound_port() {
    let _lock = PortLock::acquire(&[DOCKER_UDP_PORT_ECHO_LOCALHOST]);
    require_test_env!();

    // Port 9999 is bound to 127.0.0.1 on the remote (pre-configured in Docker)
    let child = start_port_linker(&[
        "--scan-interval",
        "1",
        "--protocol",
        "udp",
        "-p",
        "9999",
        "--no-default-excludes",
    ])
    .expect("Failed to start port-linker");

    // Wait for UDP port to be forwarded
    let port_ready = wait_for_udp_port(DOCKER_UDP_PORT_ECHO_LOCALHOST, Duration::from_secs(10));

    // Stop port-linker
    stop_port_linker(child, &[]);

    assert!(
        port_ready,
        "UDP port 9999 (bound to 127.0.0.1 on remote) was not forwarded"
    );
}

// ============================================================================
// UDP TESTS - USING BOTH TCP AND UDP PORTS
// ============================================================================

#[test]
#[timeout(30000)]
fn test_udp_both_protocols() {
    let dynamic_udp_port = allocate_test_port();
    let _lock = PortLock::acquire(&[DOCKER_TCP_PORT_HTTP, dynamic_udp_port]);
    require_test_env!();

    // Start our own UDP echo service on dynamic port
    let service_pid =
        start_remote_udp_service(dynamic_udp_port).expect("Failed to start UDP service");
    std::thread::sleep(Duration::from_millis(500));

    // Start port-linker with both protocols
    let child = start_port_linker(&[
        "--scan-interval",
        "1",
        "--protocol",
        "both",
        "-p",
        &format!("8080,{}", dynamic_udp_port),
        "--no-default-excludes",
    ])
    .expect("Failed to start port-linker");

    // Wait for TCP port 8080 to be forwarded
    let tcp_ready = wait_for_port(DOCKER_TCP_PORT_HTTP, Duration::from_secs(5));

    // Wait for UDP port to be forwarded
    let udp_ready = wait_for_udp_port(dynamic_udp_port, Duration::from_secs(10));

    // Cleanup
    stop_port_linker(child, &[DOCKER_TCP_PORT_HTTP]);
    stop_remote_service(service_pid);

    assert!(tcp_ready, "TCP port 8080 was not forwarded");
    assert!(
        udp_ready,
        "UDP port {} was not forwarded",
        dynamic_udp_port
    );
}

// ============================================================================
// UDP TESTS - DYNAMIC SERVICE DETECTION
// ============================================================================

#[test]
#[timeout(30000)]
fn test_udp_new_service_detected() {
    // Allocate two unique ports - one for initial service, one for "new" service
    let initial_port = allocate_test_port();
    let new_service_port = allocate_test_port();
    let _lock = PortLock::acquire(&[initial_port, new_service_port]);
    require_test_env!();

    // Start initial UDP service
    let initial_pid =
        start_remote_udp_service(initial_port).expect("Failed to start initial UDP service");
    std::thread::sleep(Duration::from_millis(500));

    // Start port-linker monitoring both ports
    let child = start_port_linker(&[
        "--scan-interval",
        "1",
        "--protocol",
        "udp",
        "-p",
        &format!("{},{}", initial_port, new_service_port),
        "--no-default-excludes",
    ])
    .expect("Failed to start port-linker");

    // Wait for initial port to be forwarded
    assert!(
        wait_for_udp_port(initial_port, Duration::from_secs(10)),
        "Initial UDP port {} was not forwarded",
        initial_port
    );

    // Start a new UDP service on the second port
    let new_pid =
        start_remote_udp_service(new_service_port).expect("Failed to start new UDP service");

    // Give socat time to start
    std::thread::sleep(Duration::from_secs(2));

    // Wait for port-linker to detect and forward the new port
    let new_port_ready = wait_for_udp_port(new_service_port, Duration::from_secs(10));

    // Cleanup
    stop_remote_service(initial_pid);
    stop_remote_service(new_pid);
    stop_port_linker(child, &[]);

    assert!(
        new_port_ready,
        "New UDP service on port {} was not detected and forwarded",
        new_service_port
    );
}

// ============================================================================
// UDP HEALTHCHECK AND RECONNECTION TESTS
// ============================================================================
// These tests verify proxy health monitoring and restart behavior.
// Wait times can be configured via environment variables for faster CI:
//   E2E_HEALTHCHECK_WAIT_SECS=5 E2E_HEALTHCHECK_LONG_WAIT_SECS=10 cargo test

/// Kill the udp-proxy process on the remote to simulate proxy death
fn kill_remote_udp_proxy() -> bool {
    // Find and kill all udp-proxy processes on the remote
    // Note: Don't use `-f` flag with pkill in BusyBox as it matches the SSH command line itself
    let output = ssh_exec("pkill udp-proxy 2>/dev/null; echo $?");
    match output {
        Ok(o) => {
            let status = String::from_utf8_lossy(&o.stdout).trim().to_string();
            // pkill returns 0 if at least one process was killed
            status == "0"
        }
        Err(_) => false,
    }
}

/// Check if udp-proxy is running on the remote
fn is_udp_proxy_running() -> bool {
    // Note: Don't use `-f` flag with pgrep in BusyBox as it can match the SSH command line
    let output = ssh_exec("pgrep udp-proxy >/dev/null 2>&1 && echo yes || echo no");
    match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim() == "yes",
        Err(_) => false,
    }
}

#[test]
#[timeout(30000)]
fn test_udp_proxy_restart_after_remote_kill() {
    let dynamic_port = allocate_test_port();
    let _lock = PortLock::acquire(&[dynamic_port]);
    require_test_env!();

    // Start our own UDP echo service
    let service_pid = start_remote_udp_service(dynamic_port).expect("Failed to start UDP service");
    std::thread::sleep(Duration::from_millis(500));

    // Start port-linker with UDP protocol
    let child = start_port_linker(&[
        "--scan-interval",
        "2",
        "--protocol",
        "udp",
        "-p",
        &dynamic_port.to_string(),
        "--no-default-excludes",
    ])
    .expect("Failed to start port-linker");

    // Wait for UDP port to be forwarded and working
    assert!(
        wait_for_udp_port(dynamic_port, Duration::from_secs(10)),
        "UDP port {} was not forwarded initially",
        dynamic_port
    );

    // Verify initial traffic works
    let initial_response = udp_send_and_receive(dynamic_port, b"initial test");
    assert!(
        initial_response.is_ok(),
        "Initial UDP traffic failed: {:?}",
        initial_response.err()
    );

    // Kill the udp-proxy on the remote
    eprintln!("Killing remote udp-proxy process...");
    let killed = kill_remote_udp_proxy();
    assert!(killed, "Failed to kill remote udp-proxy");

    // When the proxy is killed, the SSH channel closes immediately.
    // The port-linker detects this via ChannelClosed (not healthcheck timeout)
    // and restarts the proxy on the next scan cycle (within a few seconds).
    eprintln!("Waiting for automatic proxy restart...");

    // Wait for UDP port to become responsive again (proxy restarted)
    let port_recovered = wait_for_udp_port(dynamic_port, Duration::from_secs(10));

    // Verify traffic works after recovery
    let recovered_response = if port_recovered {
        udp_send_and_receive(dynamic_port, b"recovered test")
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Port not recovered",
        ))
    };

    // Cleanup
    stop_port_linker(child, &[]);
    stop_remote_service(service_pid);

    assert!(
        port_recovered,
        "UDP port {} did not recover after proxy restart",
        dynamic_port
    );
    assert!(
        recovered_response.is_ok(),
        "UDP traffic failed after recovery: {:?}",
        recovered_response.err()
    );
}

#[test]
#[timeout(120000)] // 2 minutes max, but configurable via env var
fn test_udp_healthcheck_keeps_proxy_alive() {
    let dynamic_port = allocate_test_port();
    let _lock = PortLock::acquire(&[dynamic_port]);
    require_test_env!();

    // Start our own UDP echo service
    let service_pid = start_remote_udp_service(dynamic_port).expect("Failed to start UDP service");
    std::thread::sleep(Duration::from_millis(500));

    // Start port-linker with UDP protocol
    let child = start_port_linker(&[
        "--scan-interval",
        "2",
        "--protocol",
        "udp",
        "-p",
        &dynamic_port.to_string(),
        "--no-default-excludes",
    ])
    .expect("Failed to start port-linker");

    // Wait for UDP port to be forwarded
    assert!(
        wait_for_udp_port(dynamic_port, Duration::from_secs(10)),
        "UDP port {} was not forwarded",
        dynamic_port
    );

    // Verify the proxy is running
    assert!(is_udp_proxy_running(), "udp-proxy should be running");

    // Wait for healthcheck interval (configurable via E2E_HEALTHCHECK_WAIT_SECS)
    // Default: 30 seconds, well under the 60s healthcheck timeout
    let wait_secs = get_healthcheck_wait_secs();
    eprintln!(
        "Waiting {} seconds to verify healthcheck keeps proxy alive...",
        wait_secs
    );
    std::thread::sleep(Duration::from_secs(wait_secs));

    // Verify the proxy is still running
    let still_running = is_udp_proxy_running();

    // Verify traffic still works
    let response = udp_send_and_receive(dynamic_port, b"after wait test");

    // Cleanup
    stop_port_linker(child, &[]);
    stop_remote_service(service_pid);

    assert!(
        still_running,
        "udp-proxy should still be running after {} seconds (healthcheck keeps it alive)",
        wait_secs
    );
    assert!(
        response.is_ok(),
        "UDP traffic failed after {}s: {:?}",
        wait_secs,
        response.err()
    );
}

#[test]
#[timeout(120000)] // 2 minutes max, but configurable via env var
fn test_udp_tunnel_survives_traffic_pause() {
    let dynamic_port = allocate_test_port();
    let _lock = PortLock::acquire(&[dynamic_port]);
    require_test_env!();

    // Start our own UDP echo service
    let service_pid = start_remote_udp_service(dynamic_port).expect("Failed to start UDP service");
    std::thread::sleep(Duration::from_millis(500));

    // Start port-linker with UDP protocol
    let child = start_port_linker(&[
        "--scan-interval",
        "2",
        "--protocol",
        "udp",
        "-p",
        &dynamic_port.to_string(),
        "--no-default-excludes",
    ])
    .expect("Failed to start port-linker");

    // Wait for UDP port to be forwarded
    assert!(
        wait_for_udp_port(dynamic_port, Duration::from_secs(10)),
        "UDP port {} was not forwarded",
        dynamic_port
    );

    // Send initial traffic
    let initial = udp_send_and_receive(dynamic_port, b"before pause");
    assert!(initial.is_ok(), "Initial traffic failed");

    // Wait with no traffic (configurable via E2E_HEALTHCHECK_LONG_WAIT_SECS)
    // Default: 45 seconds. Healthcheck pings should keep the connection alive.
    let wait_secs = get_healthcheck_long_wait_secs();
    eprintln!("Pausing traffic for {} seconds...", wait_secs);
    std::thread::sleep(Duration::from_secs(wait_secs));

    // Traffic should still work
    let after_pause = udp_send_and_receive(dynamic_port, b"after pause");

    // Cleanup
    stop_port_linker(child, &[]);
    stop_remote_service(service_pid);

    assert!(
        after_pause.is_ok(),
        "UDP traffic failed after {}s pause: {:?}",
        wait_secs,
        after_pause.err()
    );
    assert_eq!(
        after_pause.unwrap(),
        b"after pause",
        "Response mismatch after pause"
    );
}
