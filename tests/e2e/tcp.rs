//! TCP-specific end-to-end tests for port-linker

use super::*;
use ntest::timeout;
use std::time::Duration;

// ============================================================================
// TESTS - USING DOCKER TCP PORT 8080 (HTTP server)
// ============================================================================

#[test]
#[timeout(20000)]
fn test_connects_and_discovers_ports() {
    let _lock = PortLock::acquire(&[DOCKER_TCP_PORT_HTTP]);
    require_test_env!();

    // Use -p 8080 to only forward port 8080, avoiding conflicts with parallel tests
    let child = start_port_linker(&["--scan-interval", "1", "-p", "8080"])
        .expect("Failed to start port-linker");

    // Wait for port 8080 to be forwarded
    let port_8080_ready = wait_for_port(DOCKER_TCP_PORT_HTTP, Duration::from_secs(5));

    // Stop port-linker and wait for cleanup
    stop_port_linker(child, &[DOCKER_TCP_PORT_HTTP]);

    assert!(
        port_8080_ready,
        "Port 8080 was not forwarded within timeout"
    );
}

#[test]
#[timeout(20000)]
fn test_forwards_http_traffic() {
    let _lock = PortLock::acquire(&[DOCKER_TCP_PORT_HTTP]);
    require_test_env!();

    let child = start_port_linker(&["--scan-interval", "1", "-p", "8080"])
        .expect("Failed to start port-linker");

    // Wait for port 8080 to be forwarded
    assert!(
        wait_for_port(DOCKER_TCP_PORT_HTTP, Duration::from_secs(5)),
        "Port 8080 was not forwarded"
    );

    // Make HTTP request through forwarded port
    let response = send_and_receive(DOCKER_TCP_PORT_HTTP, b"GET / HTTP/1.0\r\n\r\n");

    // Stop port-linker and wait for cleanup
    stop_port_linker(child, &[DOCKER_TCP_PORT_HTTP]);

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
#[timeout(20000)]
fn test_clean_shutdown() {
    let _lock = PortLock::acquire(&[DOCKER_TCP_PORT_HTTP]);
    require_test_env!();

    let mut child = start_port_linker(&["--scan-interval", "1", "-p", "8080"])
        .expect("Failed to start port-linker");

    // Wait for port to be forwarded
    assert!(
        wait_for_port(DOCKER_TCP_PORT_HTTP, Duration::from_secs(5)),
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
        wait_for_port_closed(DOCKER_TCP_PORT_HTTP, Duration::from_secs(5)),
        "Port 8080 still open after shutdown"
    );

    // Process should have exited cleanly (or with SIGTERM)
    assert!(
        status.success() || status.code() == Some(130) || status.code().is_none(),
        "Process exited with unexpected status: {:?}",
        status
    );
}

// ============================================================================
// TESTS - USING DOCKER TCP PORT 3000 (localhost-bound echo)
// ============================================================================

#[test]
#[timeout(20000)]
fn test_localhost_bound_port() {
    let _lock = PortLock::acquire(&[DOCKER_TCP_PORT_ECHO]);
    require_test_env!();

    // Port 3000 is bound to 127.0.0.1 on the remote
    let child = start_port_linker(&["--scan-interval", "1", "-p", "3000"])
        .expect("Failed to start port-linker");

    // Wait for port to be forwarded
    let port_ready = wait_for_port(DOCKER_TCP_PORT_ECHO, Duration::from_secs(5));

    // Stop port-linker and wait for cleanup
    stop_port_linker(child, &[DOCKER_TCP_PORT_ECHO]);

    assert!(
        port_ready,
        "Port 3000 (bound to 127.0.0.1 on remote) was not forwarded"
    );
}

// ============================================================================
// TESTS - USING MULTIPLE DOCKER TCP PORTS
// ============================================================================

#[test]
#[timeout(20000)]
fn test_port_whitelist() {
    // Lock both ports we're testing behavior with
    let _lock = PortLock::acquire(&[DOCKER_TCP_PORT_HTTP, DOCKER_TCP_PORT_POSTGRES]);
    require_test_env!();

    // Only forward port 8080
    let child = start_port_linker(&["--scan-interval", "1", "-p", "8080"])
        .expect("Failed to start port-linker");

    // Wait for port 8080 to be forwarded
    assert!(
        wait_for_port(DOCKER_TCP_PORT_HTTP, Duration::from_secs(5)),
        "Port 8080 was not forwarded"
    );

    // Give it a moment to forward other ports (if it incorrectly would)
    // One scan cycle (1s) should be enough
    std::thread::sleep(Duration::from_secs(1));

    // Port 5432 should NOT be forwarded (not in whitelist)
    let port_5432_open = is_port_open(DOCKER_TCP_PORT_POSTGRES);

    // Stop port-linker and wait for cleanup
    stop_port_linker(child, &[DOCKER_TCP_PORT_HTTP]);

    assert!(
        !port_5432_open,
        "Port 5432 was forwarded despite not being in whitelist"
    );
}

#[test]
#[timeout(20000)]
fn test_port_exclusion() {
    // Lock all ports involved
    let _lock = PortLock::acquire(&[
        DOCKER_TCP_PORT_HTTP,
        DOCKER_TCP_PORT_ECHO,
        DOCKER_TCP_PORT_POSTGRES,
    ]);
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
    let port_5432_ready = wait_for_port(DOCKER_TCP_PORT_POSTGRES, Duration::from_secs(5));

    // Give time for 8080 to potentially be forwarded (one scan cycle)
    std::thread::sleep(Duration::from_secs(1));

    // Port 8080 should NOT be forwarded (excluded)
    let port_8080_open = is_port_open(DOCKER_TCP_PORT_HTTP);

    // Stop port-linker and wait for cleanup
    stop_port_linker(child, &[DOCKER_TCP_PORT_ECHO, DOCKER_TCP_PORT_POSTGRES]);

    assert!(port_5432_ready, "Port 5432 was not forwarded");
    assert!(
        !port_8080_open,
        "Port 8080 was forwarded despite being excluded"
    );
}

#[test]
#[timeout(20000)]
fn test_multiple_ports() {
    let _lock = PortLock::acquire(&[DOCKER_TCP_PORT_HTTP, DOCKER_TCP_PORT_POSTGRES]);
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
    let port_8080_ready = wait_for_port(DOCKER_TCP_PORT_HTTP, Duration::from_secs(5));
    let port_5432_ready = wait_for_port(DOCKER_TCP_PORT_POSTGRES, Duration::from_secs(5));

    // Stop port-linker and wait for cleanup
    stop_port_linker(child, &[DOCKER_TCP_PORT_HTTP, DOCKER_TCP_PORT_POSTGRES]);

    assert!(port_8080_ready, "Port 8080 was not forwarded");
    assert!(port_5432_ready, "Port 5432 was not forwarded");
}

// ============================================================================
// TESTS - USING DYNAMIC TCP PORTS (can run in parallel with each other)
// ============================================================================

#[test]
#[timeout(20000)]
fn test_new_service_detected() {
    // Allocate a unique port for this test
    let dynamic_port = allocate_test_port();
    // Also need 8080 for the initial detection check
    let _lock = PortLock::acquire(&[
        DOCKER_TCP_PORT_HTTP,
        DOCKER_TCP_PORT_ECHO,
        DOCKER_TCP_PORT_POSTGRES,
        dynamic_port,
    ]);
    require_test_env!();

    // Start port-linker monitoring all ports except defaults
    let child = start_port_linker(&["--scan-interval", "1", "--no-default-excludes"])
        .expect("Failed to start port-linker");

    // Wait for initial port 8080 to be forwarded
    assert!(
        wait_for_port(DOCKER_TCP_PORT_HTTP, Duration::from_secs(5)),
        "Initial port 8080 was not forwarded"
    );

    // Start a new service on our dynamic port on the remote
    let service_pid = start_remote_service(dynamic_port).expect("Failed to start remote service");

    // Wait for port-linker to detect and forward the new port
    let new_port_ready = wait_for_port(dynamic_port, Duration::from_secs(10));

    // Cleanup
    stop_remote_service(service_pid);
    stop_port_linker(
        child,
        &[
            DOCKER_TCP_PORT_HTTP,
            DOCKER_TCP_PORT_POSTGRES,
            DOCKER_TCP_PORT_ECHO,
        ],
    );

    assert!(
        new_port_ready,
        "New service on port {} was not detected and forwarded",
        dynamic_port
    );
}

#[test]
#[timeout(20000)]
fn test_service_removal_detected() {
    // Allocate a unique port for this test
    let dynamic_port = allocate_test_port();
    let _lock = PortLock::acquire(&[dynamic_port]);
    require_test_env!();

    // Start a temporary service on our dynamic port
    let service_pid = start_remote_service(dynamic_port).expect("Failed to start remote service");

    // Give the service a moment to start
    std::thread::sleep(Duration::from_secs(1));

    // Start port-linker watching only our dynamic port
    let child = start_port_linker(&["--scan-interval", "1", "-p", &dynamic_port.to_string()])
        .expect("Failed to start port-linker");

    // Wait for the service to be forwarded
    assert!(
        wait_for_port(dynamic_port, Duration::from_secs(5)),
        "Port {} was not forwarded",
        dynamic_port
    );

    // Stop the remote service
    stop_remote_service(service_pid);

    // Wait for port-linker to detect the removal and close the forward
    let port_closed = wait_for_port_closed(dynamic_port, Duration::from_secs(10));

    // Cleanup
    stop_port_linker(child, &[]);

    assert!(
        port_closed,
        "Port {} forward was not closed after service stopped",
        dynamic_port
    );
}
