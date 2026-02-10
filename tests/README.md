# Integration Tests for port-linker

This directory contains comprehensive integration tests for Phase 1 of the port-linker project.

## Overview

The integration test suite validates end-to-end behavior of the agent and CLI binaries, including:

- **Process lifecycle**: Spawning the agent binary, parsing its stdout for connection info, establishing QUIC connections
- **QUIC connection establishment**: TLS handshake with self-signed certificates, bidirectional stream setup
- **Protocol handshake**: Version validation and token exchange
- **Echo functionality**: Request/response fidelity across various payload sizes
- **Heartbeat mechanism**: Keep-alive ping/pong behavior
- **Error handling**: Protocol version mismatches, connection timeouts
- **Robustness**: Multiple sequential operations on the same stream

## Test Coverage

### Process Lifecycle Tests

- `test_process_lifecycle`: Full end-to-end test spawning agent, connecting client, performing echo, and clean shutdown
- `test_agent_no_connection_timeout`: Verifies agent doesn't crash when no client connects

### Echo Payload Fidelity Tests

- `test_echo_empty_payload`: Echo with zero-byte payload
- `test_echo_one_byte_payload`: Echo with single byte
- `test_echo_1kb_payload`: Echo with 1KB payload
- `test_echo_near_1mb_payload`: Echo with 900KB payload (near max frame size)

### Protocol Tests

- `test_protocol_version_validation`: Verifies codec can handle version mismatches (CLI rejects in practice)
- `test_heartbeat`: Heartbeat request/response cycle
- `test_multiple_echo_roundtrips`: Multiple sequential echo requests on same stream
- `test_mixed_echo_and_heartbeat`: Interleaved echo and heartbeat operations

## Running the Tests

### Run all integration tests
```bash
cargo test -p integration-tests
```

### Run a specific test
```bash
cargo test -p integration-tests test_process_lifecycle
```

### Run with verbose output
```bash
cargo test -p integration-tests -- --nocapture
```

## Test Architecture

### Helper Functions

- `spawn_agent()`: Spawns the agent binary and parses stdout for AGENT_READY/PORT/TOKEN
- `build_client_endpoint()`: Creates QUIC client endpoint with TLS verification disabled (for self-signed certs)
- `send_msg()` / `recv_msg()`: Length-prefixed message framing over QUIC streams
- `SkipServerVerification`: TLS certificate verifier that accepts self-signed certs

### Test Isolation

Each test:
- Spawns its own agent process on a random port
- Creates its own QUIC client endpoint
- Cleans up processes via `Drop` implementation on `AgentProcess`
- Runs independently with no shared state

### Agent Process Management

The `AgentProcess` struct manages the lifecycle of spawned agent processes:
- Parses stdout during startup to extract port and token
- Implements `Drop` to ensure processes are killed even if tests panic
- Provides clean shutdown capabilities

## What's NOT Covered

These integration tests focus on Phase 1 functionality. The following are out of scope:

- **Port discovery**: Not implemented in Phase 1
- **Port forwarding**: Not implemented in Phase 1
- **UDP data packets**: Protocol defined but not exercised
- **SSH deployment**: Tested separately in end-to-end scenarios
- **Multiple concurrent connections**: Agent accepts one connection in Phase 1
- **TLS certificate validation**: Skipped for self-signed certs in Phase 1

## Known Limitations

1. **Binary path resolution**: Tests assume the agent binary is built in `target/debug/port-linker-agent`. Run `cargo build --bin port-linker-agent` before testing.

2. **Timing sensitivity**: Some tests use small delays for process cleanup. If running on very slow systems, timeouts may need adjustment.

3. **Protocol version testing**: The version mismatch test validates codec behavior but doesn't spawn a modified agent. True version mismatch rejection is tested at the unit level in the CLI binary.

## Future Enhancements

As the project evolves, consider adding:

- **Stress tests**: High-frequency echo requests, large payload streams
- **Concurrent connection tests**: Multiple clients (when supported)
- **Port discovery integration**: Test port scanning and reporting
- **Error injection**: Simulate network failures, corrupted frames
- **Performance benchmarks**: Latency measurements, throughput testing
