# Phase 1 Test Plan: QUIC Echo Baseline

## Overview

This document defines the comprehensive test strategy for Phase 1 of port-linker. Phase 1 establishes the foundational QUIC communication layer between the CLI (host) and Agent (remote) binaries, validated through a simple echo protocol.

**Phase 1 Success Criteria:**
1. Agent starts, binds UDP, outputs handshake to stdout
2. CLI connects via QUIC using handshake info
3. Agent sends Handshake message on control stream (stream 0)
4. CLI sends EchoRequest, Agent returns EchoResponse
5. CLI validates echo payload matches

**Testing Constraints:**
- Full test suite must complete in under 20 seconds (CI requirement)
- Tests must be deterministic and isolated
- Integration tests must handle process lifecycle correctly

---

## 1. Unit Test Matrix: `protocol` Crate

### 1.1 Codec Tests (Already Implemented)

**Location:** `crates/protocol/src/codec.rs`

The codec already has solid coverage. The following tests exist and should be maintained:

| Test Name | Input | Assertions | Coverage |
|-----------|-------|------------|----------|
| `roundtrip_handshake` | `ControlMsg::Handshake` with version + token | Encode/decode produces identical message | Happy path |
| `roundtrip_port_added` | `ControlMsg::PortAdded` with TCP/8080 | Serialization preserves port and protocol | Happy path |
| `roundtrip_port_removed` | `ControlMsg::PortRemoved` with UDP/53 | Serialization preserves port and protocol | Happy path |
| `roundtrip_heartbeat` | `ControlMsg::Heartbeat` | Unit variant serializes correctly | Edge: no data |
| `roundtrip_echo_request` | `EchoRequest` with small payload | Payload preserved | Phase 1 critical |
| `roundtrip_echo_response` | `EchoResponse` with hex payload | Payload preserved | Phase 1 critical |
| `roundtrip_packet_control` | `Packet::Control(Heartbeat)` | Wrapping preserved | Envelope test |
| `roundtrip_packet_udp_data` | `UdpData` with 128 bytes | Port + data preserved | UDP path |
| `decode_garbage_returns_error` | Random bytes `[0x00, 0xFF, ...]` | Returns `Err` | Error: malformed |
| `decode_empty_returns_error` | Empty slice | Returns `Err` | Error: empty |
| `roundtrip_large_payload` | 1MB UDP data | Handles large payloads | Stress: size |

### 1.2 Additional Protocol Tests to Add

**File:** `crates/protocol/tests/protocol_edge_cases.rs`

| Test Name | Input | Assertions | Rationale |
|-----------|-------|------------|-----------|
| `handshake_empty_token` | Handshake with `token: ""` | Encodes/decodes successfully | Agent might generate empty token on failure |
| `handshake_long_token` | Token with 10,000 chars | Encodes/decodes successfully | Stress: token size |
| `handshake_unicode_token` | Token with emoji/Chinese chars | Encodes/decodes successfully | Unicode safety |
| `echo_max_size_payload` | EchoRequest with 10MB payload | Encodes successfully OR returns size error | Prevent OOM attacks |
| `port_boundary_values` | Ports: 0, 1, 80, 443, 65535 | All serialize correctly | Boundary testing |
| `protocol_version_mismatch` | Handshake with version 999 | Decodes successfully (validation is CLI/Agent responsibility) | Future compatibility |
| `nested_control_in_packet` | `Packet::Control(EchoRequest)` | Correct nesting preserved | Envelope integrity |
| `udp_data_empty_payload` | `UdpData { port: 53, data: vec![] }` | Empty vec preserved | Edge: zero-length UDP |
| `udp_data_max_mtu` | Data with 65,507 bytes (max UDP) | Serializes correctly | Stress: UDP max |
| `concurrent_encode` | Encode same message from 10 threads | All succeed, produce identical bytes | Thread safety |

**Implementation Notes:**
- Use property-based testing (e.g., `proptest` or `quickcheck`) for boundary values
- Fuzz testing should be considered for codec (see Section 7)
- Add explicit tests for `Protocol::Tcp` and `Protocol::Udp` equality/hashing

### 1.3 Constants and Type Tests

**File:** `crates/protocol/tests/protocol_types.rs`

| Test Name | Assertions | Rationale |
|-----------|------------|-----------|
| `protocol_version_is_stable` | `PROTOCOL_VERSION == 1` | Prevent accidental changes |
| `protocol_enum_hash` | Protocol variants hash consistently | Required for HashMap usage |
| `protocol_enum_equality` | `Tcp == Tcp`, `Tcp != Udp` | Verify derive(PartialEq) |
| `control_msg_clone` | Cloned messages are equal | Verify derive(Clone) |
| `control_msg_debug` | Debug output contains key fields | Debugging support |

---

## 2. Unit Test Matrix: `common` Crate

### 2.1 Token Generation Tests (Partially Implemented)

**Location:** `crates/common/src/lib.rs`

Existing tests:
- `token_is_unique`: Two tokens differ
- `token_has_prefix`: Starts with `plk-`
- `token_is_nonempty`: Length > 10

### 2.2 Additional Token Tests to Add

**File:** `crates/common/tests/token_tests.rs`

| Test Name | Input | Assertions | Rationale |
|-----------|-------|------------|-----------|
| `token_format_validation` | Generate 100 tokens | All match regex `^plk-[0-9a-f]+-[0-9a-f]+$` | Format contract |
| `token_uniqueness_stress` | Generate 10,000 tokens in tight loop | All unique (no collisions) | Collision resistance |
| `token_concurrent_generation` | Generate from 8 threads simultaneously | No panics, all unique | Thread safety |
| `token_min_entropy` | Generate 1000 tokens | Each has > 32 hex chars total | Entropy requirement |
| `token_time_component` | Generate with mocked time | Time component changes predictably | Time-based uniqueness |
| `token_no_sensitive_data` | Inspect token bytes | No kernel addresses, PIDs, etc. | Security: info leak |

### 2.3 Error Type Tests

**File:** `crates/common/tests/error_tests.rs`

| Test Name | Assertions | Rationale |
|-----------|------------|-----------|
| `error_display_format` | Each variant has meaningful Display output | User-facing errors |
| `error_from_io` | `std::io::Error` converts to `Error::Io` | Error conversion |
| `error_is_send_sync` | Error implements Send + Sync | Required for async |
| `error_source_chain` | Nested errors preserve `source()` | Error propagation |

---

## 3. Integration Test Design: End-to-End QUIC Echo

### 3.1 Test Infrastructure

**File:** `crates/integration-tests/src/lib.rs`

Create a dedicated integration test crate with helper utilities:

```rust
/// Test harness for agent/cli integration tests
pub struct TestHarness {
    agent_process: Child,
    agent_port: u16,
    agent_token: String,
    temp_dir: TempDir,
}

impl TestHarness {
    /// Starts agent, waits for handshake, returns parsed connection info
    pub async fn start_agent() -> Result<Self>;

    /// Runs CLI with given args, returns stdout/stderr
    pub async fn run_cli(&self, args: &[&str]) -> Result<Output>;

    /// Sends SIGTERM, waits 2s, sends SIGKILL if needed
    pub fn stop_agent(&mut self) -> Result<()>;
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        let _ = self.stop_agent();
    }
}
```

**Timeout Handling:**
- All subprocess operations have 5-second timeouts
- Use `tokio::time::timeout()` for async operations
- Agent stdout parsing has 2-second timeout (should be instant)

**Process Cleanup:**
- `Drop` implementation ensures cleanup on panic
- Store PIDs and use `kill -9` in CI cleanup script
- Tests spawn processes with unique temp directories to avoid conflicts

### 3.2 Agent Startup Tests

**File:** `crates/integration-tests/tests/agent_startup.rs`

| Test Name | Setup | Actions | Assertions | Failure Modes |
|-----------|-------|---------|------------|---------------|
| `agent_starts_and_outputs_handshake` | None | Start agent | Stdout contains `AGENT_READY`, `PORT=`, `TOKEN=` within 2s | Agent crashes, binds wrong port |
| `agent_binds_unique_udp_port` | Start two agents | Parse both ports | Ports differ, both in range 1024-65535 | Port collision |
| `agent_token_is_valid_format` | Start agent | Parse token | Matches `plk-*` format | Invalid token generation |
| `agent_exits_cleanly_on_sigterm` | Start agent | Send SIGTERM | Exits with code 0 within 1s | Hangs, crashes |
| `agent_handles_port_in_use` | Bind UDP port 9000 externally | Start agent | Agent either uses different port or exits gracefully | Panics, binds conflicting port |
| `agent_outputs_to_stdout_only` | Start agent | Capture stdout/stderr separately | Handshake on stdout, stderr empty (or only warnings) | Pollutes stderr |
| `agent_rejects_invalid_args` | None | Start agent with `--invalid-flag` | Exits with non-zero, prints usage | Hangs, crashes |

### 3.3 CLI Connection Tests

**File:** `crates/integration-tests/tests/cli_connection.rs`

| Test Name | Setup | Actions | Assertions | Failure Modes |
|-----------|-------|---------|------------|---------------|
| `cli_connects_to_agent` | Start agent | Run CLI with agent's port/token | CLI exits successfully | Connection refused, timeout |
| `cli_rejects_wrong_token` | Start agent | Run CLI with wrong token | CLI exits with error, message mentions auth failure | Connects anyway, hangs |
| `cli_rejects_wrong_port` | Start agent | Run CLI with port + 1 | CLI times out or reports connection error within 3s | Hangs indefinitely |
| `cli_handles_dead_agent` | Start agent, kill it | Run CLI | CLI reports "connection refused" within 3s | Hangs |
| `cli_handles_missing_args` | None | Run CLI without port/token | Exits with usage error | Crashes |
| `cli_validates_port_range` | None | Run CLI with port 99999 | Exits with "invalid port" error | Accepts invalid port |

### 3.4 QUIC Echo Tests (Core Phase 1)

**File:** `crates/integration-tests/tests/quic_echo.rs`

| Test Name | Setup | Actions | Assertions | Failure Modes |
|-----------|-------|---------|------------|---------------|
| `echo_small_payload` | Start agent + CLI | CLI sends EchoRequest with 32-byte payload | EchoResponse matches request payload exactly | Corruption, dropped response |
| `echo_empty_payload` | Start agent + CLI | Send EchoRequest with empty vec | EchoResponse has empty vec | Crashes on empty |
| `echo_large_payload` | Start agent + CLI | Send EchoRequest with 1MB payload | EchoResponse matches, completes within 5s | OOM, timeout, corruption |
| `echo_max_payload` | Start agent + CLI | Send 10MB payload | Either succeeds or returns size error (not crash) | Panic, OOM |
| `echo_unicode_payload` | Start agent + CLI | Send UTF-8 string as bytes | Exact bytes returned | Encoding corruption |
| `echo_binary_payload` | Start agent + CLI | Send random bytes (0x00-0xFF) | Exact bytes returned | Binary corruption |
| `echo_sequential` | Start agent + CLI | Send 10 EchoRequests sequentially | All 10 responses match their requests | Out-of-order, dropped |
| `echo_rapid_fire` | Start agent + CLI | Send 100 EchoRequests in tight loop | All 100 responses match | Backpressure crash |
| `echo_bidirectional` | Start agent + CLI | CLI sends echo, agent also sends echo | Both directions work | Deadlock |
| `echo_after_idle` | Start agent + CLI | Wait 10s idle, then send echo | Echo succeeds | Connection dropped |

### 3.5 Control Stream Tests

**File:** `crates/integration-tests/tests/control_stream.rs`

| Test Name | Setup | Actions | Assertions | Failure Modes |
|-----------|-------|---------|------------|---------------|
| `handshake_is_first_message` | Start agent + CLI | CLI connects | First message on stream 0 is Handshake | Wrong message type, timeout |
| `handshake_has_correct_version` | Start agent + CLI | Parse Handshake | `protocol_version == 1` | Version mismatch |
| `handshake_includes_token` | Start agent + CLI | Parse Handshake | Token matches what agent printed | Token mismatch |
| `heartbeat_keeps_connection_alive` | Start agent + CLI | Idle for 30s (if QUIC idle timeout is lower) | Connection stays alive, no errors | Connection dropped |
| `control_stream_survives_data_streams` | Start agent + CLI | Open 10 QUIC data streams, send control msg | Control message delivered | Stream interference |

---

## 4. Edge Case & Robustness Tests

### 4.1 Malformed Protocol Messages

**File:** `crates/integration-tests/tests/malformed_messages.rs`

| Test Name | Attack Vector | Expected Behavior | Security Consideration |
|-----------|---------------|-------------------|------------------------|
| `agent_handles_truncated_handshake` | CLI sends 5 bytes of invalid rkyv | Agent logs error, drops connection, stays running | DoS: crash loop |
| `agent_handles_oversized_message` | CLI sends 100MB message | Agent rejects or rate-limits, doesn't OOM | DoS: memory exhaustion |
| `agent_handles_rapid_connections` | Open 100 connections in 1 second | Agent rate-limits or accepts all, doesn't crash | DoS: connection flood |
| `cli_handles_wrong_protocol_version` | Agent sends Handshake with version 999 | CLI logs error, exits gracefully | Forward compatibility |
| `cli_handles_missing_handshake` | Agent sends EchoResponse before Handshake | CLI rejects, closes connection | Protocol violation |
| `cli_handles_duplicate_handshake` | Agent sends Handshake twice | CLI ignores or logs warning | Protocol violation |
| `agent_handles_invalid_echo_request` | CLI sends malformed EchoRequest | Agent logs error, continues running | Resilience |

### 4.2 Process Lifecycle Tests

**File:** `crates/integration-tests/tests/process_lifecycle.rs`

| Test Name | Scenario | Actions | Assertions | Cleanup |
|-----------|----------|---------|------------|---------|
| `agent_handles_sigterm_gracefully` | Agent running | Send SIGTERM | Exits code 0 within 1s | N/A |
| `agent_handles_sigkill` | Agent running | Send SIGKILL | Dies immediately | Cleanup temp files |
| `cli_handles_agent_crash_mid_echo` | Agent + CLI connected | Kill agent during echo | CLI reports error within 2s | Kill CLI if hung |
| `cli_handles_agent_restart` | Agent dies, new agent starts | CLI (if long-running) detects disconnect | Future: auto-reconnect | Kill both processes |
| `cli_exits_cleanly_on_ctrl_c` | CLI running | Send SIGINT | CLI exits code 0 or 130 within 1s | N/A |
| `agent_cleans_up_temp_files` | Agent running | Normal exit | No leftover files in /tmp | Manual cleanup |
| `agent_releases_udp_port_on_exit` | Agent running on port 9000 | Kill agent, start new one | New agent binds same port | Port leak check |

### 4.3 Payload Stress Tests

**File:** `crates/integration-tests/tests/payload_stress.rs`

| Test Name | Payload Characteristics | Expected Result | Timeout |
|-----------|-------------------------|-----------------|---------|
| `echo_all_zeros` | 1MB of 0x00 | Exact match | 3s |
| `echo_all_ones` | 1MB of 0xFF | Exact match | 3s |
| `echo_alternating_pattern` | 0x55AA repeated | Exact match | 3s |
| `echo_compressible` | Repeated "AAAA..." | Exact match (no compression) | 3s |
| `echo_random_bytes` | Crypto random | Exact match | 3s |
| `echo_utf8_multibyte` | String with emoji, CJK | Exact match | 3s |
| `echo_incrementing_sizes` | 1 byte, 2, 4, 8, ..., 1MB | All match | 10s |
| `echo_max_udp_datagram` | 65,507 bytes (UDP max) | Exact match or size error | 3s |

### 4.4 Concurrency Tests

**File:** `crates/integration-tests/tests/concurrency.rs`

| Test Name | Setup | Actions | Assertions | Rationale |
|-----------|-------|---------|------------|-----------|
| `multiple_agents_no_interference` | Start 5 agents | Each on different port | All print handshakes, no errors | Port uniqueness |
| `multiple_clis_to_one_agent` | 1 agent, 3 CLIs | All connect simultaneously | All connections succeed OR agent rejects extras gracefully | Multi-client handling |
| `concurrent_echo_requests` | Agent + CLI | Send 10 echos from different tokio tasks | All responses match their requests | Request/response correlation |
| `agent_handles_connection_churn` | Agent running | Open 50 connections, close 50, repeat | Agent stable, no memory leak | Resource cleanup |

---

## 5. Test Infrastructure & Utilities

### 5.1 Test Helpers

**File:** `crates/integration-tests/src/helpers.rs`

```rust
/// Parse agent handshake from stdout
pub fn parse_handshake(stdout: &str) -> Result<(u16, String)>;

/// Wait for agent to be ready (polls UDP port)
pub async fn wait_for_agent_ready(port: u16, timeout: Duration) -> Result<()>;

/// Generate random payload of specified size
pub fn random_payload(size: usize) -> Vec<u8>;

/// Compare payloads byte-by-byte, provide diff on mismatch
pub fn assert_payload_eq(expected: &[u8], actual: &[u8]);

/// Kill process by PID with escalating signals
pub fn kill_process(pid: u32) -> Result<()>;

/// Find available UDP port
pub fn find_free_udp_port() -> Result<u16>;
```

### 5.2 Mocking & Fixtures

**File:** `crates/integration-tests/fixtures/`

- `valid_handshake.bin`: Pre-encoded Handshake message
- `invalid_messages/*.bin`: Corpus of malformed rkyv data
- `test_payloads/*.bin`: Known-good test payloads (UTF-8, binary, large)

### 5.3 CI Considerations

**CI Configuration Requirements:**

1. **Parallel Execution:**
   - Tests must use unique ports (randomized or sequential assignment)
   - Use temp directories per test (`tempfile` crate)
   - No shared state between tests

2. **Timeout Enforcement:**
   - CI runner sets 20-second global timeout
   - Individual tests have sub-timeouts (2-5s)
   - Use `cargo test --test-threads=4` to limit parallelism

3. **Resource Limits:**
   - Set `ulimit -n 1024` to detect FD leaks
   - Monitor peak memory usage (should be < 100MB for suite)
   - Fail if any process leaks (orphaned agent/CLI)

4. **Cleanup Script:**
   ```bash
   #!/bin/bash
   # Kill any leaked test processes
   pkill -9 -f "target/debug/(agent|cli)"
   # Clean temp files
   rm -rf /tmp/port-linker-test-*
   ```

5. **Test Organization:**
   - Fast unit tests (< 1s): Run first
   - Integration tests (1-5s): Run parallel
   - Stress tests (5-10s): Run last, sequentially if needed

---

## 6. Specific Test Cases for Phase 1 MVP

### 6.1 Critical Path Test (E2E Smoke Test)

**Name:** `phase1_end_to_end_smoke_test`

**Description:** Validates the complete Phase 1 flow as described in ARCHITECTURE.md

**Steps:**
1. Start agent subprocess
2. Parse `AGENT_READY\nPORT=<port>\nTOKEN=<token>` from stdout within 2s
3. Start CLI with parsed port and token
4. CLI connects via QUIC
5. CLI receives Handshake message on stream 0
6. CLI validates protocol version is 1
7. CLI sends EchoRequest with payload `b"phase1_test"`
8. CLI receives EchoResponse within 1s
9. CLI validates payload matches exactly
10. CLI exits cleanly
11. Agent is terminated cleanly

**Assertions:**
- Agent starts without errors
- Handshake parsing succeeds
- QUIC connection established
- Handshake message has correct version and token
- Echo round-trip succeeds
- Both processes exit cleanly

**Timeout:** 10 seconds

**Failure Impact:** BLOCKS Phase 1 completion

### 6.2 Required Tests for Phase 1 Sign-Off

Before Phase 1 is considered complete, these tests MUST pass:

| Priority | Test Name | Category | Rationale |
|----------|-----------|----------|-----------|
| P0 | `phase1_end_to_end_smoke_test` | E2E | Core functionality |
| P0 | `agent_starts_and_outputs_handshake` | Integration | Bootstrapping |
| P0 | `cli_connects_to_agent` | Integration | Connectivity |
| P0 | `echo_small_payload` | Integration | Echo protocol |
| P0 | `echo_large_payload` | Integration | Real-world data |
| P0 | `handshake_is_first_message` | Integration | Protocol contract |
| P1 | `agent_handles_sigterm_gracefully` | Robustness | Cleanup |
| P1 | `cli_handles_dead_agent` | Robustness | Error handling |
| P1 | `echo_sequential` | Stress | Repeated operations |
| P1 | `decode_garbage_returns_error` | Unit | Security |
| P2 | `agent_handles_truncated_handshake` | Security | DoS prevention |
| P2 | `concurrent_echo_requests` | Concurrency | Future-proofing |

**P0 = Blocker, P1 = Required, P2 = Recommended**

---

## 7. Future Testing Considerations (Post-Phase 1)

### 7.1 Fuzz Testing

Consider adding `cargo-fuzz` targets for:
- `fuzz_target_codec_decode`: Fuzz rkyv decoder with arbitrary bytes
- `fuzz_target_handshake_parser`: Fuzz agent stdout parsing

### 7.2 Property-Based Testing

Use `proptest` for:
- Token generation invariants (uniqueness, format)
- Codec round-trip properties for all message types
- Port number validity ranges

### 7.3 Performance Benchmarks

**File:** `crates/protocol/benches/codec_bench.rs`

- Encode/decode latency for various message sizes
- Throughput for echo protocol
- Connection establishment time

### 7.4 Platform-Specific Tests

Phase 1 should work on:
- Linux x86_64
- Linux aarch64
- macOS (Darwin) x86_64
- macOS (Darwin) aarch64

Add CI matrix to test agent on Linux, CLI on both.

---

## 8. Test Execution Strategy

### 8.1 Local Development

```bash
# Run fast unit tests (< 1s)
cargo test --lib --bins

# Run integration tests
cargo test --test '*'

# Run specific integration test
cargo test --test agent_startup

# Run with verbose output
cargo test -- --nocapture --test-threads=1
```

### 8.2 CI Pipeline

```yaml
test:
  runs-on: ubuntu-latest
  timeout-minutes: 2
  steps:
    - run: cargo test --all --verbose
    - run: ./scripts/cleanup_leaked_processes.sh
```

### 8.3 Coverage Tracking

Target 80% code coverage for Phase 1:
- Protocol crate: 90%+ (critical path)
- Common crate: 85%+
- Agent/CLI: 70%+ (harder to test due to I/O)

Use `cargo-tarpaulin` or `cargo-llvm-cov`:
```bash
cargo tarpaulin --out Html --output-dir coverage/
```

---

## 9. Test Naming Conventions

- Unit tests: `test_<function>_<scenario>` (e.g., `test_encode_large_payload`)
- Integration tests: `<noun>_<verb>_<condition>` (e.g., `agent_starts_and_outputs_handshake`)
- Edge cases: `<component>_handles_<error>` (e.g., `cli_handles_dead_agent`)
- Stress tests: `<operation>_<stress_type>` (e.g., `echo_rapid_fire`)

---

## 10. Open Questions & Decisions Needed

1. **Agent Port Selection:** Should agent use a fixed range (e.g., 10000-10100) or OS-assigned ephemeral port?
   - **Recommendation:** OS-assigned for flexibility, print to stdout

2. **CLI Exit Codes:** Define semantic exit codes?
   - 0: Success
   - 1: Usage error
   - 2: Connection failed
   - 3: Protocol error

3. **Handshake Timeout:** How long should CLI wait for agent handshake?
   - **Recommendation:** 3 seconds (agent should be instant)

4. **Echo Payload Limits:** Should there be a max size?
   - **Recommendation:** 10MB hard limit to prevent OOM

5. **QUIC Configuration:** Idle timeout, max streams, etc.
   - **Recommendation:** Conservative defaults (30s idle, 100 streams)

6. **Test Data Location:** Where to store test fixtures?
   - **Recommendation:** `crates/integration-tests/fixtures/`

---

## 11. Success Metrics

Phase 1 testing is complete when:

1. All P0 and P1 tests pass consistently
2. Test suite completes in < 20 seconds
3. No flaky tests (100 consecutive runs pass)
4. Code coverage exceeds 80%
5. CI pipeline is green
6. Manual smoke test passes on Linux and macOS

---

## Appendix A: Test File Structure

```
crates/
├── protocol/
│   ├── src/
│   │   ├── codec.rs          # Has tests
│   │   └── lib.rs
│   └── tests/
│       ├── protocol_edge_cases.rs
│       └── protocol_types.rs
├── common/
│   ├── src/
│   │   ├── error.rs
│   │   └── lib.rs            # Has tests
│   └── tests/
│       ├── token_tests.rs
│       └── error_tests.rs
└── integration-tests/        # New crate
    ├── Cargo.toml
    ├── src/
    │   ├── lib.rs            # Test harness
    │   └── helpers.rs
    ├── fixtures/
    │   ├── valid_handshake.bin
    │   └── test_payloads/
    └── tests/
        ├── agent_startup.rs
        ├── cli_connection.rs
        ├── quic_echo.rs
        ├── control_stream.rs
        ├── malformed_messages.rs
        ├── process_lifecycle.rs
        ├── payload_stress.rs
        └── concurrency.rs
```

---

## Appendix B: Example Test Implementation

```rust
// crates/integration-tests/tests/quic_echo.rs

use integration_tests::{TestHarness, assert_payload_eq, random_payload};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn echo_small_payload() {
    let harness = TestHarness::start_agent()
        .await
        .expect("Failed to start agent");

    let payload = b"Hello, QUIC!".to_vec();

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        harness.send_echo_request(payload.clone())
    )
    .await
    .expect("Echo request timed out")
    .expect("Echo request failed");

    assert_payload_eq(&payload, &response);
}

#[tokio::test(flavor = "multi_thread")]
async fn echo_large_payload() {
    let harness = TestHarness::start_agent()
        .await
        .expect("Failed to start agent");

    let payload = random_payload(1_000_000); // 1 MB

    let response = tokio::time::timeout(
        Duration::from_secs(10),
        harness.send_echo_request(payload.clone())
    )
    .await
    .expect("Echo request timed out")
    .expect("Echo request failed");

    assert_payload_eq(&payload, &response);
}
```

---

## Appendix C: Debugging Failed Tests

When a test fails:

1. **Capture Logs:**
   ```bash
   RUST_LOG=debug cargo test failing_test -- --nocapture
   ```

2. **Check Process State:**
   ```bash
   ps aux | grep -E "(agent|cli)"
   lsof -i UDP  # Check if UDP port is leaked
   ```

3. **Inspect Temp Files:**
   ```bash
   ls -la /tmp/port-linker-test-*
   ```

4. **Manual Reproduction:**
   ```bash
   # Start agent manually
   ./target/debug/agent

   # In another terminal, run CLI
   ./target/debug/cli --port <port> --token <token>
   ```

5. **Binary Protocol Inspection:**
   Use `xxd` to inspect encoded messages:
   ```bash
   xxd fixtures/test_message.bin
   ```

---

**Document Version:** 1.0
**Last Updated:** 2026-02-10
**Author:** QA Test Architect
**Status:** Ready for Implementation
