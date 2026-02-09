# Comprehensive Architecture for port-linker

## 1. Executive Summary

`port-linker` is a high-performance CLI utility designed to transparently mirror a remote "Target" environment to a local "Host" machine. It connects via SSH, deploys a temporary agent, and establishes a high-fidelity tunnel that forwards all active remote services to `127.0.0.1` on the Host. Unlike standard SSH forwarding, `port-linker` actively manages the Host's network namespace, detecting port conflicts (e.g., a local Postgres blocking a remote Postgres) and offering interactive resolution (PID killing).

## 2. Workspace & Crate Architecture

The project is organized as a Cargo workspace to share protocol definitions while keeping the agent binary distinct.

| Crate | Role | Dependencies |
| :--- | :--- | :--- |
| `cli` | Host entry point. Handles SSH bootstrapping, UI (prompts), and local binding. | `monoio`, `russh`, `dialoguer`, `quinn` |
| `agent` | Remote binary. Scans OS network state and pipes traffic. | `monoio`, `quinn`, `procfs` (linux) |
| `protocol` | Shared types and serialization logic. | `rkyv`, `bytes` |
| `common` | Shared utilities (PID lookup, socket logic). | `socket2`, `libc` |

### 2.1 Why Monoio on the Agent?

While a synchronous, zero-dependency agent is attractive for size, it is incompatible with the requirement for high-performance QUIC transport. Implementing QUIC state machines (`quinn-proto`) in a custom synchronous event loop is prohibitively complex and prone to bugs.

*   **Decision:** The Agent will use `monoio` (leveraging `io_uring` for performance).
*   **Impact:** Binary size increases (~3MB), but we gain robust async I/O, reliable timers for QUIC, and massive development velocity.

## 3. Startup & Bootstrapping

1.  **Connection:** Host connects to Target via SSH (using `russh` or system ssh via `std::process::Command` if keys are complex).
2.  **Architecture Check:** Host runs `uname -m` to detect Target arch (`x86_64` vs `aarch64`).
3.  **Deployment:** Host SFTPs the matching compiled agent binary to `/tmp/port-linker-{random}`.
4.  **Execution:** Host executes the agent. The agent attempts to bind a UDP port for QUIC.
5.  **Handshake:** The agent prints its listening UDP port and a generated one-time connection token to stdout.
6.  **Tunnel Up:** Host reads the token from SSH stdout, establishes a direct QUIC connection to the Target's UDP port, and begins the session.

## 4. The "Forward All Ports" Strategy

Naively binding ports 1–65535 will crash the Host (File Descriptor exhaustion) and break OS networking (ephemeral port starvation). We use Dynamic State Synchronization.

### 4.1 Target: State Scanning

The Agent runs a background task scanning for active listeners.

*   **Linux:** Efficiently parses `/proc/net/tcp` and `/proc/net/udp`. This is faster/lighter than shelling out to `netstat`.
*   **Diffing:** It compares the current state to the previous second's state.
*   **Event:** Pushes `PortAdded(u16, Proto)` or `PortRemoved(u16, Proto)` events to the Host via the Control Stream.

### 4.2 Host: Just-in-Time (JIT) Binding

The Host only binds ports that are actually active on the Target.

*   **Ephemeral Protection:** The Host checks sysctl `net.inet.ip.portrange` (macOS) or `/proc/sys/net/ipv4/ip_local_port_range` (Linux). It refuses to bind ports in this range (typically 32768–60999) to prevents self-inflicted connectivity death.
*   **FD Safety:** The Host enforces a "Safe Limit" (e.g., 2000 active tunnels). If the Target has 50k ports open, the Host warns and caps the forwarding to prevent EMFILE crashes.

## 5. Transport Layer: QUIC

The tunnel uses QUIC (`quinn` crate) to multiplex traffic.

*   **Stream 0 (Control):** Reliable stream for `rkyv`-encoded control messages (`PortAdded`, `KillRequest`).
*   **Streams N (TCP):** Each TCP connection on the Host opens a new QUIC stream.
*   **Datagrams (UDP):** UDP packets are wrapped in QUIC Datagrams.
    *   **Why?** Standard SSH tunnels (TCP) cause "Meltdown" for UDP traffic. If one packet drops, TCP pauses all traffic. QUIC Datagrams are unreliable/unordered, preserving the native behavior of UDP.

### 5.1 Protocol (Rkyv)

We use `rkyv` for Zero-Copy serialization.

```rust
pub enum Packet {
    Control(ControlMsg),
    UdpData { port: u16, data: Vec<u8> }, // Sent as Datagram
}
```

## 6. Conflict Resolution & Interactive Killing

This is the tool's signature feature.

### 6.1 Detection

When the Host receives `PortAdded(8080)`, it attempts `TcpListener::bind("127.0.0.1:8080")`. If it fails with `AddrInUse`:

1.  **Pause:** The bind task pauses.
2.  **Identify:** The Host uses platform-specific logic (`lsof -i :8080` on macOS, `/proc` inodes on Linux) to find the PID and Process Name.

### 6.2 The Prompt (Async Safety)

The Host is running on an Async Runtime. Blocking Stdin for user input (Y/N) will freeze the heartbeats, causing the tunnel to drop.

*   **Solution:** The prompt logic is wrapped in `monoio::spawn_blocking`.
*   **UX:**
    ```text
    Remote port 8080 is active, but local port 8080 is held by: Process: node (PID: 12345)
    Kill this process? [y/N]
    ```

### 6.3 Termination

If 'Y':

1.  Host sends `SIGTERM`. Waits 1s. Sends `SIGKILL`.
2.  Host retries the bind.

## 7. Observability & Logging

Debugging distributed systems requires correlated logs. We use `tracing` to bridge the Host and Agent.

### 7.1 Agent Logging
The Agent runs headless and cannot pollute stdout (reserved for the handshake).
*   **Transport:** The Agent creates a dedicated QUIC Unidirectional Stream for logs.
*   **Format:** Log events are serialized and pushed to the Host in real-time.
*   **Bootstrapping:** Errors occurring before QUIC is established are printed to `stderr`, which SSH forwards to the Host console.

### 7.2 Host Aggregation
The Host serves as the log aggregator.
*   **Separation:** Because the Host uses a TUI (`dialoguer`), raw logs are never printed to stdout. They are written to a rolling file (e.g., `~/.local/state/port-linker/debug.log`).
*   **Correlation:** Logs are enriched with a session ID to trace the lifecycle of a request from Host Socket -> Tunnel -> Agent Socket -> Target.

## 8. Testing Strategy

Given the OS-level interactions, `port-linker` requires a rigorous testing matrix involving Docker containers and mocked process environments.

### 8.1 Unit Tests
*   **Protocol Fuzzing:** Use `cargo-fuzz` on `rkyv` deserialization to ensure the Host cannot be crashed by malformed packets from a compromised Agent.
*   **Parser Logic:** Feed the Agent's scanner mocked `/proc/net/tcp` and `/proc/net/udp` files (including edge cases like IPv6 mapping) to verify diffing logic.

### 8.2 Integration & E2E Scenarios
These tests run in a CI pipeline using Linux containers for both Host and Target. When testing locally they should use `docker`. The entire test suite MUST run in 20 seconds or less to allow for rapid development. Use of ENV variables to inject mocks is acceptable.

1.  **The "Late Bind" Case:**
    *   **Action:** Establish tunnel. *Then* start `nc -l -p 8080` on Target.
    *   **Expectation:** Host binds port 8080 within 1 second.
2.  **The "Data Integrity" Case (TCP & UDP):**
    *   **Action:**
        *   **TCP:** Host sends 100MB of random data to a mapped port; Target echoes it back.
        *   **UDP:** Host sends varied packet sizes (including MTU limits) to a mapped UDP port; Target echoes them.
    *   **Expectation:** TCP data is bit-perfect (SHA256 match). UDP packets arrive successfully, validating QUIC encapsulation.
3.  **The "Phoenix Agent" Case (Restart):**
    *   **Action:** Manually `kill -9` the Agent process on the Target while the session is active.
    *   **Expectation:** Host detects the disconnect, automatically re-deploys/restarts the Agent via SSH, and resumes port forwarding without the user needing to restart the CLI.
4.  **The "Conflict & Kill" Case:**
    *   **Action:** Host runs `python3 -m http.server 9000`. Target opens port 9000.
    *   **Expectation:** Host detects conflict. Test harness simulates "Y" to prompt. Host kills Python process. Host binds port 9000 successfully.
5.  **The "Safety Cap" Case:**
    *   **Action:** Target opens 5,000 ports. Host limit is set to 2,000.
    *   **Expectation:** Host binds exactly 2,000 ports, logs a warning, and remains stable (no `EMFILE` panic).
6.  **The "Ephemeral Guard" Case:**
    *   **Action:** Target binds a port in the Host's ephemeral range (e.g., 50000).
    *   **Expectation:** Host logs a warning and *refuses* to bind the local port to avoid collision.

## 9. Implementation Roadmap

*   **Phase 1 (The Core):** Build the `cli` and `agent` sharing the `rkyv` protocol. Get a basic QUIC echo working.
*   **Phase 2 (The Scanner):** Implement Linux `/proc` parsing in the Agent.
*   **Phase 3 (The Manager):** Implement the Host's JIT binding loop and FD safety limits.
*   **Phase 4 (The Killer):** Implement `lsof`/`/proc` PID lookup and `dialoguer` prompts inside `spawn_blocking`.
*   **Phase 5 (Polish):** Add SSH bootstrapping, Agent auto-restart logic, and structured logging.

## 10. Summary of Dependencies

*   `monoio`: Runtime for Host and Agent.
*   `quinn`: QUIC transport implementation.
*   `russh`: SSH client implementation for bootstrapping.
*   `rkyv`: Zero-copy serialization protocol.
*   `dialoguer`: Interactive CLI prompts.
*   `directories`: Finding standard paths for config/logs.
*   `ctrlc`: Handling shutdown signals gracefully.
*   `tracing`: Structured logging for observability across the tunnel.
