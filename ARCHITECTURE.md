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

### 3.1 Agent Binary Distribution & Caching

The Agent binary must be transferred to arbitrary Linux targets during SSH bootstrap (steps 2–3 above). This presents three competing requirements: **fast transfer** (the binary is sent on every cold connection), **cross-architecture support** (a macOS aarch64 Host must deploy to Linux x86_64 and aarch64 Targets), and **zero user friction** (no manual compilation or flags required).

#### 3.1.1 Binary Embedding

The CLI binary embeds pre-compiled Agent binaries for both supported Linux architectures at compile time:

*   `x86_64-unknown-linux-musl` (statically linked)
*   `aarch64-unknown-linux-musl` (statically linked)

Musl binaries are statically linked and run on any Linux distro without glibc version conflicts, eliminating "target system too old" failures.

A CLI `build.rs` script cross-compiles both targets using the `agent-release` profile. The resulting binaries are gzip-compressed and embedded via `include_bytes!`:

```rust
const AGENT_X86_64_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/agent-x86_64-linux-musl.gz"));
const AGENT_AARCH64_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/agent-aarch64-linux-musl.gz"));
```

For local development builds where cross-compiled agents are unavailable, `build.rs` falls back to the native `target/{debug,release}/port-linker-agent`. If no binary is found, the CLI emits a clear runtime error: *"Agent binary unavailable. Build with `cargo build -p agent` first, or use `--agent-binary`."*

#### 3.1.2 Compression & Size Budget

Agent binaries are compressed with **gzip -9** before embedding.

| Metric | Uncompressed | Gzip -9 |
| :--- | :--- | :--- |
| Agent binary (per-arch) | ~1.8 MB | ~950 KB |
| CLI overhead (2 arches) | ~3.6 MB | ~1.9 MB |

The Host checks for `gunzip` availability on the Target to determine the transfer method:

1.  **Compressed Transfer:** If `gunzip` is available, the Host sends the compressed payload directly over SSH and decompresses on the Target:
    ```bash
    gunzip -c > /tmp/port-linker-agent-{random} && chmod +x /tmp/port-linker-agent-{random}
    ```
    This halves transfer time on slow links.

2.  **Uncompressed Fallback:** If the Target lacks `gunzip`, the Host decompresses the embedded binary in-process and sends the uncompressed bytes over the wire. This ensures the agent can be deployed to minimal environments despite the higher bandwidth cost.

**Agent Binary Size Contributors** (measured via `cargo-bloat`, `agent-release` profile):

| Crate | .text Size | Notes |
| :--- | :--- | :--- |
| `std` | ~282 KB | Rust stdlib (irreducible) |
| `quinn_proto` + `quinn` | ~162 KB | QUIC protocol (irreducible) |
| `rustls` + `ring` | ~207 KB | TLS crypto (irreducible) |
| `regex_automata` + `regex_syntax` | ~133 KB | From `tracing-subscriber` env-filter. **Optimization target.** |
| `tracing_subscriber` | ~51 KB | Logging layer |
| `tokio` | ~43 KB | Async runtime |
| `rcgen` | ~20 KB | Self-signed cert generation |
| Agent application code | ~51 KB | Scanner, diff, log forwarding |

**Key optimization:** The Agent's `tracing-subscriber` dependency should use `default-features = false` with only `fmt` and `registry` features (no `env-filter`, no `ansi`). This eliminates the ~133 KB regex engine, reducing the binary by ~8%. The Agent uses a static `LevelFilter` or `Targets` filter instead.

**Transfer Time Estimates** (gzip-compressed ~950 KB):

| Connection | Bandwidth | Cold Transfer | Warm (Cached) |
| :--- | :--- | :--- | :--- |
| LAN | 100 MB/s | <10 ms | <50 ms |
| Fast WAN | 50 Mbps | ~150 ms | <50 ms |
| Typical WAN | 10 Mbps | ~750 ms | <50 ms |
| Slow VPN | 2 Mbps | ~3.7 s | <50 ms |

#### 3.1.3 Remote Caching

Re-transferring ~1 MB on every connection is wasteful when the Agent binary is stable for a given CLI version. The Host implements a SHA256-based persistent cache on the Target:

```
/tmp/.port-linker-cache/
  agent-{sha256_prefix}     # The agent binary (executable)
```

**Cache Protocol:**

1.  Host computes SHA256 of the (uncompressed) agent binary locally.
2.  Host checks if `/tmp/.port-linker-cache/agent-{sha256_prefix}` exists on Target via SSH.
3.  **Hit:** Symlink `/tmp/port-linker-agent-{random}` → cached copy. No transfer.
4.  **Miss:** Transfer compressed binary, decompress on Target, copy to cache directory.
5.  **Eviction:** Host removes cache entries older than 7 days during bootstrap.

Cache corruption is detected by re-validating the SHA256 of the cached file before symlinking. On mismatch, the Host ignores the cache and re-transfers.

Using `/tmp` ensures the cache survives user logout but is cleaned on reboot (stale agents purge automatically).

#### 3.1.4 Cross-Compilation CI Pipeline

The CLI release workflow cross-compiles the Agent for both architectures before building the CLI:

```yaml
jobs:
  build-agents:
    strategy:
      matrix:
        target: [x86_64-unknown-linux-musl, aarch64-unknown-linux-musl]
    steps:
      - uses: taiki-e/install-action@cross
      - run: cross build --profile agent-release --target ${{ matrix.target }} -p agent
      - run: gzip -9 -k target/${{ matrix.target }}/agent-release/port-linker-agent
      - uses: actions/upload-artifact@v4

  build-cli:
    needs: build-agents
    strategy:
      matrix:
        include:
          - { os: macos-latest, target: aarch64-apple-darwin }
          - { os: macos-latest, target: x86_64-apple-darwin }
          - { os: ubuntu-latest, target: x86_64-unknown-linux-musl }
    steps:
      - uses: actions/download-artifact@v4  # Download pre-built agents
      - run: cargo build --release -p cli   # build.rs embeds agents via include_bytes!
```

For local development, `build.rs` skips cross-compilation and falls back to searching for a native agent binary in `target/`.

#### 3.1.5 Power User Override

The `--agent-binary <PATH>` flag bypasses embedding and caching entirely:

```bash
port-linker --remote user@host --agent-binary ./target/debug/port-linker-agent
```

This transfers the specified binary directly. Useful for testing local agent changes, debugging with symbols, or deploying custom-patched agents.

#### 3.1.6 Security

*   **Binary integrity:** Embedded agents inherit the CLI binary's release signature (cosign). Verifying the CLI transitively verifies the agents.
*   **Cache poisoning:** `/tmp/.port-linker-cache` is world-writable on shared systems. The Host validates SHA256 before using any cached binary. On mismatch, the cache is ignored and the binary is re-transferred from the trusted embedded copy.
*   **Transport:** SSH provides encryption. No additional layer is needed.

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
7.  **The "Cold Cache" Case:**
    *   **Action:** Bootstrap agent on a fresh Target (no cache directory).
    *   **Expectation:** Compressed agent transfers, decompresses, cache is populated, agent starts within 5 seconds on LAN.
8.  **The "Warm Cache" Case:**
    *   **Action:** Bootstrap agent on Target with existing cache (matching SHA256).
    *   **Expectation:** No transfer occurs, symlink created, agent starts within 1 second.
9.  **The "Cache Corruption" Case:**
    *   **Action:** Corrupt the cached agent binary on the Target, then bootstrap.
    *   **Expectation:** Host detects SHA256 mismatch, ignores cache, re-transfers from embedded copy.
10. **The "Cross-Arch" Case:**
    *   **Action:** macOS aarch64 Host bootstraps to Linux x86_64 Target.
    *   **Expectation:** Correct x86_64 embedded agent is selected, transferred, and executed.
11. **The "Custom Binary" Case:**
    *   **Action:** Use `--agent-binary ./path/to/debug-agent`.
    *   **Expectation:** Custom binary is transferred directly, cache is bypassed entirely.

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
