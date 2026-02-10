<p align="center">
  <img src="assets/logo.svg" alt="port-linker logo" width="128" height="128">
</p>

# port-linker

Automatically forward every listening port from a remote machine to localhost over SSH. No configuration required.

port-linker deploys a lightweight agent to the remote host via SSH, establishes a QUIC tunnel, and continuously scans for new listening ports. When a service starts on the remote, it appears on your local machine within seconds. Desktop notifications keep you informed.

## Installation

```bash
cargo install --path .
```

## Usage

```bash
# Connect to a remote host — all discovered ports are forwarded automatically
port-linker --remote user@host

# Connect to an already-running agent directly (manual/debug mode)
port-linker --agent 192.168.1.50:12345

# Auto-kill local processes that conflict with forwarded ports
port-linker --remote user@host --conflict-resolution auto-kill

# Silently skip ports that conflict locally
port-linker --remote user@host --conflict-resolution auto-skip

# Limit the number of forwarded ports
port-linker --remote user@host --fd-limit 64

# Disable desktop notifications
port-linker --remote user@host --notifications false

# Use a custom agent binary instead of the embedded one
port-linker --remote user@host --agent-binary ./my-agent
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--remote <USER@HOST>` | Remote host to connect to via SSH | |
| `--agent <ADDR:PORT>` | Connect to an already-running agent directly | |
| `--conflict-resolution <POLICY>` | How to handle local port conflicts: `interactive`, `auto-skip`, or `auto-kill` | `interactive` |
| `--fd-limit <N>` | Maximum number of forwarded ports (FD safety limit) | unlimited |
| `--notifications <BOOL>` | Enable desktop notifications for port events | `true` |
| `--notification-sound <BOOL>` | Enable notification sounds | `true` |
| `--ssh-host-key-verification <POLICY>` | SSH host key policy: `strict`, `accept-new`, or `accept-all` | `accept-new` |
| `--agent-binary <PATH>` | Path to a custom agent binary to deploy | embedded |
| `--echo-only` | Run the echo connectivity test and exit | `false` |

## Filtered Ports

The agent automatically filters out:

- **Privileged ports** (< 1024) — system services like DHCP, DNS, NTP
- **Ephemeral ports** (32768-60999 on Linux) — transient outbound sockets
- **SSH** (22/TCP), **DNS** (53/UDP), **Tailscale** (41641/UDP)
- The agent's own QUIC endpoint

## SSH Authentication

port-linker uses your existing SSH configuration (`~/.ssh/config`) and attempts authentication in this order:

1. SSH agent (`SSH_AUTH_SOCK`)
2. Identity files from SSH config
3. Default key files (`~/.ssh/id_ed25519`, `~/.ssh/id_rsa`, `~/.ssh/id_ecdsa`)

## License

MIT
