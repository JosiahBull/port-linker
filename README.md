<p align="center">
  <img src="assets/logo.svg" alt="port-linker logo" width="128" height="128">
</p>

# port-linker

A CLI tool that connects to remote systems via SSH and automatically forwards discovered ports to localhost.

## Installation

```bash
cargo install --path .
```

## Usage

```bash
# Basic usage - connect and forward all discovered ports
port-linker user@remote-host

# Forward only specific ports
port-linker user@host -p 8080,3000,5432

# Auto-kill local processes that conflict with forwarded ports
port-linker user@host --auto-kill

# Use a specific SSH key
port-linker user@host -i ~/.ssh/my_key

# Connect on a non-standard SSH port
port-linker user@host -P 2222

# Exclude additional ports from forwarding
port-linker user@host -x 9000,9001

# Disable notifications
port-linker user@host --no-notifications --no-sound

# Verbose logging
port-linker user@host --log-level debug
```

## Options

| Option | Description |
|--------|-------------|
| `-p, --ports <PORTS>` | Only forward specific ports (comma-separated) |
| `-x, --exclude <PORTS>` | Exclude additional ports from forwarding |
| `--no-default-excludes` | Don't exclude default system ports |
| `--auto-kill` | Automatically kill conflicting local processes |
| `--no-notifications` | Disable desktop notifications |
| `--no-sound` | Disable notification sounds |
| `--log-level <LEVEL>` | Log level: trace, debug, info, warn, error (default: info) |
| `--scan-interval <SECONDS>` | Port scan interval (default: 3) |
| `-i, --identity <PATH>` | Path to SSH identity file |
| `-P, --port <PORT>` | SSH port (default: 22) |

## Default Excluded Ports

The following ports are excluded by default (use `--no-default-excludes` to forward them):

| Port | Service |
|------|---------|
| 22 | SSH |
| 53 | DNS |
| 111 | RPC/portmapper |
| 631 | CUPS printing |
| 5353 | mDNS |
| 41641 | Tailscale |

## SSH Authentication

port-linker attempts authentication in this order:

1. SSH agent (`SSH_AUTH_SOCK`)
2. Explicit identity file (`-i` flag)
3. Default key files (`~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, etc.)
4. Password prompt (if key auth fails)

## License

MIT
