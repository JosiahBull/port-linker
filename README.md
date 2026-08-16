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
4. Interactive password prompt (last resort)

Host keys are checked against `~/.ssh/known_hosts`. The default policy is
`ask`: an unknown key is shown to you and recorded only if you accept it, the
same as OpenSSH.

```
The authenticity of host 'example.com:22' can't be established.
  ssh-ed25519 key fingerprint is SHA256:gJwusF8uXoNsWC5QQVW8JT4Hp0MYtNAc5iz/db0d0PQ
Verify this fingerprint out of band before accepting. Continue connecting? [y/N]
```

A **changed** key is refused outright under every policy but `accept-all` — you
are never offered a prompt that would overwrite an existing pin. If the host was
legitimately rekeyed, remove its line from `~/.ssh/known_hosts` yourself.

With no terminal to ask on — CI, a cron job, a backgrounded run — `ask` refuses
rather than hanging, so scripted use needs an explicit policy:

| Policy | Unknown key | Changed key |
| --- | --- | --- |
| `ask` (default) | Prompts; refuses if there is no terminal | Refused |
| `strict` | Refused | Refused |
| `accept-new` | Trusted on first use and recorded | Refused |
| `accept-all` | Trusted, nothing verified | Trusted |

```bash
# Trust a host you have not connected to before, without a prompt (TOFU)
port-linker --remote user@host --ssh-host-key-verification accept-new
```

## Security

The QUIC tunnel is encrypted **and mutually authenticated end to end**. SSH is
used to introduce the two ends: the host sends its freshly generated certificate
to the agent over the SSH channel, the agent sends back its own, and each side
then accepts exactly that one certificate. Neither private key ever crosses the
network, so an on-path attacker cannot impersonate either end or read the
traffic.

Because SSH is the root of that trust, an unverified host key would undermine
everything downstream — hence the strict default above.

The agent refuses to start without this introduction, so it never accepts
connections from anyone who merely reaches its port. Binaries deployed to the
target are SHA256-verified against the copy embedded in the CLI before they run,
and session secrets are passed over stdin rather than the command line so they
are not visible to other users via `ps`.

See [ARCHITECTURE.md](ARCHITECTURE.md#52-end-to-end-security-ssh-introduced-mutual-tls) for the full trust model.

### Manual mode

`--agent` connects to an already-running agent and has no SSH channel to carry
the introduction, so it requires a session file:

```bash
# First run creates ./sess.conf and ./sess.agent, and prints instructions
port-linker --agent 10.0.0.5:45871 --session-config ./sess.conf

# Start the agent with the generated block on its stdin, paste the AGENT_CERT=
# line it prints into ./sess.conf, then re-run the same command to connect.
```

## License

MIT
