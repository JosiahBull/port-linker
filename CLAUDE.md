# Working notes for agents

Contributor-facing setup lives in [CONTRIBUTING.md](CONTRIBUTING.md); this file
is the agent-specific overlay on top of it.

## Hooks

`./scripts/install-hooks.sh` once per clone. `core.hooksPath` is per clone, so
committing `.githooks/` does not install anything — a fresh worktree has no
hooks until that runs.

## Do not merge

Open the pull request, get CI green, say it is ready, and stop. Merging is the
maintainer's call, every time. The only exception is an explicit instruction to
merge in that same message.

This holds even when a merge appears as a step in an approved plan — approving a
plan approves the approach, not each outward-facing action inside it. The same
applies to pushing a `v*` tag, which publishes a signed release.

## Building

- **Use `+stable`.** The dependency graph pulls in prerelease crypto crates
  (`rsa`, `pkcs8`) that do not build on recent nightlies.
- **`cargo install` needs `--locked`.** Without it cargo re-resolves and picks a
  newer `pkcs8` RC that `rsa 0.10.0-rc.12` cannot compile against, and the error
  looks like a toolchain problem rather than a lockfile one. `cargo build` and
  `cargo test` are unaffected because they use the lockfile already.
- **A release build embeds an agent for all five targets and fails if any is
  missing.** No single machine can produce them all — a Mac cannot build the
  Windows agents. Point `PLK_PREBUILT_DIR` at a directory of CI-built agents
  instead:

  ```bash
  gh run download <main-CI-run-id> -p 'prebuilt-*' -D /tmp/dl
  mkdir -p prebuilt && find /tmp/dl -type f -exec cp {} prebuilt/ \;
  PLK_PREBUILT_DIR=prebuilt cargo +stable install --locked --path crates/cli --force
  ```

  The path is resolved against the workspace root, not the current directory, so
  it means the same thing inside a `cross` container. Artifacts expire after a
  day, and agents older than the host can mismatch on protocol.

## CI

`Gate` is the only required status check on `main`. It is an aggregate job that
depends on every other job in `ci.yaml`, so adding a job makes it a merge gate
automatically — there is no list of check names to keep in sync.

Branch protection matches by exact job display name, and `enforce_admins` is on,
so a renamed job breaks a check that then never reports and nothing can merge.
Add the new job alongside the old, merge, update protection, then remove the old
one. Use `PATCH .../protection/required_status_checks`, never `PUT .../protection`,
which resets anything omitted.

## Tests

`cargo test --workspace --all-features` covers everything, but
`tests/integration_test.rs` spawns `target/debug/port-linker-agent` and only
rebuilds it when the file is absent. A stale agent left over from another branch
will fail a large number of tests with `AGENT_READY` timeouts that look like a
protocol bug. Delete it and rebuild when switching branches.
