# Contributing

## First, install the hooks

```bash
./scripts/install-hooks.sh
```

Hooks live in `.githooks/` so they are reviewed like any other code, but git
will not use them until `core.hooksPath` points there — and that setting is per
clone, so committing the hooks is not enough. Every fresh clone needs this once.

The pre-commit hook runs the deterministic CI gates, cheapest first, so most
failures never reach a runner. Bypass a single commit with `git commit
--no-verify`; remove it entirely with `./scripts/install-hooks.sh --uninstall`.

It is a convenience, not a guarantee — `Gate` in CI is what actually protects
`main`, and it is a required check with `enforce_admins` on. The hook only saves
you the round trip.

## Building

**Use `+stable`.** The dependency graph pulls in prerelease crypto crates
(`rsa`, `pkcs8`) that do not build on recent nightlies.

**`cargo install` needs `--locked`.** Without it cargo re-resolves and picks a
newer `pkcs8` RC that `rsa 0.10.0-rc.12` cannot compile against, and the error
looks like a toolchain problem rather than a lockfile one. `cargo build` and
`cargo test` already use the lockfile.

A release build embeds an agent for all five targets and fails if any is
missing, which no single machine can produce — a Mac cannot build the Windows
agents. Point `PLK_PREBUILT_DIR` at a directory of CI-built agents instead:

```bash
gh run download <main-CI-run-id> -p 'prebuilt-*' -D /tmp/dl
mkdir -p prebuilt && find /tmp/dl -type f -exec cp {} prebuilt/ \;
PLK_PREBUILT_DIR=prebuilt cargo +stable install --locked --path crates/cli --force
```

The path resolves against the workspace root, not the current directory, so it
means the same thing inside a `cross` container.

## Checks

Every gate is a script in `scripts/`, and each CI job runs the same script you
do — so the two cannot drift on flags.

```bash
./scripts/test.sh              # cargo test --workspace --all-features
./scripts/check-fmt.sh
./scripts/check-clippy.sh      # -D warnings
./scripts/check-docs.sh        # rustdoc -D warnings
./scripts/check-deps.sh        # refuses openssl in the runtime graph
./scripts/check-unused-deps.sh # needs a nightly toolchain and cargo-udeps
./scripts/check-dependabot.sh  # every 0.x direct dep must be pinned against minor bumps
./scripts/check-versions.sh
./scripts/check-workflows.sh
```

Each takes `--help`.

`tests/integration_test.rs` spawns `target/debug/port-linker-agent` and only
rebuilds it when the file is absent. A stale agent left over from another branch
fails a large number of tests with `AGENT_READY` timeouts that look like a
protocol bug — delete it and rebuild when switching branches.

## CI

`Gate` is the only required status check on `main`. It is an aggregate job
depending on every other job in `ci.yaml`, so adding a job makes it a merge gate
automatically; there is no list of check names to keep in sync.

Branch protection matches by exact job display name and `enforce_admins` is on,
so renaming a job breaks a check that then never reports, and nothing can merge.
Add the new job alongside the old, merge, update protection, then remove the old
one.

Note `ci.yaml` triggers on `pull_request: branches: [main]`, so a pull request
based on another branch gets no CI at all. Stacked branches need retargeting to
`main` before they can be checked.
