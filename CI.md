# CI

## Workflows

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `ci.yaml` | push to `main`, every PR, and `workflow_call` | Every merge gate. Also the suite `release.yaml` runs on a tag. |
| `release.yaml` | `v*` tag, `workflow_dispatch` | Runs `ci.yaml`, builds 8 targets, signs with cosign, publishes. |
| `dependabot-auto-merge.yaml` | `pull_request` | Enables auto-merge on Dependabot minor/patch PRs. |

`ci.yaml` carries both `workflow_call` and the `push`/`pull_request` triggers. That
direction is deliberate and is explained under [Reusable workflows](#reusable-workflows).

## The required check

**`Gate` is the only required status check on `main`.** It is an aggregate job that
`needs:` every other job in `ci.yaml` and fails unless all of them succeeded.

Read the live list:

```bash
gh api repos/JosiahBull/port-linker/branches/main/protection \
  --jq '.required_status_checks.contexts[]'
```

Before this, all sixteen job names were required individually. Two problems with that,
both of which the aggregate removes:

- **The list drifts.** Add a job, or a leg to a matrix, and it is not required until
  someone edits branch protection. A gate that cannot fail a PR looks exactly like one
  that can.
- **Check names become a public API.** Renaming a job breaks a context that then never
  reports, and with `enforce_admins: true` that blocks every merge with no way to click
  through.

`scripts/check-workflows.sh` asserts that `gate.needs` covers every job, so the first
problem cannot come back quietly.

### Losing a required context

A required context arrives only if a job with that exact display name succeeds on the
pull request's head commit. It is lost by:

1. **Renaming the job.** Including moving it into a reusable workflow, which reports as
   `<caller-job-id> / <job name>`.
2. **Adding a matrix axis.** `name: Tests` with `matrix: {os}` renders
   `Tests (ubuntu-latest)`; adding a second axis makes it `Tests (ubuntu-latest, 1.85)`.
3. **Adding `paths:` to the `pull_request:` trigger.** `ci.yaml` deliberately has none —
   a docs-only PR must still report `Gate`. The filter on `push:` is fine.
4. **Letting the job skip or be cancelled.** `Gate` treats `skipped` as failure for this
   reason.

Adding jobs, matrix *rows*, whole workflows, `permissions:` and `timeout-minutes` is
safe — none of those can remove a context.

### Renaming a required job safely

Never rename in one step. With `enforce_admins: true` and no bypass, a context that
cannot report blocks everyone, including the PR trying to fix it.

1. Add the new job alongside the old one; both run, both green.
2. Merge.
3. Add the new context to branch protection.
4. Delete the old job.
5. Remove the old context from branch protection.

Use `PATCH .../branches/main/protection/required_status_checks`, never
`PUT .../protection` — `PUT` takes the whole object and silently resets anything you
omit, including `required_conversation_resolution` and the review rules. Back up first:

```bash
gh api repos/JosiahBull/port-linker/branches/main/protection/required_status_checks \
  > required-checks-backup.json
```

Adding a *new* required context also blocks any open PR whose head predates the job that
produces it. Rebase them, or add the context while nothing is in flight.

## Local hooks

```bash
./scripts/install-hooks.sh
```

Points `core.hooksPath` at `.githooks/`. The pre-commit hook runs the fast gates —
versions, formatting, the dependency ban, workflow lint, clippy, tests — each by calling
the same script the corresponding CI job calls, so the two cannot drift on flags. It
deliberately skips the docs build, the cross-compiled agents, the release builds, the
Docker scenarios and `cargo-udeps`.

Bypass a commit with `git commit --no-verify`. The hook is the convenience; `ci.yaml` is
the gate.

## Scripts

Each gate that is more than one line lives in `scripts/`, and CI runs the script rather
than an inline copy. The script owns what the gate *means*; the workflow owns only
installing the tool it needs.

| Script | Gate |
| --- | --- |
| `check-versions.sh` | Version declared once, inherited by every member, matching `Cargo.lock`; on a tag, matching the tag |
| `check-fmt.sh` | `cargo fmt --all -- --check` |
| `check-clippy.sh` | clippy over all targets and features, warnings denied |
| `check-docs.sh` | rustdoc with warnings denied |
| `check-deps.sh` | No OpenSSL in the runtime dependency graph |
| `check-unused-deps.sh` | `cargo-udeps` (nightly) |
| `check-workflows.sh` | actionlint, shellcheck, and the `gate.needs` assertion |
| `test.sh` | Build the agent, then the workspace test suite |
| `install-hooks.sh` | Install `.githooks/` |
| `measure-agent-size.sh` | Local agent size benchmarking; not a gate |

The scripts do not export `RUSTFLAGS="-D warnings"`, which `ci.yaml` sets workflow-wide.
`RUSTFLAGS` is part of cargo's fingerprint, so exporting it locally would rebuild the
world on every commit and again on the next plain `cargo build` — the reliable way to get
a hook disabled. Nothing is lost: clippy-driver reports rustc lints, over the same
targets. `check-docs.sh` does export `RUSTDOCFLAGS`, because nothing else covers rustdoc
warnings and rustdoc keeps a separate fingerprint anyway.

## Reusable workflows

`release.yaml` calls `ci.yaml` via `uses:`, rather than `ci.yaml` being a shim over a
separate `checks.yaml`. The edge points this way on purpose.

A called workflow's jobs report as `<caller-job-id> / <job name>`. If `ci.yaml` delegated
to `checks.yaml`, every check on a PR would be renamed, which is failure mode 1 above. As
written, a PR triggers `ci.yaml` directly and the names are untouched; on a tag the names
gain a prefix, which does not matter because branch protection does not apply to tags.

The practical consequence is that a release runs the identical gate suite a PR does,
because it is literally the same file. On a tag, `GITHUB_REF_TYPE` is `tag`, so
`check-versions.sh` additionally asserts that the tag matches the declared version.

## Dependencies

Dependabot opens grouped weekly PRs for cargo and the GitHub Actions, and a monthly one
for the Docker base image. See `.github/dependabot.yml` for what is deliberately not
automated — all semver-majors, and 0.x *minor* bumps of the protocol and crypto crates
(`russh`, `quinn`, `rustls`, `rkyv`, `rcgen`, `ring`), where a 0.x minor is a breaking
change under Cargo's semver and a released CLI must interoperate with agents already
deployed on remote machines.

Auto-merge requires **Settings → General → Allow auto-merge** to be enabled on the
repository. Note that `required_conversation_resolution` is on, so a review comment on a
Dependabot PR stalls auto-merge until it is resolved — a safe failure mode, but expect it.

`dtolnay/rust-toolchain@master` is a branch reference rather than a version, so Dependabot
cannot update it and it never appears in a bump PR.

## Known gaps

- **`Docker Integration Tests` runs one scenario of seven.** `tests/docker/run-tests.sh
  ci` runs scenario E only. Widening it changes the content of a merge gate, so any flake
  would block every PR; it deserves its own change, with the scenarios fixed first.
- **`check-workflows.sh` runs shellcheck over `scripts/` and `.githooks/` only.** The
  Docker harness has roughly twenty pre-existing findings. Two are `SC2046` on
  `$(_resolve_agent_args)`, where the unquoted expansion is deliberate word-splitting and
  "fixing" it would break the scenarios — and those scripts are what a required job runs.
- **PR builds cover 3 of the 8 release targets.** A release can still fail on
  `x86_64-apple-darwin` or the gnu targets after the gates are green.
- **No MSRV and no `rust-toolchain.toml`.** CI tracks whatever `stable` currently is, so a
  new clippy release can redden `main` with no change to this repository.
