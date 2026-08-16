//! Stamp the binary with what it was built from, for `--version`.
//!
//! Everything emitted here is read back by `src/build_info.rs`, so the two
//! files are a pair: a field added below and not consumed there is dead weight
//! in a published binary, and one dropped here degrades to `unknown` there
//! rather than failing loudly. See the note on `option_env!` below for why it
//! degrades instead of breaking the build.
//!
//! # Emitted selectively, not with `all_*`
//!
//! vergen's `all_git()` and `all_cargo()` are the obvious way to write this and
//! the wrong one here. Between them they embed the last commit's author name,
//! author email and full message, and the resolved dependency list, into a
//! binary that is published and signed. None of it is displayed, so all of it
//! would be payload nobody asked for — and an author email is a person's
//! address sitting in a file strangers download.
//!
//! The sysinfo feature is off for the same reason, one step worse: it records
//! the build machine's username and hostname, which for a contributor running
//! `cargo install --path .` is their own.
//!
//! # Failures are not fatal, in two different ways
//!
//! `fail_on_error` is left off — vergen's default — but that alone is not
//! enough, because vergen degrades along two separate paths and the reader has
//! to handle both:
//!
//! * It ran and could not determine a value. The variable is emitted holding
//!   the string `VERGEN_IDEMPOTENT_OUTPUT`. A shallow clone hits this: with
//!   `actions/checkout` at its default depth of 1 there are no tags, so
//!   `git describe` has nothing to describe against on a pull request.
//! * It could not run the git instructions at all, because there is neither a
//!   repository nor a usable `git`. Then the variables are **not emitted**, and
//!   an `env!` reading one is a compile error rather than a fallback. This is
//!   the case for `cargo install --path .` from an unpacked release tarball —
//!   one of the two install paths the README documents — and for a `cross`
//!   container where git is absent or refuses a repository owned by another
//!   uid.
//!
//! `src/build_info.rs` therefore reads every one of these through
//! `option_env!`, never `env!`, and maps both the sentinel and the absent
//! variable to `unknown`. Verified by building with `GIT_DIR` pointed at a
//! path that does not exist; `env!` fails that build outright.

use std::error::Error;

// Everything comes from `vergen-gitcl`, which re-exports the whole of `vergen`.
// Depending on both would risk a version skew in the `vergen-lib` they pin
// between them, which surfaces as a trait error naming neither crate.
use vergen_gitcl::{BuildBuilder, CargoBuilder, Emitter, GitclBuilder, RustcBuilder};

fn main() -> Result<(), Box<dyn Error>> {
    // When it was built. `build_date` is dropped as redundant beside the
    // timestamp. Note this is the field that stops the binary being
    // byte-reproducible; vergen honours SOURCE_DATE_EPOCH if that ever needs
    // fixing for the signed release artifacts.
    let build = BuildBuilder::default().build_timestamp(true).build()?;

    // What it was built for. `features` and `dependencies` stay off: the former
    // is empty for this crate, the latter is a whole manifest in a string.
    let cargo = CargoBuilder::default()
        .debug(true)
        .opt_level(true)
        .target_triple(true)
        .build()?;

    // What built it. The rustc commit hash and LLVM version are omitted as
    // detail nobody reads off a CLI.
    let rustc = RustcBuilder::default().semver(true).channel(true).build()?;

    // What source it was built from.
    //
    // `sha(false)` is the full forty characters — a short SHA is ambiguous
    // across forks, and this string exists to identify a commit exactly.
    // `dirty(true)` counts untracked files, so a build with anything
    // uncommitted says so; that is the whole point of the field, since a dirty
    // build's SHA does not describe what was compiled.
    let git = GitclBuilder::default()
        .branch(true)
        .sha(false)
        .commit_timestamp(true)
        .describe(true, true, None)
        .dirty(true)
        .build()?;

    Emitter::default()
        .add_instructions(&build)?
        .add_instructions(&cargo)?
        .add_instructions(&rustc)?
        .add_instructions(&git)?
        .emit()?;

    Ok(())
}
