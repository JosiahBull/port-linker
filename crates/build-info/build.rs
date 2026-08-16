//! Stamp the binary with what it was built from, for `--version`.
//!
//! Everything emitted here is read back by `src/lib.rs`; a field emitted but
//! not printed there is dead weight in a published binary.
//!
//! Fields are enumerated rather than taken from vergen's `all_*` constructors,
//! which would also embed the last commit's author name, email and message and
//! the resolved dependency list. The sysinfo feature is off for the same
//! reason: it records the build machine's username and hostname.
//!
//! Failure degrades two ways. If vergen runs but cannot determine a value, the
//! variable is emitted holding a sentinel (a shallow CI clone hits this). If it
//! cannot run git at all — no repository, no usable `git`, as with
//! `cargo install --path .` from an unpacked release tarball — the variable is
//! **not emitted**, and `env!` would be a compile error. `src/lib.rs` therefore
//! reads everything through `option_env!` and maps both cases to `unknown`.

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
