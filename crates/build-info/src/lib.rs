//! What the binary was built from, for `--version`.
//!
//! The values are stamped in at compile time by this crate's `build.rs` (see
//! there for what is emitted and why a build with no git repository still
//! succeeds); this crate reads them back and makes them fit to print.
//!
//! It is its own crate so the vergen build-dependency tree, and the build
//! script that must re-run whenever `.git/HEAD` changes, sit behind one small
//! leaf instead of in `cli`. That contains the machinery but does not save a
//! rebuild: cargo still recompiles dependents when the stamp changes.
//!
//! clap splits the two flags itself: `version` backs `-V` (the bare number,
//! for anything parsing it) and `long_version` backs `--version` (the full
//! block, for a bug report). The version heading the block is the
//! **caller's**, passed to [`long_version`], not this crate's — the same
//! number only for as long as every member inherits `[workspace.package]
//! version`.

use std::sync::OnceLock;

/// What vergen writes when it ran but could not determine a value.
///
/// Left as-is it would surface in `--version` as
/// `commit: VERGEN_IDEMPOTENT_OUTPUT`, which reads like a bug rather than like
/// a field that was never available.
const UNAVAILABLE: &str = "VERGEN_IDEMPOTENT_OUTPUT";

/// How a value that could not be determined is shown instead.
const UNKNOWN: &str = "unknown";

/// Read a build-time variable, or `None` if it was never emitted.
///
/// `option_env!` rather than `env!`, and this is load-bearing rather than
/// defensive. vergen has two distinct failure modes and only one of them
/// produces [`UNAVAILABLE`]:
///
/// * It ran and could not determine a value — an idempotent build, a shallow
///   clone with nothing to `describe` against. The variable is emitted holding
///   the sentinel.
/// * It could not run the git instructions at all, because there is no
///   repository and no `git`. Then the variable is **not emitted**, and `env!`
///   is a compile error.
///
/// The second case is `cargo install --path .` from an unpacked release
/// tarball — one of the two install paths the README documents — so `env!`
/// here would mean the published source could not be built from.
macro_rules! build_var {
    ($name:literal) => {
        or_unknown(option_env!($name))
    };
}

/// Turn a missing, empty or sentinel value into something readable.
fn or_unknown(value: Option<&'static str>) -> &'static str {
    match value {
        Some(value) if !value.is_empty() && value != UNAVAILABLE => value,
        _ => UNKNOWN,
    }
}

/// The commit, with an explicit marker when the tree was not clean.
///
/// A dirty build is the one case where the SHA beside it is actively
/// misleading — the source that produced the binary is not the source at that
/// commit, and nobody can reconstruct the difference. Saying so is the point.
fn commit() -> String {
    let sha = build_var!("VERGEN_GIT_SHA");
    // vergen writes "true"/"false"; anything else means it could not tell, and
    // claiming the tree was clean on a guess is the wrong way to be wrong.
    match option_env!("VERGEN_GIT_DIRTY") {
        Some("true") => format!("{sha} (with uncommitted changes)"),
        Some("false") => sha.to_string(),
        // No repository to ask, so there is nothing to be dirty relative to.
        _ if sha == UNKNOWN => sha.to_string(),
        _ => format!("{sha} (clean state unknown)"),
    }
}

/// `debug` and `release` rather than vergen's `true`/`false`, which is
/// backwards from how anyone would read a line labelled "profile".
fn profile() -> &'static str {
    match option_env!("VERGEN_CARGO_DEBUG") {
        Some("true") => "debug",
        Some("false") => "release",
        _ => UNKNOWN,
    }
}

/// The full block printed by `--version`, headed by `version`.
///
/// `version` is the **caller's** — pass `env!("CARGO_PKG_VERSION")` from the
/// binary crate. Reading it here would report this helper crate's version as
/// the tool's, which is the same number only for as long as every member
/// inherits `[workspace.package] version`.
///
/// Built once and cached, because clap wants a `&'static str` and this is a
/// dozen compile-time constants that only need joining up the first time
/// anyone asks. Nothing here can fail. The cache is not keyed on `version`, so
/// the first caller fixes the string — which is what a `--version` flag wants
/// and all this is for.
pub fn long_version(version: &str) -> &'static str {
    static LONG_VERSION: OnceLock<String> = OnceLock::new();
    LONG_VERSION.get_or_init(|| {
        let branch = build_var!("VERGEN_GIT_BRANCH");
        let describe = build_var!("VERGEN_GIT_DESCRIBE");
        let opt_level = build_var!("VERGEN_CARGO_OPT_LEVEL");

        format!(
            "{version}\n\
             \n\
             commit:     {commit}\n\
             branch:     {branch}\n\
             describe:   {describe}\n\
             committed:  {committed}\n\
             built:      {built}\n\
             target:     {target}\n\
             profile:    {profile} (opt-level {opt_level})\n\
             rustc:      {rustc} ({channel})",
            commit = commit(),
            committed = build_var!("VERGEN_GIT_COMMIT_TIMESTAMP"),
            built = build_var!("VERGEN_BUILD_TIMESTAMP"),
            target = build_var!("VERGEN_CARGO_TARGET_TRIPLE"),
            profile = profile(),
            rustc = build_var!("VERGEN_RUSTC_SEMVER"),
            channel = build_var!("VERGEN_RUSTC_CHANNEL"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for the caller's version. Deliberately not this crate's, so a
    /// test that accidentally reads `CARGO_PKG_VERSION` fails instead of
    /// passing by coincidence.
    const TEST_VERSION: &str = "9.9.9-from-the-caller";

    #[test]
    fn the_sentinel_becomes_readable() {
        assert_eq!(or_unknown(Some(UNAVAILABLE)), UNKNOWN);
        assert_eq!(or_unknown(Some("")), UNKNOWN);
    }

    /// The case that would otherwise be a compile error: vergen never emitted
    /// the variable because there was no repository to read.
    #[test]
    fn a_variable_that_was_never_emitted_becomes_readable() {
        assert_eq!(or_unknown(None), UNKNOWN);
    }

    #[test]
    fn a_real_value_passes_through() {
        assert_eq!(
            or_unknown(Some("aarch64-apple-darwin")),
            "aarch64-apple-darwin"
        );
        // "unknown" is a legitimate value from a toolchain, not only a fallback.
        assert_eq!(or_unknown(Some(UNKNOWN)), UNKNOWN);
    }

    #[test]
    fn the_profile_reads_as_a_profile() {
        // Not "true"/"false", which is what vergen emits and what a reader of
        // `profile: true` would have to decode.
        assert!(matches!(profile(), "debug" | "release"));
    }

    /// Under `cargo test` this is a debug build, which makes the assertion
    /// exact rather than a restatement of the function.
    #[test]
    fn tests_run_against_a_debug_build() {
        assert_eq!(profile(), "debug");
    }

    #[test]
    fn the_commit_line_is_never_bare_when_the_tree_is_dirty() {
        let commit = commit();
        if option_env!("VERGEN_GIT_DIRTY") == Some("true") {
            assert!(
                commit.contains("uncommitted"),
                "a dirty build must say so: {commit}"
            );
        }
    }

    /// Built without a repository, the commit line is a plain `unknown` — not
    /// `unknown (clean state unknown)`, which says the same thing twice.
    #[test]
    fn the_commit_line_stays_terse_when_there_is_no_repository() {
        if option_env!("VERGEN_GIT_SHA").is_none() {
            assert_eq!(commit(), UNKNOWN);
        }
    }

    /// The version this crate reports is whatever it was handed, not its own.
    /// Those are the same number today, so an assertion against
    /// `CARGO_PKG_VERSION` would pass either way and prove nothing.
    ///
    /// The first line is also what `-V` prints, so anything parsing
    /// `--version` for a version number keeps working.
    #[test]
    fn the_first_line_is_the_callers_version() {
        let first = long_version(TEST_VERSION)
            .lines()
            .next()
            .expect("a first line");
        assert_eq!(first, TEST_VERSION);
    }

    #[test]
    fn every_field_is_present_and_labelled() {
        let long = long_version(TEST_VERSION);
        for label in [
            "commit:",
            "branch:",
            "describe:",
            "committed:",
            "built:",
            "target:",
            "profile:",
            "rustc:",
        ] {
            assert!(long.contains(label), "{label} missing from:\n{long}");
        }
    }

    /// vergen's sentinel is an implementation detail of the build script. If it
    /// reaches the terminal, `or_unknown` was skipped somewhere.
    #[test]
    fn the_vergen_sentinel_never_reaches_the_output() {
        assert!(
            !long_version(TEST_VERSION).contains(UNAVAILABLE),
            "vergen's placeholder leaked into --version:\n{}",
            long_version(TEST_VERSION)
        );
    }

    /// Guards against build.rs emitting fields this module does not print —
    /// they would be embedded in a published binary for no reason. The author
    /// email and commit message are the ones worth naming, since `all_git()`
    /// would have included them.
    #[test]
    fn nothing_personal_is_embedded() {
        assert!(
            option_env!("VERGEN_GIT_COMMIT_AUTHOR_EMAIL").is_none(),
            "build.rs must not embed the commit author's email"
        );
        assert!(
            option_env!("VERGEN_GIT_COMMIT_AUTHOR_NAME").is_none(),
            "build.rs must not embed the commit author's name"
        );
        assert!(
            option_env!("VERGEN_GIT_COMMIT_MESSAGE").is_none(),
            "build.rs must not embed the commit message"
        );
        assert!(
            option_env!("VERGEN_SYSINFO_USER").is_none(),
            "build.rs must not embed the build machine's user"
        );
        assert!(
            option_env!("VERGEN_SYSINFO_NAME").is_none(),
            "build.rs must not embed the build machine's hostname"
        );
        assert!(
            option_env!("VERGEN_CARGO_DEPENDENCIES").is_none(),
            "build.rs must not embed the dependency list"
        );
    }

    /// Cached, so repeated calls hand back the same allocation rather than
    /// rebuilding the block.
    #[test]
    fn the_block_is_built_once() {
        assert!(std::ptr::eq(
            long_version(TEST_VERSION),
            long_version(TEST_VERSION)
        ));
    }
}
