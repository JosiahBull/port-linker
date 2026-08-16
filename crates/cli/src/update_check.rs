//! Tell the user when a newer release exists.
//!
//! port-linker is installed with `cargo install --path .` or by unpacking a
//! release tarball by hand. Neither leaves anything behind that would later
//! notice a new version, so without this a user can sit on an old release
//! indefinitely. This closes that gap and nothing more: it **never downloads or
//! replaces a binary**, it only prints the version and the release URL.
//!
//! This is the only outbound network request the tool makes that is not part of
//! a tunnel the user explicitly asked for, so it is off until the user agrees to
//! it — see [`UpdateCheck`].
//!
//! # Shape
//!
//! The decision is pure and the I/O is not, which is what makes this testable
//! without a network or a terminal:
//!
//! * [`plan`] takes the policy, the state read off disk, the running version,
//!   the time and whether there is a terminal, and returns [`Plan`] — three
//!   independent answers: print a notice, ask for consent, refresh the cache.
//! * [`State`] is the on-disk cache. Parsing it never fails.
//! * Everything that touches the filesystem, the network or the user is a thin
//!   wrapper around those.
//!
//! # Timing
//!
//! The notice is printed from the cache, synchronously, and the refresh happens
//! on a detached thread. Nothing waits on github.com, so a slow or unreachable
//! network cannot delay the tunnel coming up. The cost is that the run which
//! *discovers* a new release stays quiet and the notice appears on the next one,
//! which for a notification is not worth a startup stall.

use std::fmt;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use semver::Version;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Redirects to the newest non-prerelease release.
///
/// GitHub excludes drafts and prereleases from this endpoint, which matters
/// here: `release.yaml`'s `workflow_dispatch` path publishes `dev-*` builds as
/// prereleases, and they must never be offered as an upgrade.
///
/// Built from the manifest so there is one place to change the repository, and
/// pinned by a test because that field named the wrong GitHub account until this
/// feature was written — a wrong value here would send every user to a
/// stranger's release page.
const RELEASES_LATEST_URL: &str = concat!(env!("CARGO_PKG_REPOSITORY"), "/releases/latest");

/// The prefix a `Location` must have for its tail to be treated as a version.
const RELEASES_TAG_PREFIX: &str = concat!(env!("CARGO_PKG_REPOSITORY"), "/releases/tag/v");

/// How long a cached answer is good for.
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Caps the whole request. ureq applies no timeouts of its own — every field of
/// its `Timeouts` defaults to `None` — so without this a black-holed connection
/// leaves the refresh thread alive for the life of the process.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Caps DNS, TCP and the TLS handshake within [`REQUEST_TIMEOUT`].
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Distinguishes this file's format if it ever needs to change, and identifies
/// the file as ours before anything is read from it.
const STATE_HEADER: &str = "PLK_UPDATE_V1";

/// The consent record and version cache, inside [`crate::logging::state_directory`].
const STATE_FILE_NAME: &str = "update-check.state";

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Whether to check for a newer release, and whether to ask first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum UpdateCheck {
    /// Ask once, on a terminal, and remember the answer.
    ///
    /// A run with no terminal neither asks nor checks, and records nothing — so
    /// a CI job cannot answer on behalf of the person who uses the same machine.
    #[default]
    Ask,
    /// Check without asking. Never records consent, so passing this once does
    /// not change what an unflagged run does later.
    Enabled,
    /// Never check and never ask. No network request is made.
    Disabled,
}

impl fmt::Display for UpdateCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ask => write!(f, "ask"),
            Self::Enabled => write!(f, "enabled"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

/// What the policy resolves to once the recorded answer is taken into account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Check.
    On,
    /// Do not check.
    Off,
    /// The user has not been asked yet.
    Undecided,
}

impl UpdateCheck {
    /// Fold the recorded consent into the policy.
    const fn mode(self, consent: Option<bool>) -> Mode {
        match self {
            Self::Disabled => Mode::Off,
            // Deliberately ignores the recorded answer rather than overwriting
            // it: `--update-check enabled` is for one run, not a way to flip a
            // machine-level default from the command line.
            Self::Enabled => Mode::On,
            Self::Ask => match consent {
                Some(true) => Mode::On,
                Some(false) => Mode::Off,
                None => Mode::Undecided,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// On-disk state
// ---------------------------------------------------------------------------

/// The consent record and the last answer from GitHub.
///
/// Every field is optional and [`State::parse`] cannot fail, because the two
/// kinds of data here have very different costs when lost. Losing `consent`
/// re-prompts a user who already answered; losing the cache costs one HTTP
/// request. A malformed timestamp must not be able to take the consent with it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    /// Whether the user agreed to the check. `None` means never asked.
    consent: Option<bool>,
    /// When the last attempt was made, in seconds since the Unix epoch.
    /// Advanced on a failed attempt too — see [`state_after_refresh`].
    last_check: Option<u64>,
    /// The newest release seen, exactly as GitHub reported it.
    latest_seen: Option<Version>,
}

impl State {
    /// Render the file. Fields that are `None` are omitted rather than written
    /// empty, so a reader cannot mistake "unset" for "set to nothing".
    fn encode(&self) -> String {
        let mut out = String::from(STATE_HEADER);
        out.push('\n');
        if let Some(consent) = self.consent {
            let value = if consent { "yes" } else { "no" };
            out.push_str(&format!("CONSENT={value}\n"));
        }
        if let Some(last_check) = self.last_check {
            out.push_str(&format!("LAST_CHECK={last_check}\n"));
        }
        if let Some(latest) = &self.latest_seen {
            out.push_str(&format!("LATEST_SEEN={latest}\n"));
        }
        out
    }

    /// Read the file, keeping whatever is intelligible and discarding the rest.
    ///
    /// Infallible by design, and so a deliberate departure from
    /// [`common::session`]'s `parse`, which returns a `Result`. A session file
    /// that will not parse must stop the connection; this one is a cache whose
    /// worst failure is asking a question again.
    ///
    /// A missing or unrecognised header yields the default, so a file written
    /// by some future version is ignored rather than half-understood.
    fn parse(text: &str) -> Self {
        let mut lines = text.lines();
        if lines.next().map(str::trim) != Some(STATE_HEADER) {
            return Self::default();
        }

        let mut state = Self::default();
        for line in lines {
            let Some((key, value)) = line.trim().split_once('=') else {
                continue;
            };
            match key.trim() {
                // Anything other than an exact yes/no leaves consent unset, so
                // a corrupted answer re-asks rather than assuming either way.
                "CONSENT" => {
                    state.consent = match value.trim() {
                        "yes" => Some(true),
                        "no" => Some(false),
                        _ => None,
                    };
                }
                "LAST_CHECK" => state.last_check = value.trim().parse().ok(),
                "LATEST_SEEN" => state.latest_seen = Version::parse(value.trim()).ok(),
                // Unknown keys are skipped, not fatal: a newer version of this
                // file can add fields without the older one refusing to read it.
                _ => {}
            }
        }
        state
    }

    /// Whether the cached answer is old enough to refresh.
    ///
    /// A `last_check` in the future counts as stale. Clocks move backwards —
    /// an NTP correction, a suspended VM, a dual-boot — and the alternative is
    /// a subtraction that underflows and marks the cache fresh for the next
    /// several billion years.
    fn is_stale(&self, now_unix: u64) -> bool {
        match self.last_check {
            None => true,
            Some(last) if last > now_unix => true,
            Some(last) => now_unix.saturating_sub(last) >= CHECK_INTERVAL.as_secs(),
        }
    }
}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

/// What this run should do. Three independent answers, not a single verdict —
/// notifying reads the cache and refreshing writes it, and keeping them apart
/// is what lets the notice be instant while the request happens later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Print a notice naming this version.
    notify: Option<Version>,
    /// Ask for consent and record the answer.
    prompt: bool,
    /// Make the request and rewrite the cache.
    refresh: bool,
}

/// Decide what to do. Pure: no clock, no filesystem, no network, no terminal.
fn plan(
    policy: UpdateCheck,
    state: &State,
    current: &Version,
    now_unix: u64,
    interactive: bool,
) -> Plan {
    match policy.mode(state.consent) {
        Mode::Off => Plan {
            notify: None,
            prompt: false,
            refresh: false,
        },

        // Nothing is printed before the user has agreed. A `latest_seen` sitting
        // in the file without consent means the file is inconsistent, and
        // honouring it would surface the result of a request that should never
        // have happened.
        Mode::Undecided => Plan {
            notify: None,
            prompt: interactive,
            refresh: false,
        },

        // Notifying is independent of the terminal: a run with its output piped
        // to a file should still record that an upgrade is available.
        Mode::On => Plan {
            notify: newer_than(current, state.latest_seen.as_ref()),
            prompt: false,
            refresh: state.is_stale(now_unix),
        },
    }
}

/// The cached version, if it is actually newer than what is running.
///
/// Compared on every read rather than stored as a "newer" flag, so upgrading
/// silences the notice with no need to clear anything, and a release that is
/// yanked and replaced by a lower version stops being offered.
fn newer_than(current: &Version, latest: Option<&Version>) -> Option<Version> {
    latest.filter(|latest| *latest > current).cloned()
}

/// The state to write once the user has answered. Preserves the cache.
fn state_after_consent(prev: &State, granted: bool) -> State {
    State {
        consent: Some(granted),
        ..prev.clone()
    }
}

/// The state to write after an attempt. `latest` is `None` when it failed.
///
/// `last_check` advances either way. A machine that is offline, or behind a
/// proxy whose root CA this does not trust, would otherwise pay a DNS and TLS
/// timeout on every single invocation forever; the interval exists to bound
/// attempts, not successes. The cost is that a transient outage delays the
/// notice by up to a day, which for a notification is nothing.
///
/// A failure leaves `latest_seen` alone, so a previously discovered upgrade
/// keeps being reported through an offline spell.
fn state_after_refresh(prev: &State, now_unix: u64, latest: Option<Version>) -> State {
    State {
        consent: prev.consent,
        last_check: Some(now_unix),
        // Stored verbatim on success, including when it is older than what is
        // cached. Keeping only the highest version ever seen would make the
        // cache a ratchet that a yanked release could never move back down.
        latest_seen: latest.or_else(|| prev.latest_seen.clone()),
    }
}

/// Pull the version out of a GitHub release redirect.
///
/// Requires the exact `.../releases/tag/vX.Y.Z` shape, which rejects three real
/// cases: a repository with no non-prerelease release at all, where
/// `/releases/latest` redirects to the release *list*; a `dev-*` prerelease tag;
/// and — the reason this is strict rather than a suffix search — a `Location`
/// pointing anywhere other than this repository. An arbitrary redirect target
/// must never reach [`Version::parse`].
fn version_from_release_url(location: &str) -> Option<Version> {
    let tag = location.trim().strip_prefix(RELEASES_TAG_PREFIX)?;
    // A tag is one path segment; anything further down is not a release page.
    if tag.is_empty() || tag.contains('/') {
        return None;
    }
    Version::parse(tag).ok()
}

// ---------------------------------------------------------------------------
// I/O
// ---------------------------------------------------------------------------

/// Where the consent record lives.
fn state_path() -> PathBuf {
    crate::logging::state_directory().join(STATE_FILE_NAME)
}

/// Read the state, treating every failure as "nothing recorded".
fn load(path: &Path) -> State {
    match std::fs::read_to_string(path) {
        Ok(text) => State::parse(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
        Err(e) => {
            debug!(path = %path.display(), %e, "could not read update-check state");
            State::default()
        }
    }
}

/// Write the state, replacing whatever is there.
///
/// Temp file then rename, so a reader never sees a half-written file and a
/// crash mid-write cannot destroy the previous one. The temp name carries the
/// process id because two `port-linker` processes can run at once and would
/// otherwise truncate each other's partial writes before either renamed.
///
/// Rename makes each write atomic; it does not serialise two writers, and
/// nothing here tries to. The loser of a race loses a cached version number and
/// pays one redundant request next time, which is not worth a lock file.
///
/// Note this cannot reuse `write_private_file` from `main.rs` — that is
/// `create_new(true)`, which is right for a session file written once and wrong
/// for a cache rewritten on every refresh.
fn store(path: &Path, state: &State) -> std::io::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(&tmp)?;
    file.write_all(state.encode().as_bytes())?;
    file.sync_all()?;
    drop(file);

    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Windows can refuse a rename over a file another process holds
            // open. Leaving the temp file behind would litter the state
            // directory, so clear it up before reporting the failure.
            std::fs::remove_file(&tmp).ok();
            Err(e)
        }
    }
}

/// Seconds since the Unix epoch, or `None` if the clock is before it.
fn now_unix() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Ask GitHub for the newest release.
fn fetch_latest() -> Option<Version> {
    fetch_latest_from(RELEASES_LATEST_URL)
}

/// Ask `url` for the newest release and read it out of the redirect.
///
/// A `HEAD` rather than a `GET`: everything needed is in the `Location` header,
/// and following the redirect would pull down a full HTML release page to throw
/// it away.
///
/// Returns `None` for every failure. There is no error to propagate — a version
/// check that cannot reach the network is not a reason to fail a run, and the
/// caller has nothing it could do differently.
///
/// The base URL is a parameter so the tests can point this at a local stub, the
/// same seam `sure`'s suite uses for the services it proxies — there the system
/// under test is a subprocess so the URL arrives as an environment variable;
/// here it is in-process, so a parameter does the same job without a
/// process-wide variable that parallel tests would race on.
///
/// The response is still validated against [`RELEASES_TAG_PREFIX`], so a stub
/// has to return a `Location` GitHub would plausibly have returned, and the
/// production URL is fixed at compile time.
fn fetch_latest_from(url: &str) -> Option<Version> {
    // `max_redirects(0)` makes ureq hand back the 302 instead of following it.
    // Note a 3xx is not an error even though `http_status_as_error` defaults to
    // true — ureq only converts 4xx and 5xx — so that setting is left alone and
    // genuine failures still surface as errors.
    //
    // No `https_only`: with redirects off there is exactly one request, to a URL
    // fixed at compile time, so there is no downgrade for it to prevent — and
    // setting it would mean the tests could not use a cleartext stub. What
    // actually pins the scheme is `RELEASES_TAG_PREFIX`, which every response is
    // checked against.
    let config = ureq::Agent::config_builder()
        .max_redirects(0)
        .timeout_global(Some(REQUEST_TIMEOUT))
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .user_agent(concat!("port-linker/", env!("CARGO_PKG_VERSION")))
        .build();

    let response = ureq::Agent::new_with_config(config)
        .head(url)
        .call()
        .inspect_err(|e| debug!(%e, "update check request failed"))
        .ok()?;

    let location = response
        .headers()
        .get(ureq::http::header::LOCATION)
        .and_then(|value| value.to_str().ok())?;

    version_from_release_url(location)
}

/// Show the fingerprintless consent question.
///
/// Both streams have to be terminals because dialoguer reads one and draws on
/// the other, the same requirement as the host key prompt in
/// [`crate::ssh`]. Defaults to no, and a read error or Ctrl-C collapses to the
/// same answer.
fn prompt_for_consent() -> bool {
    dialoguer::Confirm::new()
        .with_prompt(
            "port-linker can check GitHub once a day for a newer release.\n  \
             Nothing is downloaded or installed — it only prints a notice.\n\
             Check for updates?",
        )
        .default(false)
        .interact()
        .unwrap_or(false)
}

/// Whether there is a terminal to ask a question on.
fn is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// Print the notice.
///
/// `eprintln!` as well as a log event, for the same reason the host key prompt
/// does it: tracing goes only to the log file unless `RUST_LOG` is set, and
/// stdout is reserved for TUI output. A notice nobody sees is not a notice.
fn print_notice(latest: &Version, current: &Version) {
    info!(%latest, %current, "a newer release is available");
    eprintln!(
        "port-linker {latest} is available (you have {current}).\n  \
         {RELEASES_LATEST_URL}\n\
         Pass --update-check disabled to stop checking."
    );
}

/// Run the check.
///
/// Synchronous and quick: it reads a small file, may print, may ask, and hands
/// any network work to a detached thread. Call once, from `main`, before
/// dispatch — never from inside the reconnect loop.
///
/// The refresh runs on a plain [`std::thread`] rather than
/// `tokio::task::spawn_blocking` deliberately. Dropping the tokio runtime blocks
/// until in-flight blocking tasks return, and a blocking task cannot be
/// cancelled — so a `spawn_blocking` here would add up to [`REQUEST_TIMEOUT`] to
/// the exit of `--echo-only`, a flag whose entire promise is exiting
/// immediately. A detached thread is abandoned at exit instead.
pub fn run(policy: UpdateCheck) {
    let Some(now) = now_unix() else {
        debug!("system clock is before the Unix epoch; skipping the update check");
        return;
    };

    // A version cargo would not have accepted cannot happen, but this runs
    // before anything else and must not be the thing that panics.
    let Ok(current) = Version::parse(env!("CARGO_PKG_VERSION")) else {
        debug!("could not parse the running version; skipping the update check");
        return;
    };

    let path = state_path();
    let state = load(&path);
    let plan = plan(policy, &state, &current, now, is_interactive());

    if let Some(latest) = &plan.notify {
        print_notice(latest, &current);
    }

    if plan.prompt {
        let granted = prompt_for_consent();
        let state = state_after_consent(&state, granted);

        if let Err(e) = store(&path, &state) {
            // A read-only home, a container, a full disk. The check is skipped
            // for this run rather than retried, because the alternative is
            // asking the same question on every run forever with no way for the
            // user to make it stop except a flag they have not been told about.
            warn!(path = %path.display(), %e, "could not record the update-check answer");
            eprintln!(
                "warning: could not save your answer to {}: {e}\n  \
                 Set PLK_UPDATE_CHECK=disabled to stop being asked.",
                path.display()
            );
            return;
        }

        if granted {
            // Inline, unlike every other refresh, for two reasons. A detached
            // thread would be killed by a short-lived run, so the answer would
            // look like it did nothing at all. And the user is standing at a
            // terminal having just answered, so a bounded wait is invisible and
            // this is the one run that can show a result straight away.
            let refreshed = refresh(&path, &state, now);
            if let Some(latest) = newer_than(&current, refreshed.latest_seen.as_ref()) {
                print_notice(&latest, &current);
            }
        }
        return;
    }

    if !plan.refresh {
        return;
    }

    // A consenting run with a stale cache. Detached rather than
    // `tokio::task::spawn_blocking`: dropping the tokio runtime waits for
    // in-flight blocking tasks and a blocking task cannot be cancelled, so that
    // would add up to `REQUEST_TIMEOUT` to the exit of `--echo-only` — a flag
    // whose whole promise is exiting immediately. A detached thread is
    // abandoned at exit, which for a cache refresh is exactly right.
    //
    // Silent by design. Whatever the cache held was already reported above, and
    // a second notice arriving seconds later, interleaved with connection logs,
    // would be noise. A version discovered here is reported by the next run.
    std::thread::spawn(move || {
        refresh(&path, &state, now);
    });
}

/// Fetch and store. Returns the state that was written.
fn refresh(path: &Path, state: &State, now: u64) -> State {
    let latest = fetch_latest();
    debug!(?latest, "update check finished");

    let refreshed = state_after_refresh(state, now, latest);
    if let Err(e) = store(path, &refreshed) {
        debug!(path = %path.display(), %e, "could not save the update-check result");
    }
    refreshed
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).expect("valid semver")
    }

    /// The version under test is always this, so a test that cares about the
    /// comparison says so by choosing the cached value.
    fn current() -> Version {
        v("1.0.0")
    }

    const NOW: u64 = 1_755_300_000;
    const DAY: u64 = 24 * 60 * 60;

    /// A state that has consented and holds a cache of the given age.
    fn consented(latest: Option<&str>, checked_secs_ago: u64) -> State {
        State {
            consent: Some(true),
            last_check: Some(NOW - checked_secs_ago),
            latest_seen: latest.map(v),
        }
    }

    // -- Policy resolution --------------------------------------------------

    #[test]
    fn disabled_does_nothing_even_with_a_newer_version_cached() {
        let plan = plan(
            UpdateCheck::Disabled,
            &consented(Some("2.0.0"), 0),
            &current(),
            NOW,
            true,
        );
        assert_eq!(plan.notify, None, "an opted-out user must not be notified");
        assert!(!plan.prompt);
        assert!(!plan.refresh);
    }

    #[test]
    fn disabled_ignores_a_recorded_yes() {
        let plan = plan(
            UpdateCheck::Disabled,
            &consented(Some("2.0.0"), 10 * DAY),
            &current(),
            NOW,
            true,
        );
        assert!(!plan.refresh, "the flag must win over the recorded answer");
    }

    #[test]
    fn enabled_never_prompts_even_without_consent_on_a_terminal() {
        let plan = plan(
            UpdateCheck::Enabled,
            &State::default(),
            &current(),
            NOW,
            true,
        );
        assert!(!plan.prompt);
        assert!(plan.refresh);
    }

    #[test]
    fn enabled_ignores_a_recorded_no() {
        let state = State {
            consent: Some(false),
            ..State::default()
        };
        let plan = plan(UpdateCheck::Enabled, &state, &current(), NOW, false);
        assert!(plan.refresh, "the flag must win over the recorded answer");
    }

    #[test]
    fn ask_with_a_recorded_yes_behaves_like_enabled() {
        let with_consent = plan(
            UpdateCheck::Ask,
            &consented(Some("2.0.0"), 10 * DAY),
            &current(),
            NOW,
            false,
        );
        let enabled = plan(
            UpdateCheck::Enabled,
            &consented(Some("2.0.0"), 10 * DAY),
            &current(),
            NOW,
            false,
        );
        assert_eq!(with_consent, enabled);
    }

    #[test]
    fn ask_with_a_recorded_no_behaves_like_disabled() {
        let state = State {
            consent: Some(false),
            latest_seen: Some(v("2.0.0")),
            last_check: Some(NOW - 10 * DAY),
        };
        let declined = plan(UpdateCheck::Ask, &state, &current(), NOW, true);
        assert_eq!(
            declined,
            plan(UpdateCheck::Disabled, &state, &current(), NOW, true)
        );
        assert!(!declined.prompt, "a declined user must not be asked again");
    }

    #[test]
    fn ask_prompts_on_a_terminal_when_undecided() {
        let plan = plan(UpdateCheck::Ask, &State::default(), &current(), NOW, true);
        assert!(plan.prompt);
        assert!(
            !plan.refresh,
            "the request must wait for an answer, not race it"
        );
    }

    #[test]
    fn ask_is_silent_and_offline_without_a_terminal() {
        let plan = plan(UpdateCheck::Ask, &State::default(), &current(), NOW, false);
        assert!(!plan.prompt, "there is nobody to answer");
        assert!(!plan.refresh, "no consent means no request");
        assert_eq!(plan.notify, None);
    }

    /// Consent and a cached version cannot legitimately coexist, so the file has
    /// been tampered with or half-written. Printing would surface the result of
    /// a request the user never agreed to.
    #[test]
    fn an_undecided_state_never_notifies_from_a_stray_cache() {
        let state = State {
            consent: None,
            last_check: Some(NOW),
            latest_seen: Some(v("2.0.0")),
        };
        let plan = plan(UpdateCheck::Ask, &state, &current(), NOW, true);
        assert_eq!(plan.notify, None);
    }

    // -- Notifying ----------------------------------------------------------

    #[test]
    fn notifies_from_a_stale_cache_without_waiting_for_the_refresh() {
        let plan = plan(
            UpdateCheck::Enabled,
            &consented(Some("2.0.0"), 10 * DAY),
            &current(),
            NOW,
            false,
        );
        assert_eq!(plan.notify, Some(v("2.0.0")));
        assert!(plan.refresh, "and refreshes for next time");
    }

    #[test]
    fn notifies_regardless_of_a_terminal() {
        let piped = plan(
            UpdateCheck::Enabled,
            &consented(Some("2.0.0"), 0),
            &current(),
            NOW,
            false,
        );
        assert_eq!(
            piped.notify,
            Some(v("2.0.0")),
            "piping output must not swallow the notice"
        );
    }

    /// The upgrade case: after installing the version that was being advertised,
    /// the cache still names it and must go quiet without being cleared.
    #[test]
    fn an_equal_cached_version_does_not_notify() {
        let plan = plan(
            UpdateCheck::Enabled,
            &consented(Some("1.0.0"), 0),
            &current(),
            NOW,
            false,
        );
        assert_eq!(plan.notify, None);
    }

    #[test]
    fn an_older_cached_version_does_not_notify() {
        let plan = plan(
            UpdateCheck::Enabled,
            &consented(Some("0.9.0"), 0),
            &current(),
            NOW,
            false,
        );
        assert_eq!(plan.notify, None);
    }

    #[test]
    fn an_empty_cache_does_not_notify() {
        let plan = plan(
            UpdateCheck::Enabled,
            &consented(None, 0),
            &current(),
            NOW,
            false,
        );
        assert_eq!(plan.notify, None);
    }

    /// Someone running a `dev-*` build of the next version is ahead of the
    /// latest release, not behind it.
    #[test]
    fn a_prerelease_running_version_is_not_told_to_downgrade() {
        let plan = plan(
            UpdateCheck::Enabled,
            &consented(Some("1.0.0"), 0),
            &v("1.1.0-dev"),
            NOW,
            false,
        );
        assert_eq!(plan.notify, None);
    }

    #[test]
    fn semver_ordering_beats_string_ordering() {
        // The case a lexicographic comparison gets wrong.
        let plan = plan(
            UpdateCheck::Enabled,
            &consented(Some("0.10.0"), 0),
            &v("0.9.0"),
            NOW,
            false,
        );
        assert_eq!(plan.notify, Some(v("0.10.0")));
    }

    // -- Staleness ----------------------------------------------------------

    #[test]
    fn a_fresh_cache_is_not_refreshed() {
        let plan = plan(
            UpdateCheck::Enabled,
            &consented(Some("2.0.0"), DAY / 2),
            &current(),
            NOW,
            false,
        );
        assert!(!plan.refresh);
        assert_eq!(
            plan.notify,
            Some(v("2.0.0")),
            "but still reports what it knows"
        );
    }

    #[test]
    fn a_cache_older_than_the_interval_is_refreshed() {
        let plan = plan(
            UpdateCheck::Enabled,
            &consented(Some("2.0.0"), DAY + 1),
            &current(),
            NOW,
            false,
        );
        assert!(plan.refresh);
    }

    #[test]
    fn a_never_checked_state_is_stale() {
        assert!(State::default().is_stale(NOW));
    }

    /// Clocks move backwards. The subtraction this replaced would have
    /// underflowed and marked the cache fresh for the next few billion years.
    #[test]
    fn a_last_check_in_the_future_is_stale_and_does_not_panic() {
        let state = State {
            consent: Some(true),
            last_check: Some(NOW + 30 * DAY),
            latest_seen: None,
        };
        assert!(state.is_stale(NOW));
        assert!(plan(UpdateCheck::Enabled, &state, &current(), NOW, false).refresh);
    }

    // -- State transitions --------------------------------------------------

    #[test]
    fn recording_consent_preserves_the_cache() {
        let prev = consented(Some("2.0.0"), DAY);
        let next = state_after_consent(&prev, false);
        assert_eq!(next.consent, Some(false));
        assert_eq!(next.latest_seen, prev.latest_seen);
        assert_eq!(next.last_check, prev.last_check);
    }

    #[test]
    fn a_failed_refresh_still_advances_the_timestamp() {
        let prev = consented(Some("2.0.0"), 10 * DAY);
        let next = state_after_refresh(&prev, NOW, None);
        assert_eq!(
            next.last_check,
            Some(NOW),
            "an unreachable network must not be retried on every run"
        );
    }

    #[test]
    fn a_failed_refresh_keeps_the_last_known_version() {
        let prev = consented(Some("2.0.0"), 10 * DAY);
        let next = state_after_refresh(&prev, NOW, None);
        assert_eq!(
            next.latest_seen,
            Some(v("2.0.0")),
            "an offline day must not silence a known upgrade"
        );
    }

    /// A yanked release can lower the latest version. Keeping only the highest
    /// value ever seen would advertise a release that no longer exists.
    #[test]
    fn a_successful_refresh_stores_the_answer_verbatim_even_if_lower() {
        let prev = consented(Some("2.0.0"), 10 * DAY);
        let next = state_after_refresh(&prev, NOW, Some(v("1.5.0")));
        assert_eq!(next.latest_seen, Some(v("1.5.0")));
    }

    #[test]
    fn a_refresh_preserves_consent() {
        let prev = consented(None, 10 * DAY);
        let next = state_after_refresh(&prev, NOW, Some(v("2.0.0")));
        assert_eq!(next.consent, Some(true));
    }

    // -- The state file -----------------------------------------------------

    #[test]
    fn round_trips_a_fully_populated_state() {
        let state = State {
            consent: Some(true),
            last_check: Some(NOW),
            latest_seen: Some(v("1.2.3")),
        };
        assert_eq!(State::parse(&state.encode()), state);
    }

    #[test]
    fn round_trips_an_empty_state() {
        let state = State::default();
        assert_eq!(State::parse(&state.encode()), state);
    }

    #[test]
    fn round_trips_a_declined_state() {
        let state = State {
            consent: Some(false),
            ..State::default()
        };
        assert_eq!(State::parse(&state.encode()), state);
    }

    #[test]
    fn a_missing_header_yields_the_default() {
        assert_eq!(State::parse("CONSENT=yes\n"), State::default());
    }

    #[test]
    fn a_foreign_header_yields_the_default() {
        assert_eq!(
            State::parse("PLK_UPDATE_V2\nCONSENT=yes\n"),
            State::default()
        );
    }

    #[test]
    fn garbage_yields_the_default() {
        assert_eq!(State::parse("garbage"), State::default());
        assert_eq!(State::parse(""), State::default());
    }

    #[test]
    fn a_truncated_file_keeps_what_survived() {
        let state = State::parse("PLK_UPDATE_V1\nCONSENT=yes\nLAST_CH");
        assert_eq!(state.consent, Some(true));
        assert_eq!(state.last_check, None);
    }

    /// The reason parsing is per-field rather than all-or-nothing: losing the
    /// cache costs one request, losing consent re-asks a user who already
    /// answered.
    #[test]
    fn a_corrupt_timestamp_does_not_discard_consent() {
        let state = State::parse("PLK_UPDATE_V1\nCONSENT=yes\nLAST_CHECK=not-a-number\n");
        assert_eq!(state.consent, Some(true));
        assert_eq!(state.last_check, None);
    }

    #[test]
    fn an_unparseable_version_does_not_discard_consent() {
        let state = State::parse("PLK_UPDATE_V1\nCONSENT=yes\nLATEST_SEEN=not-a-version\n");
        assert_eq!(state.consent, Some(true));
        assert_eq!(state.latest_seen, None);
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let state = State::parse("PLK_UPDATE_V1\nCONSENT=yes\nFUTURE_FIELD=whatever\n");
        assert_eq!(state.consent, Some(true));
    }

    /// Anything but an exact yes or no leaves the user undecided, so a mangled
    /// answer asks again rather than guessing.
    #[test]
    fn consent_accepts_only_yes_or_no() {
        for value in ["maybe", "true", "1", "Yes", ""] {
            let text = format!("PLK_UPDATE_V1\nCONSENT={value}\n");
            assert_eq!(
                State::parse(&text).consent,
                None,
                "'{value}' must not be read as an answer"
            );
        }
    }

    #[test]
    fn a_line_without_a_separator_is_skipped() {
        let state = State::parse("PLK_UPDATE_V1\nnonsense\nCONSENT=yes\n");
        assert_eq!(state.consent, Some(true));
    }

    // -- Redirect parsing ---------------------------------------------------

    #[test]
    fn parses_a_release_tag_redirect() {
        assert_eq!(
            version_from_release_url(
                "https://github.com/JosiahBull/port-linker/releases/tag/v0.7.0"
            ),
            Some(v("0.7.0"))
        );
    }

    /// What GitHub returns for a repository whose only releases are
    /// prereleases — the `dev-*` builds `release.yaml` publishes.
    #[test]
    fn rejects_the_release_list_page() {
        assert_eq!(
            version_from_release_url("https://github.com/JosiahBull/port-linker/releases"),
            None
        );
    }

    #[test]
    fn rejects_a_non_semver_tag() {
        assert_eq!(
            version_from_release_url(
                "https://github.com/JosiahBull/port-linker/releases/tag/vdev-20260816-120000-abc1234"
            ),
            None
        );
    }

    #[test]
    fn rejects_a_tag_without_the_v_prefix() {
        assert_eq!(
            version_from_release_url(
                "https://github.com/JosiahBull/port-linker/releases/tag/0.7.0"
            ),
            None
        );
    }

    /// A redirect target is attacker-influenced input. Nothing outside this
    /// repository's release namespace may reach the version parser.
    #[test]
    fn rejects_a_foreign_host() {
        for url in [
            "https://example.com/JosiahBull/port-linker/releases/tag/v9.9.9",
            "http://github.com/JosiahBull/port-linker/releases/tag/v9.9.9",
            "https://github.com/someone-else/port-linker/releases/tag/v9.9.9",
            "https://github.com.evil.test/JosiahBull/port-linker/releases/tag/v9.9.9",
        ] {
            assert_eq!(version_from_release_url(url), None, "must reject {url}");
        }
    }

    #[test]
    fn rejects_a_deeper_path_under_the_tag_prefix() {
        assert_eq!(
            version_from_release_url(
                "https://github.com/JosiahBull/port-linker/releases/tag/v0.7.0/extra"
            ),
            None
        );
    }

    #[test]
    fn rejects_an_empty_tag() {
        assert_eq!(version_from_release_url(RELEASES_TAG_PREFIX), None);
    }

    #[test]
    fn tolerates_surrounding_whitespace() {
        assert_eq!(
            version_from_release_url(
                "  https://github.com/JosiahBull/port-linker/releases/tag/v0.7.0\r\n"
            ),
            Some(v("0.7.0"))
        );
    }

    // -- Guards -------------------------------------------------------------

    #[test]
    fn update_check_display() {
        assert_eq!(UpdateCheck::Ask.to_string(), "ask");
        assert_eq!(UpdateCheck::Enabled.to_string(), "enabled");
        assert_eq!(UpdateCheck::Disabled.to_string(), "disabled");
    }

    /// `default_value_t` renders the default through `Display` and then parses
    /// it back with the `ValueEnum` parser, so a `Display` string that is not
    /// also a valid value makes the CLI panic on startup.
    #[test]
    fn display_round_trips_through_the_value_parser() {
        use clap::ValueEnum;

        for policy in UpdateCheck::value_variants() {
            let rendered = policy.to_string();
            let parsed = UpdateCheck::from_str(&rendered, true)
                .unwrap_or_else(|_| panic!("'{rendered}' must parse back to a policy"));
            assert_eq!(*policy, parsed);
        }
    }

    /// The URLs come from `[workspace.package] repository`, which named a
    /// different person's GitHub account for the first six releases because
    /// nothing read it. Now that it decides where users are sent, it is worth
    /// asserting outright rather than trusting that someone would notice.
    #[test]
    fn the_release_urls_point_at_this_repository() {
        assert_eq!(
            RELEASES_LATEST_URL,
            "https://github.com/JosiahBull/port-linker/releases/latest"
        );
        assert_eq!(
            RELEASES_TAG_PREFIX,
            "https://github.com/JosiahBull/port-linker/releases/tag/v"
        );
    }

    /// The default has to be the variant that asks, or the first run of an
    /// upgrade would check without consent.
    #[test]
    fn the_default_policy_asks() {
        assert_eq!(UpdateCheck::default(), UpdateCheck::Ask);
        assert_eq!(
            UpdateCheck::default().mode(None),
            Mode::Undecided,
            "and an unanswered default must not resolve to on"
        );
    }

    // -- Round trip through the filesystem ----------------------------------

    /// A scratch state file removed when the test ends. There is no `tempfile`
    /// dependency in this workspace; this mirrors the RAII helper the host key
    /// tests use.
    struct ScratchState(PathBuf);

    impl ScratchState {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "plk-update-check-{name}-{}",
                common::generate_token().expect("token")
            ));
            Self(path)
        }
    }

    impl Drop for ScratchState {
        fn drop(&mut self) {
            std::fs::remove_file(&self.0).ok();
        }
    }

    #[test]
    fn a_missing_file_loads_as_the_default() {
        let scratch = ScratchState::new("missing");
        assert_eq!(load(&scratch.0), State::default());
    }

    #[test]
    fn stores_and_loads_a_state() {
        let scratch = ScratchState::new("round-trip");
        let state = State {
            consent: Some(true),
            last_check: Some(NOW),
            latest_seen: Some(v("1.2.3")),
        };
        store(&scratch.0, &state).expect("store");
        assert_eq!(load(&scratch.0), state);
    }

    /// The cache is rewritten on every refresh, so the write path must replace
    /// an existing file rather than failing on it.
    #[test]
    fn storing_twice_overwrites() {
        let scratch = ScratchState::new("overwrite");
        store(&scratch.0, &consented(Some("1.0.0"), 0)).expect("first store");
        let second = consented(Some("2.0.0"), 0);
        store(&scratch.0, &second).expect("second store");
        assert_eq!(load(&scratch.0), second);
    }

    #[test]
    fn storing_over_a_corrupt_file_recovers_it() {
        let scratch = ScratchState::new("corrupt");
        std::fs::write(&scratch.0, "garbage").expect("seed");
        assert_eq!(load(&scratch.0), State::default());

        let state = consented(Some("2.0.0"), 0);
        store(&scratch.0, &state).expect("store");
        assert_eq!(load(&scratch.0), state);
    }

    #[test]
    fn the_stored_file_leaves_no_temporary_behind() {
        let scratch = ScratchState::new("no-temp");
        store(&scratch.0, &State::default()).expect("store");
        let tmp = scratch
            .0
            .with_extension(format!("{}.tmp", std::process::id()));
        assert!(!tmp.exists(), "the temp file must be renamed away");
    }

    // -- The request, against a stubbed endpoint ----------------------------

    /// Stubs the release endpoint so the request path is covered without
    /// reaching github.com.
    ///
    /// These are the only tests that exercise the parts unit tests cannot see:
    /// that `max_redirects(0)` really does hand back the 302 rather than
    /// following it or erroring, that `http_status_as_error` (left at its
    /// default) does not turn a 3xx into an `Err`, and that the header arrives
    /// where [`fetch_latest_from`] looks for it. Getting any of those wrong
    /// would silently disable the feature.
    ///
    /// Cleartext, like `sure`'s proxy suite: the stub stands in for the origin
    /// rather than intercepting a connection to it, so TLS would only be
    /// verifying rustls against itself. What the request path needs covered is
    /// the redirect handling, and that is scheme-independent.
    mod stubbed {
        use super::*;

        use bytes::Bytes;
        use partly_proxy_lib::{
            Command, ProxyClusterBuilder, ProxyConfig, RequestMatcher, StubbedResponse,
            UpstreamTarget,
        };
        use ureq::http::StatusCode;

        /// A proxy serving exactly one stubbed response on an ephemeral port.
        ///
        /// The upstream is never reached — the stub has no `times` limit, so it
        /// answers every request — but `ProxyConfig` still wants a target, and a
        /// blackhole address makes a fall-through an obvious failure rather than
        /// a silent trip to the real internet.
        async fn serve(response: StubbedResponse) -> (String, partly_proxy_lib::ClusterHandle) {
            let cluster = ProxyClusterBuilder::new()
                .add_upstream(
                    "github",
                    ProxyConfig::http(
                        "127.0.0.1:0".parse().expect("bind address"),
                        UpstreamTarget::new("http://127.0.0.1:1"),
                    ),
                )
                .run()
                .await
                .expect("proxy starts");

            cluster
                .command_sender()
                .send(Command::Stub {
                    upstream: Some("github".into()),
                    matcher: RequestMatcher::new().path(".*"),
                    response,
                    times: None,
                })
                .await
                .expect("stub registers");

            let addr = cluster.addr("github").expect("bound address");
            (format!("http://{addr}/releases/latest"), cluster)
        }

        /// `fetch_latest_from` blocks, so it cannot run on the runtime driving
        /// the proxy.
        async fn fetch_via(response: StubbedResponse) -> Option<Version> {
            let (url, cluster) = serve(response).await;
            let latest = tokio::task::spawn_blocking(move || fetch_latest_from(&url))
                .await
                .expect("fetch does not panic");
            cluster.shutdown().await.expect("proxy shuts down");
            latest
        }

        fn redirect_to(location: &str) -> StubbedResponse {
            StubbedResponse::new(StatusCode::FOUND).header("location", location)
        }

        #[tokio::test]
        async fn reads_the_version_out_of_a_redirect() {
            let latest = fetch_via(redirect_to(
                "https://github.com/JosiahBull/port-linker/releases/tag/v9.9.9",
            ))
            .await;
            assert_eq!(latest, Some(v("9.9.9")));
        }

        /// The shape GitHub returns for a repository whose only releases are
        /// prereleases. It must not be read as an upgrade.
        #[tokio::test]
        async fn a_redirect_to_the_release_list_yields_nothing() {
            let latest = fetch_via(redirect_to(
                "https://github.com/JosiahBull/port-linker/releases",
            ))
            .await;
            assert_eq!(latest, None);
        }

        /// A redirect is attacker-influenced input even over TLS, so the check
        /// has to survive the whole request path, not just the parser.
        #[tokio::test]
        async fn a_redirect_off_this_repository_yields_nothing() {
            let latest = fetch_via(redirect_to("https://example.com/releases/tag/v9.9.9")).await;
            assert_eq!(latest, None);
        }

        #[tokio::test]
        async fn a_redirect_without_a_location_yields_nothing() {
            let latest = fetch_via(StubbedResponse::new(StatusCode::FOUND)).await;
            assert_eq!(latest, None);
        }

        #[tokio::test]
        async fn a_server_error_yields_nothing() {
            let latest = fetch_via(StubbedResponse::new(StatusCode::INTERNAL_SERVER_ERROR)).await;
            assert_eq!(latest, None);
        }

        #[tokio::test]
        async fn a_rate_limit_yields_nothing() {
            let latest = fetch_via(StubbedResponse::new(StatusCode::TOO_MANY_REQUESTS)).await;
            assert_eq!(latest, None);
        }

        /// A 200 means the redirect was followed by something, which would mean
        /// `max_redirects(0)` had stopped working.
        #[tokio::test]
        async fn a_plain_ok_yields_nothing() {
            let latest =
                fetch_via(StubbedResponse::new(StatusCode::OK).body(Bytes::from_static(b"<html>")))
                    .await;
            assert_eq!(latest, None);
        }

        /// Nothing is reachable on this port, so this covers the branch a real
        /// offline machine takes.
        #[tokio::test]
        async fn an_unreachable_endpoint_yields_nothing() {
            let latest = tokio::task::spawn_blocking(|| fetch_latest_from("http://127.0.0.1:1/"))
                .await
                .expect("fetch does not panic");
            assert_eq!(latest, None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_stored_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = ScratchState::new("perms");
        store(&scratch.0, &State::default()).expect("store");
        let mode = std::fs::metadata(&scratch.0)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "state file should be owner-only");
    }
}
