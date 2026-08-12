pub mod ephemeral;
mod error;
pub mod platform;
pub mod process;
pub mod session;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;

/// Generate an unguessable suffix for remote temp-file names.
///
/// This is drawn from the system CSPRNG, not from the clock: the remote temp
/// directory is world-writable on shared hosts, so a predictable name lets a
/// local attacker pre-create or squat the path the agent is about to occupy.
pub fn generate_token() -> Result<String> {
    Ok(format!("plk-{}", session::random_hex(16)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_unique() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn token_has_prefix() {
        let tok = generate_token().unwrap();
        assert!(
            tok.starts_with("plk-"),
            "token should start with plk-: {tok}"
        );
    }

    #[test]
    fn token_carries_full_entropy() {
        // "plk-" plus 16 bytes hex-encoded.
        let tok = generate_token().unwrap();
        assert_eq!(tok.len(), 4 + 32, "token should carry 128 bits: {tok}");
    }

    /// Regression test for predictable remote temp-file names.
    ///
    /// The previous implementation was `format!("plk-{nanos:x}-{hash:x}")`, seeded
    /// from `SystemTime` plus a `RandomState` hasher. Tokens minted close together
    /// therefore shared a long leading run of digits — the high bits of the
    /// nanosecond clock — which let a local user on the target predict the path
    /// the agent was about to occupy in a world-writable temp directory.
    ///
    /// With a CSPRNG, two tokens sharing even 8 hex digits (32 bits) has
    /// probability ~2^-32 per pair, so this cannot fail by chance.
    #[test]
    fn tokens_do_not_share_a_predictable_prefix() {
        const SAMPLES: usize = 64;
        const MAX_SHARED: usize = 8;

        let tokens: Vec<String> = (0..SAMPLES)
            .map(|_| generate_token().expect("token"))
            .collect();

        for pair in tokens.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            let a_random = a.strip_prefix("plk-").expect("prefix");
            let b_random = b.strip_prefix("plk-").expect("prefix");

            let shared = a_random
                .chars()
                .zip(b_random.chars())
                .take_while(|(x, y)| x == y)
                .count();

            assert!(
                shared < MAX_SHARED,
                "consecutive tokens share {shared} leading hex digits, which \
                 suggests a clock-derived (predictable) source: {a} / {b}"
            );
        }
    }

    /// Every token must be unique across a large batch.
    #[test]
    fn tokens_are_unique_in_bulk() {
        const SAMPLES: usize = 1000;

        let unique: std::collections::HashSet<String> = (0..SAMPLES)
            .map(|_| generate_token().expect("token"))
            .collect();

        assert_eq!(unique.len(), SAMPLES, "generate_token produced a collision");
    }
}
