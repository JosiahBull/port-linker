pub mod ephemeral;
mod error;
pub mod platform;
pub mod process;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;

/// Generate a random one-time connection token for QUIC handshake.
///
/// Uses system time + random bits to produce a unique token.
/// No cryptographic guarantees - this is for session correlation, not auth.
pub fn generate_token() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    // Use RandomState for a quick source of randomness without pulling in `rand`
    let random = RandomState::new().build_hasher().finish();

    format!("plk-{:x}-{:x}", nanos, random)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_unique() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
    }

    #[test]
    fn token_has_prefix() {
        let tok = generate_token();
        assert!(
            tok.starts_with("plk-"),
            "token should start with plk-: {tok}"
        );
    }

    #[test]
    fn token_is_nonempty() {
        let tok = generate_token();
        assert!(tok.len() > 10, "token should be reasonably long: {tok}");
    }
}
