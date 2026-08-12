//! End-to-end session security for the QUIC tunnel.
//!
//! # Trust model
//!
//! The QUIC tunnel is authenticated **mutually** with ephemeral, exactly-pinned
//! certificates. The authenticated SSH connection used to bootstrap the agent is
//! the root of trust:
//!
//! 1. The host generates a fresh [`Identity`] (self-signed cert + key) and a
//!    random session secret. The private key never leaves the host.
//! 2. The host sends the *public* half — its certificate, the session id and the
//!    session secret — to the agent over the agent's **stdin**, which travels
//!    inside the SSH channel ([`AgentSessionConfig`]).
//! 3. The agent generates its own [`Identity`] and prints only its certificate
//!    on stdout, which travels back inside the same SSH channel.
//! 4. Both sides configure TLS to accept *exactly one* certificate — the one
//!    they learned over SSH — via [`PinnedPeer`].
//!
//! The result is that neither end will complete a QUIC handshake with anyone but
//! the peer it was introduced to over SSH. An on-path attacker cannot
//! impersonate either side, because impersonation requires the private key that
//! matches the pinned certificate, and that key never crosses the network.
//!
//! Certificates are self-signed and single-use, so there is no CA, no chain
//! building, and no revocation to reason about: identity is the certificate.

use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use crate::{Error, Result};

/// ALPN protocol identifier for the tunnel.
///
/// Both ends require it, so a peer speaking any other protocol is rejected
/// during the handshake rather than after it.
pub const ALPN: &[u8] = b"port-linker/1";

/// Size of the session secret in bytes (256 bits).
const SESSION_SECRET_BYTES: usize = 32;

/// Size of the non-secret session identifier in bytes.
const SESSION_ID_BYTES: usize = 8;

/// Header line marking the start of a session config block.
const CONFIG_HEADER: &str = "PLK_SESSION_V1";

/// Terminator line for a session config block.
const CONFIG_FOOTER: &str = "END_SESSION";

/// The shared rustls crypto provider (ring).
///
/// Built once and reused so that every TLS config in the process agrees on the
/// same algorithms, and so we never depend on the process-global default
/// provider being installed.
fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
        .clone()
}

// ---------------------------------------------------------------------------
// Ephemeral identity
// ---------------------------------------------------------------------------

/// A single-use TLS identity: a self-signed certificate and its private key.
///
/// One is generated per side per session and discarded when the session ends.
pub struct Identity {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the private key.
        f.debug_struct("Identity")
            .field("cert_der_len", &self.cert_der.len())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Generate a fresh self-signed identity.
    ///
    /// `subject` is cosmetic — the peer authenticates the certificate by exact
    /// bytes, not by name — but it makes packet captures and logs readable.
    pub fn generate(subject: &str) -> Result<Self> {
        let certified = rcgen::generate_simple_self_signed(vec![subject.to_string()])
            .map_err(|e| Error::Security(format!("failed to generate session certificate: {e}")))?;

        Ok(Self {
            cert_der: certified.cert.der().to_vec(),
            key_der: certified.signing_key.serialize_der(),
        })
    }

    /// The DER-encoded certificate. This is the value the peer pins.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The certificate as a rustls type.
    pub fn certificate(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert_der.clone())
    }

    /// Rebuild an identity from previously generated DER material.
    pub fn from_der(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<Self> {
        if cert_der.is_empty() || key_der.is_empty() {
            return Err(Error::Security("session identity is incomplete".into()));
        }
        let identity = Self { cert_der, key_der };
        // Fail here rather than deep inside the TLS handshake.
        identity.private_key()?;
        Ok(identity)
    }

    /// The DER-encoded private key. Handle as a secret.
    pub fn key_der(&self) -> &[u8] {
        &self.key_der
    }

    /// The private key as a rustls type.
    pub fn private_key(&self) -> Result<PrivateKeyDer<'static>> {
        PrivateKeyDer::try_from(self.key_der.clone())
            .map_err(|e| Error::Security(format!("failed to parse session private key: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Certificate pinning
// ---------------------------------------------------------------------------

/// A TLS verifier that accepts exactly one certificate: the one learned over
/// SSH.
///
/// It implements both [`ServerCertVerifier`] and [`ClientCertVerifier`], so the
/// same type pins the agent from the host's side and the host from the agent's
/// side.
///
/// Only *identity* is overridden. Proof-of-possession — the handshake signature
/// that shows the peer holds the matching private key — is delegated to
/// rustls's own verifiers, so we are not reimplementing any cryptography.
#[derive(Debug)]
pub struct PinnedPeer {
    /// DER of the only certificate this verifier will accept.
    expected: Vec<u8>,
    provider: Arc<CryptoProvider>,
    /// Always empty: we do not hint CA subjects because there is no CA.
    no_hints: Vec<DistinguishedName>,
}

impl PinnedPeer {
    /// Pin the peer to `expected_cert_der`.
    pub fn new(expected_cert_der: &[u8]) -> Arc<Self> {
        Arc::new(Self {
            expected: expected_cert_der.to_vec(),
            provider: provider(),
            no_hints: Vec::new(),
        })
    }

    /// Check that the peer presented exactly the pinned certificate.
    fn check_pinned(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> std::result::Result<(), rustls::Error> {
        // A pinned self-signed leaf is the whole chain. Anything else is either
        // a different peer or an attempt to smuggle in a chain we would not
        // otherwise evaluate.
        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }

        if constant_time_eq(end_entity.as_ref(), &self.expected) {
            Ok(())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
}

impl ServerCertVerifier for PinnedPeer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // The server name is deliberately not checked: the pin *is* the
        // identity, and it is strictly stronger than a name match against a
        // self-signed certificate. Validity dates are likewise not enforced —
        // the certificate is generated seconds before use, and clock skew
        // between the host and target must not be able to break the tunnel.
        self.check_pinned(end_entity, intermediates)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ClientCertVerifier for PinnedPeer {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.no_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        self.check_pinned(end_entity, intermediates)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// TLS configs
// ---------------------------------------------------------------------------

/// Build the host-side TLS config: present `identity`, accept only
/// `expected_agent_cert`.
pub fn client_tls_config(
    identity: &Identity,
    expected_agent_cert: &[u8],
) -> Result<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Security(format!("failed to select TLS 1.3: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(PinnedPeer::new(expected_agent_cert))
        .with_client_auth_cert(vec![identity.certificate()], identity.private_key()?)
        .map_err(|e| Error::Security(format!("failed to install client certificate: {e}")))?;

    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(config)
}

/// Build the agent-side TLS config: present `identity`, require and accept only
/// `expected_host_cert` from the client.
pub fn server_tls_config(
    identity: &Identity,
    expected_host_cert: &[u8],
) -> Result<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Security(format!("failed to select TLS 1.3: {e}")))?
        .with_client_cert_verifier(PinnedPeer::new(expected_host_cert))
        .with_single_cert(vec![identity.certificate()], identity.private_key()?)
        .map_err(|e| Error::Security(format!("failed to install server certificate: {e}")))?;

    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(config)
}

// ---------------------------------------------------------------------------
// The SSH-delivered session config
// ---------------------------------------------------------------------------

/// The material the host hands the agent over the SSH channel.
///
/// Contains no private keys: the host's certificate is public, and the session
/// secret is a shared bearer token that only ever travels inside SSH or inside
/// the already-mutually-authenticated QUIC tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSessionConfig {
    /// Non-secret identifier used to correlate host and agent logs.
    pub session_id: String,
    /// Shared secret proving both ends came from the same SSH bootstrap.
    pub session_secret: String,
    /// The host's certificate, which the agent pins.
    pub client_cert_der: Vec<u8>,
}

impl AgentSessionConfig {
    /// Render the config for delivery on the agent's stdin.
    pub fn encode(&self) -> String {
        format!(
            "{CONFIG_HEADER}\n\
             SESSION_ID={}\n\
             SESSION_SECRET={}\n\
             CLIENT_CERT={}\n\
             {CONFIG_FOOTER}\n",
            self.session_id,
            self.session_secret,
            to_hex(&self.client_cert_der),
        )
    }

    /// Parse a config block. Unknown keys are ignored so the format can grow.
    pub fn parse(text: &str) -> Result<Self> {
        let mut session_id = None;
        let mut session_secret = None;
        let mut client_cert = None;
        let mut saw_header = false;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line == CONFIG_HEADER {
                saw_header = true;
                continue;
            }
            if line == CONFIG_FOOTER {
                break;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key {
                "SESSION_ID" => session_id = Some(value.to_string()),
                "SESSION_SECRET" => session_secret = Some(value.to_string()),
                "CLIENT_CERT" => client_cert = Some(from_hex(value)?),
                _ => {}
            }
        }

        if !saw_header {
            return Err(Error::Security(format!(
                "session config is missing the {CONFIG_HEADER} header"
            )));
        }

        let session_id =
            session_id.ok_or_else(|| Error::Security("session config has no SESSION_ID".into()))?;
        let session_secret = session_secret
            .ok_or_else(|| Error::Security("session config has no SESSION_SECRET".into()))?;
        let client_cert_der = client_cert
            .ok_or_else(|| Error::Security("session config has no CLIENT_CERT".into()))?;

        if session_secret.len() < SESSION_SECRET_BYTES {
            return Err(Error::Security(
                "session config has an implausibly short SESSION_SECRET".into(),
            ));
        }
        if client_cert_der.is_empty() {
            return Err(Error::Security(
                "session config has an empty CLIENT_CERT".into(),
            ));
        }

        Ok(Self {
            session_id,
            session_secret,
            client_cert_der,
        })
    }
}

// ---------------------------------------------------------------------------
// The host-side session file (manual `--agent` mode)
// ---------------------------------------------------------------------------

/// Host-side session material for manual mode, where there is no SSH channel to
/// carry the introduction.
///
/// This is the same block the agent receives, plus the host's private key and
/// the agent certificate to pin. It contains a private key and a bearer secret,
/// so it must be stored with owner-only permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSessionFile {
    pub session_id: String,
    pub session_secret: String,
    pub identity_cert_der: Vec<u8>,
    pub identity_key_der: Vec<u8>,
    /// The agent's certificate. `None` until the operator pastes in the
    /// `AGENT_CERT=` line the agent prints on startup.
    pub agent_cert_der: Option<Vec<u8>>,
}

impl HostSessionFile {
    /// Create a fresh session with a newly generated host identity.
    pub fn generate() -> Result<Self> {
        let identity = Identity::generate("port-linker-host")?;
        Ok(Self {
            session_id: generate_session_id()?,
            session_secret: generate_session_secret()?,
            identity_cert_der: identity.cert_der().to_vec(),
            identity_key_der: identity.key_der().to_vec(),
            agent_cert_der: None,
        })
    }

    /// Render the file.
    pub fn encode(&self) -> String {
        let agent_cert = match &self.agent_cert_der {
            Some(der) => to_hex(der),
            None => String::new(),
        };
        format!(
            "{CONFIG_HEADER}\n\
             SESSION_ID={}\n\
             SESSION_SECRET={}\n\
             CLIENT_CERT={}\n\
             CLIENT_KEY={}\n\
             AGENT_CERT={agent_cert}\n\
             {CONFIG_FOOTER}\n",
            self.session_id,
            self.session_secret,
            to_hex(&self.identity_cert_der),
            to_hex(&self.identity_key_der),
        )
    }

    /// Parse the file.
    pub fn parse(text: &str) -> Result<Self> {
        let base = AgentSessionConfig::parse(text)?;

        let mut key = None;
        let mut agent_cert = None;
        for line in text.lines() {
            let Some((k, v)) = line.trim().split_once('=') else {
                continue;
            };
            match k {
                "CLIENT_KEY" => key = Some(from_hex(v)?),
                "AGENT_CERT" if !v.trim().is_empty() => agent_cert = Some(from_hex(v)?),
                _ => {}
            }
        }

        let identity_key_der =
            key.ok_or_else(|| Error::Security("session file has no CLIENT_KEY".into()))?;

        Ok(Self {
            session_id: base.session_id,
            session_secret: base.session_secret,
            identity_cert_der: base.client_cert_der,
            identity_key_der,
            agent_cert_der: agent_cert,
        })
    }

    /// The host's TLS identity.
    pub fn identity(&self) -> Result<Identity> {
        Identity::from_der(
            self.identity_cert_der.clone(),
            self.identity_key_der.clone(),
        )
    }

    /// The block to feed the agent's stdin — public material only, no key.
    pub fn agent_config(&self) -> AgentSessionConfig {
        AgentSessionConfig {
            session_id: self.session_id.clone(),
            session_secret: self.session_secret.clone(),
            client_cert_der: self.identity_cert_der.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Randomness and comparisons
// ---------------------------------------------------------------------------

/// Generate `byte_len` cryptographically random bytes, hex-encoded.
pub fn random_hex(byte_len: usize) -> Result<String> {
    use ring::rand::SecureRandom;

    let mut buf = vec![0u8; byte_len];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| Error::Security("system random number generator failed".into()))?;
    Ok(to_hex(&buf))
}

/// Generate a fresh, unguessable session secret.
pub fn generate_session_secret() -> Result<String> {
    random_hex(SESSION_SECRET_BYTES)
}

/// Generate a short, non-secret session identifier for log correlation.
pub fn generate_session_id() -> Result<String> {
    Ok(format!("plk-{}", random_hex(SESSION_ID_BYTES)?))
}

/// Compare two session secrets without leaking their contents through timing.
pub fn secrets_match(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Constant-time byte equality.
///
/// Lengths are not secret (certificate and token sizes are public), but the
/// contents are compared without an early exit so a mismatched secret cannot be
/// recovered a byte at a time by timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    a.ct_eq(b).into()
}

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

/// Lower-case hex encoding.
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        // Writing to a String is infallible.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decode lower- or upper-case hex.
pub fn from_hex(text: &str) -> Result<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return Err(Error::Security(
            "hex value has an odd number of digits".into(),
        ));
    }

    let mut out = Vec::with_capacity(text.len().saturating_div(2));
    for pair in text.as_bytes().chunks(2) {
        let (Some(hi), Some(lo)) = (pair.first(), pair.get(1)) else {
            return Err(Error::Security("truncated hex value".into()));
        };
        let hi = hex_digit(*hi)?;
        let lo = hex_digit(*lo)?;
        out.push(hi.wrapping_shl(4) | lo);
    }
    Ok(out)
}

/// Decode a single hex digit.
fn hex_digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Ok(byte.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Ok(byte.wrapping_sub(b'A').wrapping_add(10)),
        other => Err(Error::Security(format!(
            "invalid hex digit: {:?}",
            char::from(other)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data = vec![0x00, 0x0f, 0x10, 0xff, 0xa5];
        let encoded = to_hex(&data);
        assert_eq!(encoded, "000f10ffa5");
        assert_eq!(from_hex(&encoded).unwrap(), data);
    }

    #[test]
    fn hex_accepts_uppercase() {
        assert_eq!(from_hex("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_rejects_odd_length() {
        assert!(from_hex("abc").is_err());
    }

    #[test]
    fn hex_rejects_non_hex() {
        assert!(from_hex("zz").is_err());
    }

    #[test]
    fn identity_generates_distinct_certs() {
        let a = Identity::generate("localhost").unwrap();
        let b = Identity::generate("localhost").unwrap();
        assert!(!a.cert_der().is_empty());
        assert_ne!(a.cert_der(), b.cert_der());
        assert!(a.private_key().is_ok());
    }

    #[test]
    fn session_config_roundtrip() {
        let config = AgentSessionConfig {
            session_id: "plk-0011223344556677".into(),
            session_secret: generate_session_secret().unwrap(),
            client_cert_der: Identity::generate("host").unwrap().cert_der().to_vec(),
        };

        let parsed = AgentSessionConfig::parse(&config.encode()).unwrap();
        assert_eq!(parsed, config);
    }

    #[test]
    fn session_config_rejects_missing_header() {
        let text = "SESSION_ID=x\nSESSION_SECRET=y\nCLIENT_CERT=00\nEND_SESSION\n";
        assert!(AgentSessionConfig::parse(text).is_err());
    }

    #[test]
    fn session_config_rejects_missing_fields() {
        let text = format!("{CONFIG_HEADER}\nSESSION_ID=x\n{CONFIG_FOOTER}\n");
        assert!(AgentSessionConfig::parse(&text).is_err());
    }

    #[test]
    fn session_config_rejects_short_secret() {
        let text = format!(
            "{CONFIG_HEADER}\nSESSION_ID=x\nSESSION_SECRET=abcd\nCLIENT_CERT=00\n{CONFIG_FOOTER}\n"
        );
        assert!(AgentSessionConfig::parse(&text).is_err());
    }

    #[test]
    fn session_config_ignores_unknown_keys() {
        let config = AgentSessionConfig {
            session_id: "plk-1".into(),
            session_secret: generate_session_secret().unwrap(),
            client_cert_der: vec![1, 2, 3],
        };
        let text = config.encode().replace(
            CONFIG_FOOTER,
            &format!("FUTURE_KEY=whatever\n{CONFIG_FOOTER}"),
        );
        assert_eq!(AgentSessionConfig::parse(&text).unwrap(), config);
    }

    #[test]
    fn host_session_file_roundtrip() {
        let mut file = HostSessionFile::generate().unwrap();
        file.agent_cert_der = Some(Identity::generate("agent").unwrap().cert_der().to_vec());

        let parsed = HostSessionFile::parse(&file.encode()).unwrap();
        assert_eq!(parsed, file);
        assert!(parsed.identity().is_ok());
    }

    #[test]
    fn host_session_file_tolerates_unpinned_agent() {
        let file = HostSessionFile::generate().unwrap();
        let parsed = HostSessionFile::parse(&file.encode()).unwrap();
        assert!(parsed.agent_cert_der.is_none());
    }

    #[test]
    fn host_session_file_agent_config_excludes_private_key() {
        let file = HostSessionFile::generate().unwrap();
        let encoded = file.agent_config().encode();
        assert!(!encoded.contains(&to_hex(&file.identity_key_der)));
        assert!(!encoded.contains("CLIENT_KEY"));
    }

    #[test]
    fn secrets_are_unique_and_long() {
        let a = generate_session_secret().unwrap();
        let b = generate_session_secret().unwrap();
        assert_ne!(a, b);
        // 32 bytes hex-encoded.
        assert_eq!(a.len(), SESSION_SECRET_BYTES * 2);
        assert!(secrets_match(&a, &a));
        assert!(!secrets_match(&a, &b));
    }

    #[test]
    fn secrets_match_rejects_prefix() {
        let secret = generate_session_secret().unwrap();
        let truncated: String = secret.chars().take(8).collect();
        assert!(!secrets_match(&secret, &truncated));
    }

    #[test]
    fn pinned_verifier_accepts_exact_cert_and_rejects_others() {
        use rustls::server::danger::ClientCertVerifier;

        let pinned = Identity::generate("agent").unwrap();
        let other = Identity::generate("agent").unwrap();
        let verifier = PinnedPeer::new(pinned.cert_der());
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000));

        assert!(
            verifier
                .verify_client_cert(&pinned.certificate(), &[], now)
                .is_ok()
        );
        assert!(
            verifier
                .verify_client_cert(&other.certificate(), &[], now)
                .is_err()
        );
    }

    #[test]
    fn pinned_verifier_rejects_server_impersonation() {
        use rustls::client::danger::ServerCertVerifier;

        let pinned = Identity::generate("agent").unwrap();
        let attacker = Identity::generate("agent").unwrap();
        let verifier = PinnedPeer::new(pinned.cert_der());
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000));
        let name = ServerName::try_from("localhost").unwrap();

        assert!(
            verifier
                .verify_server_cert(&pinned.certificate(), &[], &name, &[], now)
                .is_ok()
        );
        assert!(
            verifier
                .verify_server_cert(&attacker.certificate(), &[], &name, &[], now)
                .is_err()
        );
    }

    #[test]
    fn pinned_verifier_rejects_smuggled_chain() {
        use rustls::server::danger::ClientCertVerifier;

        let pinned = Identity::generate("agent").unwrap();
        let extra = Identity::generate("extra").unwrap();
        let verifier = PinnedPeer::new(pinned.cert_der());
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000));

        assert!(
            verifier
                .verify_client_cert(&pinned.certificate(), &[extra.certificate()], now)
                .is_err()
        );
    }

    #[test]
    fn tls_configs_build_and_pin_alpn() {
        let host = Identity::generate("host").unwrap();
        let agent = Identity::generate("agent").unwrap();

        let client = client_tls_config(&host, agent.cert_der()).unwrap();
        let server = server_tls_config(&agent, host.cert_der()).unwrap();

        assert_eq!(client.alpn_protocols, vec![ALPN.to_vec()]);
        assert_eq!(server.alpn_protocols, vec![ALPN.to_vec()]);
    }
}
