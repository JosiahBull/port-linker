//! QUIC TLS/crypto configuration.
//!
//! Generates self-signed certificates and builds server/client TLS configs
//! with SHA-256 fingerprint verification (TOFU model).

use ring::digest;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use std::sync::Arc;
use tracing::debug;

/// Generate a self-signed certificate for QUIC transport.
///
/// Returns (cert_der, key_der, sha256_fingerprint).
pub fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>, [u8; 32]), String> {
    let key_pair = rcgen::KeyPair::generate().map_err(|e| format!("Key generation failed: {}", e))?;
    let cert = rcgen::CertificateParams::new(vec!["port-linker-agent".to_string()])
        .map_err(|e| format!("Cert params failed: {}", e))?
        .self_signed(&key_pair)
        .map_err(|e| format!("Self-signing failed: {}", e))?;

    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();

    // Compute SHA-256 fingerprint of the DER-encoded certificate
    let fingerprint_digest = digest::digest(&digest::SHA256, &cert_der);
    let mut fingerprint = [0_u8; 32];
    fingerprint.copy_from_slice(fingerprint_digest.as_ref());

    debug!(
        "Generated self-signed cert (fingerprint: {:02x?})",
        &fingerprint[..8]
    );

    Ok((cert_der, key_der, fingerprint))
}

/// Build a quinn-proto server config with the given certificate.
pub fn build_server_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<quinn_proto::ServerConfig, String> {
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| format!("Server TLS config failed: {}", e))?;

    server_crypto.alpn_protocols = vec![b"port-linker".to_vec()];

    let mut transport = quinn_proto::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn_proto::IdleTimeout::try_from(std::time::Duration::from_secs(60))
            .map_err(|e| format!("Invalid idle timeout: {}", e))?,
    ));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));

    let mut config = quinn_proto::ServerConfig::with_crypto(Arc::new(
        quinn_proto::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| format!("QUIC server config failed: {}", e))?,
    ));
    config.transport_config(Arc::new(transport));

    Ok(config)
}

/// Build a quinn-proto client config that verifies the server's SHA-256 fingerprint.
pub fn build_client_config(
    expected_fingerprint: [u8; 32],
) -> Result<quinn_proto::ClientConfig, String> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(FingerprintVerifier {
            expected: expected_fingerprint,
        }))
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![b"port-linker".to_vec()];

    let mut transport = quinn_proto::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn_proto::IdleTimeout::try_from(std::time::Duration::from_secs(60))
            .map_err(|e| format!("Invalid idle timeout: {}", e))?,
    ));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));

    let quic_client_config =
        quinn_proto::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| format!("QUIC client config failed: {}", e))?;

    let mut config = quinn_proto::ClientConfig::new(Arc::new(quic_client_config));
    config.transport_config(Arc::new(transport));

    Ok(config)
}

/// Custom certificate verifier that checks the server cert's SHA-256 fingerprint.
///
/// Trust is established by the fingerprint being delivered over an authenticated
/// SSH channel (TOFU - Trust On First Use).
#[derive(Debug)]
struct FingerprintVerifier {
    expected: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fingerprint_digest = digest::digest(&digest::SHA256, end_entity.as_ref());
        let actual: &[u8] = fingerprint_digest.as_ref();

        if actual == self.expected.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "Certificate fingerprint mismatch: expected {:02x?}, got {:02x?}",
                self.expected.get(..8).unwrap_or(&self.expected),
                actual.get(..8).unwrap_or(actual)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}
