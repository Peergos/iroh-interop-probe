//! A plain QUIC client (noq, no multipath, no NAT traversal, no QAD) speaking iroh's
//! raw-public-key TLS. Answers: does a Rust iroh v1 endpoint accept a single-path peer?
//! Usage: plain_client <server_addr> <server_endpoint_id_hex>
use std::sync::Arc;

use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime, alg_id},
};

const ALPN: &[u8] = b"iroh-interop/echo/0";

#[derive(Debug)]
struct PinnedRpk {
    expected_spki: Vec<u8>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedRpk {
    fn verify_server_cert(&self, ee: &CertificateDer, _: &[CertificateDer], _: &ServerName, _: &[u8], _: UnixTime)
        -> Result<ServerCertVerified, rustls::Error> {
        if ee.as_ref() != self.expected_spki.as_slice() {
            return Err(rustls::Error::General("unexpected server key".into()));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer, _: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("tls12".into()))
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer, d: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature_with_raw_key(m, &SubjectPublicKeyInfoDer::from(c.as_ref()), d, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { vec![SignatureScheme::ED25519] }
    fn requires_raw_public_keys(&self) -> bool { true }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let args: Vec<String> = std::env::args().collect();
    let server: std::net::SocketAddr = args[1].parse()?;
    let server_id = hex::decode(&args[2])?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let kp = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    use ring::signature::KeyPair;
    let my_spki = rustls::sign::public_key_to_spki(&alg_id::ED25519, kp.public_key().as_ref());
    let signing = provider.key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec())))?;
    let certified = Arc::new(rustls::sign::CertifiedKey::new(vec![CertificateDer::from(my_spki.to_vec())], signing));
    println!("client id: {}", hex::encode(kp.public_key().as_ref()));

    let verifier = Arc::new(PinnedRpk {
        expected_spki: rustls::sign::public_key_to_spki(&alg_id::ED25519, &server_id).to_vec(),
        algs: provider.signature_verification_algorithms,
    });
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(rustls::client::AlwaysResolvesClientRawPublicKeys::new(certified)));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.enable_sni = false;

    let quic = noq::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut cfg = noq::ClientConfig::new(Arc::new(quic));
    let transport = noq::TransportConfig::default();
    cfg.transport_config(Arc::new(transport));

    let ep = noq::Endpoint::client("0.0.0.0:0".parse()?)?;
    ep.set_default_client_config(cfg);
    let conn = ep.connect(server, "localhost")?.await?;
    println!("connected; multipath negotiated = {}", conn.is_multipath_enabled());
    for i in 0..3 {
        let (mut send, mut recv) = conn.open_bi().await?;
        let msg = format!("hello from a single-path client #{i}");
        send.write_all(msg.as_bytes()).await?;
        send.finish()?;
        let resp = recv.read_to_end(1 << 16).await?;
        assert_eq!(resp, msg.as_bytes());
        println!("echo ok: {}", String::from_utf8_lossy(&resp));
    }
    conn.close(0u32.into(), b"bye");
    ep.wait_idle().await;
    Ok(())
}
