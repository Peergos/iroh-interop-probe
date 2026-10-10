//! The bench client over plain noq (single path, no multipath), to compare noq's single-path performance with
//! iroh's multipath connections. Usage: plain_bench <server_addr> <server_endpoint_id_hex> <up|down> <bytes>
use std::sync::Arc;

use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime, alg_id},
};

const ALPN: &[u8] = b"iroh-bench/0";
const CHUNK: usize = 64 * 1024;

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
    let args: Vec<String> = std::env::args().collect();
    let server: std::net::SocketAddr = args[1].parse()?;
    let server_id = hex::decode(&args[2])?;
    let upload = args[3] == "up";
    let size: u64 = args[4].parse()?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let kp = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    use ring::signature::KeyPair;
    let my_spki = rustls::sign::public_key_to_spki(&alg_id::ED25519, kp.public_key().as_ref());
    let signing = provider.key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec())))?;
    let certified = Arc::new(rustls::sign::CertifiedKey::new(vec![CertificateDer::from(my_spki.to_vec())], signing));
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
    let mut transport = noq::TransportConfig::default();
    transport.stream_receive_window((8u32 << 20).into()).receive_window((80u32 << 20).into()).send_window(80 << 20);
    if let Ok(paths) = std::env::var("PLAIN_MULTIPATH") {
        transport.max_concurrent_multipath_paths(paths.parse()?);
    }
    cfg.transport_config(Arc::new(transport));

    let ep = noq::Endpoint::client("0.0.0.0:0".parse()?)?;
    ep.set_default_client_config(cfg);
    let conn = ep.connect(server, "localhost")?.await?;
    let start = std::time::Instant::now();
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut header = [0u8; 9];
    header[0] = if upload { b'u' } else { b'd' };
    header[1..].copy_from_slice(&size.to_be_bytes());
    send.write_all(&header).await?;
    let total = if upload {
        let buf = vec![0xabu8; CHUNK];
        let mut left = size;
        while left > 0 {
            let n = left.min(CHUNK as u64) as usize;
            send.write_all(&buf[..n]).await?;
            left -= n as u64;
        }
        send.finish()?;
        let mut count = [0u8; 8];
        recv.read_exact(&mut count).await?;
        u64::from_be_bytes(count)
    } else {
        send.finish()?;
        let mut buf = vec![0u8; CHUNK];
        let mut total = 0u64;
        while let Some(n) = recv.read(&mut buf).await? {
            total += n as u64;
        }
        total
    };
    let secs = start.elapsed().as_secs_f64();
    println!("{} {} bytes in {:.3}s = {:.1} MiB/s (multipath {})", args[3], total, secs, total as f64 / secs / (1 << 20) as f64, conn.is_multipath_enabled());
    if std::env::var("BENCH_STATS").is_ok() {
        println!("{:#?}", conn.stats());
    }
    conn.close(0u32.into(), b"bye");
    ep.wait_idle().await;
    Ok(())
}
