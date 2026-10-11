//! A Rust iroh endpoint (address lookup disabled) dialing a known direct address and/or relay, then
//! echoing over a few bidirectional streams.
//! Usage: iroh_client <addr|-> <endpoint_id_hex> [count] [relay_url]
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayMap, RelayMode, RelayUrl, endpoint::presets};

const ALPN: &[u8] = b"iroh-interop/echo/0";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let args: Vec<String> = std::env::args().collect();
    let addr: Option<std::net::SocketAddr> = if args[1] == "-" { None } else { Some(args[1].parse()?) };
    let id = PublicKey::from_bytes(&hex::decode(&args[2])?.try_into().unwrap())?;
    let count: usize = args.get(3).map(|c| c.parse()).transpose()?.unwrap_or(3);

    let relay: Option<RelayUrl> = args.get(4).map(|u| u.parse()).transpose()?;
    let relay_mode = match &relay {
        Some(url) => RelayMode::Custom(RelayMap::from(url.clone())),
        None => RelayMode::Disabled,
    };
    let mut builder = Endpoint::builder(presets::Minimal)
        .relay_mode(relay_mode)
        .clear_address_lookup();
    // IROH_RELAY_CA: a PEM certificate to trust for the relay, e.g. a test relay's self-signed one.
    if let Ok(ca) = std::env::var("IROH_RELAY_CA") {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        builder = builder.ca_tls_config(iroh::tls::CaTlsConfig::custom_roots([CertificateDer::from_pem_file(ca)?]));
    }
    let endpoint = builder.bind().await?;
    println!("client id: {}", hex::encode(endpoint.id().as_bytes()));
    let mut target = EndpointAddr::new(id);
    if let Some(addr) = addr {
        target = target.with_ip_addr(addr);
    }
    if let Some(url) = relay {
        target = target.with_relay_url(url);
    }
    // IROH_CLIENT_WAIT_ONLINE: dial only once on the relay and the public address is known, like a long-running node.
    if std::env::var("IROH_CLIENT_WAIT_ONLINE").is_ok() {
        endpoint.online().await;
        println!("client addr: {:?}", endpoint.addr().ip_addrs().collect::<Vec<_>>());
    }
    let conn = endpoint.connect(target, ALPN).await?;
    println!("connected to {}", conn.remote_id());
    print_path_events(&conn, "client");
    for i in 0..count {
        let (mut send, mut recv) = conn.open_bi().await?;
        let msg = format!("hello from rust iroh #{i}");
        send.write_all(msg.as_bytes()).await?;
        send.finish()?;
        let resp = recv.read_to_end(1 << 16).await?;
        anyhow::ensure!(resp == msg.as_bytes(), "echo mismatch: {:?}", String::from_utf8_lossy(&resp));
        println!("echo ok: {msg}");
    }
    if let Ok(ms) = std::env::var("IROH_CLIENT_LINGER_MS") {
        // Keep the connection open so iroh can open more paths, then echo once more.
        tokio::time::sleep(std::time::Duration::from_millis(ms.parse()?)).await;
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(b"after linger").await?;
        send.finish()?;
        let resp = recv.read_to_end(1 << 16).await?;
        anyhow::ensure!(resp == b"after linger", "echo mismatch after linger");
        println!("echo ok: after linger");
    }
    conn.close(0u32.into(), b"bye");
    endpoint.close().await;
    Ok(())
}

/// Prints the connection's path events, for the interop tests to follow.
pub fn print_path_events(conn: &iroh::endpoint::Connection, who: &'static str) {
    use futures_lite::StreamExt;
    let mut events = conn.path_events();
    tokio::spawn(async move {
        while let Some(event) = events.next().await {
            println!("{who} path event: {event:?}");
        }
    });
}
