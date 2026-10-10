//! A Rust iroh endpoint (relay and address lookup disabled) dialing a known direct address, then echoing over
//! a few bidirectional streams. Usage: iroh_client <addr> <endpoint_id_hex> [count]
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayMode, endpoint::presets};

const ALPN: &[u8] = b"iroh-interop/echo/0";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let args: Vec<String> = std::env::args().collect();
    let addr: std::net::SocketAddr = args[1].parse()?;
    let id = PublicKey::from_bytes(&hex::decode(&args[2])?.try_into().unwrap())?;
    let count: usize = args.get(3).map(|c| c.parse()).transpose()?.unwrap_or(3);

    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .bind()
        .await?;
    println!("client id: {}", hex::encode(endpoint.id().as_bytes()));
    let conn = endpoint.connect(EndpointAddr::new(id).with_ip_addr(addr), ALPN).await?;
    println!("connected to {}", conn.remote_id());
    for i in 0..count {
        let (mut send, mut recv) = conn.open_bi().await?;
        let msg = format!("hello from rust iroh #{i}");
        send.write_all(msg.as_bytes()).await?;
        send.finish()?;
        let resp = recv.read_to_end(1 << 16).await?;
        anyhow::ensure!(resp == msg.as_bytes(), "echo mismatch: {:?}", String::from_utf8_lossy(&resp));
        println!("echo ok: {msg}");
    }
    conn.close(0u32.into(), b"bye");
    endpoint.close().await;
    Ok(())
}
