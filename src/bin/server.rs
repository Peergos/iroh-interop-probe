//! Reference iroh echo endpoint for interop testing: address lookup disabled, bound to a fixed UDP
//! address, relay disabled unless given. Usage: server [bind_addr] [secret_key_hex] [relay_url]
use iroh::{
    Endpoint, RelayMap, RelayMode, RelayUrl, SecretKey,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};

pub const ALPN: &[u8] = b"iroh-interop/echo/0";

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        println!("accepted connection from {}", connection.remote_id());
        loop {
            let Ok((mut send, mut recv)) = connection.accept_bi().await else { break };
            let n = tokio::io::copy(&mut recv, &mut send).await?;
            println!("echoed {n} bytes");
            send.finish()?;
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let args: Vec<String> = std::env::args().collect();
    let bind = args.get(1).cloned().unwrap_or("127.0.0.1:4433".into());
    let secret = match args.get(2) {
        Some(h) => SecretKey::from_bytes(&hex::decode(h)?.try_into().unwrap()),
        None => SecretKey::generate(),
    };
    let relay: Option<RelayUrl> = args.get(3).map(|u| u.parse()).transpose()?;
    let relay_mode = match &relay {
        Some(url) => RelayMode::Custom(RelayMap::from(url.clone())),
        None => RelayMode::Disabled,
    };
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .relay_mode(relay_mode)
        .clear_address_lookup()
        .bind_addr(bind.as_str())?
        .bind()
        .await?;
    println!("endpoint id: {}", hex::encode(endpoint.id().as_bytes()));
    println!("bound: {:?}", endpoint.bound_sockets());
    if relay.is_some() {
        endpoint.online().await;
        println!("relay: {:?}", endpoint.addr().relay_urls().next());
    }
    let router = Router::builder(endpoint).accept(ALPN, Echo).spawn();
    tokio::signal::ctrl_c().await?;
    router.shutdown().await?;
    Ok(())
}
