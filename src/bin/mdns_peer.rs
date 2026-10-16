//! A Rust iroh endpoint whose only address lookup is mDNS (iroh-mdns-address-lookup), relay disabled.
//! Usage: mdns_peer serve [secret_key_hex]   -- echo server, prints each endpoint it discovers
//!        mdns_peer dial <endpoint_id_hex> [count]   -- dials by id alone, then echoes
use futures_lite::StreamExt;
use iroh::{
    Endpoint, PublicKey, RelayMode, SecretKey,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};

const ALPN: &[u8] = b"iroh-interop/echo/0";

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        println!("accepted connection from {}", hex::encode(connection.remote_id().as_bytes()));
        loop {
            let Ok((mut send, mut recv)) = connection.accept_bi().await else { break };
            tokio::io::copy(&mut recv, &mut send).await?;
            send.finish()?;
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let args: Vec<String> = std::env::args().collect();
    let secret = match (args[1].as_str(), args.get(2)) {
        ("serve", Some(h)) => SecretKey::from_bytes(&hex::decode(h)?.try_into().unwrap()),
        _ => SecretKey::generate(),
    };
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .bind()
        .await?;
    let mdns = MdnsAddressLookup::builder().build(endpoint.id())?;
    endpoint.address_lookup()?.add(mdns.clone());
    println!("endpoint id: {}", hex::encode(endpoint.id().as_bytes()));

    let mut events = mdns.subscribe().await;
    tokio::spawn(async move {
        while let Some(event) = events.next().await {
            match event {
                DiscoveryEvent::Discovered { endpoint_info, .. } => println!(
                    "discovered {} addrs {:?} relays {:?}",
                    hex::encode(endpoint_info.endpoint_id.as_bytes()),
                    endpoint_info.ip_addrs().collect::<Vec<_>>(),
                    endpoint_info.relay_urls().map(|u| u.to_string()).collect::<Vec<_>>()
                ),
                DiscoveryEvent::Expired { endpoint_id } => println!("expired {}", hex::encode(endpoint_id.as_bytes())),
                _ => {}
            }
        }
    });

    match args[1].as_str() {
        "serve" => {
            let router = Router::builder(endpoint).accept(ALPN, Echo).spawn();
            tokio::signal::ctrl_c().await?;
            router.shutdown().await?;
        }
        "dial" => {
            let id = PublicKey::from_bytes(&hex::decode(&args[2])?.try_into().unwrap())?;
            let count: usize = args.get(3).map(|c| c.parse()).transpose()?.unwrap_or(3);
            let conn = endpoint.connect(id, ALPN).await?;
            println!("connected to {}", hex::encode(conn.remote_id().as_bytes()));
            for i in 0..count {
                let (mut send, mut recv) = conn.open_bi().await?;
                let msg = format!("hello from rust iroh #{i}");
                send.write_all(msg.as_bytes()).await?;
                send.finish()?;
                let resp = recv.read_to_end(1 << 16).await?;
                anyhow::ensure!(resp == msg.as_bytes(), "echo mismatch");
                println!("echo ok: {msg}");
            }
            conn.close(0u32.into(), b"bye");
            endpoint.close().await;
        }
        other => anyhow::bail!("unknown mode {other}"),
    }
    Ok(())
}
