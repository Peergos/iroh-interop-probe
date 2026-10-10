//! Resolves a pkarr packet from the DHT (no relays) and prints "timestamp <t>" then "<name> TXT <value>" lines.
//! Usage: pkarr_resolve <bootstrap,...> <public_key_hex>
use pkarr::{Client, PublicKey, ResolvePolicy, dns::rdata::RData};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let bootstrap: Vec<String> = args[1].split(',').map(String::from).collect();
    let key = PublicKey::try_from(hex::decode(&args[2])?.as_slice())?;
    let client = Client::builder()
        .no_default_network()
        .no_relays()
        .bootstrap(&bootstrap)
        .dht(|c| { c.bind_address = Some(std::net::Ipv4Addr::LOCALHOST); c })
        .build()?;
    let packet = client.resolve(&key, ResolvePolicy::NetworkOnly).await?;
    println!("timestamp {}", packet.timestamp().as_u64());
    for rr in packet.all_resource_records() {
        if let RData::TXT(txt) = &rr.rdata {
            println!("{} TXT {}", rr.name, String::try_from(txt.clone())?);
        }
    }
    Ok(())
}
