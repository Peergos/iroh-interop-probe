//! Publishes a pkarr packet with TXT records to the DHT (no relays).
//! Usage: pkarr_publish <bootstrap,...> <secret_key_hex> <name> <value> [value...]
use pkarr::{Client, Keypair, SignedPacket};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let bootstrap: Vec<String> = args[1].split(',').map(String::from).collect();
    let secret: [u8; 32] = hex::decode(&args[2])?.try_into().unwrap();
    let keypair = Keypair::from_secret_key(&secret);
    let mut builder = SignedPacket::builder();
    for value in &args[4..] {
        builder = builder.txt(args[3].as_str().try_into()?, value.as_str().try_into()?, 30);
    }
    let packet = builder.sign(&keypair)?;
    let client = Client::builder()
        .no_default_network()
        .no_relays()
        .bootstrap(&bootstrap)
        .dht(|c| { c.bind_address = Some(std::net::Ipv4Addr::LOCALHOST); c })
        .build()?;
    let stored = client.publish(&packet).await?;
    println!("published {} timestamp {} stored on {}", keypair.public_key().to_z32(), packet.timestamp().as_u64(), stored);
    Ok(())
}
