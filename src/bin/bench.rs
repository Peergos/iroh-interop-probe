//! Throughput benchmark. Usage:
//!   bench server [bind_addr] [secret_key_hex]
//!   bench client <addr> <endpoint_id_hex> <up|down> <bytes> [streams]
//! Each stream starts with a mode byte ('u' or 'd') and a u64 size. For 'u' the client sends size bytes and the
//! server replies with the u64 count it read; for 'd' the server sends size bytes.
use iroh::{
    Endpoint, EndpointAddr, PublicKey, RelayMode, SecretKey,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use std::time::Instant;

const ALPN: &[u8] = b"iroh-bench/0";
const CHUNK: usize = 64 * 1024;

#[derive(Debug, Clone)]
struct Bench;

impl ProtocolHandler for Bench {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        loop {
            let Ok((mut send, mut recv)) = connection.accept_bi().await else { break };
            tokio::spawn(async move {
                let r: anyhow::Result<()> = async {
                    let mut header = [0u8; 9];
                    recv.read_exact(&mut header).await?;
                    let size = u64::from_be_bytes(header[1..].try_into().unwrap());
                    if header[0] == b'u' {
                        let mut buf = vec![0u8; CHUNK];
                        let mut total = 0u64;
                        while let Some(n) = recv.read(&mut buf).await? {
                            total += n as u64;
                        }
                        send.write_all(&total.to_be_bytes()).await?;
                    } else {
                        write_bytes(&mut send, size).await?;
                    }
                    send.finish()?;
                    send.stopped().await?;
                    Ok(())
                }
                .await;
                if let Err(e) = r {
                    eprintln!("stream error: {e:#}");
                }
            });
        }
        if std::env::var("BENCH_STATS").is_ok() {
            println!("{:#?}", connection.stats());
        }
        Ok(())
    }
}

async fn write_bytes(send: &mut iroh::endpoint::SendStream, size: u64) -> anyhow::Result<()> {
    let buf = vec![0xabu8; CHUNK];
    let mut left = size;
    while left > 0 {
        let n = left.min(CHUNK as u64) as usize;
        send.write_all(&buf[..n]).await?;
        left -= n as u64;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("server") => server(&args[2..]).await,
        Some("client") => client(&args[2..]).await,
        _ => anyhow::bail!("usage: bench server|client ..."),
    }
}

async fn server(args: &[String]) -> anyhow::Result<()> {
    let bind = args.first().cloned().unwrap_or("127.0.0.1:4433".into());
    let secret = match args.get(1) {
        Some(h) => SecretKey::from_bytes(&hex::decode(h)?.try_into().unwrap()),
        None => SecretKey::generate(),
    };
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .bind_addr(bind.as_str())?
        .bind()
        .await?;
    println!("endpoint id: {}", hex::encode(endpoint.id().as_bytes()));
    println!("bound: {:?}", endpoint.bound_sockets());
    let router = Router::builder(endpoint).accept(ALPN, Bench).spawn();
    tokio::signal::ctrl_c().await?;
    router.shutdown().await?;
    Ok(())
}

async fn client(args: &[String]) -> anyhow::Result<()> {
    let addr: std::net::SocketAddr = args[0].parse()?;
    let id = PublicKey::from_bytes(&hex::decode(&args[1])?.try_into().unwrap())?;
    let upload = match args[2].as_str() {
        "up" => true,
        "down" => false,
        m => anyhow::bail!("bad mode {m}"),
    };
    let size: u64 = args[3].parse()?;
    let streams: u64 = args.get(4).map(|s| s.parse()).transpose()?.unwrap_or(1);
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .bind()
        .await?;
    let conn = endpoint.connect(EndpointAddr::new(id).with_ip_addr(addr), ALPN).await?;
    let per_stream = size / streams;
    let start = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..streams {
        let conn = conn.clone();
        tasks.push(tokio::spawn(async move {
            let (mut send, mut recv) = conn.open_bi().await?;
            let mut header = [0u8; 9];
            header[0] = if upload { b'u' } else { b'd' };
            header[1..].copy_from_slice(&per_stream.to_be_bytes());
            send.write_all(&header).await?;
            if upload {
                write_bytes(&mut send, per_stream).await?;
                send.finish()?;
                let mut count = [0u8; 8];
                recv.read_exact(&mut count).await?;
                anyhow::ensure!(u64::from_be_bytes(count) == per_stream, "short upload");
                Ok(per_stream)
            } else {
                send.finish()?;
                let mut buf = vec![0u8; CHUNK];
                let mut total = 0u64;
                while let Some(n) = recv.read(&mut buf).await? {
                    total += n as u64;
                }
                anyhow::ensure!(total == per_stream, "short download");
                Ok(total)
            }
        }));
    }
    let mut total = 0u64;
    for t in tasks {
        total += t.await??;
    }
    let secs = start.elapsed().as_secs_f64();
    println!("{} {} bytes in {:.3}s = {:.1} MiB/s", args[2], total, secs, total as f64 / secs / (1 << 20) as f64);
    conn.close(0u32.into(), b"bye");
    endpoint.close().await;
    Ok(())
}
