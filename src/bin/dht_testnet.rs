//! A local mainline DHT of n nodes. Prints "bootstrap: <addr> <addr> ..." and runs until killed.
//! Usage: dht_testnet [n]
fn main() -> anyhow::Result<()> {
    let n: usize = std::env::args().nth(1).map(|s| s.parse()).transpose()?.unwrap_or(10);
    let testnet = mainline::Testnet::builder(n).build()?;
    println!("bootstrap: {}", testnet.bootstrap.join(" "));
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
