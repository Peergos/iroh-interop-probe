//! Prints BLAKE3 hash and derive_key outputs for inputs of byte pattern i % 251, one per line:
//! <len> <hash_hex> <derive_key_hex>
const CONTEXT: &str = "iroh-relay handshake v1 challenge signature";

fn main() {
    for len in [0usize, 1, 16, 63, 64, 65, 1023, 1024, 1025, 2048, 3073, 8193, 31745] {
        let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        println!(
            "{} {} {}",
            len,
            blake3::hash(&input).to_hex(),
            hex::encode(blake3::derive_key(CONTEXT, &input))
        );
    }
}
