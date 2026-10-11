# iroh-interop-probe

Rust binaries on iroh 1.3 used as the reference peer by [jiroh](https://github.com/peergos/jiroh)'s interop tests
and benchmark. Build with `cargo build --release`; jiroh's tests look for them in `../interop-probe/target/release`,
so clone this repo as `interop-probe` next to jiroh.

| binary | what |
|---|---|
| `server` | iroh echo endpoint (`iroh-interop/echo/0`), optionally with a relay; prints its path events |
| `iroh_client` | iroh client dialling a direct address and/or relay, echoing; `IROH_CLIENT_LINGER_MS` keeps it open so iroh can open more paths, `IROH_CLIENT_WAIT_ONLINE` dials only once its public address is known |
| `plain_client` | plain noq client (no multipath, NAT traversal or QAD) speaking iroh's raw public key TLS |
| `bench` | throughput server/client (`iroh-bench/0`), wire compatible with jiroh's `Bench`; `BENCH_STATS` prints connection stats and RTT/cwnd samples |
| `plain_bench` | the bench client over plain noq, optionally with multipath (`PLAIN_MULTIPATH`) |
| `pkarr_publish`, `pkarr_resolve`, `dht_testnet` | pkarr on a local mainline testnet |
| `blake3_vectors` | BLAKE3 test vectors for jiroh's implementation |

`IROH_RELAY_CA` (a PEM file) makes `server` and `iroh_client` trust a test relay's certificate, as jiroh's
`nat-test.sh` needs.
