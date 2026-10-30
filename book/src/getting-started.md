# Getting started

The repository pins the Rust toolchain in `rust-toolchain.toml`. Clone the project and run:

```bash
git clone https://github.com/RevokeTrace/revoketrace.git
cd revoketrace
cargo build --release --locked --bin revoketrace
./target/release/revoketrace help
```

Offline analysis needs no network connection. To run the repository's reproducible example, follow the [offline analysis command in README](https://github.com/RevokeTrace/revoketrace#offline-analysis). Its stored fixture is **incomplete evidence**, so the expected classification is `UNVERIFIED_FORECAST` and exit code `10`.

Live analysis is optional and Testnet-only. It requires reachable Horizon and Stellar RPC endpoints. A successful live observation is still bounded current-tip evidence, not an exhaustive ledger snapshot.

[Complete CLI reference](https://github.com/RevokeTrace/revoketrace/blob/main/docs/cli.md)
