# Verification and reproducibility

RevokeTrace treats several kinds of evidence differently:

- Pinned Stellar Core and CAP references explain the protocol rules being modeled.
- Unit tests cover normal, boundary, malformed, contradictory, and file-safety behavior using synthetic or stored inputs.
- The repository has one documented real Testnet fixture for a clawback-only transition. It does not prove live forced redemption or complete ledger capture.
- A fresh live command is a bounded current-tip observation, not historical proof or transaction preflight.

From a clean checkout, contributors can reproduce the core checks with:

```bash
cargo fmt --check
cargo test --locked
cargo build --release --locked --bin revoketrace
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo audit --deny warnings
RUSTDOCFLAGS="-Dwarnings" cargo doc --workspace --no-deps --locked
```

Run the [documented offline example](https://github.com/RevokeTrace/revoketrace#offline-analysis) with the release binary or `cargo run`. It is expected to return `UNVERIFIED_FORECAST` and exit code `10`; that is a useful reproducible forecast, not transaction approval.

The [verification and claims index](https://github.com/RevokeTrace/revoketrace/blob/main/docs/verification.md) and [test matrix](https://github.com/RevokeTrace/revoketrace/blob/main/research/test-matrix.md) identify the relevant source, test, evidence type, and remaining limitation for each critical claim.
