# RevokeTrace

RevokeTrace is a read-only Rust CLI and forecasting engine for Stellar Classic issuer authorization changes. It evaluates supplied ledger evidence and forecasts CAP-0038 liquidity-pool redemption effects; it never signs, constructs, broadcasts, or repairs transactions.

The CLI documentation entry point is [docs/cli.md](docs/cli.md). It contains the command reference, versioned JSON schema, exit codes, security boundaries, and known limitations.

Report files are written through an exclusively created, flushed temporary file.
Without `--force`, the final installation is atomic and no-replace; an existing or
concurrently created destination is never overwritten. `--force` permits replacement
of a non-symbolic-link destination, subject to the trusted-output-directory race
limitation documented in [docs/cli.md](docs/cli.md).

## Install and build

The repository pins Rust in `rust-toolchain.toml`. From a checkout:

```bash
cargo build --release --locked --bin revoketrace
./target/release/revoketrace help
```

Use `cargo run --locked --bin revoketrace -- ...` when running directly from the checkout.

## Offline analysis

Offline mode reads an existing `Snapshot` JSON file and makes no network request. The included fixture is a bounded, incomplete-evidence example:

```bash
cargo run --locked --bin revoketrace -- analyze \
  --snapshot fixtures/live-testnet-discovery.json \
  --operation SetTrustLineFlags \
  --source-account GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG \
  --trustor GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB \
  --asset-code FLUTTER \
  --asset-issuer GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG \
  --before-flags 1 --after-flags 0 \
  --tx-source-account GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG \
  --sequence 42 --operation-index 0
```

This fixture is expected to return exit code `10` and print `UNVERIFIED_FORECAST`. That classification is an internally consistent forecast with warnings, not a successful transaction preflight. The output reports the two affected pools, exact integer withdrawals, claimable-balance IDs, reserve/sponsorship deltas, and the fact that pool deletion cannot be forecast without counter evidence.

To export the stable JSON report without overwriting an existing file:

```bash
cargo run --locked --bin revoketrace -- analyze \
  --snapshot fixtures/live-testnet-discovery.json \
  --operation SetTrustLineFlags \
  --source-account GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG \
  --trustor GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB \
  --asset-code FLUTTER \
  --asset-issuer GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG \
  --before-flags 1 --after-flags 0 \
  --format json --output report.json
```

Inspect a saved report with:

```bash
revoketrace inspect --report report.json
```

## Bounded live Testnet analysis

Live mode requires explicit Testnet network and endpoint values. It reuses the existing bounded Horizon candidate enumeration and single-batch Stellar RPC evidence adapter. A successful live acquisition is still bounded current-tip evidence; it does not prove complete historical or ledger-wide coverage.

```bash
revoketrace live \
  --network-passphrase 'Test SDF Network ; September 2015' \
  --horizon-url https://horizon-testnet.stellar.org \
  --rpc-url https://soroban-testnet.stellar.org \
  --operation SetTrustLineFlags \
  --source-account ISSUER_G_ACCOUNT \
  --trustor TRUSTOR_G_ACCOUNT \
  --asset-code ASSET \
  --asset-issuer ISSUER_G_ACCOUNT \
  --before-flags 1 --after-flags 0 \
  --tx-source-account ISSUER_G_ACCOUNT --sequence 42 --operation-index 0
```

The command does not sign or submit the requested authorization change. Network failures and malformed or contradictory RPC evidence fail closed with nonzero exit codes. A live run is not claimed here because its result depends on current Testnet state.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Command completed; this is not transaction approval. |
| 10 | Valid forecast containing warnings (`UNVERIFIED_FORECAST`). |
| 20 | Inconclusive or contradictory evidence. |
| 30 | Unsupported operation or protocol. |
| 40 | Invalid CLI input or input file. |
| 50 | Live network/RPC failure. |
| 60 | Report output failure. |
| 70 | Internal error. |

## Dependencies and repository policy

Milestone 5 adds no dependencies. Reports use the existing `serde`/`serde_json` stack, and the repository continues to use `Cargo.lock` with locked builds. Dependency updates remain manually reviewed; no automated dependency-update bot or scheduled update workflow is used.

CI runs formatting, locked tests, and locked clippy checks. GitHub branch-protection settings are repository administration and are not inferred from the workflow file.
