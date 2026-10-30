<div align="center">

# RevokeTrace

**Read-only Stellar Classic authorization forecasting**

[![CI](https://github.com/RevokeTrace/revoketrace/actions/workflows/ci.yml/badge.svg)](https://github.com/RevokeTrace/revoketrace/actions/workflows/ci.yml)
[![Documentation](https://img.shields.io/badge/Documentation-mdBook-blue)](https://revoketrace.github.io/revoketrace/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Rust 1.97.1](https://img.shields.io/badge/Rust-1.97.1-orange)](rust-toolchain.toml)
[![Release](https://img.shields.io/github/v/release/RevokeTrace/revoketrace?label=Release)](https://github.com/RevokeTrace/revoketrace/releases)

[Documentation](https://revoketrace.github.io/revoketrace/) · [Getting started](https://revoketrace.github.io/revoketrace/getting-started.html) · [Releases](https://github.com/RevokeTrace/revoketrace/releases) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

</div>

RevokeTrace is a read-only Rust CLI and forecasting engine for Stellar Classic issuer authorization changes. It evaluates supplied ledger evidence and forecasts CAP-0038 liquidity-pool redemption effects. It never signs, constructs, broadcasts, or repairs transactions.

It is useful to Stellar issuers, protocol researchers, and maintainers investigating what an authorization change may do to affected liquidity-pool positions. It reports modeled withdrawals, claimable-balance effects, sponsorship and reserve deltas, and evidence limitations. It does not prove that a transaction will succeed or that a supplied snapshot is a complete ledger view.

Start with the [Documentation](https://revoketrace.github.io/revoketrace/) or the [CLI reference](docs/cli.md) for commands, JSON reports, exit codes, input limits, and file-safety behavior. The [scope document](docs/scope.md) defines the evidence model and security boundary. Protocol findings and provenance notes are recorded in [the Phase 4C verification matrix](research/phase4c-protocol-verification.md) and [the evidence audit](research/authoritative-evidence-audit.md).

The [1.0.0 release-candidate record](CHANGELOG.md) summarizes the candidate contract, reproduction path, and remaining release limitations. It is not a published release.

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

The project has no network requirement for offline analysis. Live mode is an optional bounded Stellar Testnet observation and requires reachable Horizon and RPC endpoints.

## What the CLI helps investigate

`analyze` evaluates a caller-supplied snapshot without contacting the network. `live` obtains a bounded current-tip Testnet snapshot through the existing adapter. `inspect` reads a saved versioned report without authenticating or recomputing it.

The engine can model CAP-0038 pool redemptions, integer withdrawal amounts, claimable-balance IDs when complete operation context is supplied, clawback flags, sponsorship, reserve effects, and pool-deletion counters when the relevant evidence is present. It also identifies missing or contradictory evidence.

`UNVERIFIED_FORECAST` means that the supplied data passed the modeled checks but is not a transaction approval. `SUPPORTED_BLOCKED` means that a modeled supported precondition or reserve/sponsorship limit fails. `SUPPORTED_SAFE` is not emitted. Bounded current-tip discovery cannot prove exhaustive or historical ledger coverage.

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
cargo run --locked --bin revoketrace -- inspect --report report.json
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

## Protocol evidence and fixtures

The [protocol research index](research/phase4c-protocol-verification.md) links the pinned Stellar Core source review, CAP references, the real flag-only Testnet fixture, and the remaining unverified cases. The [discovery feasibility record](research/discovery-feasibility-proof.md) distinguishes live observations, stored network-response captures, and synthetic fixtures. CAP-0038 edge cases are under [fixtures/cap0038](fixtures/cap0038/).

Stored and synthetic fixtures are not interchangeable with independently verified ledger evidence. The repository does not claim a live forced-redemption transaction, full historical capture, or complete multi-operation sponsorship verification.

## Development and contribution

Run the locked test and lint commands before submitting a change. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the pinned toolchain, fixture and protocol-evidence requirements, commit practice, and review expectations. Report security vulnerabilities using the process in [SECURITY.md](SECURITY.md). Do not put exploit details in a public issue.

## Dependencies and repository policy

Reports use the existing `serde` and `serde_json` stack, and the repository continues to use `Cargo.lock` with locked builds. Dependency updates remain manually reviewed. No automated dependency-update bot or scheduled update workflow is used.

The project declares the MIT license. See [LICENSE](LICENSE).

CI runs formatting, locked tests, a locked binary build, and strict locked Clippy checks. Rust documentation and `cargo audit` are useful local checks but are not currently CI jobs. GitHub branch-protection settings are repository administration and are not inferred from the workflow file.
