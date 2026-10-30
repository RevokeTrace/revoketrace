# Changelog

## 1.0.0 release candidate

This is a release-candidate record for maintainer review. It does not create a
Git tag, publish a GitHub release, or publish the crate. Those actions require
explicit maintainer authorization.

RevokeTrace 1.0.0 includes:

- A local, read-only CLI for `SetTrustLineFlags` and `AllowTrust` forecasts.
- Offline snapshot analysis and bounded current-tip Stellar Testnet analysis.
- CAP-0038 pool-redemption forecasts, including integer amounts, claimable
  balances, sponsorship and reserve effects, and pool-deletion counters when
  the required evidence is available.
- Deterministic human-readable output and versioned JSON reports with schema
  version 1.
- Fail-closed handling for incomplete, contradictory, unsupported, malformed,
  oversized, or unsafe input.

### Build and reproduce

The repository pins Rust in [rust-toolchain.toml](rust-toolchain.toml). Build
the release binary with:

```bash
cargo build --release --locked --bin revoketrace
./target/release/revoketrace version
```

The [offline analysis example](README.md#offline-analysis) reproduces a
bounded forecast from the stored fixture. The expected result is
`UNVERIFIED_FORECAST`, with exit code `10`. It is a modeled forecast with
evidence limitations, not transaction approval. See the [CLI reference](docs/cli.md)
for the complete command, report, exit-code, and file-safety contract.

### Compatibility and evidence boundary

The report contract remains `schema_version: 1` and
`report_type: "revoketrace.forecast"`. This candidate reports tool version
`1.0.0`; it does not silently change the JSON schema or add a safe-preflight
classification.

Offline snapshots and saved reports remain untrusted caller data. Live mode is
bounded current-tip Testnet evidence. It does not prove exhaustive ledger
coverage or historical state. `SUPPORTED_SAFE` is unreachable,
`UNVERIFIED_FORECAST` is not transaction approval, and `SUPPORTED_BLOCKED` is a
modeled blocker rather than a complete network preflight result. Report
inspection validates an envelope only and does not authenticate provenance.

Full multi-operation sponsorship behavior and a live forced-redemption fixture
covering every modeled effect remain unverified. RevokeTrace does not sign,
construct, broadcast, or automatically repair transactions, and it does not
provide an authoritative transaction-success result.

Protocol source reviews and evidence limitations are recorded in the [protocol
verification matrix](research/phase4c-protocol-verification.md). Contributor
requirements are in [CONTRIBUTING.md](CONTRIBUTING.md), and security reports
must follow [SECURITY.md](SECURITY.md).

No cross-platform binary is claimed by this record. A locally built binary and
its unsigned checksum are build outputs, not publisher authentication.
