# Changelog

## Unreleased

- Protocol policy: versions 18 to 29 are evaluated and any other version is refused as `UNSUPPORTED` (exit code 30), in offline, live, and stored-capture paths. v1.0.0 only enforced the lower bound. A snapshot without a protocol version now carries the warning `W_PROTOCOL_UNVERIFIED`. The live adapter checks the RPC-reported version before decoding the header and requires the decoded header version to agree. Rationale and evidence: [protocol support decision](research/protocol-support-decision.md).
- Live endpoints must use `https://`. Plain `http://` is accepted only for loopback hosts. Documented that endpoint URLs are recorded verbatim in live reports. The `curl` transport now ignores configuration files (`-q`), restricts protocols and redirects in `curl` itself, never follows redirects, and treats non-2xx HTTP statuses as network failures.

## 1.0.0 (published)

Published 2026-10-30: [RevokeTrace v1.0.0](https://github.com/RevokeTrace/revoketrace/releases/tag/v1.0.0), from immutable source commit `9b0e10121a4413d07e6323bd351a6ed4680279bb`.

The release is source-distributed. GitHub provides the release source archives,
but no independently verified downloadable binary is attached. Later
documentation improvements on `main` are not automatically part of the tagged
source archive.

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
`report_type: "revoketrace.forecast"`. v1.0.0 reports tool version `1.0.0`; it
does not silently change the JSON schema or add a safe-preflight classification.

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
