# RevokeTrace CLI

This is the command-line documentation entry point. RevokeTrace is local, read-only software: it evaluates evidence already supplied by the caller or acquired through the bounded Testnet adapter. It does not sign, construct, broadcast, or repair Stellar transactions.

## Commands

### `revoketrace version`

Prints the CLI version. `revoketrace help` and `revoketrace help <command>` print command help.

### `revoketrace analyze`

Analyzes a local JSON `Snapshot`, or an `AuthoritativeCaptureArtifact` containing a snapshot. The file is bounded to 8 MiB and is never sent to a network service. Caller-supplied authority labels are not promoted; the existing evidence adapter derives the evidence classification from snapshot properties.

Required options:

```text
--snapshot PATH
--operation SetTrustLineFlags|AllowTrust
--source-account ISSUER
--trustor ACCOUNT
--asset-code CODE
--asset-issuer ISSUER
--before-flags N
--after-flags N
```

`--source-account` must equal `--asset-issuer`. Optional transaction context must be complete when used:

```text
--tx-source-account ACCOUNT --sequence SEQUENCE --operation-index INDEX
```

If that context is absent, the engine can still forecast amounts but will explicitly leave claimable-balance IDs uncomputed.

### `revoketrace live`

Acquires bounded current-tip Testnet evidence through the existing `AuthoritativeEvidenceAdapter`, then evaluates the same engine as offline mode. Required network options are explicit:

```text
--network-passphrase 'Test SDF Network ; September 2015'
--horizon-url https://...
--rpc-url https://...
```

The adapter uses Horizon only to enumerate candidates and uses a bounded, single RPC `getLedgerEntries` request with the existing maximum of 200 keys. It verifies requested keys, XDR identities, ledger-sequence consistency, canonical pool IDs, sponsorship XDR, reserve/header values, and `liquidityPoolUseCount` where available. It does not implement an indexer or historical ledger service. Live mode currently accepts only Stellar Testnet.

### `revoketrace inspect`

Reads a versioned JSON report, validates its schema version/type, and displays its forecast classification, warnings, errors, reserve/sponsorship effects, and evidence limitations. It does not recompute the forecast or treat the report as a cryptographic certificate.

## Output and file safety

Text is the default output. Use `--format json` for the stable report schema below. `--output PATH` writes through a temporary file in the target directory, flushes it, and atomically installs it. Existing files and symbolic-link targets are rejected unless `--force` is supplied; symbolic-link output targets remain rejected. A failed write does not install a partial report. Paths containing `..` are rejected for output files. `--output -` writes to stdout.

Endpoints reject credentials, query strings, fragments, whitespace, and control characters. Reports contain public account and evidence identifiers only; credential-bearing endpoints are rejected before report generation.

## JSON report schema

Every JSON report has these top-level fields in this order:

```json
{
  "schema_version": 1,
  "report_type": "revoketrace.forecast",
  "tool": { "name": "revoketrace", "version": "0.1.0" },
  "mode": "offline",
  "operation": {},
  "evidence": {},
  "forecast": {},
  "warnings": [],
  "errors": []
}
```

No timestamp, random identifier, or network-tip metadata is added by the CLI, so equivalent validated inputs produce byte-equivalent pretty JSON reports.

### `operation`

Contains the requested operation, source account, optional transaction source, trustor, `{code, issuer}` asset identity, before/after flags, optional sequence and operation index, and the engine-derived requested transition (`NO_EFFECT`, `MAINTAIN_LIABILITIES_ONLY`, or `FORCED_POOL_REDEMPTION`).

### `evidence`

Contains network passphrase, ledger/entry/target sequences, source provenance, manifest digest, coverage, derived evidence classification, optional base reserve and protocol version, sponsorship-evidence completeness, and a sorted `limitations` array.

Evidence classifications are:

- `UNTRUSTED_CANDIDATE`
- `BOUNDED_CURRENT_TIP_RPC`
- `LEDGER_CONSISTENT_INCOMPLETE`
- `COMPLETE_AUTHORITATIVE_LEDGER` (not reachable from caller-supplied CLI snapshots)
- `INVALID_OR_CONTRADICTORY`

`BOUNDED_CURRENT_TIP_RPC` means exactly what it says: the bounded current-tip candidate set was checked. It is not complete ledger coverage.

### `forecast`

Contains the engine classification, transition, sorted pool redemptions, sorted claimable balances, and sorted account deltas. Forecast classifications currently emitted by the CLI are:

- `UNVERIFIED_FORECAST`: internally modeled output with unresolved evidence limitations; never a successful transaction preflight.
- `SUPPORTED_BLOCKED`: the modeled protocol rules identify a supported blocker.
- `INCONCLUSIVE`: required evidence is missing or contradictory.
- `UNSUPPORTED`: the operation or protocol is outside the supported scope.

The engine has no independently verified safe-preflight path, so the CLI does not emit a `SUPPORTED_SAFE` result.

Each pool redemption includes both exact integer withdrawals, claimable-balance forecasts, and:

```json
"pool_deletion": {
  "forecast": true,
  "limitation": null
}
```

When `pool_shares_trust_line_count` is absent, `forecast` is `null` and `limitation` explains why deletion was not guessed. Account deltas include subentry and sponsorship changes, reserve-unit changes, and reserve effects in stroops when base-reserve evidence exists.

Warnings and errors are objects with stable `code` and human-readable `message` fields. Collections are sorted before serialization. Missing values are represented as JSON `null` rather than fabricated defaults.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Command execution completed. A modeled blocked result is not approval. |
| 10 | Valid forecast containing warnings, normally `UNVERIFIED_FORECAST`. |
| 20 | Inconclusive or contradictory evidence. |
| 30 | Unsupported operation or protocol. |
| 40 | Invalid arguments, StrKeys, asset identities, paths, JSON, or input size. |
| 50 | Live transport/network or RPC failure. |
| 60 | Safe report-output failure. |
| 70 | Internal error. |

Exit status describes the CLI result, not a promise that a Stellar transaction would succeed. In particular, exit code `10` is intentionally nonzero and must not be used as a transaction preflight approval.

## Known limitations

- Offline input preserves its provenance but cannot independently establish that the snapshot covers the complete ledger.
- Live discovery is bounded, current-tip evidence. Horizon candidate enumeration cannot prove that every affected pool was found.
- `SUPPORTED_SAFE` is unreachable until an independent authoritative capture verifier exists.
- Pool deletion is forecast only when verified `poolSharesTrustLineCount` evidence is present and coherent.
- Full historical ledger indexing, database storage, dashboards, signing, transaction broadcasting, Soroban authorization interception, and automatic repair are out of scope.
- The CLI has been tested with fixture-backed offline invocations. A live result depends on current Testnet availability and is not fabricated when the network is unavailable.
