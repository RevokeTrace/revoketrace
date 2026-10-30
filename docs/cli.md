# RevokeTrace CLI

This is the command-line documentation entry point. RevokeTrace is local, read-only software: it evaluates evidence already supplied by the caller or acquired through the bounded Testnet adapter. It does not sign, construct, broadcast, or repair Stellar transactions. See [the scope document](scope.md) for the project boundary and [the protocol research](../research/phase4c-protocol-verification.md) for source and fixture provenance.

## Commands

### `revoketrace version`

Prints the CLI version. `revoketrace help` and `revoketrace help <command>` print command help.

### `revoketrace analyze`

Analyzes a local JSON `Snapshot`, or a caller-supplied `AuthoritativeCaptureArtifact` containing a snapshot. The file is bounded to 8 MiB and is never sent to a network service. The artifact name does not make its contents authoritative. Caller-supplied authority labels are not promoted; the existing evidence adapter derives the evidence classification from snapshot properties.

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

`AllowTrust` may change only the two authorization flags. Its before and after values must preserve the trustline's non-authorization flags, including `clawback_enabled`; use `SetTrustLineFlags` for an operation that explicitly changes those flags.

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

Schema validation is an envelope check only. `inspect` does not authenticate the
report, verify its provenance or manifest digest, promote caller-supplied evidence,
recompute transaction safety, or approve a transaction. In particular,
`UNVERIFIED_FORECAST` remains unverified when it is inspected.

A saved report is caller-supplied data. Anyone can edit one, including its
evidence classification (for example to `COMPLETE_AUTHORITATIVE_LEDGER`), its
forecast classification, its warnings, and its limitations. `inspect` therefore
presents the file as follows:

- Text output starts with a `NOT VERIFIED BY REVOKETRACE` notice. It states that the file was supplied by the caller, that its origin is unauthenticated, that the forecast was not recomputed, and that this is not transaction approval.
- The copied classifications are labelled `Saved evidence classification (unverified claim)` and `Saved forecast classification (not recomputed)`. Warnings, errors, and limitations are labelled as written in the file, and an empty limitations list is explained as not meaning that no limitations exist.
- `--format json` prints the saved schema 1 document unchanged, so existing consumers keep working. Because that document cannot carry a notice, the same warning is printed to standard error. Do not treat the JSON from `inspect` as a fresh RevokeTrace result.
- The exit code follows the saved forecast classification, so an edited file can produce exit code `0` or `10`. The exit code of `inspect` is not evidence that the forecast is correct.
- A file whose forecast classification is not one RevokeTrace emits (such as `SUPPORTED_SAFE`) is rejected as invalid input (exit code 40).

To get a forecast you can rely on, run `analyze` or `live` on the evidence itself.

## Output and file safety

Text is the default output. Use `--format json` for the stable report schema below.
`--output PATH` creates an exclusive temporary file in the destination directory,
writes and flushes the complete report, and then installs it. Without `--force`,
installation uses an atomic same-filesystem hard-link operation that cannot replace
an existing directory entry; the earlier existence check is only a clearer error
fast path. A destination created concurrently therefore wins and the report
installation fails with exit code `60` rather than overwriting it. Filesystems that
do not support hard links cannot be used for no-force report installation.

With `--force`, an existing non-symbolic-link destination is replaced with an
atomic same-directory rename. Pre-existing symbolic-link destinations and direct
symbolic-link output directories are rejected, and rename never dereferences a
symbolic-link destination. Portable standard-library APIs cannot make the
non-symbolic-link check and forced replacement one conditional operation against a
hostile process changing the path concurrently; the output directory must therefore
be trusted when `--force` is used. A failed write or installation removes its
temporary file and does not install a partial report. Paths containing `..` are
rejected for output files. `--output -` writes to stdout.

Endpoints must use `https://`. Plain `http://` is accepted only for a loopback host (`localhost`, `127.0.0.1`, or `[::1]`), because TLS is the only protection for the Horizon and RPC responses. Endpoints also reject embedded user information, `%` encoding, query strings, fragments, whitespace, and control characters. Live reports record both endpoint URLs verbatim. Validation cannot detect a secret placed in the URL path, so use public endpoints that need no key in the URL. Reports otherwise contain public account and evidence identifiers only.

Live requests are made by the system `curl` executable, started with a fixed set of options:

- `-q` is the first option, so `curl` does not read `.curlrc` or any configuration under `CURL_HOME`. A configuration file cannot add redirect following, a different proxy, or looser certificate settings.
- `curl` itself is limited to `https` (or `http` for the loopback hosts above) with `--proto` and `--proto-redir`, and TLS 1.2 or later is required for HTTPS. A URL with another scheme, such as `file://`, or cleartext to a remote host, is refused before `curl` starts.
- Redirects are never followed (`--max-redirs 0`). A 3xx answer is an error, and the redirect target is not contacted.
- Any HTTP status outside 200 to 299 is a network failure (exit code 50), and the response body is not used. HTTP 429 is reported as rate limited. The request has no retry on these statuses.
- The request body is sent literally (`--data-raw`) and URL globbing is off.

Proxy and CA environment variables such as `HTTPS_PROXY` and `SSL_CERT_FILE` are still honored. They belong to the operator's trusted environment. `curl` has no environment setting that turns certificate verification off.

## JSON report schema

Every JSON report has these top-level fields in this order:

```json
{
  "schema_version": 1,
  "report_type": "revoketrace.forecast",
  "tool": { "name": "revoketrace", "version": "1.0.0" },
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
- `UNSUPPORTED`: the operation or protocol is outside the supported scope. Protocol versions 18 to 29 are evaluated; anything else is refused.

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
- Live results depend on current Testnet availability and are observations of bounded current-tip evidence. They are not fabricated when the network is unavailable and are never presented as historical completeness or transaction success.
