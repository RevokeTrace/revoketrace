# RevokeTrace submission pack (draft)

> **2026-10-31 evidence update:** The original summary reported a read-only Testnet forecast at CLI ledger 5490344 and a separate RPC response at ledger 5490345, but the original output was not retained. A new, reproducible PR #20 capture is recorded with its exact CLI stdout/stderr and a full separate `getLatestLedger` response: the CLI reported ledger 5490828 (`UNVERIFIED_FORECAST`, exit 10), while the separate RPC request reported protocol 29 at ledger 5490831. See the [observation record](../research/testnet-live-observation-2026-10-31.md). Neither capture establishes transaction success, exhaustive discovery, a real forced redemption, program approval, or submission readiness. The October 30 blocked attempt remains historical.

Prepared 2026-10-30. This is submission preparation. It is not an application, it records no approval, and it does not say the project is ready to submit. Open items are listed at the end.

## Project identity

| Item | Value |
| --- | --- |
| Project | RevokeTrace |
| Repository | https://github.com/RevokeTrace/revoketrace |
| Documentation | https://revoketrace.github.io/revoketrace/ (deployment confirmed by a successful hosted workflow; the site could not be fetched from the research sandbox) |
| License | MIT (GitHub reports `mit`) |
| Release | https://github.com/RevokeTrace/revoketrace/releases/tag/v1.0.0, source only, no binary assets |
| Release source commit | `9b0e10121a4413d07e6323bd351a6ed4680279bb` (annotated tag object `984eec70af723c30bfc26864ddf9ef31fe67378a`) |
| `main` when this pack was drafted | `7326436a4e5dae801240cefbd5722b2719a049a8` |
| Candidate source commit | Not fixed. The code changes (PRs 14 to 18) are on `main` (`2c01428` at the time of writing); the commit to submit is the one after this pull request (19) merges. It must be recorded at freeze. |
| Primary deliverable | The `revoketrace` command-line program (Rust 1.97.1, `stellar-xdr` 28.0.1) |

## Problem

An asset issuer who revokes a holder's authorization on a trustline can change much more than that one trustline. Since protocol 18 (CAP-0038), removing the holder's `AUTHORIZED_TO_MAINTAIN_LIABILITIES` permission forces the holder out of every liquidity pool that uses the asset. For each pool the network deletes the holder's pool-share trustline, withdraws the holder's share of both reserves with floor rounding, and creates a claimable balance for each nonzero withdrawn asset that the holder does not issue. Reserves are released and re-assigned, a sponsor must be able to take on the new claimable balances, and the whole operation fails if reserve or sponsorship limits are not met. The result depends on which pools exist, their reserves and share totals, who sponsors each entry, and account reserve counters. None of that is visible in the operation itself.

RevokeTrace models that outcome before anyone acts, from evidence the caller supplies or a bounded Testnet read.

## Why Stellar

The tool exists only because of Stellar Classic mechanics: the `SetTrustLineFlags` and `AllowTrust` operations, the difference between full authorization and maintain-liabilities authorization, CAP-0038 forced redemption, CAP-0038 claimable-balance ID derivation (a SHA-256 over an `ENVELOPE_TYPE_POOL_REVOKE_OP_ID` preimage), and Classic sponsorship and reserve accounting. It does not wrap an unrelated feature in a blockchain label. It reads ledger entries and decodes Stellar XDR.

## Implemented solution

- **Offline analysis.** `analyze` evaluates a JSON snapshot without any network access.
- **Bounded live Testnet observation.** `live` reads a bounded current-tip view through Horizon (candidate enumeration) and one Stellar RPC `getLedgerEntries` batch of at most 200 keys. Testnet only.
- **Forecasting engine.** Integer redemption amounts, claimable-balance IDs when the operation context is supplied, reserve and sponsorship deltas, and pool-deletion predictions when counter evidence exists.
- **Evidence validation.** Ledger sequences must agree, pool IDs must match their canonical derivation, XDR must decode, and the protocol version must be inside the reviewed range 18 to 29. The evidence classification is derived by the program and cannot be set by the caller.
- **Reports.** Deterministic human text and a schema-1 JSON report.
- **Fail-closed results.** Missing, stale, mixed, contradictory, unsupported, or malformed input yields `INCONCLUSIVE`, `UNSUPPORTED`, or an input error, never a safe result. `SUPPORTED_SAFE` is not emitted.

## Reproduction

Prerequisites: `git`, `curl` (only for live mode), and Rust through `rustup`. The repository pins Rust 1.97.1 in `rust-toolchain.toml`.

```bash
git clone https://github.com/RevokeTrace/revoketrace
cd revoketrace
cargo build --release --locked --bin revoketrace
./target/release/revoketrace version
```

Offline example, using the stored fixture (not newly obtained network state):

```bash
./target/release/revoketrace analyze \
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

Expected: the report prints `UNVERIFIED_FORECAST` and the process exits with code 10. Exit code 10 means the forecast is internally consistent but carries warnings, here that discovery is not independently verified, pool deletion cannot be forecast without counter evidence, and sponsorship evidence is incomplete. It is not a successful preflight and not transaction approval. Other exit codes: 0 completed, 20 inconclusive, 30 unsupported, 40 invalid input, 50 live network failure, 60 report output failure, 70 internal error.

Tests and checks:

```bash
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo audit --deny warnings
RUSTDOCFLAGS="-Dwarnings" cargo doc --workspace --no-deps --locked
```

A scripted demonstration with a recorded transcript is in [`submission/demo/`](demo/). Run `submission/demo/run-demo.sh`; it clones the current commit and builds from the clone.

## Evidence

| Evidence | Location |
| --- | --- |
| Source | `src/lib.rs` (engine), `src/evidence.rs` (evidence adapter), `src/discovery.rs`, `src/report.rs`, `src/cli.rs`, `src/protocol.rs` |
| Claims and their status | [docs/verification.md](../docs/verification.md) |
| Test mapping | [research/test-matrix.md](../research/test-matrix.md) |
| Protocol references | [protocol support decision](../research/protocol-support-decision.md), [Phase 4C verification](../research/phase4c-protocol-verification.md), CAP-0038 |
| Hosted CI on `main` at `7326436` | [CI run](https://github.com/RevokeTrace/revoketrace/actions/runs/41128519091) and [Documentation run](https://github.com/RevokeTrace/revoketrace/actions/runs/41128519089), both successful |
| Real Testnet evidence | The stored capture `fixtures/live-testnet-discovery.json`, one flag-only operation recorded in Phase 4C, and the bounded CLI recapture with separate RPC response in the [2026-10-31 observation](../research/testnet-live-observation-2026-10-31.md). The October 30 attempt was [blocked](../research/testnet-live-attempt-2026-10-30.md). |
| Comparable projects | [ecosystem comparison](../research/ecosystem-eligibility-2026-10-30.md) |
| Audit and freeze record | [audit-record.md](audit-record.md) |

## Security

- No private-key custody, wallet authentication, transaction signing, envelope construction, or broadcast. The dependencies are `serde`, `serde_json`, `stellar-xdr`, `sha2`, and `hex`.
- Untrusted input: snapshots, saved reports, Horizon and RPC responses, and file paths are all treated as untrusted. Evidence classification is derived, never read from the caller.
- Known report limitation: `inspect` does not authenticate a saved report or recompute its forecast, so a report can be edited. Its output says so, and its exit code follows the saved label.
- Live endpoints must use `https://` (loopback excepted), and the `curl` transport reads no configuration file, never follows redirects, and rejects any non-2xx HTTP status. The RPC-reported protocol version is checked before the header is decoded. The RPC server is not asked which network it serves.
- Private vulnerability reporting is enabled for the repository (confirmed through the GitHub API on 2026-10-30). The policy is in [SECURITY.md](../SECURITY.md) and promises no response time.
- Independent audit status: no independent third-party security audit has taken place. Automated tests, `cargo audit`, and agent-assisted review are not a substitute and are not described as one.

## Current limitations

- Bounded current-tip discovery is not exhaustive or historical capture.
- No authoritative complete-ledger verification is shipped. `COMPLETE_AUTHORITATIVE_LEDGER` cannot be produced from caller-supplied data.
- There is no guaranteed transaction-success preflight.
- Full multi-operation sponsorship behavior is not verified against a live ledger.
- A complete live forced-redemption evidence set has not been demonstrated. The only real Testnet operation recorded is flag-only.
- The October 30 attempt was blocked by the then-current network environment. A later bounded CLI observation completed on October 31; its separate `getLatestLedger` response reported protocol 29, but was three ledgers later than the CLI capture and is not the CLI's exact header. No real forced-redemption execution was observed.
- Protocol versions 18 to 29 are the reviewed range. The separate October 31 provider response reported protocol 29; this does not extend the supported range or establish the protocol version of the CLI capture's exact header.
- A provider on a different network from the supplied passphrase is not detected.

## Program readiness

| Program | Label | Basis |
| --- | --- | --- |
| Drips (Stellar Wave) | NOT VERIFIED | Official documentation could not be read. Secondary summaries say repository approval is discretionary and required before issues are published. Whether a submission window is open is unknown. No approval is verified in the available evidence. |
| GrantFox | NOT VERIFIED | No eligibility or submission rules were found, and the site returned HTTP 403 earlier. No approval is verified in the available evidence. |

This preparation pass submitted no application and created no program issues. The repository contains no independently verified application or approval record for either program. Details and sources: [ecosystem comparison](../research/ecosystem-eligibility-2026-10-30.md).

## Submission materials

| Material | Status |
| --- | --- |
| Repository | Exists, public, MIT |
| Documentation site | Deployed by a successful workflow; not fetched from the sandbox |
| Release | Exists, source only, v1.0.0 |
| CLI demonstration | Script and transcript from an actual run; no screen recording was made |
| Test evidence | Local runs recorded in [docs/verification.md](../docs/verification.md) (202 tests); hosted CI is green on `main` through `6ea854d`; this pull request's own checks are shown on the pull request |
| Testnet evidence | Bounded live CLI transcript and separate full `getLatestLedger` response retained in [the dated observation](../research/testnet-live-observation-2026-10-31.md); no transaction was executed and no exhaustive discovery or forced-redemption effect was independently observed |
| Slide deck, video, second repository | Do not exist |
| Any program's own required materials | Unknown, because the programs' rules were not read |

## Open items

1. Merge this pull request (19), then fix the candidate commit and record it in the freeze record.
2. Add `docs` as a required status check (administrator).
3. Add repository topics (administrator): suggested `stellar`, `stellar-network`, `rust`, `cli`, `liquidity-pools`, `protocol-analysis`.
4. Assess whether the retained bounded observation satisfies any specific program's evidence requirements; it is not a forced-redemption execution or proof of exhaustive discovery.
5. Read the Drips and GrantFox official rules and record them.
6. Decide whether to require an independent approval on `main`.
