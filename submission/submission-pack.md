# RevokeTrace submission pack (readiness dossier)

> **Readiness review dated 2026-10-31:** The repository baseline reviewed was `main` at `1b31580fc634343a62b278566b0b510c81ce241e`. PRs #1 through #20 were merged at that point. This is a preparation document, not an application, approval, or freeze record. The current-source offline demonstration transcript is linked below. The October 31 live CLI capture from source `9a419ebf74194359db45b79fb274e58d29c4e4de` remains a bounded `UNVERIFIED_FORECAST` at ledger 5491146, exit 10. Its retained output is separate from the earlier CLI summary that was withdrawn after an issuer transcription error. The separately retained RPC response at ledger 5490831/protocol 29 is not the live CLI's exact header. See the [observation record](../research/testnet-live-observation-2026-10-31.md). No capture establishes transaction success, exhaustive discovery, an executed forced redemption, program approval, or submission readiness. The October 30 blocked attempt remains historical.

This dossier distinguishes code readiness, evidence readiness, program eligibility, and actual application or approval status. The source candidate is not frozen. Any final submission should identify the exact post-review `main` commit and rerun the listed checks against it.

## Project identity

| Item | Value |
| --- | --- |
| Project | RevokeTrace |
| Repository | https://github.com/RevokeTrace/revoketrace |
| Documentation | https://revoketrace.github.io/revoketrace/ (main Documentation/deploy workflow passed at `3a7e762973cb4e3c3277e18fe0014037c437ca4e`; direct `curl` returned HTTP 200 for the site root and all seven linked chapters on 2026-10-31) |
| License | MIT (GitHub reports `mit`) |
| Release | https://github.com/RevokeTrace/revoketrace/releases/tag/v1.0.0, source only, no binary assets |
| Release source commit | `9b0e10121a4413d07e6323bd351a6ed4680279bb` (annotated tag object `984eec70af723c30bfc26864ddf9ef31fe67378a`) |
| `main` baseline reviewed | `1b31580fc634343a62b278566b0b510c81ce241e` (2026-10-31) |
| Candidate status | Not frozen. This exact baseline is the code candidate assessed by this pass; the documentation readiness changes are still subject to PR review and merge, after which the final source commit and checks must be recorded. |
| Primary deliverable | The `revoketrace` command-line program (Rust 1.97.1, `stellar-xdr` 28.0.1) |

The published `v1.0.0` source archive is fixed at the release commit above. It predates the reviewed `main` baseline; later code and documentation changes on `main` are not part of the `v1.0.0` archive. The tag and release remain unchanged.

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

Local verification on the reviewed baseline `1b31580fc634343a62b278566b0b510c81ce241e` passed: `cargo fmt --check`, `cargo test --locked` (202 tests), release build, strict Clippy, `cargo audit --deny warnings`, warning-denied rustdoc, `mdbook build` with mdBook 0.4.52, `scripts/check-doc-links.py`, and `git diff --check`. The final current-source executable demonstration is [`transcript-1b31580.txt`](demo/transcript-1b31580.txt). Its release binary was built from a clean clone at that exact commit. These results are local, not a substitute for CI on a later candidate.

Reproducible check commands (CI pins mdBook 0.4.52):

```bash
cargo install mdbook --version 0.4.52 --locked
cargo fmt --check
cargo test --locked
cargo build --release --locked --bin revoketrace
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo audit --deny warnings
RUSTDOCFLAGS="-Dwarnings" cargo doc --workspace --no-deps --locked
mdbook build
python3 scripts/check-doc-links.py
```

Run `submission/demo/run-demo.sh` to create a fresh transcript from the current checkout. The older [`transcript.txt`](demo/transcript.txt) is retained as historical evidence from its recorded source commit; it is not output from the current candidate.

## Evidence

| Evidence | Location |
| --- | --- |
| Source | `src/lib.rs` (engine), `src/evidence.rs` (evidence adapter), `src/discovery.rs`, `src/report.rs`, `src/cli.rs`, `src/protocol.rs` |
| Claims and their status | [docs/verification.md](../docs/verification.md) |
| Test mapping | [research/test-matrix.md](../research/test-matrix.md) |
| Protocol references | [protocol support decision](../research/protocol-support-decision.md), [Phase 4C verification](../research/phase4c-protocol-verification.md), CAP-0038 |
| Hosted Rust CI on reviewed `main` baseline | [CI run 41242363654](https://github.com/RevokeTrace/revoketrace/actions/runs/41242363654), successful on `1b31580fc634343a62b278566b0b510c81ce241e` |
| Last observed successful main Documentation/deploy workflow | [Documentation run 41159173318](https://github.com/RevokeTrace/revoketrace/actions/runs/41159173318), successful on `3a7e762973cb4e3c3277e18fe0014037c437ca4e`. The workflow deploys only on main pushes affecting book files or the workflow. Direct checks on 2026-10-31 returned HTTP 200 for the root and all seven linked chapters after an earlier request timed out. |
| Real Testnet evidence | The stored capture `fixtures/live-testnet-discovery.json`, one flag-only operation recorded in Phase 4C, and the byte-preserved stdout/stderr from the fresh 20:42 CLI capture. The separately retained `getLatestLedger` response is an earlier observation, not the CLI header. See the [2026-10-31 observation](../research/testnet-live-observation-2026-10-31.md). The October 30 attempt was [blocked](../research/testnet-live-attempt-2026-10-30.md). |
| Comparable projects | [ecosystem comparison](../research/ecosystem-eligibility-2026-10-30.md) |
| Audit and freeze record | [audit-record.md](audit-record.md) |

## Security

- No private-key custody, wallet authentication, transaction signing, envelope construction, or broadcast. The dependencies are `serde`, `serde_json`, `stellar-xdr`, `sha2`, and `hex`.
- Untrusted input: snapshots, saved reports, Horizon and RPC responses, and file paths are all treated as untrusted. Evidence classification is derived, never read from the caller.
- Known report limitation: `inspect` does not authenticate a saved report or recompute its forecast, so a report can be edited. Its output says so, and its exit code follows the saved label.
- Live endpoints must use `https://` (loopback excepted), and the `curl` transport reads no configuration file, never follows redirects, and rejects any non-2xx HTTP status. The RPC-reported protocol version is checked before the header is decoded. The RPC server is not asked which network it serves.
- Private vulnerability reporting was enabled according to the GitHub repository API on 2026-10-31 (`enabled: true`). The policy is in [SECURITY.md](../SECURITY.md) and promises no response time.
- Independent audit status: no independent third-party security audit has taken place. Automated tests, `cargo audit`, and agent-assisted review are not a substitute and are not described as one.

## Current limitations

- Bounded current-tip discovery is not exhaustive or historical capture.
- No authoritative complete-ledger verification is shipped. `COMPLETE_AUTHORITATIVE_LEDGER` cannot be produced from caller-supplied data.
- There is no guaranteed transaction-success preflight.
- Full multi-operation sponsorship behavior is not verified against a live ledger.
- A complete live forced-redemption evidence set has not been demonstrated. The only real Testnet operation recorded is flag-only.
- The October 30 attempt was blocked by the then-current network environment. A bounded CLI observation completed on October 31 at ledger 5491146; its raw output is retained. The separate `getLatestLedger` response at ledger 5490831/protocol 29 predates that capture and is not its exact header. No real forced-redemption execution was observed.
- Protocol versions 18 to 29 are the reviewed range. The separate October 31 provider response reported protocol 29; this does not extend the supported range or establish the protocol version of the CLI capture's exact header.
- A provider on a different network from the supplied passphrase is not detected.

## Program readiness

| Program | Label | Basis |
| --- | --- | --- |
| Drips (Stellar Wave) | ELIGIBILITY NOT VERIFIED | The official public page showed no active or upcoming Wave. Repository applications require GitHub organization onboarding, repository sync, an application to a Wave Program, and organizer approval. Maintainer-app limits and RevokeTrace's private application status were not checked. No application or approval is verified. |
| GrantFox OSS Contributions | NOT READY TO APPLY | The official guide calls for a connected GitHub account, project application form, and a required video pitch of about five minutes. It gives a one-to-two-month age and activity guideline. RevokeTrace was four days old at this review and no pitch is in this dossier. Review is manual. No application or approval is verified. The current campaign and private account status remain unknown. |

This review submitted no application, accessed no program account, and created no program issues. Private application or approval status was not inspected. The repository contains no independently verified application or approval record. The dated official-source comparison, comparator review, and maintainer next steps are in [program readiness](../research/program-readiness-2026-10-31.md). The October 30 ecosystem report remains a historical record, not the current eligibility assessment.

## Submission materials

| Material | Status |
| --- | --- |
| Repository | Exists, public, MIT |
| Documentation site | Last successful main deployment workflow observed at `3a7e762`; direct requests on 2026-10-31 returned HTTP 200 for the root and all seven linked chapters. An earlier request from this environment timed out. |
| Release | Exists, source only, v1.0.0 |
| CLI demonstration | Script plus an actual release-binary transcript from clean source commit `1b31580`; older transcript retained separately as historical. No screen recording was made. |
| Test evidence | Local checks on `1b31580` are summarized above and traced in [docs/verification.md](../docs/verification.md). Hosted Rust CI passed on that exact commit; the last main Documentation/deploy workflow is on `3a7e762`. |
| Testnet evidence | Raw stdout/stderr and capture metadata for the fresh bounded CLI observation are linked in [the dated record](../research/testnet-live-observation-2026-10-31.md); the separate raw RPC response is earlier and does not establish the CLI header. No transaction was executed or exhaustive discovery or forced-redemption effect independently observed |
| Slide deck, video, second repository | Do not exist |
| Drips application materials | Public process documented; private account/org state and future Wave application availability require maintainer review in the Drips app |
| GrantFox application materials | Required video pitch not prepared; assess the age/activity guideline and active Campaign rules before applying |

## Maintainer actions before any application

1. Review and merge the documentation readiness PR only after independent review and both workflow checks pass. Then rerun the documented checks on the resulting `main` commit before freezing a candidate.
2. Verify `main` branch protection in repository settings. Current API access did not confirm whether pull requests, approvals, required `rust`/`docs` checks, force-push restrictions, or deletion restrictions are enforced. Do not infer enforcement from green CI.
3. If considering Drips, use the maintainer's own Drips account to verify organization onboarding, repository listing/application state, application limits, and the next relevant Wave. The public page currently shows no active or upcoming Wave.
4. If considering GrantFox, wait until the repository meets its published age/activity guideline, prepare the required pitch, and verify whether a suitable active Campaign is accepting projects. The OSS directory being public does not establish funded campaign participation.
5. Keep the live evidence limitations visible. The October 31 capture is a bounded `UNVERIFIED_FORECAST`, not proof of exhaustive discovery or a forced-redemption execution.

No maintainer account action, application, grant request, release, or program issue publication has been performed as part of this assessment.
