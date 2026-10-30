# Verification and claims index

This index makes important RevokeTrace claims traceable without treating all evidence as equivalent. "Covered by test" means a repository test exercised a stored or synthetic input. It is not independent ledger evidence. "Tested locally" records an audit command, not a hosted CI result.

Audit date: 2026-10-30. The audit baseline was `main` at `55a5b94861ae3ef10ca91c40b7bcc12c90f63222`; the immutable `v1.0.0` tag peels to `9b0e10121a4413d07e6323bd351a6ed4680279bb`.

| Claim | Implementation / source | Evidence and environment | Status | Limitation |
| --- | --- | --- | --- | --- |
| Authorization transitions distinguish maintain-liabilities revocation | `src/lib.rs::classify_transition` | `maintain_liabilities_transition_does_not_redeem`, `clearing_maintain_liabilities_enters_redemption_path`, `allow_trust_cannot_change_non_authorization_flags`; pinned Core review in [Phase 4C](../research/phase4c-protocol-verification.md) | COVERED BY TEST | No claim of future transaction success. |
| CAP-0038 redemptions use canonical pool order and floor arithmetic | `evaluate`, `forecast_amount` in `src/lib.rs` | `test_deterministic_pool_ordering_observable_difference`, `exact_integer_redemption_uses_floor`, `test_target_failure_mode_10_integer_overflow_and_underflow` | COVERED BY TEST | Inputs remain bounded model evidence. |
| Claimable-balance IDs use the CAP-0038 XDR preimage | `derive_pool_revoke_claimable_balance_id` | `derives_cap0038_pool_revoke_id_from_xdr_preimage`; Core/CAP source links in [Phase 4C](../research/phase4c-protocol-verification.md) | COVERED BY TEST | IDs are omitted when complete operation context is unavailable. |
| Pool counters, sponsorship, reserve effects, and blockers fail closed | `evaluate` and `validate_snapshot` in `src/lib.rs` | target failure-mode tests 1-17 and `test_adversarial_14_incorrect_sponsorship_identity` | COVERED BY TEST | Full multi-operation sponsorship handoffs are not independently verified. |
| Live acquisition validates bounded current-tip responses | `AuthoritativeEvidenceAdapter::acquire_live_evidence` in `src/evidence.rs` | mock RPC/Horizon tests including `test_positive_bounded_current_tip_rpc_classification`, adversarial tests 1-19 | COVERED BY TEST | A bounded response set is not complete or historical ledger evidence. |
| A real Testnet operation decodes and a clawback-only change does not trigger redemption | `src/lib.rs` test fixture | `independent_testnet_fixture_clawback_only_change_is_not_forced_redemption`; Testnet operation recorded in the test comment and [Phase 4C](../research/phase4c-protocol-verification.md) | VERIFIED BY EXTERNAL EVIDENCE | It is not a live forced-redemption fixture and does not establish pre-state completeness. |
| Report JSON is deterministic and schema-1 remains the current contract | `src/report.rs`, `src/cli.rs` | `report_diagnostic_sorting_is_stable`, `deterministic_fixture_reports_have_stable_json` | COVERED BY TEST | Compatibility beyond schema 1 is not promised. |
| Saved-report inspection cannot promote provenance or look verified | `execute_inspect`, `ReportDocument::validate_schema`, `render_human_inspection` | `inspect_preserves_saved_report_classification_without_authenticating_provenance`, `inspect_rejects_unsupported_report_schema`, and the binary-level tests in `tests/inspect_cli.rs` that check real stdout, stderr, and exit codes for genuine, forged-authority, edited-classification, `SUPPORTED_SAFE`, bad-schema, malformed, and JSON reports | TESTED LOCALLY | Inspection is an envelope check, not report authentication. The exit code follows the saved label, and a determined reader can ignore the notice. |
| Input and report-output safeguards are bounded and conservative | `src/cli.rs` | malformed/oversized reader, endpoint, overwrite, concurrent installation, failed installation, and symlink tests | COVERED BY TEST | `--force` needs a trusted output directory, as documented in [CLI](cli.md). |
| Release source is v1.0.0 | annotated tag and GitHub release | [published v1.0.0 release](https://github.com/RevokeTrace/revoketrace/releases/tag/v1.0.0), tag target above | VERIFIED | Source-distributed release; no independently verified binary asset is claimed. |
| Hosted documentation is available | GitHub Pages workflow and site | HTTPS request to `https://revoketrace.github.io/revoketrace/` returned HTTP 200 during this audit | VERIFIED | A Pages deployment does not prove future link availability. |
| Locked build, tests, format, Clippy, audit, and rustdoc pass | repository `Cargo.lock` and toolchain | Local audit run: `cargo fmt --check`, `cargo test --locked` (153 tests), release build, strict Clippy, `cargo audit --deny warnings`, warning-denied rustdoc, and `git diff --check` | TESTED LOCALLY | Local verification is separate from GitHub Actions. |

## Protocol and dependency boundary

The source review is pinned to Stellar Core `05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4`. The crate is locked to `stellar-xdr` 28.0.1 and Rust 1.97.1. The Core pin documents semantics; the XDR crate supplies generated types; tests cover the implemented operation subset. They are different forms of evidence. A newer Core or XDR release needs an explicit compatibility review before support is claimed.

Live mode checks a header-derived protocol version and rejects versions below 18. The release does not assert an open-ended upper protocol range or compatibility with future ledger changes. [Compatibility research](../research/compatibility-matrix.md) preserves the original source-review details.

## Audit findings at the starting baseline

No **BLOCKER** was confirmed in the implementation audit. The correction work below addresses accuracy and traceability gaps; it does not add a new product capability.

| Classification | Finding | Evidence | Consequence and correction |
| --- | --- | --- | --- |
| IMPORTANT FIX | README and changelog called the published v1.0.0 release a candidate; the security policy said private reporting was disabled. | Published release/tag and repository security setting. | Corrected before this document; the release record is now accurately linked and the policy describes the enabled GitHub private-reporting form. |
| IMPORTANT FIX | `inspect` had envelope-only behavior but no direct command-dispatch regression test. | `src/cli.rs` test module. | Corrected with the two inspect tests named above. |
| DOCUMENTATION MISMATCH | Historical research contained time-bound phase, tool, or test-count statements that could be read as current. | The affected research files identify their original dates. | Short current-status notices link readers to the architecture, scope, and evidence index without rewriting historical research. |
| DOCUMENTATION MISMATCH | The repository had no concise current architecture, claims index, or maintenance/release procedure. | Documentation inventory. | Corrected by [architecture](architecture.md), this index, and [maintenance](maintenance.md). |
| KNOWN LIMITATION | Discovery remains bounded and current-tip only; no independently verified live forced-redemption fixture covers every modeled effect. | `src/evidence.rs`, fixtures, and Phase 4C record. | Deliberately retained and stated as a limitation, never a completed capability. |
| NOT APPLICABLE | A backend, indexer, database, dashboard, signing, broadcasting, or separate deployment service. | Project scope and implementation. | These are intentionally absent from this CLI. |

For the scenario-by-scenario test mapping, see [the test matrix](../research/test-matrix.md). For the actual architecture, see [architecture](architecture.md).
