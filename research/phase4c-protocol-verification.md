# Phase 4C: Deterministic Forecasting and Protocol Verification

> **Historical verification notice, 2026-10-27.** The pinned Core citations and fixture provenance below remain important evidence. The phase labels, baseline commit, and test totals record that verification session and are not current release status. See [the verification index](../docs/verification.md), [architecture](../docs/architecture.md), and [scope](../docs/scope.md) for the present implementation boundary and unresolved limits.

**Phase:** Phase 4C
**Date:** 2026-10-27
**Status:** Independent verification pass against stellar-core source and Stellar Testnet
**Pinned Stellar Core Reference:** commit `05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4`
(github.com/stellar/stellar-core) — fetched directly for this phase via
`raw.githubusercontent.com` and the GitHub Git Trees API. Network access to
GitHub and to Horizon Testnet (`horizon-testnet.stellar.org`) was available
during this phase; both were used, and every source citation and fixture
below was independently re-verified against live responses, not reused from
memory or from Phase 4B's prior write-up.
**Protocol references:** CAP-0038, CAP-0033, CAP-0035, CAP-0003.

## 1. Scope and method

This phase does not re-implement reserve/sponsorship accounting (Phase 4B
already did that correctly in most respects — see section 3). Its job is to
independently re-derive the protocol rules from the pinned stellar-core
source, compare them against `src/lib.rs`, `src/discovery.rs`, and
`src/evidence.rs`, fix genuine discrepancies, and document what remains
unverifiable.

Baseline: `main` at `3be3cc9` (PR #5 merged), 117 tests passing
(`cargo test --locked`). After this phase: 129 tests passing (122 after
the initial pass, plus 7 more added by the pool-shares-trust-line-count
evidence-integrity correction below).

## 2. Source files independently fetched for this phase

All of the following were downloaded verbatim from
`https://raw.githubusercontent.com/stellar/stellar-core/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/...`
during this session (not fabricated, not recalled from training data):

- `src/transactions/TrustFlagsOpFrameBase.cpp` / `.h` — shared
  `SetTrustLineFlags`/`AllowTrust` apply logic (`doApply`, `removeOffers`).
- `src/transactions/TransactionUtils.cpp` — `getRevokeID`,
  `removeOffersAndPoolShareTrustLines`, `getPoolWithdrawalAmount`,
  `decrementPoolSharesTrustLineCount`, `decrementLiquidityPoolUseCount`,
  `prefetchPoolShareTrustLinesByAccountAndGetKeys`.
- `src/transactions/SetTrustLineFlagsOpFrame.cpp` / `.h`,
  `src/transactions/AllowTrustOpFrame.cpp` / `.h`.
- `src/transactions/ChangeTrustOpFrame.cpp`,
  `src/transactions/LiquidityPoolWithdrawOpFrame.cpp`,
  `src/transactions/CreateClaimableBalanceOpFrame.cpp`,
  `src/transactions/ClawbackOpFrame.cpp`,
  `src/transactions/SponsorshipUtils.cpp`,
  `src/ledger/TrustLineWrapper.cpp` — supporting context.

The full repository tree at the pinned commit was also listed via the
GitHub Git Trees API to locate the correct file names (e.g.
`TrustFlagsOpFrameBase.cpp`, which is not named after either concrete
operation and would otherwise have been missed).

## 3. Verification matrix

| Protocol rule | stellar-core source (pinned SHA) | RevokeTrace implementation | Verification result |
|---|---|---|---|
| Forced redemption trigger (maintain-liabilities → unauthorized) | `TrustFlagsOpFrameBase.cpp::doApply`: `shouldRemoveOffers = isAuthorizedToMaintainLiabilities(trust) && !isAuthorizedToMaintainLiabilitiesUnsafe(expectedFlagValue)` | `lib.rs::classify_transition` / `maintains_liabilities` (masks only `AUTHORIZED_FLAG \| AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG`) | **Confirmed correct.** Independently re-derived and cross-checked with a real testnet fixture (`independent_testnet_fixture_clawback_only_change_is_not_forced_redemption`) proving a clawback-bit-only change is not misclassified as forced redemption. |
| Canonical pool-share processing order | `TransactionUtils.cpp::prefetchPoolShareTrustLinesByAccountAndGetKeys`: `std::sort(poolTLKeys.begin(), poolTLKeys.end())` over `LedgerKey` (same trustor ⇒ reduces to byte-order of the 32-byte pool ID) | `lib.rs::evaluate`, `affected_pools.sort_by` on decoded 32-byte pool ID | **Confirmed correct.** Existing test `test_deterministic_pool_ordering_observable_difference` already proves canonical byte order (not ASCII hex order) is used. |
| Redemption amount / rounding | `TransactionUtils.cpp::getPoolWithdrawalAmount`: `bigDivideOrThrow(shares, reserve, total, ROUND_DOWN)` (128-bit intermediate, floor) | `lib.rs::forecast_amount`: `u128` intermediate, integer (floor) division | **Confirmed correct.** |
| Issuer-claimant skip / zero-amount skip | `TransactionUtils.cpp` `redeemIntoClaimableBalance` lambda: returns early (no claimable balance, a burn event instead) when `amount == 0` or `isIssuer(accountID, assetInPool)` | `lib.rs::evaluate`: `if amount > 0 && *asset_issuer != pool.owner` | **Confirmed correct.** |
| Clawback flag inheritance on the created claimable balance | `TransactionUtils.cpp`: clawback is set on the new claimable balance iff the trustor's own credit trustline for that constituent asset `isClawbackEnabled()` at the time of redemption (native assets never inherit it) | `lib.rs::evaluate`: looks up the matching `CreditTrustlineState`, requires it to exist, be unambiguous, and not be newer than the snapshot ledger; fails closed (`eval_errors`) otherwise | **Confirmed correct**, and already defended by `test_evaluator_never_assumes_clawback_disabled_when_constituent_evidence_mismatched_or_missing` from Phase 4B. |
| Claimable-balance ID derivation (`ENVELOPE_TYPE_POOL_REVOKE_OP_ID`) | `TransactionUtils.cpp::getRevokeID`: SHA-256 over `HashIDPreimage{type=POOL_REVOKE_OP_ID, revokeID={sourceAccount, seqNum, opNum, liquidityPoolID, asset}}` | `lib.rs::derive_pool_revoke_claimable_balance_id`, using `stellar_xdr::HashIdPreimage::PoolRevokeOpId` directly (the canonical XDR type, not a hand-rolled preimage layout) | **Confirmed correct.** Delegating to the XDR crate's own encoding removes an entire class of hand-transcription bugs. |
| Sponsorship sandwich for the created claimable balance | `TransactionUtils.cpp`: if the pool-share trustline's sponsor is itself sponsored, the claimable balance is created under *that* sponsor's sponsor, not the immediate sponsor | `lib.rs::evaluate`: `active_replacement_sponsor` looked up from `snapshot.sponsorship_handoffs` | **Confirmed correct** for the arithmetic/lookup logic itself. This is *not* a claim that the engine can independently verify a caller-supplied `sponsorship_handoffs` list is complete or accurate — it cannot (see Section 6); `sponsorship_evidence_complete` fails closed to `Inconclusive`/`UnverifiedForecast` whenever that evidence is anything less than fully reconciled, per Phase 4B. |
| Liquidity-pool counter changes (`poolSharesTrustLineCount` → pool entry deletion) | `TransactionUtils.cpp::decrementPoolSharesTrustLineCount`: erases the `LiquidityPoolEntry` once the count reaches 0 | **Gap found and fixed in this phase.** `PoolShareState.pool_shares_trust_line_count` (new, optional) + `PoolRedemptionForecast.pool_will_be_deleted` (new). Returns `None` with an explicit warning when evidence is absent; fails closed (`Inconclusive`) on contradictory evidence (count already 0 while the trustline still exists). | **Fixed.** Phase 4B's forecast omitted this spec-required output entirely. |
| `liquidityPoolUseCount` decrement on constituent credit trustlines | `TransactionUtils.cpp::decrementLiquidityPoolUseCount` | Tracked only as a discovery-completeness check (`liquidity_pool_use_count` must match the number of discovered affected pools) — the *post-operation* decremented value is not forecast | **Documented limitation**, not fixed this phase: this is ledger bookkeeping, not itself a pass/fail condition, and forecasting the exact post-op value would require also forecasting every other pool this account participates in. Left out of scope; not required for the Classification/pass-fail contract. |
| Protocol version gating (`SetTrustLineFlags` requires protocol ≥ 17; pool redemption requires ≥ `V_18`) | `TrustFlagsOpFrameBase.cpp` / `TransactionUtils.cpp`: `protocolVersionStartsFrom(ledgerVersion, ProtocolVersion::V_10\|V_18)` | `lib.rs::validate_snapshot`: rejects `protocol_version < 18` | **Confirmed conservative (not a bug).** RevokeTrace's floor (18) is stricter than core's actual minimum for the operation itself; this is intentional fail-closed behavior, not a discrepancy requiring correction. |
| Trust-to-self rejection | `TrustFlagsOpFrameBase.cpp::doApply`: `SelfNotAllowed` for `AllowTrust` from protocol ≥ 3; explicitly rejected in `doCheckValid` for `SetTrustLineFlags` | `map_allow_trust_result(AllowTrustResultCode::SelfNotAllowed) -> SupportedBlocked` | **Confirmed correct** at the result-code mapping layer (RevokeTrace does not re-implement `doCheckValid`; it classifies the *observed* result code, which is the architecture's documented boundary). |
| CAP-0033 sponsorship/reserve reuse on direct (non-sandwiched) redemption | `TransactionUtils.cpp`: non-sandwich case intentionally allows the claimable balance to reuse the pool-share trustline's exact reserve even if the account is below minimum balance (`createEntryWithPossibleSponsorship` is *not* used in this branch) | `lib.rs::evaluate` / Phase 4B commit `bd407dd` "Correct protocol accounting for direct reserve reuse" | **Confirmed correct**, already covered by `test_target_failure_mode_6_direct_reserve_reuse_succeeds_when_account_below_minimum_balance`. |

## 4. Independent fixtures

### 4.1 Real Stellar Testnet fixture (used in a deterministic comparison test)

- **Network:** Stellar Testnet (`Test SDF Network ; September 2015`)
- **Ledger:** 5417676
- **Transaction hash:** `8856ad8fc4f91d5ad3021e7bbc35f9aedc3977286fa1a07d936e6de49e402d84`
- **Operation:** index 0, `set_trust_line_flags`, source
  `GDEYL6GBXNOB2RRRWOKBFX6EY3K5SFCKTWH43DX5KCNJGHLZSAOK7DAL`, trustor
  `GCTWO2J7M4T7KKQ3UTJ4DFL7AH6ACX45FKW2NPVLMH5CD6L3IWRNVB2B`, asset `SKY`
  (credit_alphanum4), `clear_flags: [clawback_enabled]`
- **Result:** successful (`result_xdr` decodes to
  `SetTrustLineFlagsResultCode::Success`)
- **Source:** retrieved 2026-10-27 directly from Horizon testnet
  (`https://horizon-testnet.stellar.org/operations/23268741240365057` and
  the corresponding `/transactions/<hash>` endpoint). `envelope_xdr` and
  `result_xdr` are embedded verbatim in
  `src/lib.rs::independent_testnet_fixture_clawback_only_change_is_not_forced_redemption`
  and decoded with the project's own `stellar-xdr` crate at test time — not
  hand-transcribed.
- **What it proves:** the real, independently observed result code maps to
  `Classification::UnverifiedForecast` under RevokeTrace's own mapping
  function, and the real `set_flags`/`clear_flags` pair (clawback only)
  does not get classified as a forced pool-share redemption transition.
- **What it does not prove:** this operation did not involve a pool-share
  trustline, a claimable balance, or a sponsorship transition, so it
  exercises only the flag-mapping and transition-classification surfaces,
  not pool redemption amounts, IDs, or sponsorship handoffs. Pre-operation
  ledger state (the trustline's flags immediately before this operation)
  was not independently captured from a ledger export; the `before_flags`
  used in the transition-classification half of the test is an assumption
  stated explicitly in the test, not observed evidence. This is the
  honest boundary of what a single Horizon operation record offers without
  a full `getLedgerEntries`/historical-ledger diff.

### 4.2 Why no pool-redemption / claimable-balance testnet fixture was obtained

A scan of the 500 most recent Testnet operations (two full Horizon pages,
descending from the current tip) found three `set_trust_line_flags`
operations and zero `SetTrustLineFlags` operations that actually triggered
forced liquidity-pool redemption (none of the trustors held pool-share
trustlines in the affected asset at the time). Current Testnet traffic is
dominated by Soroban `invoke_host_function` calls. Locating a genuine,
historical forced-redemption transaction would require either paging much
further back (risking Horizon's retention window) or constructing one live
(creating accounts, a pool, depositing, then revoking) — which this phase
did not attempt, consistent with the project's read-only, no-broadcast
mandate. This is recorded as an honest gap rather than a synthetic
substitute: **no pool-redemption fixture in this repository is claimed to
be real protocol evidence; all pool-redemption test fixtures remain the
synthetic, explicitly-labeled constructions from Phase 4A/4B.**

## 5. Discrepancies found and fixed

1. **Liquidity-pool counter changes were not forecast at all** (Section 3,
   row 8). Fixed by adding `pool_shares_trust_line_count` evidence and
   `pool_will_be_deleted` output, with explicit fail-open-as-unknown
   (warning) when evidence is missing and fail-closed (`Inconclusive`) on
   contradictory evidence. See commit "Forecast liquidity-pool counter
   deletion against verified pool evidence".

2. **The `pool_shares_trust_line_count` extraction itself (the correction
   above) silently downgraded a malformed counter to missing evidence.**
   `src/discovery.rs` and `src/evidence.rs` both decoded the raw XDR
   `i64` with `u32::try_from(...).ok()`, which collapses *any* invalid
   value — negative, or larger than `u32::MAX` — into `None`. Downstream,
   `None` is treated as "evidence not supplied" (an explicit warning,
   `pool_will_be_deleted: None`), not as "evidence is malformed." A
   negative or unrepresentable counter in a ledger entry is not merely
   absent evidence; it is contradictory or corrupt evidence and must be
   rejected outright. Fixed by validating the raw `i64` explicitly before
   conversion in both files and returning `DiscoveryError::ParseError`
   (→ `Classification::Inconclusive`) on failure, instead of swallowing
   the error. A valid nonnegative counter (including `0`, which is
   contradictory only in combination with an existing pool-share
   trustline — see `contradictory_zero_pool_shares_trust_line_count_fails_closed`
   in `src/lib.rs`, unaffected by this fix) is still retained exactly.
   Covered by four new tests in each of `src/discovery.rs` and
   `src/evidence.rs`: negative counter, unrepresentable (> `u32::MAX`)
   counter, positive counter retained exactly, and zero counter retained
   exactly (not collapsed to `None`) when a pool-share trustline exists.

No other genuine discrepancies between the pinned stellar-core source and
the Phase 4B implementation were found during this pass. Every other rule
in the verification matrix above was already implemented correctly.

## 6. What remains unsupported or unverified after this phase

- **`liquidityPoolUseCount` post-operation value** is not forecast (see
  matrix row 9) — only used as a discovery-completeness check.
- **No independently verified fixture exists for forced pool redemption,
  claimable-balance creation, or sponsorship-sandwich behavior on live
  Stellar Testnet or Mainnet.** All such coverage remains synthetic,
  explicitly labeled as such in the test names and fixture files, and is
  not claimed as "real protocol evidence" per the spec's requirement.
- **Multi-operation transaction streams** (earlier operations in the same
  transaction affecting the same account/trustline before the revoke,
  multiple interleaved sponsorship begin/end pairs, multiple revocations
  in one transaction) are still only partially modeled via the
  caller-supplied `sponsorship_handoffs` list; the evaluator has no way to
  independently verify that list reflects the complete operation stream of
  the real transaction. This remains a documented limitation (see
  `docs/scope.md`), not a solved problem — a manually supplied handoff is
  evidence of what the caller asserts, not proof the full transaction is
  valid.
- **`SupportedSafe`** remains unreachable in this codebase; nothing in this
  phase changes that, and nothing should be read as claiming otherwise.
- Full historical ledger-diff verification (pre- and post-operation ledger
  entries for a specific real transaction) was not performed; this would
  require either `stellar-core`/`stellar-rpc` `getTransaction` with full
  meta XDR, or a captive-core replay, neither of which was exercised in
  this phase beyond what Horizon's JSON-level operation/transaction
  endpoints expose.

## 7. Evidence and classification boundary audit

No changes were made to the classification boundaries themselves in this
phase. Re-confirmed by direct code reading (not re-implemented):

- `Classification::SupportedSafe` has zero producing call sites in
  `src/lib.rs`, `src/discovery.rs`, or `src/evidence.rs` — confirmed via
  `grep -n "SupportedSafe" src/*.rs`, which shows only the enum
  declaration and a doc comment.
- `DiscoveryCoverage::CompleteAuthoritativeLedger` is only ever set by
  `AuthoritativeEvidenceAdapter::validate_and_classify` after it has
  independently reconciled sponsorship, trustline, and pool-share evidence
  against ledger entries fetched over RPC — never from caller-supplied
  snapshot fields directly.
- All four new tests added in this phase (`missing_pool_shares_trust_line_count_evidence_leaves_deletion_unforecast`,
  `pool_deletion_is_forecast_deterministically_when_counter_evidence_is_supplied`,
  `pool_survives_redemption_when_other_trustlines_remain`,
  `contradictory_zero_pool_shares_trust_line_count_fails_closed`) exercise
  exactly this boundary for the new field: missing evidence → warning, not
  a guess; contradictory evidence → `Inconclusive`, not a guess.
