# Reserve, Sponsorship, and Operation-Context Audit

**Phase:** Phase 4B  
**Date:** 2026-10-27  
**Status:** Complete Technical Audit & Protocol Gap Analysis  
**Pinned Stellar Core Reference:** Commit `05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4`  
**Protocol References:** [CAP-0038](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0038.md), [CAP-0033](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0033.md), [CAP-0035](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0035.md), [CAP-0003](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0003.md)

---

## 1. Executive Summary

Phase 4A established bounded current-tip ledger evidence, header-derived base reserves, entry sponsorship XDR parsing (`extXdr`), and fail-closed property classifications.
Phase 4B extends this foundation by implementing exact reserve accounting, deterministic sponsorship state transitions, and rigorous operation-context reconstruction for Stellar Classic authorization revocation forecasts.

This audit inspects the merged codebase (`src/lib.rs`, `src/discovery.rs`, `src/evidence.rs`) against official Stellar Core source code and protocol specifications. It identifies what is currently implemented, what is partially modeled, and what is missing across nine critical functional areas before implementing changes.

---

## 2. Systematic Audit of the Existing Implementation

### 2.1 Account Minimum Balances
- **Current State:** Implemented in `minimum_balance(&AccountState, base_reserve: u64)`.
  - Calculates: `units = 2 + subentries + num_sponsoring - num_sponsored`.
  - Minimum balance in stroops: `units * base_reserve`.
  - Checks: `balance_stroops >= minimum_balance + selling_liabilities_stroops`.
- **Gaps & Discrepancies:**
  - `AccountState` lacks `buying_liabilities_stroops`. While selling liabilities lock balance away from being spent, buying liabilities affect offer validity and negative balance checks.
  - Underflow conditions (e.g. `num_sponsored > 2 + subentries + num_sponsoring`) return an error string rather than structured fail-closed classifications.
  - Pre-existing reserve violations: if an account is already below reserve prior to the operation, Stellar Core semantics behave differently for non-sandwich reserve reuse versus sandwich reserve creation.

### 2.2 Subentry and Sponsorship Counters
- **Current State:**
  - Enforces `num_sponsoring + subentries <= UINT32_MAX`.
  - Models `subentries -= 2` per deleted pool-share trustline.
- **Gaps & Discrepancies:**
  - In `src/lib.rs:762-772`, there is an accounting double-counting defect in the previous spike code: when an unsponsored pool-share trustline is in a sponsorship sandwich, `owner_delta.num_sponsoring` was incremented AND `replacement_delta.num_sponsoring` was incremented. Under Stellar Core, only the replacement sponsor sponsors the resulting claimable balance.
  - Counter limits: Stellar Core explicitly requires `numSponsoring + numSubentries + claimable_balances_to_sponsor <= UINT32_MAX` on the sponsor. If exceeded, the operation fails with `opTOO_MANY_SPONSORING`.

### 2.3 Sponsored Trustline Removal
- **Current State:**
  - When `pool.sponsor` is present, `owner.subentries -= 2`, `owner.num_sponsored -= 2`, and `sponsor.num_sponsoring -= 2`.
- **Gaps & Discrepancies:**
  - Stellar Core's `removeOffersAndPoolShareTrustLines` in `TransactionUtils.cpp:1675-1685` deletes pool-share trustlines and frees their reserves *before* instantiating claimable balances.
  - The target credit trustline's `liquidityPoolUseCount` must be decremented for each deleted pool share (`TransactionUtils.cpp:1876-1881`). The credit trustline itself is NOT removed, but its authorization flag is cleared/mutated.
  - Target credit trustline sponsorship: if the credit trustline itself is sponsored, revoking authorization does NOT delete the credit trustline, so its sponsorship remains intact.

### 2.4 Forced Liquidity-Pool Redemption
- **Current State:**
  - Calculates withdrawal amounts using floor division: `amount = floor(shares * reserve / total_shares)`.
- **Gaps & Discrepancies:**
  - **Deterministic Iteration Order:** In `TransactionUtils.cpp:98`, Stellar Core explicitly sorts candidate pool-share keys using `std::sort(poolTLKeys.begin(), poolTLKeys.end())`. Because hash-map iteration is non-deterministic across platforms, RevokeTrace must enforce canonical lexicographical sorting by pool ID / ledger key before processing redemptions.
  - When all pool shares are redeemed and `total_pool_shares` drops to 0, or `poolSharesTrustLineCount` drops to 0, Stellar Core erases the `LiquidityPoolEntry` (`decrementPoolSharesTrustLineCount`, `TransactionUtils.cpp:1850-1865`).

### 2.5 Claimable-Balance Creation
- **Current State:**
  - Creates a `ClaimableBalanceForecast` for each nonzero constituent asset where `owner != issuer`.
- **Gaps & Discrepancies:**
  - **Clawback Flag Inheritance (CAP-0035):** In `TransactionUtils.cpp:1718-1730`, if the withdrawn asset is not native, Core checks whether clawback is enabled on the constituent asset trustline (`assetTrustLine.isClawbackEnabled()`). If enabled, the created claimable balance must have `CLAIMABLE_BALANCE_FLAG_CLAWBACK_ENABLED` set. The current engine completely omits this flag.
  - **Claimant Predicate:** Unconditionally claimable by the trustor (`ClaimantType::ClaimantTypeV0`).

### 2.6 Claimable-Balance Sponsorship and Reserves
- **Current State:**
  - Partially assigns sponsor based on `SponsorshipHandoff`.
- **Gaps & Discrepancies:**
  - In Stellar Core, the sponsor of each claimable balance is determined by `getTrustLineBacker`:
    1. If `poolTL` had an explicit sponsor $S$, `cbSponsoringAcc = S`.
    2. If `poolTL` was unsponsored, `cbSponsoringAcc = trustor`.
  - Next, Core checks whether `cbSponsoringAcc` is in an active sponsorship sandwich (`loadSponsorship(ltxInner, cbSponsoringAcc)`):
    - **Case A: In a Sponsorship Sandwich (Replacement Sponsor $C$):**
      Claimable balance is sponsored by $C$. Core calls `createEntryWithPossibleSponsorship`. Because $C$ did not hold the deleted pool-share trustline, $C$ must have sufficient available balance (`balance >= min_balance + selling_liabilities`) and counter capacity (`numSponsoring + subentries < UINT32_MAX`). If $C$ lacks balance, Core returns `LOW_RESERVE` (failing the op with `SET_TRUST_LINE_FLAGS_LOW_RESERVE` or `ALLOW_TRUST_LOW_RESERVE`).
    - **Case B: Not in a Sponsorship Sandwich:**
      `cbSponsoringAcc` sponsors the claimable balance directly. Core calls `establishEntrySponsorship` without `createEntryWithPossibleSponsorship`, explicitly allowing the claimable balance to reuse the reserve freed by the deleted pool-share trustline (even if the account was below minimum balance due to an earlier base-reserve increase).
  - Current RevokeTrace does not model this critical distinction between sandwich and non-sandwich reserve reuse.

### 2.7 Buying and Selling Liabilities
- **Current State:**
  - Selling liabilities are checked: `balance >= minimum_balance + selling_liabilities`.
  - Buying liabilities are omitted.
- **Gaps & Discrepancies:**
  - Under CAP-0003, buying liabilities represent native balance promised to buy offers. They cannot be used to satisfy reserve requirements.
  - Negative liabilities must be detected and rejected as `Inconclusive`.
  - Selling liabilities must be preserved when evaluating post-operation account solvency.

### 2.8 Operation Source and Transaction Sequence
- **Current State:**
  - `derive_pool_revoke_claimable_balance_id` implements `HashIdPreimageRevokeId`.
- **Gaps & Discrepancies:**
  - `OperationSpec` currently conflates transaction source and operation source:
    `HashIdPreimageRevokeId` requires `txSourceAccount`, `seqNum`, and `opNum`.
    In Stellar transactions:
    - An operation can specify an optional `sourceAccount`. For `SetTrustLineFlagsOp` or `AllowTrustOp`, the operation source account must be the asset issuer.
    - The transaction envelope has its own `sourceAccount` (the fee source and sequence source) and `seqNum`.
    - `opNum` is the 0-indexed position of the operation within the transaction.
  - When transaction source, sequence number, or operation index are omitted or unknown:
    The engine must NOT fabricate an ID. It must output `claimable_balance_id: None` (uncomputed) while still computing exact withdrawal amounts and reserve deltas.

### 2.9 Sponsorship Begin/End Ordering
- **Current State:**
  - Validates `begin_operation_index < revoke_operation_index < end_operation_index`.
- **Gaps & Discrepancies:**
  - Does not model the full transaction operation stream.
  - Does not verify that `BeginSponsoringFutureReservesOp` has a matching `EndSponsoringFutureReservesOp` within the same transaction.
  - Does not verify that the sponsored account in `BeginSponsoringFutureReservesOp` matches the backer of the pool-share trustline.
  - Does not detect nested or conflicting sponsorship sandwiches.

---

## 3. Stellar Core Implementation Blueprint

| Core Function | File & Lines | Exact Behavior |
| :--- | :--- | :--- |
| `removeOffersAndPoolShareTrustLines` | `TransactionUtils.cpp:1624-1840` | Gated $\ge$ Protocol 18. Calls DEX offer removal, prefetches pool trustlines, sorts keys deterministically, iterates pools, releases trustline reserves, redeems into claimable balances, decrements `liquidityPoolUseCount`. |
| `prefetchPoolShareTrustLinesByAccountAndGetKeys` | `TransactionUtils.cpp:70-103` | Loads matching pool trustlines from live bucket index; executes `std::sort(poolTLKeys.begin(), poolTLKeys.end())`. |
| `getTrustLineBacker` | `TransactionUtils.cpp:32-42` | Returns `ext.v1().sponsoringID` if present; otherwise returns `accountID`. |
| `redeemIntoClaimableBalance` | `TransactionUtils.cpp:1690-1790` | Skips if amount is 0 or owner is issuer. Derives revoke ID. Sets clawback flag if enabled on asset trustline. Calls `createEntryWithPossibleSponsorship` if in sandwich; otherwise reuses freed reserve directly via `establishEntrySponsorship`. |
| `decrementLiquidityPoolUseCount` | `TransactionUtils.cpp:1870-1890` | Decrements `liquidityPoolUseCount` on non-native, non-issuer asset trustlines. Throws if count becomes negative. |
| `decrementPoolSharesTrustLineCount` | `TransactionUtils.cpp:1850-1868` | Decrements `poolSharesTrustLineCount` on `LiquidityPoolEntry`. If 0, erases the pool entry. |

---

## 4. Phase 4B Implementation Plan

1. **Enhanced Operation & Transaction Context Models (`src/lib.rs`):**
   - Introduce `TransactionContext` containing `tx_source_account`, `sequence_number`, `operations`, and `active_sponsorship_context`.
   - Distinguish transaction source from operation source.
   - Support `claimable_balance_id: Option<String>` to cleanly represent unknown versus computed IDs.
2. **Exact Checked Reserve & Solvency Calculations:**
   - Incorporate buying and selling liabilities.
   - Enforce checked arithmetic for all deltas and bounds (`UINT32_MAX` sponsorship limits).
3. **Deterministic Sponsorship State Engine:**
   - Implement `get_trustline_backer`.
   - Implement sandwich vs non-sandwich reserve reuse rules.
   - Fail closed with `SupportedBlocked` (`SET_TRUST_LINE_FLAGS_LOW_RESERVE` / `opTOO_MANY_SPONSORING`) when sandwich sponsor lacks reserves.
4. **Clawback Flag Modeling:**
   - Check constituent asset trustline clawback flag and propagate to `ClaimableBalanceForecast`.
5. **Deterministic Pool Key Ordering:**
   - Sort affected pools canonically prior to redemption.
   - Match Stellar Core `std::sort` behavior.
6. **Comprehensive Negative & Edge-Case Test Suite:**
   - Implement tests covering all 17 target failure modes specified in the requirements.

---

## 5. Protocol Verification and Accounting Rule Mapping

The following table records the protocol verification for each accounting rule implemented in Phase 4B:

### Rule 1: Account Minimum Balance and Liabilities
- **Protocol Source:** Stellar Core `AccountEntry.cpp`, CAP-0003, CAP-0033.
- **Applicable Protocol Version:** $\ge 14$ (sponsorship), $\ge 18$ (CAP-0038).
- **Input Requirements:** `subentries: u32`, `num_sponsoring: u32`, `num_sponsored: u32`, `base_reserve_stroops: u64`, `balance_stroops: i64`, `selling_liabilities_stroops: i64`, `buying_liabilities_stroops: i64`.
- **State Transition:**
  - $\text{units} = 2 + \text{subentries} + \text{num\_sponsoring} - \text{num\_sponsored}$.
  - $\text{min\_balance} = \text{units} \times \text{base\_reserve}$.
  - Post-operation solvency check: $\text{balance} \ge \text{min\_balance} + \text{selling\_liabilities}$.
- **Failure Conditions:**
  - Counter underflow/overflow: fails closed as `Classification::Inconclusive`.
  - Selling liabilities exceed balance: fails closed as `Classification::Inconclusive`.
  - Buying liabilities + balance exceeds `i64::MAX`: fails closed as `Classification::Inconclusive`.
  - Post-operation balance below required minimum balance: fails closed as `Classification::SupportedBlocked` (`SET_TRUST_LINE_FLAGS_LOW_RESERVE`).
- **Tests Proving Implementation:**
  - `test_target_failure_mode_6_insufficient_minimum_balance_on_trustor`
  - `test_target_failure_mode_7_invalid_sponsorship_counters`
  - `test_target_failure_mode_9_buying_and_selling_liabilities`
  - `test_target_failure_mode_10_integer_overflow_and_underflow`

### Rule 2: Sponsored Pool-Share Trustline Removal
- **Protocol Source:** Stellar Core `TransactionUtils.cpp:1675-1685` (`removeOffersAndPoolShareTrustLines`), CAP-0038, CAP-0033.
- **Applicable Protocol Version:** $\ge 18$.
- **Input Requirements:** `PoolShareTrustlineState` (with optional `sponsor`), owner `AccountState`, sponsor `AccountState` (if sponsored).
- **State Transition:**
  - If unsponsored: owner `subentries -= 2`.
  - If sponsored: owner `subentries -= 2`, owner `num_sponsored -= 2`, sponsor `num_sponsoring -= 2`.
  - Target credit trustline `liquidityPoolUseCount` decrements by 1.
- **Failure Conditions:**
  - Missing sponsor account in snapshot: fails closed as `Classification::Inconclusive`.
  - Sponsor counter does not account for two-reserve trustline: fails closed as `Classification::Inconclusive`.
- **Tests Proving Implementation:**
  - `test_target_failure_mode_1_unsponsored_redemption`
  - `test_target_failure_mode_2_sponsored_pool_share_trustline_removal`
  - `test_target_failure_mode_8_missing_sponsor_account`

### Rule 3: Forced Liquidity Pool Redemption
- **Protocol Source:** Stellar Core `TransactionUtils.cpp:1690-1790`, CAP-0038 (`redeemIntoClaimableBalance`, `decrementPoolSharesTrustLineCount`).
- **Applicable Protocol Version:** $\ge 18$.
- **Input Requirements:** `LiquidityPoolEntry`, owner pool shares, total pool shares, constituent asset reserves.
- **State Transition:**
  - Integer redemption via floor division: $\text{amount} = \lfloor \text{shares} \times \text{reserve} / \text{total\_shares} \rfloor$.
  - Pool share count and pool entries updated deterministically.
- **Failure Conditions:**
  - Total pool shares is zero: fails closed as `Classification::Inconclusive`.
  - Reserve multiplication overflow: fails closed as `Classification::Inconclusive`.
- **Tests Proving Implementation:**
  - `test_target_failure_mode_1_unsponsored_redemption`
  - `test_target_failure_mode_4_multiple_affected_pools_deterministic_accumulation`
  - `exact_integer_redemption_uses_floor`

### Rule 4: Claimable Balance Creation & Clawback Flag Inheritance
- **Protocol Source:** Stellar Core `TransactionUtils.cpp:1718-1730`, CAP-0035, CAP-0038.
- **Applicable Protocol Version:** $\ge 18$.
- **Input Requirements:** Constituent redemption amount $> 0$, asset issuer $\ne$ owner, constituent asset trustline flags.
- **State Transition:**
  - Creates a claimable balance for each non-issuer constituent asset with non-zero payout.
  - If constituent asset trustline has `TRUSTLINE_CLAWBACK_ENABLED_FLAG`, sets `clawback_flag_enabled: true` on the created claimable balance forecast.
- **Failure Conditions:**
  - Contradictory constituent assets or incomplete asset identity: fails closed as `Classification::Inconclusive`.
- **Tests Proving Implementation:**
  - `test_clawback_flag_propagation`
  - `test_target_failure_mode_1_unsponsored_redemption`

### Rule 5: Claimable Balance Sponsorship and Reserve Reuse
- **Protocol Source:** Stellar Core `TransactionUtils.cpp:1735-1785`, CAP-0038, CAP-0033.
- **Applicable Protocol Version:** $\ge 18$.
- **Input Requirements:** Pool-share backer (`pool.sponsor.unwrap_or(pool.owner)`), active `SponsorshipHandoff` entries.
- **State Transition:**
  - **Non-Sandwich (Direct Sponsorship):** Backer sponsors CB directly via `establishEntrySponsorship`. Reuses freed reserves from deleted pool share without requiring surplus balance above minimum balance. Backer `num_sponsoring += num_cb` (if trustor, net subentry change $-2 + 2$ balances out).
  - **Sandwich (Replacement Sponsor):** Replacement sponsor $C$ sponsors CB via `createEntryWithPossibleSponsorship`. $C$ did not hold the deleted pool share, so $C$ must have sufficient balance ($\text{balance} \ge \text{min\_balance} + \text{selling\_liabilities}$) and counter headroom ($\text{num\_sponsoring} + \text{subentries} + \text{num\_cb} \le \text{UINT32\_MAX}$). $C.\text{num\_sponsoring} += \text{num\_cb}$.
- **Failure Conditions:**
  - Sandwich sponsor has insufficient balance: fails closed as `Classification::SupportedBlocked` (`SET_TRUST_LINE_FLAGS_LOW_RESERVE`).
  - Counter limit exceeded: fails closed as `Classification::SupportedBlocked` (`opTOO_MANY_SPONSORING`).
- **Tests Proving Implementation:**
  - `test_target_failure_mode_3_sponsored_claimable_balance_creation_in_sandwich`
  - `test_target_failure_mode_5_sponsor_reserve_exhaustion`
  - `active_sponsorship_handoff_can_block_on_low_reserve`

### Rule 6: Deterministic Pool Iteration Ordering
- **Protocol Source:** Stellar Core `TransactionUtils.cpp:98` (`std::sort(poolTLKeys.begin(), poolTLKeys.end())`).
- **Applicable Protocol Version:** $\ge 18$.
- **Input Requirements:** Multiple affected pool-share trustlines.
- **State Transition:** Candidate pools sorted canonically by `pool_id` (Stellar Core ledger key order) before redemption and counter delta accumulation.
- **Failure Conditions:** Platform-dependent iteration order discrepancies.
- **Tests Proving Implementation:**
  - `test_target_failure_mode_4_multiple_affected_pools_deterministic_accumulation`

### Rule 7: Operation Context Reconstruction & Revoke ID Derivation
- **Protocol Source:** Stellar Core CAP-0038 Section "Claimable Balance ID", `HashIdPreimageRevokeId`.
- **Applicable Protocol Version:** $\ge 18$.
- **Input Requirements:** `tx_source_account`, `sequence`, `operation_index`, `pool_id`, constituent asset.
- **State Transition:**
  - When all context fields are present: derives exact 32-byte SHA-256 hash ID via `derive_pool_revoke_claimable_balance_id`.
  - When any context field is missing: outputs `claimable_balance_id: None` with an explicit warning, maintaining exact counter and amount accounting without fabricating IDs.
- **Failure Conditions:**
  - Operation source is not asset issuer: fails closed as `Classification::Inconclusive`.
  - Trustor equals operation source: fails closed as `Classification::Inconclusive`.
  - Transaction source account missing from snapshot: fails closed as `Classification::Inconclusive`.
  - Missing operation index when sponsorship handoffs exist: fails closed as `Classification::Inconclusive`.
- **Tests Proving Implementation:**
  - `test_target_failure_mode_11_missing_transaction_sequence`
  - `test_target_failure_mode_12_missing_operation_index`
  - `test_target_failure_mode_17_conflicting_operation_context`
  - `derives_cap0038_pool_revoke_id_from_xdr_preimage`

### Rule 8: Sponsorship Sandwich Ordering & Validation
- **Protocol Source:** Stellar Core `BeginSponsoringFutureReservesOpFrame.cpp`, `EndSponsoringFutureReservesOpFrame.cpp`, CAP-0033.
- **Applicable Protocol Version:** $\ge 14$.
- **Input Requirements:** `begin_operation_index`, `revoke_operation_index`, `end_operation_index`.
- **State Transition:** Verifies strict ordering: `begin < revoke < end`. Confirms non-nested single handoff per target account.
- **Failure Conditions:**
  - Missing end operation index (unclosed sandwich): fails closed as `Classification::Inconclusive`.
  - Begin index $\ge$ revoke index: fails closed as `Classification::Inconclusive`.
  - End index $\le$ revoke index: fails closed as `Classification::Inconclusive`.
  - Conflicting handoffs for the same target account: fails closed as `Classification::Inconclusive`.
- **Tests Proving Implementation:**
  - `test_target_failure_mode_13_sponsorship_begin_end_ordering`

### Rule 9: Protocol Version Gating
- **Protocol Source:** Stellar Core `TransactionUtils.cpp:1624`.
- **Applicable Protocol Version:** $\ge 18$.
- **Input Requirements:** Header-derived `protocol_version: Option<u32>`.
- **State Transition:** Protocol version $< 18$ fails before evaluating CAP-0038 pool redemptions.
- **Failure Conditions:**
  - Protocol version $< 18$: returns `Classification::Unsupported`.
- **Tests Proving Implementation:**
  - `test_target_failure_mode_14_unsupported_protocol_version`

### Rule 10: Evidence Coherence and Discovery Completeness
- **Protocol Source:** CAP-0038 `liquidityPoolUseCount`, RevokeTrace trust model.
- **Applicable Protocol Version:** $\ge 18$.
- **Input Requirements:** Snapshot ledger sequence, entries ledger sequence, entry last modified sequences, `liquidityPoolUseCount`.
- **State Transition:** Requires exact ledger sequence alignment and complete discovery coverage reconciliation.
- **Failure Conditions:**
  - `entries_ledger_sequence != ledger_sequence`: fails closed as `Classification::Inconclusive`.
  - Any ledger entry `last_modified_ledger_seq > ledger_sequence`: fails closed as `Classification::Inconclusive`.
  - Target credit trustline `liquidityPoolUseCount != discovered_affected_pools.len()`: fails closed as `Classification::Inconclusive`.
- **Tests Proving Implementation:**
  - `test_target_failure_mode_15_mixed_ledger_evidence`
  - `test_target_failure_mode_16_incomplete_discovery`

---

## 6. Safety Boundaries, Blockers, and Phase 4C Readiness

### 6.1 Safety Invariants Maintained
- `SupportedSafe` remains strictly unreachable. No code path produces a safe forecast without independent full-ledger capture verification.
- `CompleteAuthoritativeLedger` remains strictly unreachable for caller-supplied snapshots.
- Missing or contradictory evidence fails closed as `Classification::Inconclusive`.
- Known reserve exhaustion fails closed as `Classification::SupportedBlocked`.
- No signing, broadcasting, key storage, indexing, or external paid infrastructure.

### 6.2 Remaining Blockers & Next Phase
- Phase 4B implements exact reserve, sponsorship, and operation-context modeling, backed by 101 unit tests and verified against official Stellar Core source code.
- Phase 4C (CLI and reporting interface) cannot begin until Phase 4B has been reviewed and merged into `main`.
