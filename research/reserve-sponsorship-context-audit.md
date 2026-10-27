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
6. **Comprehensive Negative & Edge-Case Test Suite:**
   - Implement tests covering all 17 target failure modes specified in the requirements.
