# Ledger Consistency Models and Point-in-Time Guarantees

**Phase:** Phase 1C (Discovery Source and Ledger Consistency)  
**Date:** 2026-10-27  
**Status:** Research-only feasibility evidence  

---

## 1. The Challenge of Ledger Consistency in Stellar Classic Preflight

Evaluating a proposed issuer revocation requires reading multiple interrelated ledger entries:
1. Target account (`AccountEntry`)
2. Asset issuer account (`AccountEntry`)
3. Target credit trustline (`TrustLineEntry` + `TrustLineEntryExtensionV2`)
4. Pool-share trustlines (`TrustLineEntry` for each affected pool share)
5. Liquidity pool parameters (`LiquidityPoolEntry` for each constant-product pool)

If these entries are read across different ledger sequences, the evaluation is subject to **phantom reads, torn state, and invalid reserve calculations**.

This document investigates the four ledger consistency models and defines the bounded consistency evidence demonstrated by RevokeTrace. It does not certify complete discovery or complete reserve/sponsorship preflight readiness.

---

## 2. Investigation of Consistency Approaches

### Approach 1: Bounded Current-Tip Single-Batch Evidence (DEMONSTRATED)
- **Mechanism:** Submit all required `LedgerKey`s (target trustor, issuer, credit trustline, all candidate pool-share trustlines, and all candidate pool entries) in a **single atomic request** to Stellar RPC `getLedgerEntries`.
- **Underlying Engine Guarantee:** Soroban RPC is backed by an internal Captive Core instance. When `getLedgerEntries` is invoked, Captive Core executes the query against a single locked read snapshot of the ledger at its current close tip (`latestLedger`).
- **Atomicity boundary:** The response is treated as one current-tip read, and the prototype additionally requires exact requested-key coverage, decoded identity/type matches, and `lastModifiedLedgerSeq <= latestLedger`. This does not establish historical completeness or sponsorship/base-reserve completeness.
- **Bound:** Up to 200 ledger keys can be queried atomically in one request. For an issuer revocation preflight, a typical account holds 0 to a few dozen pool shares (bounded by the account's subentry limit, maximum 1,000 subentries on Stellar Classic). A single batch accommodates all keys for $>99.9\%$ of accounts.

### Approach 2: Historical Point-in-Time Ledger Export (UNSUPPORTED OVER PUBLIC APIS)
- **Question:** Can RevokeTrace query entries as they existed at an arbitrary historical ledger $L < \text{tip}$ using public endpoints?
- **Finding:** **NO.**
  1. Stellar RPC `getLedgerEntries` silently ignores the `ledger` parameter.
  2. Public Horizon instances retain historical transaction execution results, but `/accounts/{id}` only reflects current ingested state.
  3. `lastModifiedLedgerSeq <= L` is **not** a proof of state at ledger $L$:
     - **False Absence:** If a pool-share trustline existed at ledger $L$ but was deleted or redeemed at ledger $M$ ($L < M \le \text{tip}$), querying the tip returns `null` (not found). RevokeTrace would falsely conclude the pool share never existed at ledger $L$.
     - **Torn State:** If an entry was modified at ledger $M > L$, querying the tip returns the post-$M$ state, which may have different balances, flags, or reserve requirements.
- **Verdict:** Point-in-time historical discovery without external trust requires running a local Captive Core or parsing raw History Archive BucketList dumps. It is **unproven** on public endpoints.

### Approach 3: Verifiable Indexed Checkpoint (PARTIALLY PLAUSIBLE, LATENCY-CONSTRAINED)
- History Archives publish complete cryptographic BucketList checkpoints every 64 ledgers (sequences $63, 127, 191, \dots$).
- While cryptographically authoritative, this approach introduces:
  1. Checkpoint latency of up to 5 minutes (up to 64 ledgers behind current consensus).
  2. Multi-gigabyte download and decompression requirements.
  3. Complexity that makes it unsuitable for an interactive CLI preflight utility.

### Approach 4: Cross-Endpoint Drift and Eventual Consistency
- If Horizon is queried at timestamp $t_1$ and Stellar RPC is queried at timestamp $t_2$:
  - Stellar ledgers close every $\approx 5$ seconds.
  - Horizon might be at ledger $L_{\text{hz}}$, while Stellar RPC is at ledger $L_{\text{rpc}}$ ($L_{\text{hz}} \ne L_{\text{rpc}}$).
- **Resolution in RevokeTrace:**
  - Horizon is **only** used to seed candidate pool IDs. Horizon's state balances, sequence numbers, and flags are **completely discarded**.
  - All identity-bearing, state-bearing, and reserve-bearing data are fetched afresh in the single RPC batch at $L_{\text{rpc}}$.
  - The counter invariant $K == N$ verifies whether the candidate seed from Horizon matches the on-chain reality at $L_{\text{rpc}}$.

---

## 3. Formal Invariant: Counter as a Bounded Candidate-Set Check

Let:
- $T$ be the target credit trustline on-chain at ledger $L_{\text{rpc}}$.
- $N = T.\text{liquidityPoolUseCount}$ be the authoritative counter maintained by Stellar Core.
- $\mathcal{C}_{\text{hz}} = \{P_1, P_2, \dots, P_K\}$ be the candidate pool IDs returned by Horizon for trustor $A$.
- $\mathcal{P}_{\text{rpc}}$ be the set of distinct pool entries returned in the atomic RPC batch at ledger $L_{\text{rpc}}$ such that:
  1. Cryptographic ID matches: $\text{derive\_constant\_product\_pool\_id}(P_i.\text{params}) == P_i$.
  2. Asset matches: $P_i$ pairs $(A_{\text{code}}, A_{\text{issuer}})$.
  3. Trustor ownership matches: Trustor $A$ holds a `TrustLineEntry` for $P_i$ with `shares > 0`.

### Bounded conclusion:
$$\text{If } |\mathcal{P}_{\text{rpc}}| == N \text{ and all supplied entries are validated in one batch at } L_{\text{rpc}},$$
$$\text{then the supplied candidate set reconciles with the target counter at } L_{\text{rpc}}.$$ 

This is not a general completeness theorem: an external omission before the RPC request cannot
be detected merely because the returned subset is internally consistent. The prototype therefore
does not issue a complete reserve/sponsorship preflight verdict.

### Failure Modes and Fail-Closed Behavior:

| Anomaly / Adversarial Condition | Horizon / Candidate Output | RPC Batch Observation | Reconciliation Result | RevokeTrace Safety Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **Horizon Omission (Lag / Drop)** | Misses 1 pool ($K = N - 1$) | Batch has $N - 1$ pools | $K < N$ mismatch | **Fail Closed (`Inconclusive`)** |
| **Horizon Stale Addition** | Returns deleted pool | RPC returns null for deleted pool | Key not found / $K \ne N$ | **Fail Closed (`Inconclusive`)** |
| **Spurious Pool (Wrong Asset)** | Returns pool pairing other asset | Filtered out by asset check | $|\mathcal{P}_{\text{rpc}}| < N$ mismatch | **Fail Closed (`Inconclusive`)** |
| **Duplicate Candidate IDs** | Returns duplicate pool IDs | Detected by duplicate check | Duplicate rejected | **Fail Closed (`Inconclusive`)** |
| **Modified / Newer Ledger** | Pool updated at $L > L_{\text{rpc}}$ | `lastModified > latestLedger` | Sequence mismatch | **Fail Closed (`Inconclusive`)** |
| **Zero Affected Pools** | Account has no pool shares ($K = 0$) | $T.\text{liquidityPoolUseCount} == 0$ | $0 == 0$ matches | **Clean No-Effect Transition** |

---

## 4. Summary of Demonstrated vs. Unproven Consistency

1. **Demonstrated:**
   - Bounded current-tip response validation across target credit trustline, pool trustlines, and pool entries.
   - Rejection of many observed Horizon/RPC inconsistencies, including omissions in the supplied key set, wrong identities, and counter mismatch.
2. **Unproven / Unsupported:**
   - Historical point-in-time consistency at an arbitrary past ledger $L < \text{tip}$ without running a local Captive Core instance.
3. **Safety Classification Implication:**
   - Because point-in-time historical discovery, base-reserve configuration, and sponsorship evidence remain incomplete, the output is research-only and cannot be a complete safety preflight. `SupportedSafe` remains unreachable.
   - `SupportedSafe` remains unreachable until an authoritative capture adapter (e.g. native Captive Core streaming) is integrated in a future phase.
