# Discovery Feasibility Evaluation: Stored Network-Response Fixture & Live RPC Constraints

Research date: 2026-10-27.  
Scope: Methodological evaluation of pool-share discovery feasibility, distinguishing stored network-response fixtures, live network queries, and offline preflight forecasting.

---

## 1. Nature of the Demonstrated Evidence

To prevent any ambiguity, the evidence in this repository is strictly categorized as follows:

| Category | Actual Evidence in Repository | Boundary / Limitation |
| --- | --- | --- |
| **Live Network Observations** | Explicit curl / JSON-RPC queries executed against `https://soroban-testnet.stellar.org`. | Can observe live state at current tip only (`latestLedger`); cannot query arbitrary historical ledgers. |
| **Stored Network-Response Fixtures** | [`fixtures/live-testnet-discovery.json`](../fixtures/live-testnet-discovery.json). | Snapshot of actual XDR responses captured from Testnet at ledger 5413920, replayed offline. |
| **Synthetic Test Fixtures** | Existing unit fixtures in `fixtures/cap0038/`. | Hand-crafted models of edge cases (reserve arithmetic, sponsorship ordering). |
| **Proposed Revocation Forecasts** | `evaluate(&op, &snapshot)` in `src/lib.rs`. | **Offline preflight calculation only**. No transaction was signed, broadcast, or submitted to the Stellar network. |
| **Actually Executed Transactions** | **None**. | No private keys or network mutation. No revocation transaction hash exists or is claimed. |
| **Completeness Status** | **PLAUSIBLE BUT UNPROVEN**. | Mathematical proof holds for consistent snapshots; live historical completeness is unproven on public RPC. |

---

## 2. Demonstrated Scenario: Stellar Testnet Recorded State

The recorded network-response fixture captures a real multi-pool trustor state from Stellar Testnet:

### Recorded Pre-State Identifiers
- **Network**: Stellar Testnet (`Test SDF Network ; September 2015`)
- **Captured Ledger Sequence**: `5413920`
- **Trustor Account**: `GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB`
- **Asset Code**: `FLUTTER`
- **Asset Issuer**: `GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG`
- **Asset Type**: `credit_alphanum12` (XDR `AssetCode12(b"FLUTTER\0\0\0\0\0")`)
- **Captured Invariant**: `TrustLineEntry.ext.v1.ext.v2.liquidity_pool_use_count == 2`

### Recorded Affected Pools (2 distinct pools)
1. **Pool 1**: `00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46`
   - Constituent Asset A: `SDK:GA5Q3FBUPYK4T3BQDILVTDFN2TCLLNBDYABMFZRXTE2BLXP5CZXOQFWM`
   - Constituent Asset B: `FLUTTER:GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG`
   - Fee: 30 bps (0.3%)
   - Trustor Pool Shares Balance: `600,000,000` stroops (`60.0000000` shares)
   - Pool Reserves: Reserve A = `700,000,000` stroops, Reserve B = `514,506,217` stroops
   - Total Pool Shares: `600,000,000` stroops
2. **Pool 2**: `078ff7f339a3a1c950812bd143431498f880082e0ebdb95fb348a5b87693465c`
   - Constituent Asset A: `native` (XLM)
   - Constituent Asset B: `FLUTTER:GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG`
   - Fee: 30 bps (0.3%)
   - Trustor Pool Shares Balance: `4,980,000,000` stroops (`498.0000000` shares)
   - Pool Reserves: Reserve A = `4,980,000,000` stroops, Reserve B = `4,980,000,000` stroops
   - Total Pool Shares: `4,980,000,000` stroops

---

## 3. Live RPC Observations & Consistency Limitations

### 3.1 Live Network Verification Command
The target entries can be observed in real time on Stellar Testnet:
```bash
curl -s -X POST https://soroban-testnet.stellar.org \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getLedgerEntries",
    "params": {
      "keys": [
        "AAAAAQAAAAAe7Ld2ci6ZEYafG+wIq/EksRc5HBSsC3ZQc0ne0Qd4cgAAAAJGTFVUVEVSAAAAAAAAAAAAcEtPmLg7BL0jwUklenrbkmoXI5nAU9MtLXK7Mck3EOk=",
        "AAAAAQAAAAAe7Ld2ci6ZEYafG+wIq/EksRc5HBSsC3ZQc0ne0Qd4cgAAAAMAFx/+AvET6yhsT+BkLOufG1COCcYWA3SiK7mrQkCtRg==",
        "AAAAAQAAAAAe7Ld2ci6ZEYafG+wIq/EksRc5HBSsC3ZQc0ne0Qd4cgAAAAMHj/fzOaOhyVCBK9FDQxSY+IAILg69uV+zSKW4dpNGXA==",
        "AAAABQAXH/4C8RPrKGxP4GQs658bUI4JxhYDdKIruatCQK1G",
        "AAAABQeP9/M5o6HJUIEr0UNDFJj4gAguDr25X7NIpbh2k0Zc"
      ]
    }
  }'
```

### 3.2 Observed Network Limitations
1. **Tip-Only Responses**: The live RPC returns the current head sequence (e.g. `latestLedger: 5414248`), confirming that the endpoint ignores historical ledger parameters.
2. **`lastModifiedLedgerSeq <= L` Does Not Prove State at $L$**:
   Observing `lastModifiedLedgerSeq == 2518476` at tip ledger 5414248 demonstrates that the entry has not changed since ledger 2518476, but this does NOT generalize to arbitrary historical ledger state across arbitrary accounts:
   - If an entry was modified or deleted at ledger $M > L$, a live tip query cannot retrieve its value as of $L$.
   - Live RPC queries across multiple network roundtrips can read across ledger boundaries, violating snapshot atomicity.
3. **No Blind Enumeration**:
   Stellar RPC requires all 5 keys to be provided upfront. If an indexer or caller fails to supply one of the keys, RPC has no mechanism to alert the caller that an unqueried pool exists.

---

## 4. Stored Discovery Manifest & Verification Assertions

The stored discovery manifest is derived canonically:
```text
Test SDF Network ; September 2015
5413920
00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46
078ff7f339a3a1c950812bd143431498f880082e0ebdb95fb348a5b87693465c
```
Manifest SHA-256 Digest:
`fe73e23f1769045ae984f21ad44b0af2c4e44951cb56aed2ca890d22407b5380`

### Mandatory Executable Checks (Enforced in Code)
- **Manifest Hash Assertion**: `assert_eq!(manifest_hash, expected)`
- **Target Ledger Consistency**: `assert_eq!(snapshot.ledger_sequence, target_ledger)`
- **Exact Cryptographic Derivation**:
  `derive_constant_product_pool_id(sdk, flutter, 30) == pool1_id`
  `derive_constant_product_pool_id(native, flutter, 30) == pool2_id`
- **Cardinality Equality**:
  `assert_eq!(discovered_pools.len(), target_tl.liquidity_pool_use_count.unwrap())`

---

## 5. Refusal Invariants & Fail-Closed Behavior

The evaluator strictly fails closed (returning `INCONCLUSIVE`) when:
1. **Incomplete Count**: If candidate pools count $K \ne \text{liquidityPoolUseCount}$.
2. **Mixed Ledger Sequences**: If any entry's `lastModifiedLedgerSeq > snapshot.ledger_sequence`.
3. **Wrong Issuer**: If a pool references an asset with matching code but differing issuer.
4. **Duplicate Pool Identities**: If duplicate `pool_id`s are supplied.
5. **Unproven Source**: If `liquidityPoolUseCount` is missing or unverified, the engine flags coverage as unproven.

---

## 6. Honest Verdict & Feasibility Status

**DISCOVERY FEASIBILITY PLAUSIBLE BUT UNPROVEN**

- **Why Plausible**: The on-chain `liquidityPoolUseCount` invariant in CAP-0038 and canonical pool parameter derivation provide a sound protocol-level mechanism to detect any omitted or spurious pool-share trustline on a given account.
- **Why Unproven on Live Network**: Public Stellar RPC provides neither blind enumeration nor historical point-in-time consistency. Achieving complete discovery on live networks requires either:
  1. A single-batch live tip read (restricted to current state, max 200 keys), or
  2. Running a dedicated Captive-Core instance against history archives.
- Neither option has been productionized in this spike. Therefore, claiming live discovery completeness is technically dishonest. The feasibility is **PLAUSIBLE BUT UNPROVEN**.
