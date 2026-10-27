# Live Discovery Feasibility Proof and Limitations

Research date: 2026-10-27.  
Scope: Reproducible demonstration of complete pool-share discovery on live Stellar network.

---

## 1. Demonstrated Feasibility Case: Stellar Testnet

We executed and captured a live, multi-pool authorization revocation scenario on Stellar Testnet.

### Target Scenario Identifiers
- **Network**: Stellar Testnet (`Test SDF Network ; September 2015`)
- **Pinned Target Ledger**: `5413920`
- **Trustor Account**: `GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB`
- **Asset Code**: `FLUTTER`
- **Asset Issuer**: `GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG`
- **Asset Type**: `credit_alphanum12` (XDR `AssetCode12(b"FLUTTER\0\0\0\0\0")`)

### Discovered Affected Pools (2 distinct pools)
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

## 2. Reproducible Verification Commands

### Step 1: Query Credit Trustline via Stellar RPC
```bash
curl -s -X POST https://soroban-testnet.stellar.org \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getLedgerEntries",
    "params": {
      "keys": [
        "AAAAAQAAAAAe7Ld2ci6ZEYafG+wIq/EksRc5HBSsC3ZQc0ne0Qd4cgAAAAJGTFVUVEVSAAAAAAAAAAAAcEtPmLg7BL0jwUklenrbkmoXI5nAU9MtLXK7Mck3EOk="
      ]
    }
  }'
```

**Observed Result**:
- `lastModifiedLedgerSeq`: `2518476` (valid at target ledger `5413920`)
- `xdr`: `AAAAAQAAAAAe7Ld2ci6ZEYafG+wIq/EksRc5HBSsC3ZQc0ne0Qd4cgAAAAJGTFVUVEVSAAAAAAAAAAAAcEtPmLg7BL0jwUklenrbkmoXI5nAU9MtLXK7Mck3EOkABmUE6DAGgH//////////AAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAIAAAAA`
- Decoded XDR Extension:
  `TrustLineEntry.ext.v1.ext.v2.liquidity_pool_use_count == 2`

### Step 2: Query Discovered Pool-Share Trustlines and Pools via Stellar RPC
```bash
curl -s -X POST https://soroban-testnet.stellar.org \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "getLedgerEntries",
    "params": {
      "keys": [
        "AAAAAQAAAAAe7Ld2ci6ZEYafG+wIq/EksRc5HBSsC3ZQc0ne0Qd4cgAAAAMAFx/+AvET6yhsT+BkLOufG1COCcYWA3SiK7mrQkCtRg==",
        "AAAAAQAAAAAe7Ld2ci6ZEYafG+wIq/EksRc5HBSsC3ZQc0ne0Qd4cgAAAAMHj/fzOaOhyVCBK9FDQxSY+IAILg69uV+zSKW4dpNGXA==",
        "AAAABQAXH/4C8RPrKGxP4GQs658bUI4JxhYDdKIruatCQK1G",
        "AAAABQeP9/M5o6HJUIEr0UNDFJj4gAguDr25X7NIpbh2k0Zc"
      ]
    }
  }'
```

**Observed Result**:
- All 4 entries returned with `lastModifiedLedgerSeq <= 5413920`.
- All entries decode to valid XDR.
- Pool 1 and Pool 2 both contain `FLUTTER:GBYEWT4...`.
- Reconciled Count: 2 pools discovered $\equiv$ `liquidity_pool_use_count == 2`.

---

## 3. Discovery Manifest

The reproducible manifest SHA-256 is derived from canonical serialization:
```text
Test SDF Network ; September 2015
5413920
00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46
078ff7f339a3a1c950812bd143431498f880082e0ebdb95fb348a5b87693465c
```
Manifest SHA-256 Digest:
`fe73e23f1769045ae984f21ad44b0af2c4e44951cb56aed2ca890d22407b5380`

---

## 4. Refusal Scenarios & Limitations

### 4.1 Proven Refusal Behaviors
The engine refuses closed (returns `INCONCLUSIVE`) when:
1. **Omitted Pool**: If only 1 of the 2 pools is supplied in the manifest, `verified_count (1) != liquidityPoolUseCount (2)`.
2. **Mixed Ledger Sequence**: If an entry has `lastModifiedLedgerSeq > target_ledger`.
3. **Wrong Issuer / Asset**: If a pool references an asset with matching code but differing issuer.
4. **Duplicate Pool Identities**: If the manifest or snapshot repeats a `pool_id`.
5. **Unproven Coverage**: If `liquidityPoolUseCount` is missing or cannot be fetched, discovery completeness cannot be claimed.

### 4.2 Unresolved Infrastructure Requirements
1. **Pubnet RPC Access**: SDF does not host a free public JSON-RPC endpoint for Mainnet. Production CLI execution against pubnet requires an API key or dedicated node (e.g. SorobanRPC.com, QuickNode, Alchemy, or self-hosted captive-core).
2. **Historical Ledger Horizon**: Stellar RPC only retains a rolling window of recent ledgers (~120,960 ledgers, ~7 days). For preflight analysis anchored to an older ledger, a full-history archive reader or captive-core fallback is necessary.
