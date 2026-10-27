# Comparison of Pool-Share Discovery Architectures

Research date: 2026-10-27.  
Scope: Evaluating discovery mechanisms for Stellar Classic pool-share trustlines affected by issuer authorization revocation.

---

## 1. Overview of Evaluated Approaches

We investigated four architectural approaches for discovering liquidity-pool share trustlines:

1. **Approach A: Stellar RPC Alone** (Official JSON-RPC / Soroban RPC)
2. **Approach B: Horizon or Existing Indexed APIs** (SDF Horizon REST endpoints)
3. **Approach C: Stellar Core / Captive-Core / Ledger-State Export** (Direct BucketList / History Archive ingestion)
4. **Approach D: Existing External Indexer or Data Service** (Hubble BigQuery, Stellar Expert, Subsquid/Zephyr)

---

## 2. In-Depth Evaluation Matrix

| Evaluation Dimension | Approach A: Stellar RPC Alone | Approach B: Horizon API | Approach C: Captive Core / State Export | Approach D: External Indexer (Hubble/etc.) |
| --- | --- | --- | --- | --- |
| **Completeness Guarantee** | **None (Cannot enumerate)**. `getLedgerEntries` requires explicit keys; no wildcard or secondary index exists. | **Unproven**. Account balances array lists pool shares, but drops `liquidityPoolUseCount`, provides no cryptographic proof. | **Authoritative**. Directly scans BucketList or replays `LedgerCloseMeta`. | **Unproven**. Relies on third-party ingestion and custom SQL schemas; no consensus-backed proof. |
| **Ledger Consistency** | Single-ledger snapshot via `getLedgerEntries` at `latestLedger`. Batch limit 200 keys. | **Poor**. Returns current database state (`Latest-Ledger` header); multi-page requests risk ledger drift. | **Strictly pinned**. Can anchor to any historical ledger checkpoint or close meta. | **Lagged**. Ingestion lag ranges from minutes to hours; read-time consistency uncoordinated with live ledger. |
| **Historical Availability** | State only exists at current tip (`getLedgerEntries`); event retention is limited (~7 days). | **Tip-only for state**. State tables store latest view; does not serve historical trustline balances at past ledgers. | **Full history**. Any ledger from history archives can be reconstructed. | **High for analytics**, but historical state reconstruction requires point-in-time table queries. |
| **Pagination & Omission Risks** | **Fatal**. Impossible to paginate unknown pool IDs without a known key set. | **High**. Horizon JSON drops `liquidityPoolUseCount`. Large balance arrays have no page hashes or inclusion proofs. | **Zero**. In-memory iteration over complete BucketList snapshot. | **Medium**. Subject to pagination bugs, indexing race conditions, or omitted event types. |
| **Operational Requirements** | Extremely lightweight (simple HTTPS JSON-RPC calls). | Extremely lightweight (simple HTTPS REST calls). | **Extremely heavy**. Requires running Core binary, downloading gigabytes of buckets, or captive-core process. | Medium to heavy (requires external API keys, cloud billing, or self-hosted indexer stack). |
| **Third-Party Dependence** | Dependent on RPC endpoint availability (SDF runs testnet; pubnet requires ecosystem RPCs). | Dependent on Horizon host (SDF operates public Horizon for testnet and pubnet). | Independent (can run locally against public decentralized history archives). | High (vendor lock-in, proprietary schemas, rate limits). |
| **Reproducibility** | High for explicit key lookups; zero for blind discovery. | Moderate (subject to backend DB sync and mutation across calls). | Exact and fully deterministic across runs. | Moderate to low (historical database mutations and schema migrations). |
| **Suitability for CLI-First MVP** | **Unusable alone for discovery**; excellent for key verification. | Usable as a **candidate discovery tier**, but insufficient as authoritative proof. | Impractical for a lightweight, fast CLI preflight tool (too heavy/slow). | Unsuitable for offline or low-latency preflight workflows. |

---

## 3. Detailed Architectural Breakdown

### Approach A: Stellar RPC Alone

- **Mechanism**: Calls `getLedgerEntries` with base64-encoded `LedgerKey`s.
- **Enumeration Capability**: None. Stellar RPC is a strict key-value lookup service backed by captive core or an in-memory key cache. It deliberately exposes no secondary indices (`getLedgerEntriesByAccount` does not exist).
- **Why it Fails Alone**: A pool-share trustline key requires `PoolID = SHA256(assetA, assetB, fee)`. Because the counter-asset in the pool can be any asset in the Stellar universe, brute-forcing all potential counter-assets is computationally infeasible.
- **Role in Solution**: While RPC cannot *discover* pool IDs out of thin air, it provides the exact, authoritative, single-ledger XDR bytes (`LedgerEntryData::Trustline`) for any candidate key provided to it.

### Approach B: Horizon or Existing Indexed APIs

- **Mechanism**: Calls `GET /accounts/{account_id}`. Inspects the `balances` array for objects where `asset_type == "liquidity_pool_shares"`.
- **Observed Behavior on Live Network**:
  - Live query to Horizon testnet (`GET /accounts/GAPOZN3...`) successfully returns multiple liquidity pool share positions:
    - Pool `00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46`
    - Pool `078ff7f339a3a1c950812bd143431498f880082e0ebdb95fb348a5b87693465c`
- **Critical Flaws**:
  1. **Field Truncation**: As demonstrated by live inspection, Horizon's JSON serializer completely omits `liquidityPoolUseCount`. The field is deserialized internally by Horizon's ingestion engine but is not exposed in the API response.
  2. **No Historical Pinning**: Querying `/accounts/{id}?ledger=X` is ignored by Horizon; it always returns the latest state in PostgreSQL.
  3. **No Cryptographic Proof**: An omitted balance cannot be detected from Horizon's response alone.

### Approach C: Stellar Core / Captive-Core / Ledger-State Export

- **Mechanism**: Run an embedded captive-core instance or fetch History Archive State (`history-xxxxxxxx.json`) and associated `BucketList` files directly from cloud storage (S3/GCS).
- **Completeness Guarantee**: 100% authoritative. Captive-core computes the exact BucketList hash validated by Stellar consensus.
- **Operational Feasibility**:
  - A pubnet `BucketList` snapshot exceeds 40 GB compressed and 150+ GB uncompressed.
  - Downloading, extracting, and scanning the BucketList on every CLI invocation requires minutes to hours of execution time and tens of gigabytes of disk/memory bandwidth.
  - Captive-core requires installing the C++ `stellar-core` binary on the host machine, violating the lightweight, zero-system-dependency requirement of a Rust CLI.

### Approach D: Existing External Indexers (Hubble, Stellar Expert, Zephyr)

- **Mechanism**: Query Hubble (BigQuery) or Stellar Expert REST API.
- **Completeness Guarantee**: Unproven. These are downstream analytics databases.
- **Drawbacks**:
  - Hubble requires Google Cloud credentials and BigQuery query billing. Ingestion latency is typically 5 to 15 minutes behind the live ledger tip.
  - Stellar Expert is a community-run service without consensus guarantees or uptime SLAs.
  - Neither service provides cryptographic inclusion or exclusion proofs.

---

## 4. Historical Ledger Consistency Analysis and State Drift

A core requirement of trustworthy preflight analysis is verifying that all evaluated ledger entries represent a mutually consistent snapshot at an exact ledger sequence $L$.

### 4.1 Stellar RPC `getLedgerEntries` Lacks Historical Query Support
Empirical testing on live testnet RPC (`https://soroban-testnet.stellar.org`) confirms:
- The JSON-RPC method `getLedgerEntries` accepts only `{"keys": [...]}`. Passing a `ledger` sequence parameter is silently ignored by the endpoint.
- Responses always return the node's current ledger tip (`latestLedger`).
- Stellar RPC nodes do not maintain a historical index of past ledger entry versions; state is overwritten as new ledgers close.

### 4.2 Why `lastModifiedLedgerSeq <= L` Does Not Prove State at Ledger $L$
It is a logical error to assume that observing `lastModifiedLedgerSeq <= L` on a live tip read proves the entry's value at historical ledger $L$:
1. **Unobserved Post-L Deletion**: If an entry existed at ledger $L$ and was deleted at ledger $L + 10$, a live query at $L + 100$ will return null. The preflight engine would incorrectly conclude the entry never existed at $L$.
2. **Post-L Mutation Overwrites**: If an entry was modified at ledger $L - 5$ and modified again at ledger $L + 5$, a live query returns the state as of $L + 5$. The historical state at $L$ is permanently lost to RPC.
3. **Multi-Request Ledger Drift**: Because Stellar ledgers close every ~5 seconds, querying entries across multiple RPC calls exposes the preflight tool to inter-request ledger closes. Entry A might be retrieved at ledger $T$, while Entry B is retrieved at ledger $T + 1$ following an intervening state change.

### 4.3 Atomic Consistency Bounded to Current Tip
Single-batch retrieval (up to 200 keys in a single `getLedgerEntries` call) guarantees atomic consistency **only for the current live tip** (`latestLedger`). It provides zero consistency guarantees for historical ledgers $L < \text{latestLedger}$.

---

## 5. Architectural Decision Conclusion

No single existing public service satisfies both:
1. **Lightweight, fast execution** suitable for a CLI preflight tool, AND
2. **Authoritative, tamper-evident completeness proof** backed by Stellar protocol invariants at an arbitrary historical ledger.

Therefore, an isolated, monolithic approach fails:
- Relying on RPC alone fails because RPC cannot enumerate and cannot query historical state.
- Relying on Horizon alone fails because Horizon cannot prove completeness and drops `liquidityPoolUseCount`.
- Relying on Captive Core alone fails because the infrastructure footprint (>40GB state) is prohibitive for a CLI tool.

The **Two-Tier Verifiable Discovery Architecture** (detailed in [`selected-architecture.md`](selected-architecture.md)) provides a mathematically sound design, but because current public endpoints cannot serve historical point-in-time state, **live discovery completeness is classified as PLAUSIBLE BUT UNPROVEN**.
