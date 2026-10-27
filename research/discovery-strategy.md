# Pool-share discovery and completeness strategy

Research date: 2026-10-27. This is a design proof for refusing incomplete analysis; it is not a live capture implementation.

## Required pre-state

For an issuer authorization transition, a complete snapshot must contain:

1. The operation source, trustor, issuer, asset, sequence, operation index, network passphrase, and protocol version.
2. The affected credit trustline, issuer/account flags, balances, liabilities, `liquidityPoolUseCount`, and sponsorship extension.
3. Every pool-share trustline owned by the trustor whose pool parameters contain the revoked asset.
4. Each referenced `LiquidityPoolEntry`, including pool ID, ordered constituent assets, reserves, and total pool shares.
5. All account entries needed for reserve balance, subentry count, `numSponsoring`, and `numSponsored` checks.
6. Sponsorship context for each pool-share trustline, including an active Begin/End sponsorship sandwich when the proposed envelope contains one.
7. Any underlying asset trustlines needed to determine issuer ownership and clawback-related output flags.

## Sources and guarantees

| Source | What it can provide | Completeness guarantee |
| --- | --- | --- |
| Stellar RPC `getLedgerEntries` | Explicit account, trustline, pool, and sponsorship-related ledger keys; XDR and `lastModifiedLedgerSeq` | Key lookup only; maximum 200 keys; it does not enumerate all pool-share trustlines by account+asset. [API reference](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getLedgerEntries) |
| Horizon account/ledger APIs | Account balances and some trustline/offer views | Useful indexed views, but not a proof that every pool-share trustline and sponsorship extension was discovered. |
| Full ledger-entry capture / trusted index | Enumeration of all relevant trustline entries, followed by direct RPC verification | Can establish completeness only if the capture is contiguous, network-pinned, and reconciled to the target ledger. |
| Stellar Core internal lookup | `loadPoolShareTrustLinesByAccountAndAsset` during application | Authoritative for core execution, but not an externally callable discovery endpoint. [Source](https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/transactions/TransactionUtils.cpp) |

## Proposed completeness proof

The future capture adapter must:

1. Pin one network and target ledger sequence.
2. Obtain an authoritative account+asset pool-share enumeration from a full ledger capture or a trusted indexer whose indexing coverage and ledger checkpoint are recorded.
3. Record every discovered trustline ledger key and hash the sorted manifest.
4. Fetch each manifest key and every referenced pool/account/asset trustline using RPC, batching no more than 200 keys per request.
5. Require `latestLedger` to be at or after the target ledger, and require each entry’s `lastModifiedLedgerSeq` to be no later than the target ledger. Historical reads must come from a source that can actually serve the target ledger, not merely current state.
6. Reconcile pool IDs, pool parameters, asset ordering, owner, sponsor, and account counters. Duplicate keys, contradictory values, missing references, or changed ledger sequences invalidate the snapshot.
7. Store endpoint, network passphrase, target/read ledger, request keys, returned entry hashes, discovery manifest hash, and source version.

## Sponsorship ordering boundary

The pinned core implementation first identifies the pool-share trustline's actual backer (`getTrustLineBacker`), deletes that trustline to release its two-reserve liability, and then creates each claimable balance. If the backer is currently in a sponsorship sandwich, core uses the sandwich's replacement sponsor and checks that account's available reserve and sponsoring-counter capacity. Outside a sandwich, core establishes sponsorship with the backer and deliberately reuses the reserve released by the deleted pool-share trustline. [Core implementation](https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/transactions/TransactionUtils.cpp)

The current RPC discovery response does not expose enough evidence to establish the actual
pool-share sponsor, sponsor counters, reserve liability, or a Begin/revoke/End operation sandwich.
The prototype therefore marks sponsorship evidence incomplete and does not promote discovery into
a complete preflight snapshot. A future capture adapter must obtain and reconcile those fields
before modeling sponsorship replacement or claimable-balance sponsorship.

## Mandatory refusal conditions

Return `INCONCLUSIVE`, never `UNVERIFIED_FORECAST` or `SUPPORTED_SAFE`, when any of the following holds:

- enumeration is based only on explicit RPC lookups or a non-auditable account view;
- the source cannot prove it covered all pool-share trustlines for the account and revoked asset;
- any referenced pool, account, asset trustline, sponsorship extension, or operation context is missing;
- reads span ledgers without a consistency proof, or an entry is newer than the target ledger;
- a pool ID does not hash to the supplied pool parameters, assets are contradictory, or sponsorship counters do not reconcile;
- active sponsorship operations are omitted or their order cannot be established;
- network, protocol version, or XDR branch is unsupported.

The current repository demonstrates a bounded Phase 1B and Phase 1C two-tier discovery-verification shape:
- Autonomous Candidate Enumeration: Horizon `/accounts/{trustor}` balances enumerate candidate pool-share trustlines without caller-supplied pool IDs.
- Atomic Single-Batch Core Verification: Candidate pools, target credit trustline, and accounts are fetched in a single RPC `getLedgerEntries` batch at the current ledger tip.
- The target credit trustline's `liquidityPoolUseCount` is checked against discovered pool-share trustlines.
- Pool IDs are cryptographically derived from canonical constant-product parameters (`derive_constant_product_pool_id`).
- A bounded live RPC observation checks exact keys at the current tip; response order is irrelevant, and missing, duplicate, unexpected, malformed, or contradictory entries are refused.
- Separately, an offline recorded network-response fixture ([`fixtures/live-testnet-discovery.json`](../fixtures/live-testnet-discovery.json)) is replayed at Stellar Testnet ledger 5413920 by the executable demonstration ([`examples/live_discovery.rs`](../examples/live_discovery.rs)). The live observation is never combined with that historical fixture into one verified snapshot.
- Historical ledger consistency is not proven on public RPC endpoints without Captive Core. If any check fails, the evaluation returns `INCONCLUSIVE`.
- Deep research findings are documented in:
  - [`authoritative-core-discovery.md`](authoritative-core-discovery.md): Stellar Core internal discovery mechanics and protocol invariants.
  - [`discovery-architectures.md`](discovery-architectures.md): Comparison of RPC, Horizon, Captive Core, and Indexers.
  - [`trusted-discovery-sources.md`](trusted-discovery-sources.md): Comprehensive evaluation of candidate sources and two-tier architecture.
  - [`ledger-consistency-models.md`](ledger-consistency-models.md): Detailed investigation of consistency guarantees, tip vs historical state, and fault detection.
  - [`selected-architecture.md`](selected-architecture.md): Two-Tier Verifiable Discovery Architecture and mathematical completeness proof.
  - [`discovery-feasibility-proof.md`](discovery-feasibility-proof.md): Recorded network fixture evaluation, live RPC constraints, and failure invariants.

Synthetic fixtures and caller-supplied `LedgerCapture` metadata continue to produce at most `UNVERIFIED_FORECAST`, never `SUPPORTED_SAFE`. Any count discrepancy, mixed ledger, or omission fails closed as `INCONCLUSIVE`. No actual revocation transaction was executed. Live discovery feasibility remains **PARTIALLY DEMONSTRATED**, and Phase 2 remains blocked until trusted capture streaming is integrated.
