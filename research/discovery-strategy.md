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

The spike therefore records the actual pool-share sponsor, requires explicit Begin/revoke/End operation indices for a modeled handoff, checks sponsor counters and liabilities, and refuses to infer an active sponsorship context for an unsponsored trustline. It does not construct or decode a full transaction envelope, so this remains a feasibility boundary rather than complete operation-order proof.

## Mandatory refusal conditions

Return `INCONCLUSIVE`, never `SUPPORTED_SAFE`, when any of the following holds:

- enumeration is based only on explicit RPC lookups or a non-auditable account view;
- the source cannot prove it covered all pool-share trustlines for the account and revoked asset;
- any referenced pool, account, asset trustline, sponsorship extension, or operation context is missing;
- reads span ledgers without a consistency proof, or an entry is newer than the target ledger;
- a pool ID does not hash to the supplied pool parameters, assets are contradictory, or sponsorship counters do not reconcile;
- active sponsorship operations are omitted or their order cannot be established;
- network, protocol version, or XDR branch is unsupported.

The current repository has no capture adapter and therefore makes no live complete-discovery claim. The evaluator now requires a manifest whose pool IDs exactly match the supplied pool-share entries, whose ledger target matches the snapshot, and whose SHA-256 digest matches the canonical manifest material. Synthetic fixtures may use `SyntheticFixture`; they are deterministic test evidence only. A caller cannot obtain a safe result by setting a standalone `discovery_complete` boolean.
