# Protocol compatibility

> **Historical research notice, 2026-10-27.** This is a Phase 1 source review, retained as evidence of the original analysis rather than a complete statement of v1.0.0 support. The release implements the documented bounded subset and rejects live protocol versions below 18. Consult [verification](../docs/verification.md) and [scope](../docs/scope.md) for current support and limitations.

Research date: 2026-10-27. This is a Phase 1 source review, not a statement of production support.

Source pins used in this review: `stellar-core` `05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4` (`master` on the review date), `rs-stellar-xdr` `v28.0.1` at `ced6bd3cc9f5d8d03445bdf0d7e907814822b370`, and current `rs-stellar-xdr` release `v30.0.0` at `3c2aa43d2ab54d429ae44aa5143d805bf5dba7e2`. The crate is pinned to 28.0.1 for the feasibility spike; 30.0.0 is now the latest visible release and requires a compatibility review before changing the pin.

## Decision-critical behavior

CAP-0038's executable-style rule is:

```text
tl = asset trustline owned by the affected account
if authorized_to_maintain_liabilities(tl.flags)
   && !authorized_to_maintain_liabilities(expected_flags):
    discover every pool-share trustline owned by the same account that uses
    the revoked asset
    for each pool-share trustline, redeem using the LiquidityPoolWithdrawOp
    arithmetic, then delete the pool-share trustline
    create one unconditional claimable balance per nonzero withdrawn asset
    unless the owner is that asset's issuer
    sponsor each claimable balance according to the CAP-0038 sponsorship rule
    fail the whole operation if reserve or sponsorship limits fail
```

The trigger is the transition out of `AUTHORIZED_TO_MAINTAIN_LIABILITIES`, not merely clearing `AUTHORIZED_FLAG`. Therefore:

| Before | Requested after | Forced pool redemption? | Reason |
| --- | --- | --- | --- |
| fully authorized | maintain-liabilities-only | no | maintain-liabilities permission remains |
| maintain-liabilities-only | unauthorized / cleared | yes | permission is removed |
| fully authorized | unauthorized / cleared | yes | transition removes maintain-liabilities permission |
| fully authorized | maintain-liabilities-only | no | the position remains withdrawable |

`AllowTrustOp` and `SetTrustLineFlagsOp` share this revocation extension. CAP-0038 says their existing validity conditions remain unchanged. The operation can fail with the protocol's low-reserve result (`ALLOW_TRUST_LOW_RESERVE` or `SET_TRUST_LINE_FLAGS_LOW_RESERVE`) or with `opTOO_MANY_SPONSORING` when the selected sponsor cannot create the required claimable balances.

## Redemption arithmetic

For a constant-product pool and a pool-share balance `amount`, the withdrawal amount for each constituent is the integer floor of:

```text
withdrawn = floor(amount * reserve / total_pool_shares)
```

The implementation must use checked integer multiplication/division. Stellar Classic amounts are signed 64-bit stroops; a `u128` intermediate is sufficient for two nonnegative `int64` inputs, but invalid negative values must be rejected before conversion. The result can be zero for either asset, so zero/one/two claimable outputs are all protocol-valid.

Worked example: reserves A/B = 5,000/8,000 stroops, total shares = 1,000, holder shares = 125. Redemption yields A = `floor(125*5000/1000) = 625` and B = `floor(125*8000/1000) = 1000`. If the holder is not issuer of either asset, two claimable balances are created. If it is issuer of A, only B produces a claimable balance. If both withdrawn amounts are zero, no claimable balance is created.

The pool-share trustline counts as two base reserves. The corresponding `LiquidityPoolEntry` has no reserve of its own and can be deleted when the last pool-share trustline disappears. Current core deletes the pool-share trustline before creating claimable balances, freeing the reserve capacity. For a non-sandwich sponsor, core intentionally reuses that released reserve even if the base reserve later increased; this is distinct from the stricter reserve check needed for an active sponsorship sandwich.

## Claimable-balance IDs and sponsorship

CAP-0038 derives each ID as `sha256(HashIDPreimage::ENVELOPE_TYPE_POOL_REVOKE_OP_ID { sourceAccount, seqNum, opNum, liquidityPoolID, asset })`. The operation source, sequence number, operation index, pool ID, and output asset are therefore required inputs for exact IDs; a fixture that omits them can predict amounts but must not claim exact generated IDs.

The initial sponsor is the pool-share trustline sponsor, or the trustor if the trustline is unsponsored. CAP-0038 then follows an active sponsorship sandwich to its sponsor. Current core also sorts pool-share keys because sponsorship outcomes can otherwise depend on iteration order. This is why account reserve counters, entry sponsorship, and in-transaction sponsorship context are part of the minimum complete snapshot. The selected sponsor needs both available native balance and counter capacity; the relevant limit is `numSponsoring + numSubentries + claimable_balances_to_sponsor <= UINT32_MAX`.

## Protocol/version boundaries

CAP-0038 is the source of truth for Classic AMM behavior. CAP-0046-06 is excluded from the engine's operation domain: its `set_authorized` method exposes SAC contract semantics and deliberately uses maintain-liabilities-only when deauthorizing an account balance to avoid pulling offers and pool shares. That is evidence for the distinction, not an implementation target.

The current `stellar-core` source inspection confirms the boundary in executable code. At commit `05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4`, `TrustFlagsOpFrameBase::doApply` computes the expected flags, then calls `removeOffers` only when the old trustline is maintain-liabilities-authorized and the expected value is not. `removeOffersAndPoolShareTrustLines` is gated at protocol version 18, obtains pool-share trustlines through core's account+asset ledger lookup, sorts the discovered pool trustline keys before processing, deletes the pool-share trustline to release reserves, computes both withdrawal amounts with `getPoolWithdrawalAmount`, and maps low reserve / too-many-sponsoring outcomes to operation failure. `SetTrustLineFlagsOpFrame::isOpSupported` requires protocol version 17. This confirms that discovery completeness, ordering, and protocol version belong in the future compatibility model.

CAP-0035 supplies the Classic revocability/clawback flags and the trustline clawback interaction. It does not replace CAP-0038's pool-redemption rule.

The kickoff's release assertion is stale: the official release page currently lists 30.0.0, while 28.0.1 is the spike's pinned baseline. The 28.x decoder successfully supports the feasibility test, but this does not establish compatibility with protocol 30 or all current network versions. A production engine must bind the decoded XDR branch and ledger protocol version to an explicit compatibility table.

## Open questions before Phase 2

1. Confirm the exact current `stellar-core` source path and core tests for the pool-revoke implementation and reserve failure cases, then pin commit hashes.
2. Confirm the exact `stellar-xdr` Rust module/features and generated enum names for all supported protocol branches.
3. Define a complete discovery adapter: `getLedgerEntries` accepts at most 200 explicit ledger keys and returns `latestLedger`, entry keys, XDR, and `lastModifiedLedgerSeq`, but it does not enumerate all pool-share trustlines referencing an asset/account. A trusted indexer or full ledger-entry capture is required for discovery, followed by direct RPC reads and same-ledger checks.
4. Decide whether the first exact-ID fixture includes a real transaction envelope or models the preimage fields directly.
5. Validate actual network operation-result names and protocol version gating in a testnet capture; do not infer them from prose alone.

## Sources

- CAP-0038: https://github.com/stellar/stellar-protocol/blob/master/core/cap-0038.md (accessed 2026-10-27), especially the SetTrustLineFlags/AllowTrust pseudocode, withdrawal arithmetic, result codes, sponsorship rationale, and reserve discussion.
- CAP-0035: https://github.com/stellar/stellar-protocol/blob/master/core/cap-0035.md (accessed 2026-10-27).
- CAP-0046-06: https://github.com/stellar/stellar-protocol/blob/master/core/cap-0046-06.md (accessed 2026-10-27), `set_authorized` semantics.
- CAP index: https://github.com/stellar/stellar-protocol/blob/master/core/README.md (accessed 2026-10-27).
- RPC `getLedgerEntries`: https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getLedgerEntries (accessed 2026-10-27).
- Rust XDR releases: https://github.com/stellar/rs-stellar-xdr/releases (accessed 2026-10-27).
- Stellar Core `SetTrustLineFlagsOpFrame.cpp`: https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/transactions/SetTrustLineFlagsOpFrame.cpp (inspected 2026-10-27).
- Stellar Core `TrustFlagsOpFrameBase.cpp`: https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/transactions/TrustFlagsOpFrameBase.cpp (inspected 2026-10-27).
- Stellar Core `TransactionUtils.cpp`: https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/transactions/TransactionUtils.cpp (inspected 2026-10-27).
- Stellar Core authorization tests: https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/transactions/test/SetTrustLineFlagsTests.cpp (inspected 2026-10-27).
