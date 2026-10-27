# Authoritative Stellar Core Discovery Behavior

Research date: 2026-10-27.  
Pinned Stellar Core commit: `05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4` (`master`).  
Reference CAP: [CAP-0038: Liquidity Pools](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0038.md).

---

## 1. Executive Summary

When an asset issuer modifies trustline authorization via Classic `SetTrustLineFlagsOp` or `AllowTrustOp`, Stellar Core evaluates whether the operation removes the `AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG`. If maintain-liabilities authorization is revoked, Stellar Core does not merely mutate the directly named credit trustline; it executes an in-protocol cascade that force-redeems all liquidity-pool share trustlines owned by the trustor that reference the revoked asset.

This document records the exact, line-by-line behavior of Stellar Core when enumerating and processing these pool-share trustlines, explains the protocol invariants governing discovery, and establishes what constitutes an authoritative completeness proof at a particular ledger.

---

## 2. Triggering the Revocation Cascade

In Stellar Core, the authorization change is evaluated in `TrustFlagsOpFrameBase::doApply` ([`src/transactions/TrustFlagsOpFrameBase.cpp:54-135`](https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/transactions/TrustFlagsOpFrameBase.cpp#L54-L135)):

```cpp
// Check if need to remove offer
shouldRemoveOffers =
    isAuthorizedToMaintainLiabilities(trust) &&
    !isAuthorizedToMaintainLiabilitiesUnsafe(expectedFlagValue);
```

When `shouldRemoveOffers` evaluates to `true`, Stellar Core invokes:

```cpp
if (protocolVersionStartsFrom(ledgerVersion, ProtocolVersion::V_10) &&
    shouldRemoveOffers)
{
    if (!removeOffers(ltx, res, opEventManager))
    {
        return false;
    }
}
```

In `TrustFlagsOpFrameBase::removeOffers` ([lines 26-52](https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/transactions/TrustFlagsOpFrameBase.cpp#L26-L52)), Core calls `removeOffersAndPoolShareTrustLines`:

```cpp
auto removeResult = removeOffersAndPoolShareTrustLines(
    ltx, getOpTrustor(), getOpAsset(), mParentTx.getSourceID(),
    mParentTx.getSeqNum(), getOpIndex(), opEventManager);
```

---

## 3. Enumeration Mechanism in Stellar Core

The function `removeOffersAndPoolShareTrustLines` is implemented in [`src/transactions/TransactionUtils.cpp:1624-1840`](https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/transactions/TransactionUtils.cpp#L1624-L1840).

### 3.1 Protocol Version Gating
The pool-share redemption path is strictly gated to protocol version 18 and later:
```cpp
if (protocolVersionIsBefore(ltxInner.loadHeader().current().ledgerVersion,
                            ProtocolVersion::V_18))
{
    return RemoveResult::SUCCESS;
}
```
Prior to Protocol 18 (which introduced CAP-0038), liquidity pools did not exist on Stellar.

### 3.2 Prefetching and Deterministic Sorting
To discover affected pool shares, Core calls `prefetchPoolShareTrustLinesByAccountAndGetKeys`:

```cpp
static std::vector<LedgerKey>
prefetchPoolShareTrustLinesByAccountAndGetKeys(AbstractLedgerTxn& ltx,
                                               AccountID const& accountID,
                                               Asset const& asset)
{
    LedgerTxn ltxInner(ltx);
    auto poolShareTrustLines =
        ltxInner.loadPoolShareTrustLinesByAccountAndAsset(accountID, asset);

    if (poolShareTrustLines.empty())
    {
        return {};
    }

    prefetchForRevokeFromPoolShareTrustLines(ltxInner, accountID,
                                             poolShareTrustLines);

    std::vector<LedgerKey> poolTLKeys;
    for (auto const& poolShareTrustLine : poolShareTrustLines)
    {
        poolTLKeys.emplace_back(LedgerEntryKey(poolShareTrustLine.current()));
    }

    // The ordering of poolTLKeys isn't deterministic across the network because
    // getPoolShareTrustLinesByAccountAndAsset returns an UnorderedMap, which is
    // why we need to sort here. There's a subtle bug in pool share revocation
    // and sponsorships where the operation can succeed or fail based on the
    // order of the pool share trustlines.
    std::sort(poolTLKeys.begin(), poolTLKeys.end());

    return poolTLKeys;
}
```

> [!IMPORTANT]
> **Deterministic Ordering Invariant**: Because hash-map iteration order is non-deterministic across platforms, Stellar Core explicitly sorts the candidate `poolTLKeys` via `std::sort(poolTLKeys.begin(), poolTLKeys.end())`. The processing order directly impacts reserve consumption and sponsorship limits: if sponsor accounts have limited reserves, an operation might succeed or fail depending on which pool is redeemed first. RevokeTrace must mirror this exact sorting.

### 3.3 Underlying BucketList Secondary Index
Tracing `loadPoolShareTrustLinesByAccountAndAsset`:
1. `LedgerTxn::loadPoolShareTrustLinesByAccountAndAsset` delegates to `LedgerTxnRoot::Impl::getPoolShareTrustLinesByAccountAndAsset` ([`src/ledger/LedgerTxn.cpp:3615`](https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/ledger/LedgerTxn.cpp#L3615)).
2. `LedgerTxnRoot` queries the snapshot view: `getApplyLedgerView().loadPoolShareTrustLinesByAccountAndAsset(account, asset)`.
3. In `SearchableLiveBucketListSnapshot::loadPoolShareTrustLinesByAccountAndAsset` ([`src/bucket/BucketListSnapshot.cpp:453-492`](https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/bucket/BucketListSnapshot.cpp#L453-L492)):
   - Core iterates across all buckets in the live `BucketList`:
   ```cpp
   auto trustLineLoop = [&](std::shared_ptr<LiveBucket const> const& bucket) {
       static std::vector<PoolID> const emptyVec = {};
       auto const& poolIDs = bucket->isEmpty()
                                 ? emptyVec
                                 : bucket->getIndex().getPoolIDsByAsset(asset);
       for (auto const& poolID : poolIDs)
       {
           LedgerKey trustlineKey(TRUSTLINE);
           trustlineKey.trustLine().accountID = accountID;
           trustlineKey.trustLine().asset.type(ASSET_TYPE_POOL_SHARE);
           trustlineKey.trustLine().asset.liquidityPoolID() = poolID;
           trustlinesToLoad.emplace(trustlineKey);
       }
       return Loop::INCOMPLETE;
   };
   loopAllBuckets(trustLineLoop);
   ```
   - In `LiveBucketIndex::getPoolIDsByAsset(asset)` ([`src/bucket/LiveBucketIndex.cpp:260-283`](https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/bucket/LiveBucketIndex.cpp#L260-L283)), Stellar Core consults an in-memory or on-disk secondary index `mAssetPoolIDMap` constructed when each bucket is generated.
   - For every `poolID` in that bucket containing `asset`, Core constructs a candidate `LedgerKey` for `(trustor, poolID)` and queries the bucket for that key.

---

## 4. In-Protocol Invariant: `liquidityPoolUseCount`

Stellar Core's internal secondary index is NOT exposed via JSON-RPC or public network APIs. However, the Stellar protocol enforces a strict on-chain invariant that enables authoritative, cryptographic verification of completeness.

### 4.1 Specification in CAP-0038
In CAP-0038, the XDR definition of `TrustLineEntry` is extended via `TrustLineEntryExtensionV2`:
```c
struct TrustLineEntryExtensionV2
{
    int32 liquidityPoolUseCount;
    union switch (int v)
    {
    case 0:
        void;
    } ext;
};
```
CAP-0038 explicitly defines the purpose of this field:
> *"This proposal introduces `TrustLineEntryExtensionV2.liquidityPoolUseCount`, which keeps track of the number of pool trust lines an asset trust line is used in. The extension is used to make sure the trust line is not deleted while corresponding pool trust lines exist. This is required because without the asset trust line, there is no way to deauthorize the trust line and force a redemption of the related pool shares."*

### 4.2 Enforcement in Stellar Core Code
1. **Creation**: When an account creates a pool-share trustline in `ChangeTrustOpFrame::tryIncrementPoolUseCount` ([`src/transactions/ChangeTrustOpFrame.cpp:50-80`](https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/transactions/ChangeTrustOpFrame.cpp#L50-L80)):
   - An account CANNOT create a pool-share trustline without already holding an established, authorized trustline for each constituent asset.
   - Stellar Core increments `liquidityPoolUseCount` on the underlying asset trustline:
   ```cpp
   ++prepareTrustLineEntryExtensionV2(
         assetTrustLine.current().data.trustLine())
         .liquidityPoolUseCount;
   ```
2. **Deletion Prevention**: In `ChangeTrustOpFrame::doApply` ([lines 208-213](https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/transactions/ChangeTrustOpFrame.cpp#L208-L213)):
   - A credit trustline CANNOT be deleted if `liquidityPoolUseCount != 0`:
   ```cpp
   if (!isPoolShare && hasTrustLineEntryExtV2(tlEntry()) &&
       tlEntry().ext.v1().ext.v2().liquidityPoolUseCount != 0)
   {
       innerResult(res).code(CHANGE_TRUST_CANNOT_DELETE);
       return false;
   }
   ```
3. **Revocation Decrement**: During `removeOffersAndPoolShareTrustLines` ([`src/transactions/TransactionUtils.cpp:1876-1881`](https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/transactions/TransactionUtils.cpp#L1876-L1881)):
   - As each pool-share trustline is force-redeemed and deleted, `decrementLiquidityPoolUseCount` decrements the counter:
   ```cpp
   if (--getTrustLineEntryExtensionV2(
             assetTrustLine.current().data.trustLine())
             .liquidityPoolUseCount < 0)
   {
       throw std::runtime_error("liquidityPoolUseCount is negative");
   }
   ```

### 4.3 Deductive Completeness Proof
Because `liquidityPoolUseCount`:
1. Starts at 0,
2. Increments by exactly 1 for every pool-share trustline created on `trustor` containing `asset`,
3. Decrements by exactly 1 for every pool-share trustline deleted,
4. Prevents deletion of the credit trustline while non-zero, and
5. Is recorded directly in the target credit trustline's on-chain XDR (`TrustLineEntryExtensionV2`),

**the value of `liquidityPoolUseCount` on the target credit trustline at ledger $L$ is the exact cardinality of affected pool-share trustlines on that account.**

---

## 5. Ledger Entries Required for Evaluation

To accurately evaluate authorization revocation, integer redemption amounts, and sponsorship/reserve consequences, RevokeTrace requires the following exact ledger entries at target ledger $L$:

| Entry Type | Key Parameters | Specific Required Fields | Purpose |
| --- | --- | --- | --- |
| `AccountEntry` | `trustor` Account ID | `balance`, `sellingLiabilities`, `subentries`, `numSponsored`, `numSponsoring` | Baseline reserve unit calculation and available XLM balance. |
| `TrustLineEntry` | `(trustor, revoked_asset)` | `flags`, `liabilities`, `ext.v1.ext.v2.liquidityPoolUseCount` | Authorization transition boundary check; authoritative proof of affected pool count. |
| `TrustLineEntry` (per pool) | `(trustor, pool_id)` | `balance` (shares), `ext.v1.sponsor` | Exact shares redeemed; identifying trustline backer/sponsor. |
| `LiquidityPoolEntry` (per pool) | `pool_id` | `assetA`, `assetB`, `reserveA`, `reserveB`, `totalPoolShares`, `poolSharesTrustLineCount` | Canonical parameter verification (`SHA256(params) == pool_id`); integer redemption arithmetic. |
| `TrustLineEntry` (underlying) | `(trustor, other_asset)` | `flags` (`isClawbackEnabled()`) | Setting `CLAIMABLE_BALANCE_FLAG_CLAWBACK_ENABLED` on non-native output claimable balance. |
| `AccountEntry` (sponsors) | Sponsor Account ID | `balance`, `sellingLiabilities`, `numSponsoring` | Verifying reserve capacity for newly created claimable balances when in a sponsorship sandwich. |

---

## 6. Verification and Reference Sources

1. **Stellar Core Repository**:
   - `src/transactions/TransactionUtils.cpp`: commit `05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4`
   - `src/transactions/TrustFlagsOpFrameBase.cpp`: lines 26-140
   - `src/transactions/ChangeTrustOpFrame.cpp`: lines 50-82, 199-220
   - `src/bucket/BucketListSnapshot.cpp`: lines 453-492
   - `src/bucket/LiveBucketIndex.cpp`: lines 260-283
2. **Protocol Specifications**:
   - CAP-0038: https://github.com/stellar/stellar-protocol/blob/master/core/cap-0038.md
   - CAP-0035 (Asset Clawback): https://github.com/stellar/stellar-protocol/blob/master/core/cap-0035.md
   - CAP-0033 (Sponsored Reserves): https://github.com/stellar/stellar-protocol/blob/master/core/cap-0033.md
