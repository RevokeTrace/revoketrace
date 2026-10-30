# Protocol support decision

Decision date: 2026-10-30. Status: enforced in code by `src/protocol.rs`.

RevokeTrace evaluates ledger protocol versions 18 to 29 inclusive. A version below 18 or above 29 is refused as `UNSUPPORTED` (exit code 30). A snapshot with no protocol version is still evaluated, but the report carries the warning `W_PROTOCOL_UNVERIFIED`, because the version cannot be checked.

This is a review boundary. It is not a claim that every version in the range was observed on a live network or that a transaction will succeed.

## Why 18 is the lower bound

CAP-0038 pool-share trustlines and forced redemption start at protocol 18. In Stellar Core `removeOffersAndPoolShareTrustLines` returns early when the ledger version is before `V_18`. `SetTrustLineFlags` itself needs only protocol 17, so 18 is deliberately stricter than the operation's own minimum.

## Why 29 is the upper bound

Three findings, all from the Core revision already pinned by this project (`05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4`), reviewed on 2026-10-30.

1. **The revoke path has no version gate above 18.** A search of `src/transactions` (excluding tests) for `ProtocolVersion::V_19` through `V_31` found gates only in unrelated code: fee and preconditions in `TransactionFrame.cpp` and `FeeBumpTransactionFrame.cpp`, Soroban and event handling, offer crossing in `OfferExchange.cpp` and `ManageOfferOpFrameBase.cpp` (V_29), `BumpSequence`, `Merge`, `SetOptions`, and the XDR depth check in `validateXDRForProtocol`. None of `TrustFlagsOpFrameBase.cpp`, `SetTrustLineFlagsOpFrame.cpp`, `AllowTrustOpFrame.cpp`, `LiquidityPoolWithdrawOpFrame.cpp`, `SponsorshipUtils.cpp`, `CreateClaimableBalanceOpFrame.cpp`, or the redemption code in `TransactionUtils.cpp` contains a gate above V_18 other than the `V_19` branch in `maybeUpdateAccountOnLedgerSeqUpdate`, which concerns account sequence metadata. The pinned Core build reports `MAX_SUPPORTED_PROTOCOL_VERSION = 30` in `src/util/ProtocolVersion.h`.
2. **The entry and transaction XDR RevokeTrace decodes did not change.** The `stellar-xdr` 28.0.1 crate was generated from `stellar-xdr` commit `9c9c145953e80990d6ff1ae3a6a973a0ce6d0694`. Core's pinned XDR submodule is `4f524bbac80c781c06e4fb5fc93a2d0d331d6705`. `Stellar-ledger-entries.x` and `Stellar-transaction.x` are byte-identical between the two. The differences are in `Stellar-ledger.x` (two new `StellarValue` arms), `Stellar-types.x` (`TimePointMs`), `Stellar-contract.x` (a CAP-0084 conditional), and `Stellar-contract-config-setting.x` (new Soroban cost types).
3. **Protocol 30 ledger headers cannot be decoded.** The new `StellarValue` arms are `STELLAR_VALUE_SIGNED_MS` and `STELLAR_VALUE_EMPTY_TX_SET_MS`. Core selects them when `protocolHasMsCloseTime` is true, and `MS_CLOSE_TIME_PROTOCOL_VERSION` is `V_30`. The 28.0.1 crate does not know these arms, so a protocol 30 header would fail decoding. The policy refuses 30 by version first, so the user sees an explicit unsupported result instead of a decode error.

The bound is therefore 29, set by item 3. It is not taken from the crate version, from fixtures, or from the Core maximum. Raising it needs a new review, normally together with a reviewed `stellar-xdr` upgrade.

## Evidence by version

| Version | Source review at Core pin | Synthetic tests | Real ledger evidence | Decoder (`stellar-xdr` 28.0.1) | Policy |
| --- | --- | --- | --- | --- | --- |
| below 17 | Not applicable, no pools | Rejected (`17` tested) | None | Not relevant | Refused |
| 17 | Operation exists, no pools | Rejected | None | Not relevant | Refused |
| 18 | Gate confirmed | Boundary test (CLI, engine) | None recorded | Decodes | Supported |
| 19 to 28 | No revoke-path gate found | 20 (engine fixture) | None recorded | Decodes | Supported |
| 29 | No revoke-path gate found | 29 (live adapter mocks), boundary test | None recorded | Decodes | Supported |
| 30 | Core supports it | Refusal test | None | Header decode fails | Refused |
| 31 and above | Not reviewed (Core treats V_31 as unsafe next version) | Refusal test (`31`, `u32::MAX`) | None | Unknown | Refused |

"Real ledger evidence: none recorded" means the repository does not record the protocol version of any real ledger it captured. The Testnet clawback observation in [Phase 4C](phase4c-protocol-verification.md) was a flag-only operation. This record does not claim that any specific protocol version was observed live.

Mainnet and Testnet protocol schedules were not verified from an official source in this pass. Secondary reports list Protocol 28 as the latest mainnet vote and Protocol 30 votes for November 2026. Treat those reports as unverified.

## What the policy does not cover

- Offer-crossing changes at protocol 29 are outside this tool's model. Offers are removed by revocation, but offer matching is not simulated.
- Soroban, fee, and precondition changes do not affect the modeled effects, and RevokeTrace does not claim transaction success.
- A source review of one Core revision is not a proof of equivalence for later Core revisions.
- No independent third party reviewed this decision.

## Where the policy is enforced

- Offline snapshots: `validate_snapshot` in `src/lib.rs` returns an `unsupported protocol version` error, which becomes `UNSUPPORTED` and exit code 30.
- Live ledger header and stored capture validation: `check_protocol_version` in `src/evidence.rs` returns `DiscoveryError::UnsupportedProtocolVersion`, which maps to exit code 30.
- Missing version: warning `W_PROTOCOL_UNVERIFIED` and the limitation `protocol version evidence is unavailable`.

## Sources

- Stellar Core `ProtocolVersion.h` at the pin: https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/util/ProtocolVersion.h
- Stellar Core `TransactionUtils.cpp` at the pin: https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/transactions/TransactionUtils.cpp
- Stellar Core `HerderImpl.cpp` (`makeStellarValue`) at the pin: https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/herder/HerderImpl.cpp
- `stellar-xdr` at the crate commit: https://github.com/stellar/stellar-xdr/tree/9c9c145953e80990d6ff1ae3a6a973a0ce6d0694
- `stellar-xdr` at the Core submodule commit: https://github.com/stellar/stellar-xdr/tree/4f524bbac80c781c06e4fb5fc93a2d0d331d6705
- CAP-0038: https://github.com/stellar/stellar-protocol/blob/master/core/cap-0038.md
- Earlier review: [protocol compatibility](protocol-compatibility.md) and [Phase 4C verification](phase4c-protocol-verification.md).

All Core and XDR files above were fetched on 2026-10-30 and compared locally.
