# Protocol and XDR compatibility matrix

Research date: 2026-10-27. This is evidence for the feasibility spike, not a production support claim.

## Pinned inputs and verification

| Component | Revision/version | Verification |
| --- | --- | --- |
| Stellar Core | `05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4` (`master`) | `git ls-remote https://github.com/stellar/stellar-core.git HEAD refs/heads/master` |
| Rust XDR baseline | `stellar-xdr 28.0.1`, tag `ced6bd3cc9f5d8d03445bdf0d7e907814822b370` | `cargo tree -i stellar-xdr`; `git ls-remote https://github.com/stellar/rs-stellar-xdr.git refs/tags/v28.0.1` |
| Rust XDR latest observed | `30.0.0`, tag `3c2aa43d2ab54d429ae44aa5143d805bf5dba7e2` | official [release page](https://github.com/stellar/rs-stellar-xdr/releases) and `git ls-remote` |
| Rust toolchain | `1.97.1` | `rustc --version`; [rust-toolchain.toml](../rust-toolchain.toml) |
| SDK dependencies | None | `Cargo.toml` contains `stellar-xdr`, `serde`, `serde_json`, `sha2`, and `hex`; no Stellar network SDK or submission client |

The crate deliberately remains pinned to 28.0.1. The 28.0.1 generated XDR types and the pinned-core source references are the only compatibility evidence exercised by this spike. The newer 30.0.0 release has not been compatibility-tested and is not silently substituted; its presence on the release page is not evidence that this evaluator supports protocol 30.

## Supported protocol boundary

| Behavior | Core/XDR evidence | Spike status |
| --- | --- | --- |
| `SetTrustLineFlagsOp` supported from protocol v17 | [`SetTrustLineFlagsOpFrame::isOpSupported`](https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/transactions/SetTrustLineFlagsOpFrame.cpp) | Source verified; no network capture |
| Pool-share redemption extension active from protocol v18 | [`removeOffersAndPoolShareTrustLines`](https://github.com/stellar/stellar-core/blob/05c6328c13b595c52b6ad1ecd1e69cd9b2a582d4/src/transactions/TransactionUtils.cpp) | Source verified |
| `AllowTrust` and `SetTrustLineFlags` low-reserve result codes | [CAP-0038](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0038.md), [XDR generated enums](https://github.com/stellar/rs-stellar-xdr/blob/v28.0.1/src/generated/allow_trust_result_code.rs) | Source verified |
| `opTOO_MANY_SPONSORING` | [XDR generated enum](https://github.com/stellar/rs-stellar-xdr/blob/v28.0.1/src/generated/operation_result_code.rs), current core transaction utility | Source verified |
| Source/issuer/trustor relationship | Current core `SetTrustLineFlagsOpFrame::doCheckValid` and `TrustFlagsOpFrameBase::doApply` | Spike now requires source = asset issuer, distinct trustor, exactly one matching target trustline, and exact code+issuer asset identity |
| SAC authorization behavior | [CAP-0046-06](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0046-06.md) | Explicitly unsupported |
| CAP-0077 validator freeze | [CAP catalog](https://github.com/stellar/stellar-protocol/blob/master/core/README.md) | Explicitly unsupported |

## Result mapping

The proof functions in `src/lib.rs` map authoritative XDR variants as follows:

- `AllowTrustResultCode::Success` → `SUPPORTED_SAFE` for the observed result only.
- `AllowTrustResultCode::{Malformed, NoTrustLine, TrustNotRequired, CantRevoke, SelfNotAllowed, LowReserve}` → `SUPPORTED_BLOCKED`.
- `SetTrustLineFlagsResultCode::Success` → `SUPPORTED_SAFE` for the observed result only.
- All defined non-success `SetTrustLineFlagsResultCode` variants → `SUPPORTED_BLOCKED`.
- `OperationResultCode::OpNotSupported` → `UNSUPPORTED`.
- `OperationResultCode::OpInner` → `INCONCLUSIVE` until its nested operation result is decoded.
- Other defined outer operation failures → `SUPPORTED_BLOCKED`.

These mappings do not convert an observed network success into a guarantee about a future transaction. The evaluator does not currently inspect a snapshot protocol-version field, so it must not claim network compatibility from these mappings alone. Unknown protocol versions, missing nested results, or unrecognized XDR values remain outside the supported mapping.

## Verification commands and result

```text
rtk cargo test
rtk proxy git ls-remote https://github.com/stellar/stellar-core.git HEAD refs/heads/master
rtk proxy git ls-remote https://github.com/stellar/rs-stellar-xdr.git refs/tags/v28.0.1 refs/tags/v30.0.0
```

The result-code and ID tests pass locally. `rustfmt` and `clippy` are not installed for the pinned toolchain, so those checks remain blocked by the environment.
