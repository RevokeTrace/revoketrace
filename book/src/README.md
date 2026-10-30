# RevokeTrace

RevokeTrace is a read-only Rust CLI for forecasting the effects of Stellar Classic issuer authorization changes, including modeled CAP-0038 liquidity-pool redemptions.

It supports offline analysis of caller-supplied snapshots and bounded current-tip Stellar Testnet observations. It does not sign, construct, broadcast, or repair transactions.

**A forecast is not transaction approval.** `UNVERIFIED_FORECAST` is an internally modeled result with unresolved evidence limitations. `SUPPORTED_SAFE` is not emitted.

Start with [Getting started](getting-started.md), then read [Commands and reports](commands.md) and [Evidence and safety](evidence-and-safety.md).

[Source repository](https://github.com/RevokeTrace/revoketrace) · [Release notes](https://github.com/RevokeTrace/revoketrace/blob/main/CHANGELOG.md)
