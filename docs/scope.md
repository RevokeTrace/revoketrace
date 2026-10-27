# RevokeTrace scope

RevokeTrace is a read-only preflight engine for Stellar Classic issuer authorization changes. Phase 1 establishes the protocol boundary and feasibility; later phases may implement the engine and CLI only if this gate remains valid.

## In scope for the MVP

- Classic `SetTrustLineFlagsOp` and `AllowTrustOp` authorization transitions.
- `AUTHORIZED_FLAG`, `AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG`, revocability, and clawback-related Classic flags as inputs to validation.
- CAP-0038 automatic redemption of affected Classic liquidity-pool share trustlines.
- Exact integer amounts, trustline/pool/claimable-balance/sponsorship/reserve deltas.
- Immutable fixture/snapshot inputs with network, ledger, source, and completeness provenance.
- Offline JSON/plain-text reports with `SUPPORTED_SAFE`, `SUPPORTED_BLOCKED`, `INCONCLUSIVE`, and `UNSUPPORTED`.

## Explicitly out of scope

No private keys, signing, transaction construction, broadcasting, automatic repair, policy enforcement, Soroban contract/SAC authorization interception, CAP-0077 validator freeze, database/indexer/dashboard/API, or generic risk/compliance scoring.

## Safety boundary

The engine must fail closed. `SUPPORTED_SAFE` is a forecast against a complete, coherent snapshot and never means that the network will accept, include, or preserve the operation. Missing pool discovery, missing sponsorship context, stale/mixed-ledger data, wrong network, unsupported protocol version, or unvalidated result mappings must not produce SAFE.

## Phase 1 status

The repository currently contains a deliberately small XDR decoder and offline evaluator as a feasibility spike. It is not yet the Phase 2 engine: it does not prove complete pool-share discovery, model every Classic ledger entry or sponsorship-sandwich transition, compute exact claimable-balance IDs, or validate all network result mappings. The pinned `stellar-xdr` 28.0.1 dependency is a baseline; the official release page currently shows 30.0.0, pending compatibility review.

The spike has no signing, transaction construction, network submission, capture adapter, or live-ledger mutation path. Its `SUPPORTED_SAFE` label means only that the supplied synthetic snapshot passed the currently modeled checks; it is not a network-success prediction or operational safety guarantee.
