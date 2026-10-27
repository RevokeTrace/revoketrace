# RevokeTrace scope

RevokeTrace is a read-only preflight engine for Stellar Classic issuer authorization changes. Phase 1 establishes the protocol boundary and feasibility; later phases may implement the engine and CLI only if this gate remains valid.

## In scope for the MVP

- Classic `SetTrustLineFlagsOp` and `AllowTrustOp` authorization transitions.
- `AUTHORIZED_FLAG`, `AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG`, revocability, and clawback-related Classic flags as inputs to validation.
- CAP-0038 automatic redemption of affected Classic liquidity-pool share trustlines.
- Exact integer amounts, trustline/pool/claimable-balance/sponsorship/reserve deltas.
- Immutable fixture/snapshot inputs with network, ledger, source, and completeness provenance.
- Offline JSON/plain-text reports with `UNVERIFIED_FORECAST`, `SUPPORTED_BLOCKED`, `INCONCLUSIVE`, and `UNSUPPORTED`. `SUPPORTED_SAFE` is reserved for a future independently verified ledger capture.

## Explicitly out of scope

No private keys, signing, transaction construction, broadcasting, automatic repair, policy enforcement, Soroban contract/SAC authorization interception, CAP-0077 validator freeze, database/indexer/dashboard/API, or generic risk/compliance scoring.

## Safety boundary

The engine must fail closed. The current spike can report `UNVERIFIED_FORECAST` when supplied data is internally coherent, but it cannot prove that every affected ledger entry was discovered. Missing pool discovery, missing sponsorship context, stale/mixed-ledger data, wrong network, unsupported protocol version, or unvalidated result mappings must produce `INCONCLUSIVE`. No current code path produces `SUPPORTED_SAFE`.

The Phase 1C discovery prototype validated a bounded single-batch RPC response against exact
requested keys and decoded XDR identities. Phase 4A establishes the authoritative ledger evidence
adapter and trust model:
- Evidence classifications are strictly derived from verified properties: `UntrustedCandidate`,
  `BoundedCurrentTipRpc`, `LedgerConsistentIncomplete`, `CompleteAuthoritativeLedger`, and `InvalidOrContradictory`.
- Public RPC queries fetch `getLatestLedger` to extract authoritative `base_reserve` and `protocolVersion`
  from `headerXdr`, and parse `extXdr` on `getLedgerEntries` to extract ledger entry `sponsoring_id`.
- Caller-supplied labels cannot promote evidence to authoritative status.
- Treating a ledger-close delta (`LedgerCloseMeta`) as a complete state snapshot is rejected.
- When full historical state, complete sponsor account graphs, or base-reserve configurations are
  unverified, evidence remains bounded or incomplete. `SUPPORTED_SAFE` remains unreachable.

## Phase 1 status

The repository currently contains a deliberately small XDR decoder and offline evaluator as a feasibility spike. It is not yet the Phase 2 engine: it does not prove complete pool-share discovery, model every Classic ledger entry or sponsorship-sandwich transition, compute exact claimable-balance IDs, or validate all network result mappings. The pinned `stellar-xdr` 28.0.1 dependency is a baseline; the official release page currently shows 30.0.0, pending compatibility review.

The spike has no signing, transaction construction, network submission, capture adapter, or live-ledger mutation path. Its `UNVERIFIED_FORECAST` label means only that the supplied snapshot passed internally modeled checks; it is not a network-success prediction or operational safety guarantee.
