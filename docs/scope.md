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
  `BoundedCurrentTipRpc`, `LedgerConsistentIncomplete`, `CompleteAuthoritativeLedger` (reserved), and `InvalidOrContradictory`.
- Public RPC queries fetch `getLatestLedger` to extract authoritative `base_reserve` and `protocolVersion`
  from `headerXdr`, and parse `extXdr` on `getLedgerEntries` to extract ledger entry `sponsoring_id`.
- Strict sequence binding binds `header.ledger_seq == rpc.latest_ledger` with a bounded atomic retry loop,
  rejecting torn-state captures across ledger transitions.
- Caller-supplied booleans, enums, manifest digests, or labels can never promote evidence to authoritative completeness.
  `CompleteAuthoritativeLedger` is unreachable for caller-supplied snapshots until an independent capture verifier exists.
- The live demonstration verifies a bounded candidate set at the current network tip (`BoundedCurrentTipRpc`),
  not an independently complete ledger export.
- Treating a ledger-close delta (`LedgerCloseMeta`) as a complete state snapshot is rejected.
- When full historical state, complete sponsor account graphs, or base-reserve configurations are
  unverified, evidence remains bounded or incomplete. `SUPPORTED_SAFE` remains strictly unreachable.

Phase 4B implements exact reserve, sponsorship, and operation-context accounting:
- **Minimum-Balance Rules & Reserve Reuse**: Uses checked integer arithmetic for `units = 2 + subentries + num_sponsoring - num_sponsored`,
  incorporating selling and buying liabilities. Accurately distinguishes direct reserve reuse (allowing accounts below minimum reserve to reuse freed pool-share reserves without a new balance check) from active sponsorship sandwiches (which require balance solvency and sponsorship counter capacity checks on replacement sponsors).
- **Constituent Clawback Fail-Closed Verification**: Strictly verifies constituent credit trustlines in the ledger snapshot, rejecting missing, stale, or contradictory trustlines as `INCONCLUSIVE`.
- **Operation-Context Reconstruction**: Distinguishes transaction source from operation source,
  validates sequence ranges (`seq > 0 && seq <= i64::MAX`), encodes canonical `HashIdPreimage::PoolRevokeOpId` XDR preimages for CAP-0038 claimable-balance ID derivation,
  and outputs uncomputed ID indicators when transaction context is incomplete while failing closed on invalid supplied context.
- **Deterministic Ordering**: Canonical decoded 32-byte pool ID sorting mirrors Stellar Core's `std::sort(poolTLKeys)` to ensure deterministic reserve consumption across all platforms and hex casing.
- **Safety Boundary**: Blockers are classified as `SUPPORTED_BLOCKED` only when base reserve, sponsorship evidence, and discovery completeness are established; otherwise results fail closed as `INCONCLUSIVE`. `SUPPORTED_SAFE` remains strictly unreachable.

## Phase 4B status

Phase 4B implements and tests exact reserve accounting, deterministic sponsorship transitions, constituent clawback flag propagation, and operation-context reconstruction, backed by 117 unit tests and comprehensive testing across all target failure modes.

Safety boundaries remain strictly enforced:
- `SUPPORTED_SAFE` is unreachable without an independent authoritative capture verifier.
- Any missing or unproven operation context, mixed-ledger evidence, or sponsorship mismatch fails closed as `INCONCLUSIVE`.
- Phase 4C cannot begin until Phase 4B is merged into `main` following independent review.

## Historical feasibility spike status

The repository currently contains a deliberately small XDR decoder and offline evaluator as a feasibility spike. It is not yet the Phase 2 engine: it does not prove complete pool-share discovery, model every Classic ledger entry or sponsorship-sandwich transition, compute exact claimable-balance IDs, or validate all network result mappings. The pinned `stellar-xdr` 28.0.1 dependency is a baseline; the official release page currently shows 30.0.0, pending compatibility review.

The spike has no signing, transaction construction, network submission, capture adapter, or live-ledger mutation path. Its `UNVERIFIED_FORECAST` label means only that the supplied snapshot passed internally modeled checks; it is not a network-success prediction or operational safety guarantee.
