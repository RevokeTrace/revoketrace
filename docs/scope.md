# RevokeTrace scope

The command reference is [docs/cli.md](cli.md). This document records the current engine scope and protocol boundary. See [architecture](architecture.md) for the implemented design, [verification](verification.md) for claim evidence, and [maintenance](maintenance.md) for upkeep and releases. Historical design records remain under [research](../research/).

RevokeTrace is a read-only forecasting engine and CLI for Stellar Classic issuer authorization changes. v1.0.0 implements the bounded-evidence scope described here. It does not eliminate the stated evidence limitations.

## In scope

- Classic `SetTrustLineFlagsOp` and `AllowTrustOp` authorization transitions.
- `AUTHORIZED_FLAG`, `AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG`, revocability, and clawback-related Classic flags as validation inputs.
- CAP-0038 automatic redemption of affected Classic liquidity-pool share trustlines.
- Exact integer amounts, trustline, pool, claimable-balance, sponsorship, and reserve deltas.
- Immutable fixture and snapshot inputs with network, ledger, source, and completeness provenance.
- Offline JSON and plain-text reports with `UNVERIFIED_FORECAST`, `SUPPORTED_BLOCKED`, `INCONCLUSIVE`, and `UNSUPPORTED` classifications.

## Explicitly out of scope

RevokeTrace does not handle private keys, signing, transaction construction, broadcasting, automatic repair, policy enforcement, Soroban contract or SAC authorization interception, CAP-0077 validator freeze, databases, indexers, dashboards, hosted APIs, or generic risk and compliance scoring.

## Evidence model and safety boundary

The engine must fail closed. It can report `UNVERIFIED_FORECAST` when supplied data is internally coherent, but it cannot prove that every affected ledger entry was discovered. Missing pool discovery, missing sponsorship context, stale or mixed-ledger data, wrong network, unsupported protocol versions, and contradictory inputs must not become a safe result.

- Offline snapshots are caller-supplied and remain untrusted or incomplete.
- Live discovery uses Horizon for bounded candidate enumeration and a single-batch current-tip RPC read. It is classified as `BOUNDED_CURRENT_TIP_RPC`, not as a complete historical ledger export.
- Evidence classifications are derived from validated properties. Caller-supplied labels, manifests, or authority claims cannot produce `COMPLETE_AUTHORITATIVE_LEDGER`.
- `SUPPORTED_BLOCKED` is a modeled protocol or reserve and sponsorship blocker, not a complete transaction preflight result.
- Protocol versions 18 to 29 are evaluated; other versions are `UNSUPPORTED`. A missing protocol version produces `W_PROTOCOL_UNVERIFIED`. See the [protocol support decision](../research/protocol-support-decision.md).
- `SUPPORTED_SAFE` is unreachable until an independent authoritative capture verifier exists.
- `inspect` validates a report envelope only. It does not authenticate provenance, recompute the forecast, or approve a transaction.

The protocol matrix, pinned Stellar Core reference, Testnet fixture provenance, and remaining limitations are maintained in [research/phase4c-protocol-verification.md](../research/phase4c-protocol-verification.md). The evidence-adapter boundary is described in [research/authoritative-evidence-audit.md](../research/authoritative-evidence-audit.md).

## Historical phase records

Milestones 1 through 6 are merged and audited. Some research files preserve statements such as "Phase 2 remains blocked" or "Phase 4C cannot begin" because those statements describe the repository at the time of the earlier investigation. They are historical records, not the current project status. Current contributor-facing guidance is in [CONTRIBUTING.md](../CONTRIBUTING.md).
