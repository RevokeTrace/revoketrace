# Architecture

RevokeTrace is a local Rust CLI and forecasting engine. It reads either a caller-supplied snapshot or a bounded Testnet observation, validates that evidence, forecasts the requested Classic authorization transition, then produces a deterministic text or JSON report.

The main workflow is:

1. `analyze` reads a bounded local snapshot, while `live` asks Horizon for candidate pool-share balances and Stellar RPC for a bounded same-ledger entry set.
2. The evidence adapter validates identities, XDR, ledger sequences, canonical pool IDs, and relevant counters.
3. The engine models authorization flags, CAP-0038 withdrawals, claimable-balance IDs when operation context is complete, sponsorship, reserves, and pool deletion where the required evidence exists.
4. The report layer emits schema-1 JSON or readable text with explicit limitations.

`inspect` is intentionally different: it validates and renders a saved report envelope but does not recompute it, authenticate it, or promote its provenance.

The project has no wallet, private-key handling, signing, transaction construction, broadcasting, database, indexer, backend, or dashboard. The bounded live adapter is not a ledger-completeness service.

For module responsibilities, the data-flow diagram, trust boundaries, and interface details, read the [current architecture document](https://github.com/RevokeTrace/revoketrace/blob/main/docs/architecture.md).
