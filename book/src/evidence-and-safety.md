# Evidence and safety

RevokeTrace models Stellar Classic authorization changes using validated snapshots and conservative classification. Its live adapter enumerates candidate pools through Horizon and verifies a bounded batch of ledger entries through Stellar RPC.

**This does not prove exhaustive pool discovery or historical ledger completeness.** Caller-supplied labels, manifest digests and saved reports cannot make a snapshot authoritative.

- `UNVERIFIED_FORECAST` means the modeled result has unresolved evidence limitations.
- `SUPPORTED_BLOCKED` means a modeled supported blocker was identified, not that every transaction precondition was checked.
- `INCONCLUSIVE` means required evidence is missing, malformed or contradictory.
- `UNSUPPORTED` means the requested operation or protocol is outside the supported scope.
- `SUPPORTED_SAFE` remains unreachable.

Known limitations include incomplete verification of full multi-operation sponsorship handoffs, lack of a live forced-redemption fixture covering every modeled effect, and no authoritative transaction-success preflight.

For the exact protocol verification matrix and fixture provenance, see [Phase 4C protocol verification](https://github.com/RevokeTrace/revoketrace/blob/main/research/phase4c-protocol-verification.md). For scope, see [Scope](https://github.com/RevokeTrace/revoketrace/blob/main/docs/scope.md).

RevokeTrace does not handle private keys, transaction signing, transaction construction, broadcasting, or automatic repair.
