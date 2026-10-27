# Problem validation

Research date: 2026-10-27.

## Proposed problem

An issuer's Classic `SetTrustLineFlags` or `AllowTrust` authorization change can have effects outside the directly named trustline: offers may be removed, pool-share positions can be force-redeemed, pool-share trustlines can disappear, claimable balances can be created, sponsors can inherit new reserve obligations, and the entire operation can fail. A pre-signing report needs to prove it has the relevant state before it says anything stronger than inconclusive.

This is a deterministic protocol-impact analysis problem, not issuer risk scoring, compliance eligibility, wallet monitoring, or a transaction submission service.

## What is predictable

- Whether the proposed flag transition crosses the maintain-liabilities boundary.
- Whether the operation is a supported Classic operation and whether issuer/account/asset identities are internally consistent.
- The affected pool-share set only when the input is complete and its source-completeness evidence is trustworthy.
- Per-pool integer redemption amounts, zero/one/two output count, trustline deletion, pool-entry deletion, and reserve-unit deltas.
- Claimable-balance preimage fields when operation source, sequence, operation index, pool ID, and asset are present.
- Known protocol failure classes when the relevant account balances, reserve counters, sponsorship relations, and limits are present.

## What remains conditional or unknown

- A live endpoint cannot prove it discovered every affected pool-share trustline merely by returning successful key lookups. The discovery manifest must identify the enumeration source and its completeness proof.
- Mixed-ledger reads, stale `lastModifiedLedgerSeq`, different network passphrases, and missing sponsorship extensions make the result inconclusive.
- A result called `SUPPORTED_SAFE` means “the modeled preconditions and reserve checks pass for the supplied snapshot”; it is not a guarantee of inclusion or future ledger state.
- Exact network result mapping and protocol capability flags need live XDR/core validation before being treated as stable API.

## Result semantics

| Internal classification | Meaning | Required behavior |
| --- | --- | --- |
| `SUPPORTED_SAFE` | Supported operation; complete, coherent snapshot; modeled result has no known blocking condition | Report predicted deltas and warnings; never call it network confirmation |
| `SUPPORTED_BLOCKED` | Supported operation; complete snapshot; a modeled protocol precondition or reserve/sponsorship limit fails | Report the blocking reason and affected entries |
| `INCONCLUSIVE` | A supported operation cannot be safely evaluated because required state is missing, stale, mixed-ledger, or discovery is incomplete | Fail closed; do not downgrade to safe |
| `UNSUPPORTED` | Operation, asset domain, protocol version, or state shape is outside the MVP implementation | Identify the exact unsupported feature |

## Stop conditions

Stop Phase 1 and report `STOP` if source inspection finds a materially equivalent approved implementation, if no credible completeness strategy can enumerate affected pool-share state, if protocol/version compatibility cannot be pinned, or if reserve arithmetic remains ambiguous. Current evidence does not meet those stop conditions, but it does require a conditional gate because Drips/GrantFox coverage is incomplete and no testnet reproduction exists.

## Sources and date-stamped reconnaissance

- CAP-0038: https://github.com/stellar/stellar-protocol/blob/master/core/cap-0038.md, accessed 2026-10-27.
- CAP-0035: https://github.com/stellar/stellar-protocol/blob/master/core/cap-0035.md, accessed 2026-10-27.
- CAP-0046-06: https://github.com/stellar/stellar-protocol/blob/master/core/cap-0046-06.md, accessed 2026-10-27.
- Drips Stellar Wave repository directory: https://www.drips.network/wave/stellar/repos, accessed 2026-10-27. The directory reports 843 approved repositories but is not a proof that no equivalent exists; direct search results were limited.
- GrantFox public contributor site: https://contribute.grantfox.xyz/, accessed 2026-10-27. The listing was not machine-verifiable in this spike; treat GrantFox equivalence/eligibility as unverified.
