# Ecosystem and competition reconnaissance

Research date: 2026-10-27. Repositories were inspected at source level from shallow clones; commit IDs are recorded for reproducibility. This is bounded reconnaissance, not an absolute uniqueness claim.

| Project | Observed source capability | Boundary versus RevokeTrace | Evidence |
| --- | --- | --- | --- |
| ReserveRoute | JavaScript engine plans sponsored credit-trustline reserve transfers/removals with integer stroop accounting, snapshot fingerprints, and explicit unsupported pool-share/claimable-balance limits. Snapshot says it is not a complete sponsorship inventory. | Adjacent reserve-transfer planning; it does not simulate issuer authorization transitions, CAP-0038 redemption, pool arithmetic, or generated claimable-balance effects. | https://github.com/reserveroute/reserveroute-engine; inspected commit `fdd7627`, `index.mjs`, `README.md`, `INTEGRATION.md`, 2026-10-27. |
| Compliance Primitives | Soroban contracts for denylist, jurisdiction, pause/freeze, and compliance aggregation. | On-chain policy/compliance controls, not a read-only Classic ledger impact simulator. | https://github.com/stellar-compliance-kit/compliance-primitives; inspected commit `8d0ee6a`, `ARCHITECTURE.md`, contracts, 2026-10-27. |
| Sylox | Soroban `RiskOracle` and event registry score issuer/asset signals including freezes, clawbacks, liquidity, and issuer actions. | Risk scoring and protection market; no deterministic preflight forecast of a single Classic authorization operation. | https://github.com/Sylox-labs/sylox; inspected commit `8915413`, `README.md`, `contracts/risk-oracle`, `event-registry`, 2026-10-27. |
| Stellar-Guard | UI/backend/Soroban governance for CAP-0077 quorum freeze proposals; source includes build/submit routes and a freeze-governance contract. | Governance-controlled freeze mechanism, explicitly outside issuer-initiated Classic authorization and outside this MVP. | https://github.com/Virelis/Stellar-Guard; inspected commit `5e8c317`, `README.md`, `backend/src/routes/freeze.ts`, 2026-10-27. |

## Verdict

No inspected repository is materially equivalent to the proposed narrow mechanism. ReserveRoute is the closest engineering neighbor but explicitly leaves liquidity-pool shares and claimable balances unsupported. This is sufficient to continue the technical spike, not sufficient to claim uniqueness or program approval.

Drips reconnaissance is incomplete: the current public directory shows 843 approved Stellar repositories, but the page's search/filter surface and dynamic results do not provide a reliable exhaustive text query for the mechanism. GrantFox was not independently enumerable in this environment. Before submission, repeat both checks with saved query strings, timestamps, returned records, and uncertainty notes.

## Source links

- Drips: https://www.drips.network/wave/stellar/repos
- GrantFox: https://contribute.grantfox.xyz/
- CAP-0038: https://github.com/stellar/stellar-protocol/blob/master/core/cap-0038.md
