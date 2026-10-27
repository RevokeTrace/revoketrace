# Ecosystem and competition reconnaissance

Research date: 2026-10-27. Repositories were inspected at source level from shallow clones where cloning completed; commit IDs are recorded for reproducibility. This is bounded reconnaissance, not an absolute uniqueness claim.

| Project | Observed source capability | Boundary versus RevokeTrace | Evidence |
| --- | --- | --- | --- |
| ReserveRoute | JavaScript engine plans sponsored credit-trustline reserve transfers/removals with integer stroop accounting, snapshot fingerprints, and explicit unsupported pool-share/claimable-balance limits. Snapshot says it is not a complete sponsorship inventory. | Adjacent reserve-transfer planning; it does not simulate issuer authorization transitions, CAP-0038 redemption, pool arithmetic, or generated claimable-balance effects. | https://github.com/reserveroute/reserveroute-engine; inspected commit `fdd7627`, `index.mjs`, `README.md`, `INTEGRATION.md`, 2026-10-27. |
| Compliance Primitives | Soroban contracts for denylist, jurisdiction, pause/freeze, and compliance aggregation. | On-chain policy/compliance controls, not a read-only Classic ledger impact simulator. | https://github.com/stellar-compliance-kit/compliance-primitives; inspected commit `8d0ee6a`, `ARCHITECTURE.md`, contracts, 2026-10-27. |
| Sylox | Soroban `RiskOracle` and event registry score issuer/asset signals including freezes, clawbacks, liquidity, and issuer actions. | Risk scoring and protection market; no deterministic preflight forecast of a single Classic authorization operation. | https://github.com/Sylox-labs/sylox; inspected commit `8915413`, `README.md`, `contracts/risk-oracle`, `event-registry`, 2026-10-27. |
| Stellar-Guard | Candidate adjacent project named in kickoff; this environment did not complete a reproducible source checkout, so its code-level capability is not certified here. | Treat as unverified adjacency until a source checkout and commit pin are recorded; do not use README-only evidence for uniqueness. | https://github.com/Virelis/Stellar-Guard; checkout incomplete on 2026-10-27. |

## Verdict

No inspected repository is materially equivalent to the proposed narrow mechanism. ReserveRoute is the closest engineering neighbor but explicitly leaves liquidity-pool shares and claimable balances unsupported. This is sufficient to continue the technical spike, not sufficient to claim uniqueness or program approval.

Drips reconnaissance is incomplete: the current public directory shows 843 approved Stellar repositories, but the page's search/filter surface and dynamic results do not provide a reliable exhaustive text query for the mechanism. GrantFox returned HTTP 403 to the research fetcher on 2026-10-27, so its records were not independently enumerable. Before submission, repeat both checks with saved query strings, timestamps, returned records, and uncertainty notes.

## Source links

- Drips: https://www.drips.network/wave/stellar/repos
- GrantFox: https://contribute.grantfox.xyz/
- CAP-0038: https://github.com/stellar/stellar-protocol/blob/master/core/cap-0038.md

## Search log

Access date for all searches: 2026-10-27. Search results are bounded evidence, not proof of global absence.

| Source | Exact query or method | Result |
| --- | --- | --- |
| GitHub repository search | `https://github.com/search?q=stellar+SetTrustLineFlags+liquidity+pool&type=repositories` | No materially equivalent repository identified in returned results. |
| GitHub code/search web query | `site:github.com Stellar "SetTrustLineFlags" "liquidity pool"` | Returned CAP-0038 and Stellar protocol/core sources; no equivalent product identified. |
| GitHub code/search web query | `site:github.com Stellar issuer revocation claimable balance sponsorship` | Returned protocol/core and adjacent sponsorship material; no equivalent preflight engine identified. |
| GitHub code/search web query | `site:github.com Stellar "AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG" pool` | Returned CAP-0038/CAP-0035 and core tests; no equivalent product identified. |
| Drips | Opened `https://www.drips.network/wave/stellar/repos`; used visible Search repos/filter surface for `revoke`, `authorization`, `liquidity`, `pool`, `sponsorship`, and `trustline` | Page reported 843 approved repositories. Dynamic search does not expose a reproducible exhaustive result export; no equivalent was verified. |
| GrantFox | Opened `https://contribute.grantfox.xyz/`; attempted public search/fetch for `Stellar`, `revocation`, `trustline`, `liquidity pool`, and `sponsorship` | Fetch returned HTTP 403. No conclusion about equivalence or eligibility is permitted. |
| GitHub source inspection | Shallow clones of ReserveRoute and Compliance Primitives; source-level inspection of relevant files and pinned commits | Adjacent/different mechanisms; details above. Sylox clone did not complete and Stellar-Guard checkout was unavailable, so those remain unverified in this pass. |

## Classification

- **Verified equivalent implementation:** none in the searched and accessible sources.
- **Adjacent but materially different:** ReserveRoute (sponsored reserve transfer/removal planning), Compliance Primitives (Soroban compliance contracts), Sylox (risk scoring/event registry).
- **No equivalent found in searched sources:** bounded GitHub and accessible Drips results only.
- **Not exhaustively checked:** GrantFox, inaccessible/incomplete repository checkouts, and the full dynamic Drips catalog.
