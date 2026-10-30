# Ecosystem comparison and program eligibility, 2026-10-30

This updates [the 2026-10-27 reconnaissance](ecosystem-recon.md), which stays as the historical record. It does not claim that RevokeTrace is unique, approved, or eligible for any program.

## Method and limits

- Four comparator repositories from the earlier pass were cloned shallowly on 2026-10-30 and inspected at the pinned commits below. Their code was not executed.
- Mechanism terms (`AllowTrust`, `SetTrustLineFlags`, `AUTHORIZED_TO_MAINTAIN`, liquidity pool, claimable balance, sponsor, revoke, CAP-0038, clawback) were searched in each clone with `git grep`. A term count shows where a mechanism is absent. It does not show quality.
- Web search results are summaries produced by a search tool. They are secondary evidence and are marked as such.
- `docs.drips.network` and `communityfund.stellar.org` did not resolve from the research environment because they are outside its allowed network domains. Official Drips and Stellar Community Fund pages could not be read. Nothing below about those programs comes from an official page opened in this pass.
- A search that returns no match is not proof that nothing exists anywhere.

## Comparators

| Comparator | Verified source and date | Implemented capability | Material overlap | Important difference | Independently verified | Remaining uncertainty |
| --- | --- | --- | --- | --- | --- | --- |
| ReserveRoute engine | https://github.com/reserveroute/reserveroute-engine at `fdd7627` (committed 2026-10-23), checked 2026-10-30 | JavaScript planner for sponsored-reserve transfers and removals of credit trustlines, with integer stroop accounting. Its README states it is not a complete sponsorship inventory. | Reserve and sponsorship accounting for trustlines. | No `AllowTrust` or `SetTrustLineFlags`, no liquidity pool code, no revocation logic (zero matches). Claimable balances appear only as an unsupported entry type. | Yes, by source search | Its separate backend and other components were not inspected. |
| Compliance Primitives | https://github.com/stellar-compliance-kit/compliance-primitives at `8d0ee6a` (2026-10-26) | Soroban contracts for allowlist, denylist, and jurisdiction gating. | None found. | On-chain Soroban policy. None of the mechanism terms appear. | Yes, by source search | Large repository (630 files). Only term searches and the README were read. |
| Sylox | https://github.com/Sylox-labs/sylox at `8915413` (2026-10-23) | Risk scoring and a protection market for anchor-issued tokens. Reads Horizon asset statistics that include `authorized_to_maintain_liabilities` balances. | Reads authorization-related balances as a risk signal. | No operation-level forecast, no pool redemption, no sponsorship model. Testnet only per its README. | Yes, by source search | Large repository (389 files). Only term searches and the README were read. |
| Stellar-Guard | https://github.com/Virelis/Stellar-Guard at `5e8c317` (2026-05-28) | Soroban multisig governance for CAP-0077 freeze proposals. Its README says the underlying `freeze_entry` host function is not available on Testnet. | None found. | Different mechanism (CAP-0077 quorum freeze), not CAP-0038 revocation. | Yes, by source search | The earlier pass could not check this repository out. This pass could. |
| Horizon and Hubble effect records | https://developers.stellar.org/docs/data/hubble/data-catalog/data-dictionary/liquidity-pools and https://docs.dune.com/data-catalog/stellar/history_effects, via search summaries on 2026-10-30 | After-the-fact records of revocation effects, including revoked pool reserves and claimable balance IDs. | Describes the same on-ledger outcome. | Reports what happened. It does not forecast an operation before it is submitted. | No, search summaries only | Pages not opened directly. |
| Stellar RPC `simulateTransaction` and SDK simulation | Search results on 2026-10-30 | Described for Soroban invocation. | Possible preflight overlap. | The search did not show that it covers Classic operations such as `SetTrustLineFlags`. | No | Needs a direct read of the Stellar RPC documentation. |

### Conclusion

- Exact or material equivalent: none found in the sources searched.
- Adjacent projects: ReserveRoute (reserve accounting), Sylox (risk signals), Horizon and Hubble effects (after-the-fact records).
- Partial overlap: none that implements the CAP-0038 forecast.
- Unverified: whether RPC simulation covers Classic operations, and any project not returned by the searches.

This supports saying that no equivalent was found in the searched sources. It does not support saying that none exists.

## Programs

### Drips (Stellar Wave)

| Question | Finding | Source |
| --- | --- | --- |
| Official documentation | BLOCKED. `docs.drips.network` did not resolve from the research environment. | Fetch attempt, 2026-10-30 |
| Repository approval | Search summaries of the Drips maintainer documentation say repository applications need approval from the Wave Program organizers, and that the organizer keeps sole discretion over which repositories are admitted. | Search summary, 2026-10-30, citing https://docs.drips.network/wave/maintainers/participating-in-a-wave and https://docs.drips.network/wave/terms-and-rules |
| Issue publication | The same summaries say issues can be labeled for a Wave only after the repository is approved for that Wave. | Same |
| Current submission window and program status | NOT VERIFIED. No official page was read. | |
| Contribution and reward rules | NOT VERIFIED. | |
| Approved projects | The 2026-10-27 pass saw 843 approved Stellar repositories on https://www.drips.network/wave/stellar/repos but could not search them reliably. Whether RevokeTrace is listed was not established. | [ecosystem-recon.md](ecosystem-recon.md) |
| RevokeTrace status | NOT VERIFIED. There is no evidence in this repository that it has applied or been approved. | |

### GrantFox

| Question | Finding | Source |
| --- | --- | --- |
| Official documentation | BLOCKED. The 2026-10-27 pass received HTTP 403 from https://contribute.grantfox.xyz/. `communityfund.stellar.org` did not resolve on 2026-10-30. | [ecosystem-recon.md](ecosystem-recon.md), fetch attempt |
| What it is | A search summary of a Stellar Community Fund page describes GrantFox as a collaboration platform for Stellar projects and contributors that syncs with GitHub, and calls it an early-stage beta. | Search summary, 2026-10-30, citing https://communityfund.stellar.org/project/grantfox-4zq |
| Eligibility, repository submission, issue rules | NOT VERIFIED. The search found no eligibility or submission rules. | |
| RevokeTrace status | NOT VERIFIED. | |

## Program readiness labels

| Program | Label | Reason |
| --- | --- | --- |
| Drips | NOT VERIFIED | Official rules and the submission window could not be read. Secondary sources say approval is discretionary and required before issues are published. |
| GrantFox | NOT VERIFIED | No eligibility or submission rules were found. |

No application was submitted, and no issues were created for either program. Do not publish issues on this repository for a program until its current pre-approval rules have been read from the official source.

## Remaining actions for a maintainer

1. Allow `docs.drips.network` and `communityfund.stellar.org` in the research environment, or read them directly, and record the submission window, eligibility rules, and issue rules here.
2. Open GrantFox directly and record what it requires.
3. Check the Stellar RPC documentation for whether `simulateTransaction` covers Classic operations.
