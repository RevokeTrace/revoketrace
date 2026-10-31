# Program eligibility and ecosystem review, 2026-10-31

## Scope and evidence date

This review was made on 2026-10-31 against RevokeTrace `main` at `1b31580fc634343a62b278566b0b510c81ce241e`. GitHub reports that the repository was created at `2026-10-27T07:25:59Z`. PRs #1 through #20 are merged. The review covers public program information and repository-level evidence. It does not inspect a maintainer's private Drips or GrantFox account, submit an application, request identity documents, or establish approval.

Program pages and rules can change. The links below are the official sources checked for this dated snapshot. Search results and partially rendered project directories are not proof that a project is absent from a complete program catalog.

## Drips Stellar Wave

### Current public status

The [official Stellar Wave page](https://www.drips.network/wave/stellar) displayed Wave 10 as the latest cycle, dated October 15 to October 22, 2026, and stated that there were no active or upcoming Waves when checked. It described the Stellar Wave as a recurring program, but supplied no next start date. Therefore:

- The Stellar Wave Program exists and has run recent cycles.
- No contributor work could be placed into an active or announced upcoming cycle on the checked public page.
- Whether the maintainer app is currently accepting repository applications for a future cycle is **NOT VERIFIED**. The public documentation describes an application process, but the account-specific repository selection and limits require the Drips app.

The repository directory displayed 839 repositories approved for the Stellar Wave Program. The page has a search field, but its text response exposed only part of the directory and no reproducible full-result export. A text search of the returned page did not find `RevokeTrace`; that is not evidence that the repository is absent from all approved records. RevokeTrace's approved status is **NOT VERIFIED**.

### Public repository onboarding and issue rules

The [maintainer guide](https://docs.drips.network/wave/maintainers/participating-in-a-wave/) says the maintainer signs in with GitHub, onboards the hosting organization, installs the Drips Wave GitHub App, selects public repositories to sync, and applies those repositories to a specific Wave Program. Organizers approve or reject each repository, and the app provides the status. Organizers retain discretion over admission under the [terms](https://docs.drips.network/wave/terms-and-rules/).

Issues become available to add to a Wave after repository approval. Applying the `Stellar Wave` label is only effective for an approved repository. Maintainers select issue complexity. The guide currently lists base point values of 100, 150, and 200 for Trivial, Medium, and High. The [maintainer FAQ](https://docs.drips.network/wave/maintainers/faq/) advises scoping issues before a cycle, reviewing applications during the week-long Wave, and merging work in time for points to count. Terms prohibit low-effort or bad-faith work, including trivial changes submitted solely to earn points and low-quality, untested, or misunderstood generated contributions.

Application caps are cycle-specific. The [application-limits guide](https://docs.drips.network/wave/maintainers/repo-application-limits/) says a program may set per-user and per-organization limits, either, both, or neither. The configured allowance is displayed in the application flow. No current numeric limit was available without account access.

If an application is rejected, the public guide requires an in-app appeal rather than a new application. It describes a two-week wait before the first appeal, a one-month wait after an unsuccessful appeal, and a maximum of three appeals per repository. The terms also set individual participant conditions, including age/adult status and sanctions-related restrictions; reward allocation can require KYC/KYB. Those are maintainer or participant checks. This review did not request or handle identity information.

### RevokeTrace status

No application or approval record is present in the repository or the public GitHub records reviewed. That does not reveal whether a maintainer has made a private application. The correct program verdict is **ELIGIBILITY NOT VERIFIED**.

The next maintainer action, if desired, is to sign in to the Drips app, inspect the RevokeTrace organization and repository status and current cycle limits, and confirm whether an application for the Stellar Wave Program can be submitted for a future cycle. Do not add Wave labels or present issues as funded before repository approval and an active Wave are confirmed.

The official [HackMeridian onboarding page](https://landing.drips.network/hackmeridian/) describes a special cohort with a November 7 application date. It is limited to projects built at HackMeridian. No evidence reviewed here establishes that RevokeTrace was built or accepted there, so this cohort is not treated as applicable.

## GrantFox OSS Contributions

### Platform and application process

The public [GrantFox Open Source page](https://www.grantfox.xyz/open-source) was available and displayed a project directory count of 74, a project search field, and featured projects. The public contributor application root returned HTTP 200 during this review. Account and project onboarding require GitHub sign-in; this review did not sign in or inspect private onboarding state. The public response does not establish that new project applications are currently being accepted. The platform's [official documentation index](https://docs.grantfox.xyz/llms.txt) exposes a current maintainer guide.

The [Create Your Project guide](https://docs.grantfox.xyz/user-manual-guides/oss-contributions-guide/maintainer-guide/create-your-project.md) says a maintainer connects a GitHub account, selects a project/repository available to that account, completes a project application form, and supplies a required video pitch of about five minutes in English or Spanish. It gives repository age of one to two months and consistent development activity as a general guideline, not a guaranteed admission rule. The guide describes a review that can approve a project or reject it with feedback. This is a manual review, not automatic approval.

After project creation, the [Adding Repos guide](https://docs.grantfox.xyz/user-manual-guides/oss-contributions-guide/maintainer-guide/maintaining-your-project/adding-repos.md) says public, non-hidden GitHub repositories can be selected and synced. Repository addition alone does not add work to a campaign. If a Campaign is active, the repository must also be registered to it for issues to appear in that Campaign. The [Campaigns guide](https://docs.grantfox.xyz/oss-contributions/campaigns.md) describes campaign-specific participation windows, issue registration, contributor assignments, pull requests, review, and post-campaign reward processing.

The reviewed public material did not establish a current Campaign date, a general geography or programming-language eligibility rule, or that an active funded campaign is currently accepting new projects. It did not state that issues must predate account registration; it does describe active Campaign repositories publishing and registering issues. These details remain **NOT VERIFIED** where not stated in the guides. The public site advertises OSS issue discovery and the documentation describes campaign-specific visibility. Contributors can still make ordinary GitHub contributions, but no GrantFox campaign reward is established without the applicable campaign and its rules. The public marketing page and maintainer guide are consistent about project discovery and GitHub integration; the account-specific acceptance state remains unknown.

The [rejection guide](https://docs.grantfox.xyz/user-manual-guides/oss-contributions-guide/maintainer-guide/if-your-project-is-rejected.md) says projects rejected for one campaign may reapply after a wait: at least one campaign after the first rejection, two after the second, and four after the third; after a fourth rejection the project cannot apply again. It states that reapplication does not guarantee approval.

### RevokeTrace status and current blocker

The GitHub API reports that the RevokeTrace repository was created on October 27, four days before this review. That is materially younger than GrantFox's one-to-two-month repository-age guideline, which the guide presents as guidance rather than a fixed eligibility cutoff. The required short pitch video is also not present in the submission materials. On the evidence available, RevokeTrace is **NOT READY TO APPLY** to GrantFox OSS Contributions. A maintainer can reassess after the repository has aged beyond the guideline and the required project pitch is prepared, and should confirm current intake and Campaign status in the public platform or signed-in flow.

The public directory displayed six featured cards out of 74 projects and did not contain the text `RevokeTrace` in its rendered response. The complete directory search was not independently enumerable here. No conclusion that RevokeTrace is or is not listed is justified. The app account status, any prior application, campaign registration, and approval are private or otherwise **NOT VERIFIED**.

The [Stellar Community Fund entry for GrantFox](https://communityfund.stellar.org/project/grantfox-4zq) is a grant/program record about GrantFox itself. It is not a GrantFox OSS project approval for RevokeTrace and does not imply any RevokeTrace grant or eligibility.

## Material overlap review

The classifications below describe mechanisms, not project quality. Source references are pinned to the checked commit where source was inspected. Searches did not enumerate every Stellar project or every program-approved repository, so this is a bounded comparison rather than an exclusivity claim.

| Project | Source and pinned revision | Evidence method | Implemented mechanism | Overlap classification | Program listing status |
| --- | --- | --- | --- | --- | --- |
| Stellar CLI | [`stellar/stellar-cli` at `90a3d42d9327ccfaa0d301373766f45beae3e6d9`](https://github.com/stellar/stellar-cli/tree/90a3d42d9327ccfaa0d301373766f45beae3e6d9) | General-purpose CLI; source review of command modules and README | General Stellar transaction, account, contract, and network operations. Includes transaction build, simulate, sign, submit workflows. | `ADJACENT`. Not a read-only forecast of CAP-0038 pool effects, evidence coverage, or sponsorship outcomes. Not every simulation path was reviewed for Classic effects. | Drips/GrantFox listing not checked. |
| Stellar Lab | [Official site](https://lab.stellar.org/) | Official product description, not source code | Web interface for building, importing, inspecting, simulating, and submitting Stellar transactions and interacting with endpoints. | `ADJACENT`. The public description does not establish RevokeTrace's offline evidence checks and specialized CAP-0038 impact model. | Drips/GrantFox listing not checked. |
| `stellarguard/multisig-utils` | [`src/lib/multisig.ts` at `0ffbb57f6930b26ceb80cf50300156e310dc55b8`](https://github.com/stellarguard/multisig-utils/blob/0ffbb57f6930b26ceb80cf50300156e310dc55b8/src/lib/multisig.ts), and its [README](https://github.com/stellarguard/multisig-utils/blob/0ffbb57f6930b26ceb80cf50300156e310dc55b8/README.md) | Direct source and README inspection | TypeScript utility evaluates whether transaction signatures meet current signer weights and operation threshold categories. README identifies limitations when earlier operations alter signer/account state. | `PARTIAL OVERLAP`. It evaluates needed signatures; it does not model issuer revocation, CAP-0038 withdrawal, claimable balances, or reserve/sponsorship effects. | Drips/GrantFox listing not checked. |
| ReserveRoute engine | [`index.mjs` at `fdd7627d9c850e707fb34b0061a0b6675ce2509a`](https://github.com/reserveroute/reserveroute-engine/blob/fdd7627d9c850e707fb34b0061a0b6675ce2509a/index.mjs) and its [scope statement](https://github.com/reserveroute/reserveroute-engine/blob/fdd7627d9c850e707fb34b0061a0b6675ce2509a/README.md) | Direct source and README inspection | Plans transfers/removals of sponsored credit trustlines and computes related reserve effects. Implementation bounds entry types and says it is not a complete sponsorship inventory. | `PARTIAL OVERLAP`. Shared reserve/sponsorship reasoning. No issuer authorization changes, pool discovery, CAP-0038 redemption, or claimable-balance forecast. | Drips/GrantFox listing not checked. |
| SEP-30 and Stellar Recoverysigner | [SEP-0030 at Stellar Protocol commit `62a67297ea14562ada30702d7e0f9d1cfbbfd2fa`](https://github.com/stellar/stellar-protocol/blob/62a67297ea14562ada30702d7e0f9d1cfbbfd2fa/ecosystem/sep-0030.md); [SDF explanation](https://stellar.org/blog/developers/sep-30-recoverysigner-user-friendly-key-management) | Protocol specification and SDF technical explanation | Multi-party account recovery uses authenticated recovery services and account signers to help restore control after key loss. | `DISTINCT MECHANISM`. Recovery and signing protocol, not an issuer-side impact forecast. RevokeTrace handles no keys. | Not a repository application; no Drips/GrantFox status asserted. |
| Sylox | [`Sylox-labs/sylox` at `891541383e73c315dc140e2e762af52b9f2330d7`](https://github.com/Sylox-labs/sylox/tree/891541383e73c315dc140e2e762af52b9f2330d7), including risk-oracle source | Direct source and README inspection | Soroban risk scoring and protection-market concepts use issuer actions, liquidity, and market signals. | `ADJACENT`. Authorization events and liquidity are risk inputs, not deterministic simulation of one Classic operation's ledger effects. | Drips/GrantFox listing not checked. |
| Stellar Compliance Primitives | [`stellar-compliance-kit/compliance-primitives` at `8d0ee6aeec5e6289c4e758b264cf023c0f8079d1`](https://github.com/stellar-compliance-kit/compliance-primitives/tree/8d0ee6aeec5e6289c4e758b264cf023c0f8079d1), contracts and README | Direct source and README inspection | Soroban allowlist, denylist, and jurisdiction controls enforce application policy. | `DISTINCT MECHANISM`. On-chain policy enforcement does not forecast the Classic issuer operation. | Drips/GrantFox listing not checked. |
| Trustless OSS, visible in GrantFox's featured directory | [`Trustless-OSS/Trustless-OSS` at `0538532c87f95b94a74590d7abcaa5e52e043521`](https://github.com/Trustless-OSS/Trustless-OSS/tree/0538532c87f95b94a74590d7abcaa5e52e043521), app routes and escrow integrations | Direct source repository and public GrantFox directory listing | GitHub issue bounties connect merged pull requests to Stellar USDC escrow payout workflows. | `ADJACENT`. Contributor incentives and escrow settlement, not Classic trustline authorization or CAP-0038 forecasting. Wallet and transaction workflows are outside RevokeTrace's scope. | Confirmed visible on GrantFox's public directory; Drips listing not checked. |
| Stellar-Guard | Previously inspected commit `5e8c317` in the 2026-10-30 record; current public URL returned 404 | Historical source inspection only | Historical repository description covered Soroban multisig governance for a freeze proposal. | `UNVERIFIED` as a current project. Historical comparison is not treated as current source evidence. | Current public listing not checked. |

No materially equivalent implementation was confirmed in the code and public materials examined. `stellarguard/multisig-utils` is the closest authorization-specific partial overlap; ReserveRoute is the closest reserve-accounting overlap. This bounded review does not establish that no equivalent exists, and it does not establish approval by Drips or GrantFox. The Drips directory and full GrantFox project search were not exhaustively enumerable in the public responses available to this review.

## Readiness summary

| Dimension | Status | Evidence and remaining condition |
| --- | --- | --- |
| Code and test readiness | **READY for technical review** | Candidate `main` `1b31580fc634343a62b278566b0b510c81ce241e`; 202 locked tests and requested Rust checks passed locally; current `main` Rust CI passed. This is not an external security audit. |
| Evidence and demonstration readiness | **CONDITIONALLY READY** | Retained bounded live CLI stdout/stderr and metadata are linked from the [observation record](testnet-live-observation-2026-10-31.md). The run was on PR source `9a419eb...`, exited 10, and was `UNVERIFIED_FORECAST`. It is not forced-redemption execution or exhaustive discovery. A current-source offline demo from a clean clone at `1b31580` is preserved in [`submission/demo/transcript-1b31580.txt`](../submission/demo/transcript-1b31580.txt); it uses a stored fixture, not fresh network data. After an initial timed-out request, direct `curl` checks on 2026-10-31 returned HTTP 200 for the published root and each of the seven `SUMMARY.md` chapters. |
| Drips repository eligibility | **ELIGIBILITY NOT VERIFIED** | No upcoming Wave shown; approved-repository and maintainer-app status require a private app check. |
| GrantFox project eligibility | **NOT READY TO APPLY** | Public guide age guideline is one to two months; the repository was four days old. The required pitch video is not prepared in this pack. |
| Application or approval status | **NOT VERIFIED** | No public or repository application/approval record was found. This review made no application. Private account state is unknown. |

## Sources checked

Public program pages and docs were checked on 2026-10-31:

- [Stellar Wave overview and cycle status](https://www.drips.network/wave/stellar)
- [Stellar Wave approved repository directory](https://www.drips.network/wave/stellar/repos)
- [Drips maintainer participation guide](https://docs.drips.network/wave/maintainers/participating-in-a-wave/)
- [Drips repository application limits](https://docs.drips.network/wave/maintainers/repo-application-limits/)
- [Drips terms and rules](https://docs.drips.network/wave/terms-and-rules/)
- [GrantFox Open Source public directory](https://www.grantfox.xyz/open-source)
- [GrantFox documentation index](https://docs.grantfox.xyz/llms.txt)
- [GrantFox project creation](https://docs.grantfox.xyz/user-manual-guides/oss-contributions-guide/maintainer-guide/create-your-project.md)
- [GrantFox repository onboarding](https://docs.grantfox.xyz/user-manual-guides/oss-contributions-guide/maintainer-guide/maintaining-your-project/adding-repos.md)
- [GrantFox campaigns](https://docs.grantfox.xyz/oss-contributions/campaigns.md)
- [GrantFox rejection and reapplication](https://docs.grantfox.xyz/user-manual-guides/oss-contributions-guide/maintainer-guide/if-your-project-is-rejected.md)
- [Stellar Community Fund record for GrantFox](https://communityfund.stellar.org/project/grantfox-4zq)
