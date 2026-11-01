# Final audit and freeze record (draft, not frozen)

> **Current-state addendum, 2026-10-31:** This record's original findings are an October 30 snapshot. The latest reviewed `main` is `1b31580fc634343a62b278566b0b510c81ce241e`; PRs #1 through #20 are merged. Rust CI passed on that commit at [run 41242363654](https://github.com/RevokeTrace/revoketrace/actions/runs/41242363654). The latest successful main Documentation/deploy workflow observed is [run 41159173318](https://github.com/RevokeTrace/revoketrace/actions/runs/41159173318) at `3a7e762973cb4e3c3277e18fe0014037c437ca4e`. After an earlier timed-out request, direct HTTP checks returned 200 for the public documentation root and all seven linked chapters on 2026-10-31. The workflow job names are `rust` and `docs`. Repository topics are present. GitHub's private-vulnerability-reporting endpoint returned `enabled: true`. Current Drips and GrantFox status is in the [dated program-readiness report](../research/program-readiness-2026-10-31.md). This review made no program application; private account/application state was not inspected. The earlier branch API access problem is corrected in the governance update below.

> **Governance correction, 2026-11-01:** The earlier integration returned an empty visible ruleset list and HTTP 404 from `/branches/main/protection`. A subsequent successful [branch API response](https://api.github.com/repos/RevokeTrace/revoketrace/branches/main) for `main` at `1b31580fc634343a62b278566b0b510c81ce241e` reported `protected: true`, `protection.enabled: true`, and required status checks enforced for everyone with contexts `rust` and `docs`. Branch protection and both required checks are verified. This response does not establish review-approval requirements, force-push/deletion restrictions, bypass permissions, or other administrative settings. No repository settings were changed.

The 20:16 PR #20 transcript from commit `963453caa98039477ef88897d8b9da017dd8c379` contained an issuer transcription mismatch and is withdrawn; its stdout was not retained as bytes. A fresh fixture-derived capture from commit `9a419ebf74194359db45b79fb274e58d29c4e4de` retained raw stdout/stderr and reported ledger 5491146, exit 10. The separate full RPC response retained at ledger 5490831/protocol 29 is an earlier observation, not the later CLI header. See [the dated record](../research/testnet-live-observation-2026-10-31.md). The new capture does not freeze the submission or independently verify a forced-redemption execution.

Historical audit prepared 2026-10-30. It was done by an agent working in a sandbox. It is not an independent third-party security audit or certification. Scope: source, security, repository, and external evidence for the pre-submission pass. The findings below are retained for history; current repository, CI, program, and governance states are summarized in the addendum and readiness report.

## Findings

Classes: A blocker, B stale or cosmetic, C known limitation, D important pre-submission fix, E non-blocking backlog.

### A: Blockers

None confirmed in the implementation. Remaining external conditions are the unverified Drips account/repository state and GrantFox's repository age guideline and required pitch. This review made no program application. Branch protection and required CI checks are verified in the 2026-11-01 governance correction. See the dated readiness report for program status.

### D: Important pre-submission fixes

| ID | Finding | Evidence | Status |
| --- | --- | --- | --- |
| D1 | Only a lower protocol bound was enforced, so an unreviewed newer protocol would be evaluated. | `src/evidence.rs`, `src/lib.rs` at `7326436`; [decision](../research/protocol-support-decision.md) | Fixed in PR 14, merged as `965b2c5`. Range 18 to 29. |
| D2 | `inspect` printed a caller-supplied report under the same title and field names as a fresh forecast. A doctored `COMPLETE_AUTHORITATIVE_LEDGER` label looked authoritative. | `tests/inspect_cli.rs`, [transcript step 9](demo/transcript.txt) | Fixed in PR 15, merged as `5d2ef06`. Schema 1 unchanged. |
| D3 | The documentation check was filtered by path, was not required by branch protection, and `mdbook build` exited 0 for a missing chapter or broken link. | Historical GitHub API query and local negative tests | Workflow fixed in PR 16, merged as `91cd30a`. The earlier limited API requests did not establish current settings; the subsequent branch endpoint verifies that `rust` and `docs` are required (see 2026-11-01 correction). |
| D4 | Live mode accepted `http://` for any host although the documentation says HTTPS. TLS is the only authenticity layer for provider responses. | `validate_endpoint` at `7326436`; `tests/live_cli.rs` | Fixed in PR 17, merged as `6ea854d`. |
| D5 | `SECURITY.md` omitted supported versions, trust boundaries, resource bounds, dependency scanning, and audit status. | `SECURITY.md` at `7326436` | Fixed in PR 19, merged by `3a7e762`. |
| D6 | The CLI reference said credential-bearing endpoints are rejected. A secret in the URL path is accepted and recorded in the report. | Run of `live` with a path token; `ReportSource` fields | Documentation corrected. Behavior documented as a limitation. |
| D7 | The repository had no topics. | GitHub API returned an empty list in the original audit | Superseded: repository topics were present in the GitHub API response on 2026-10-31. |
| D8 | The live adapter decoded `headerXdr` before applying the protocol range, so a real protocol 30 header would have exited 50 instead of 30. Found in maintainer review, after the first version of PR 14. | Mutation check: removing the new pre-decode check makes `unsupported_rpc_protocol_is_refused_before_the_header_is_decoded` fail with `ParseError`; `tests/live_protocol_cli.rs` | Fixed in `d9e7fd4`, part of the merge of PR 14. |
| D9 | The `curl` transport read `.curlrc`, relied on nothing in `curl` to enforce the protocol policy, could follow redirects through a configuration file, and noticed an HTTP error status only if its body failed to parse. Found in maintainer review. | `tests/curl_transport.rs`, including a control run that shows plain `curl` obeys a hostile `.curlrc`; removing `-q` makes the test fail | Fixed in `07d3572`, part of the merge of PR 17. |

### C: Known limitations

- Bounded current-tip discovery is not exhaustive or historical.
- The program does not ask the RPC server which network it serves. A provider on another network is not detected.
- Live forced-redemption behavior and multi-operation sponsorship are not verified against a live ledger.
- At the time of the October 30 audit, no live Testnet run had succeeded; that attempt was blocked by the sandbox network policy. A later bounded capture is recorded in the update above; it does not prove exhaustive discovery or a real forced redemption.
- The range 18 to 29 remains a source-review boundary. The separately retained response reported protocol 29 at ledger 5490831, about 26 minutes before the fresh CLI capture at 5491146. It is not that capture's exact header and does not widen supported protocol behavior.
- `--force` needs a trusted output directory. A killed process can leave a hidden temporary file.
- Earlier audit requests to dedicated branch-protection endpoints failed, but a subsequent branch API response verifies `main` protection and required `rust`/`docs` checks. That response does not establish review-approval requirements, force-push/deletion restrictions, or bypass permissions. The maintainer has stated that reviewer approvals are intentionally not required at this stage.
- Offer-matching changes at protocol 29 are outside the model.

### E: Non-blocking backlog

- Add an RPC `getNetwork` check. It needs a live run to verify the response shape, so it was not written blind.
- Give malformed provider data an exit code different from an unreachable provider (both are 50 now).
- CI builds a debug binary and installs `cargo-audit` and `mdBook` from source on every run.
- The package is named `revoketrace-spike`, which reads as a prototype.
- `book/src` repeats content from `docs/`.

### B: Stale or cosmetic

- The v1.0.0 release title is `RevokeTrace v1.0.0.` with a trailing period. The release was left unchanged.
- Test counts of 153 in the verification index and test matrix were updated to 202. Historical research files keep their dated counts.

### Not applicable

Smart contracts, wallet integration, a backend or database, a second repository, transaction confirmation, payment settlement, background-job recovery, and wallet-signing recovery. The project has none of these by design.

## Areas reviewed

| Area | Result |
| --- | --- |
| CLI validation | Strict option parsing, account and asset validation, bounded input. Endpoint rule tightened (D4). |
| Protocol checks | Single policy now (D1). |
| Classification | Evidence classification is derived. A caller cannot set it, and `inspect` now labels it (D2). |
| Arithmetic | `u128` with `checked_mul` for redemption, bounds checks against `i64::MAX`, shares not above total are validated. No overflow path was found. |
| XDR parsing | Decoder 28.0.1 matches Core's entry and transaction XDR at the pin. Protocol 30 headers cannot be decoded. |
| Output installation | Exclusive temporary file, no-replace hard link, rename for `--force`, symbolic links refused. No defect found. |
| Secrets | No key handling. Endpoint user information rejected. Path secrets are not detected (D6). |
| Resource bounds | 8 MiB input, 10,000 items, 16 MiB response, 200 keys, 3 capture attempts, timeout 1 to 300 seconds. |
| Network transport | `curl` runs with `-q`, protocol and redirect limits enforced by `curl`, TLS 1.2 or later, no redirects followed, and non-2xx statuses rejected (D9). Retries are bounded to 3 capture attempts. |
| Workflow permissions | `contents: read`; only the `deploy` job has `pages: write` and `id-token: write`; `pull_request`, not `pull_request_target`; actions pinned by SHA. |
| Dependencies | `cargo audit --deny warnings` exit 0, 1,395 advisories, 31 crates. No update bots. |

## Freeze record

**Status: not frozen.** The source candidate has been reviewed, but the documentation updates from this pass are not merged, program-specific account states remain private or unverified, and current branch protection was not confirmed.

| Field | Value |
| --- | --- |
| Candidate commit assessed in this pass | `1b31580fc634343a62b278566b0b510c81ce241e`; not frozen. The final source commit must be recorded after any readiness PR is reviewed and merged. |
| Date | 2026-10-31 current-state addendum; original audit dated 2026-10-30 |
| Git status of source baseline | Clean at the verified `main` baseline before this documentation branch was created |
| Merged pull requests relevant to the project state | PRs #1 through #20 merged on the verified baseline. The current readiness documentation change is separate and must be reviewed before merge. |
| Hosted CI and branch protection | Rust CI passed on `main` at `1b31580` ([run 41242363654](https://github.com/RevokeTrace/revoketrace/actions/runs/41242363654)). Documentation/deploy last passed on `main` at `3a7e762` ([run 41159173318](https://github.com/RevokeTrace/revoketrace/actions/runs/41159173318)). A successful branch API response on 2026-11-01 verifies `main` is protected and requires `rust` and `docs`; see the governance correction above. Other protection settings remain unverified. |
| Documentation deployment | The successful deployment workflow at `3a7e762` was observed. Direct HTTP checks returned 200 for the site root and all seven linked chapters on 2026-10-31. |
| Release identity | v1.0.0, tag object `984eec70af723c30bfc26864ddf9ef31fe67378a`, commit `9b0e10121a4413d07e6323bd351a6ed4680279bb`, unchanged |
| Verified evidence | See [docs/verification.md](../docs/verification.md) |
| Local checks on `1b31580` (2026-10-31) | `cargo fmt --check`, `cargo test --locked` (202 tests), release build, strict Clippy, `cargo audit --deny warnings`, warning-denied rustdoc, mdBook 0.4.52, `scripts/check-doc-links.py`, and `git diff --check` passed. A clean-clone release-binary demonstration is preserved at [transcript-1b31580.txt](demo/transcript-1b31580.txt). |
| Known limitations | See class C above |
| Program status | Drips: **ELIGIBILITY NOT VERIFIED**. GrantFox OSS Contributions: **NOT READY TO APPLY** on the documented repository age guideline and missing required video pitch. This review made no application; private account status was not inspected. See [program readiness](../research/program-readiness-2026-10-31.md). |

### Current actions before a program application or final freeze

1. Before merging a documentation PR, verify `rust` and `docs` pass on its exact head. After merge, rerun the documented checks on the resulting `main` commit before freezing a candidate. Those contexts are verified as required on `main`; reviewer approvals are intentionally not required at this stage, and no settings were changed.
2. Before freezing a submission candidate, record the final post-merge `main` SHA and rerun the locked checks and demo on that exact source.
3. The maintainer must inspect Drips organization/repository/application state and current Wave availability in their own account if they choose to apply.
4. Reassess GrantFox after meeting its public repository age/activity guideline, prepare the required video pitch, and check current Campaign eligibility. No application has been submitted.
5. Preserve the bounded Testnet evidence limitations; it is not an executed forced-redemption result or transaction preflight.

If a submission-critical defect is found after freeze, fix it, redo the affected checks, and repeat this audit.
