# Final audit and freeze record (draft, not frozen)

> **2026-10-31 evidence update:** The 20:16 PR #20 transcript from commit `963453caa98039477ef88897d8b9da017dd8c379` contained an issuer transcription mismatch and is withdrawn; its stdout was not retained as bytes. A fresh fixture-derived capture from commit `9a419ebf74194359db45b79fb274e58d29c4e4de` retained raw stdout/stderr and reported ledger 5491146, exit 10. The separate full RPC response retained at ledger 5490831/protocol 29 is an earlier observation, not the later CLI header. See [the dated record](../research/testnet-live-observation-2026-10-31.md). The findings below describe the original October 30 audit snapshot. The new capture does not freeze the submission or independently verify a forced-redemption execution.

Prepared 2026-10-30. The review below was done by an agent working in a sandbox. It is not an independent third-party security audit or certification. Scope: source, security, repository, and external evidence for the pre-submission pass.

## Findings

Classes: A blocker, B stale or cosmetic, C known limitation, D important pre-submission fix, E non-blocking backlog.

### A: Blockers

None confirmed in the implementation. Submission-level conditions that are outside the code (unverified program rules, this pull request not yet merged) are in the freeze record below.

### D: Important pre-submission fixes

| ID | Finding | Evidence | Status |
| --- | --- | --- | --- |
| D1 | Only a lower protocol bound was enforced, so an unreviewed newer protocol would be evaluated. | `src/evidence.rs`, `src/lib.rs` at `7326436`; [decision](../research/protocol-support-decision.md) | Fixed in PR 14, merged as `965b2c5`. Range 18 to 29. |
| D2 | `inspect` printed a caller-supplied report under the same title and field names as a fresh forecast. A doctored `COMPLETE_AUTHORITATIVE_LEDGER` label looked authoritative. | `tests/inspect_cli.rs`, [transcript step 9](demo/transcript.txt) | Fixed in PR 15, merged as `5d2ef06`. Schema 1 unchanged. |
| D3 | The documentation check was filtered by path, was not required by branch protection, and `mdbook build` exited 0 for a missing chapter or broken link. | GitHub branch API (required checks: `rust` only); local negative tests | Workflow fixed in PR 16, merged as `91cd30a`; `docs`, `deploy` and `rust` all passed on `main`. **Open:** `main` still requires only `rust` (branch API, 2026-10-30), so an administrator must add `docs`. |
| D4 | Live mode accepted `http://` for any host although the documentation says HTTPS. TLS is the only authenticity layer for provider responses. | `validate_endpoint` at `7326436`; `tests/live_cli.rs` | Fixed in PR 17, merged as `6ea854d`. |
| D5 | `SECURITY.md` omitted supported versions, trust boundaries, resource bounds, dependency scanning, and audit status. | `SECURITY.md` at `7326436` | Fixed in PR 19 (this pull request). |
| D6 | The CLI reference said credential-bearing endpoints are rejected. A secret in the URL path is accepted and recorded in the report. | Run of `live` with a path token; `ReportSource` fields | Documentation corrected. Behavior documented as a limitation. |
| D7 | The repository has no topics. | GitHub API `topics` returned an empty list | **Open:** needs administrator access, which this session lacked. |
| D8 | The live adapter decoded `headerXdr` before applying the protocol range, so a real protocol 30 header would have exited 50 instead of 30. Found in maintainer review, after the first version of PR 14. | Mutation check: removing the new pre-decode check makes `unsupported_rpc_protocol_is_refused_before_the_header_is_decoded` fail with `ParseError`; `tests/live_protocol_cli.rs` | Fixed in `d9e7fd4`, part of the merge of PR 14. |
| D9 | The `curl` transport read `.curlrc`, relied on nothing in `curl` to enforce the protocol policy, could follow redirects through a configuration file, and noticed an HTTP error status only if its body failed to parse. Found in maintainer review. | `tests/curl_transport.rs`, including a control run that shows plain `curl` obeys a hostile `.curlrc`; removing `-q` makes the test fail | Fixed in `07d3572`, part of the merge of PR 17. |

### C: Known limitations

- Bounded current-tip discovery is not exhaustive or historical.
- The program does not ask the RPC server which network it serves. A provider on another network is not detected.
- Live forced-redemption behavior and multi-operation sponsorship are not verified against a live ledger.
- At the time of the October 30 audit, no live Testnet run had succeeded; that attempt was blocked by the sandbox network policy. A later bounded capture is recorded in the update above; it does not prove exhaustive discovery or a real forced redemption.
- The range 18 to 29 remains a source-review boundary. The separately retained response reported protocol 29 at ledger 5490831, about 26 minutes before the fresh CLI capture at 5491146. It is not that capture's exact header and does not widen supported protocol behavior.
- `--force` needs a trusted output directory. A killed process can leave a hidden temporary file.
- `main` requires zero approvals, so a green CI run is the only enforced gate.
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

**Status: not frozen.** Submission cannot be declared ready while the items below are unresolved.

| Field | Value |
| --- | --- |
| Candidate commit | Not set. `main` was at `2c01428` when this record was updated, and this pull request (19) is not yet merged. The commit to submit must be recorded after it merges. |
| Date | 2026-10-30 (draft) |
| Git status of the working branch | Clean at the last commit of the evidence branch |
| Merged pull requests relevant to this pass | 14 (protocol range), 15 (inspect labelling), 16 (documentation check), 17 (HTTPS endpoints and `curl` hardening), 18 (failure tests). All were merged by the GitHub account Hollujay, not by this review. 19 (this one) is open. |
| Hosted CI | `main` at `91cd30a`: `deploy`, `docs`, `rust` successful. `main` at `6ea854d`: `rust` successful. `main` at `2c01428`: `rust` still running when this was written. Hosted CI for this pull request is recorded in its checks, not here. |
| Documentation deployment | Hosted deploy succeeded on `main` at `91cd30a`, with the new workflow. The site itself was not fetched from the sandbox. |
| Release identity | v1.0.0, tag object `984eec70af723c30bfc26864ddf9ef31fe67378a`, commit `9b0e10121a4413d07e6323bd351a6ed4680279bb`, unchanged |
| Verified evidence | See [docs/verification.md](../docs/verification.md) |
| Historical local checks (2026-10-30) | fmt, 202 tests (181 unit, 21 binary-level), release build, Clippy, audit, rustdoc, mdBook 0.4.52, link check, `git diff --check` passed on the earlier evidence branch. These counts are not the result of this latest evidence correction. |
| Known limitations | See class C above |
| Program eligibility | Drips NOT VERIFIED, GrantFox NOT VERIFIED |

### Remaining blockers to a ready declaration

1. This pull request (19) must pass hosted CI on its current head, be reviewed, and be merged.
2. An administrator must require the `docs` check and add topics.
3. Review the byte-preserved October 31 capture. It does not provide exhaustive discovery or an executed forced-redemption fixture; assess those limitations against any future program requirements.
4. The Drips and GrantFox rules must be read from official sources.
5. After 19 merges, the candidate commit must be recorded and the checks re-run on it, including the demonstration transcript.

If a submission-critical defect is found after freeze, fix it, redo the affected checks, and repeat this audit.
