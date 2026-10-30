# Final audit and freeze record (draft, not frozen)

Prepared 2026-10-30. The review below was done by an agent working in a sandbox. It is not an independent third-party security audit or certification. Scope: source, security, repository, and external evidence for the pre-submission pass.

## Findings

Classes: A blocker, B stale or cosmetic, C known limitation, D important pre-submission fix, E non-blocking backlog.

### A: Blockers

None confirmed in the implementation. Submission-level conditions that are outside the code (unverified program rules, unmerged changes) are in the freeze record below.

### D: Important pre-submission fixes

| ID | Finding | Evidence | Status |
| --- | --- | --- | --- |
| D1 | Only a lower protocol bound was enforced, so an unreviewed newer protocol would be evaluated. | `src/evidence.rs`, `src/lib.rs` at `7326436`; [decision](../research/protocol-support-decision.md) | Fixed in the protocol pull request. Range 18 to 29. |
| D2 | `inspect` printed a caller-supplied report under the same title and field names as a fresh forecast. A doctored `COMPLETE_AUTHORITATIVE_LEDGER` label looked authoritative. | `tests/inspect_cli.rs`, [transcript step 9](demo/transcript.txt) | Fixed in the inspect pull request. Schema 1 unchanged. |
| D3 | The documentation check was filtered by path, was not required by branch protection, and `mdbook build` exited 0 for a missing chapter or broken link. | GitHub branch API (required checks: `rust` only); local negative tests | Workflow fixed in the docs pull request. **Open:** an administrator must require `docs`. |
| D4 | Live mode accepted `http://` for any host although the documentation says HTTPS. TLS is the only authenticity layer for provider responses. | `validate_endpoint` at `7326436`; `tests/live_cli.rs` | Fixed in the endpoint pull request. |
| D5 | `SECURITY.md` omitted supported versions, trust boundaries, resource bounds, dependency scanning, and audit status. | `SECURITY.md` at `7326436` | Fixed in the documentation pull request. |
| D6 | The CLI reference said credential-bearing endpoints are rejected. A secret in the URL path is accepted and recorded in the report. | Run of `live` with a path token; `ReportSource` fields | Documentation corrected. Behavior documented as a limitation. |
| D7 | The repository has no topics. | GitHub API `topics` returned an empty list | **Open:** needs administrator access, which this session lacked. |

### C: Known limitations

- Bounded current-tip discovery is not exhaustive or historical.
- The program does not ask the RPC server which network it serves. A provider on another network is not detected.
- Live forced-redemption behavior and multi-operation sponsorship are not verified against a live ledger.
- No live Testnet run succeeded in this pass. It was blocked by the sandbox network policy.
- The range 18 to 29 is a source-review boundary with no recorded real-ledger protocol version.
- `--force` needs a trusted output directory. A killed process can leave a hidden temporary file.
- `main` requires zero approvals, so a green CI run is the only enforced gate.
- Offer-matching changes at protocol 29 are outside the model.

### E: Non-blocking backlog

- Add an RPC `getNetwork` check. It needs a live run to verify the response shape, so it was not written blind.
- Pass `-q`, `--proto =https`, and `--fail` to `curl`, or use a Rust HTTP client, so that a `.curlrc`, a redirect, or an HTTP error status cannot change behavior.
- Give malformed provider data an exit code different from an unreachable provider (both are 50 now).
- CI builds a debug binary and installs `cargo-audit` and `mdBook` from source on every run.
- The package is named `revoketrace-spike`, which reads as a prototype.
- `book/src` repeats content from `docs/`.

### B: Stale or cosmetic

- The v1.0.0 release title is `RevokeTrace v1.0.0.` with a trailing period. The release was left unchanged.
- Test counts of 153 in the verification index and test matrix were updated to 184. Historical research files keep their dated counts.

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
| Workflow permissions | `contents: read`; only the `deploy` job has `pages: write` and `id-token: write`; `pull_request`, not `pull_request_target`; actions pinned by SHA. |
| Dependencies | `cargo audit --deny warnings` exit 0, 1,395 advisories, 31 crates. No update bots. |

## Freeze record

**Status: not frozen.** Submission cannot be declared ready while the items below are unresolved.

| Field | Value |
| --- | --- |
| Candidate commit | Not set. The pull requests are unmerged. |
| Date | 2026-10-30 (draft) |
| Git status of the working branch | Clean at the last commit of the evidence branch |
| Merged pull requests relevant to this pass | None. The previous alignment pull request was #13. |
| Hosted CI | Last result: `main` at `7326436`, CI and Documentation both successful. No hosted run exists for the new changes. |
| Documentation deployment | Hosted deploy succeeded for `7326436`. The site was not fetched from the sandbox. |
| Release identity | v1.0.0, tag object `984eec70af723c30bfc26864ddf9ef31fe67378a`, commit `9b0e10121a4413d07e6323bd351a6ed4680279bb`, unchanged |
| Verified evidence | See [docs/verification.md](../docs/verification.md) |
| Local checks | fmt, 184 tests, release build, clippy, audit, rustdoc, mdBook 0.4.52, link check, `git diff --check` all passed on the evidence branch |
| Known limitations | See class C above |
| Program eligibility | Drips NOT VERIFIED, GrantFox NOT VERIFIED |

### Remaining blockers to a ready declaration

1. The pull requests must be pushed, pass hosted CI, be reviewed, and be merged. This session could not push (the GitHub App lacks access to the repository).
2. An administrator must require the `docs` check and add topics.
3. A live Testnet run must be made from an environment with network access.
4. The Drips and GrantFox rules must be read from official sources.
5. The candidate commit must be recorded after merge, followed by a re-run of the checks on it.

If a submission-critical defect is found after freeze, fix it, redo the affected checks, and repeat this audit.
