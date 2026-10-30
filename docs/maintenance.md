# Maintenance and release procedure

RevokeTrace is a small, local, read-only Rust CLI. Maintenance should preserve that boundary and leave an honest, reviewable history.

## Routine work

Reproduce a reported behavior with the smallest safe input, record the exact command and result, and classify it as a reproducible bug, duplicate, unsupported request, blocked investigation, or documented limitation. A valid fix gets a focused regression test that checks the actual failure or classification boundary. Do not create speculative issues, fabricated fixtures, or work merely to expand a backlog.

Review pull requests against [CONTRIBUTING.md](../CONTRIBUTING.md), [scope](scope.md), and [security policy](../SECURITY.md). Pay particular attention to provenance, classification precedence, XDR/key identity, numeric bounds, network and file limits, report output paths, workflow changes, dependencies, release metadata, and any wording that could turn a forecast into an approval claim. Keep one commit per genuine logical unit; do not rewrite published history or add artificial splits, AI co-author trailers, or attribution footers.

## GitHub governance

The 2026-10-30 audit verified active `main` branch protection: pull requests are required, the strict `rust` check is required, conversation resolution and stale-review dismissal are enabled, administrators are included, and force pushes and branch deletion are disabled. GitHub private vulnerability reporting is enabled; its current procedure is in [SECURITY.md](../SECURITY.md).

### Documentation check

`.github/workflows/docs.yml` builds the mdBook on every pull request, with no path filter, in a job whose check name is `docs`. A path filter would leave a required check pending on pull requests that do not touch the book. Pull request runs only build. Uploading and deploying the Pages artifact are limited to pushes to `main` and to a manual run on `main`. The workflow uses read-only `contents` permission, and only the `deploy` job holds `pages: write` and `id-token: write`. It uses the `pull_request` event, not `pull_request_target`, so pull request code never runs with repository secrets.

The `docs` job runs `scripts/check-doc-links.py`, which fails on a relative Markdown link whose target file does not exist, and `mdbook build`, which fails on a malformed configuration or a chapter listed in `SUMMARY.md` that does not exist (`create-missing = false`). It does not check external URLs, in-page anchors, or prose accuracy, and mdBook does not reject every Markdown mistake, so a green `docs` run shows only that the book builds and its local links resolve.

A passing `docs` run is not a merge gate until branch protection requires it. When this workflow was added, GitHub's branch API listed `rust` as the only required status check. After this workflow is on `main`, an administrator should add `docs` under Settings, Branches, the `main` rule, Require status checks to pass before merging. Add it only after a `docs` run has appeared on a pull request, because GitHub offers only check names it has seen. Then confirm the effective rule:

```bash
curl -s https://api.github.com/repos/RevokeTrace/revoketrace/branches/main | jq '.protection.required_status_checks.contexts'
```

The expected output lists both `docs` and `rust`. Until it does, do not describe documentation validation as enforced.

The configured required-approval count is zero because no independently available reviewer was confirmed during the audit. That is a governance limitation, not evidence that review occurred. When an independent maintainer or reviewer is available, an administrator should require at least one approval and, where the platform supports it, approval of the latest push. Confirm the effective rule in GitHub branch settings and do not infer protection from a green CI run alone.

## Dependencies and protocol changes

Review dependencies manually. Run advisory checks and the locked test suite before accepting a change. A Rust, `stellar-xdr`, or Stellar Core reference change needs a stated compatibility decision, relevant source/CAP review, and new or updated tests where semantics change. Do not assume a newer generated XDR crate works merely because it is newer. The repository does not use automated dependency-update bots or scheduled update workflows without separate authorization.

Protocol claims must distinguish pinned-source review, synthetic tests, stored captures, and independently observed ledger evidence. Cite the exact Core revision, CAP, fixture provenance, or observation. Never manufacture transaction hashes, complete-capture claims, or live results.

## Versioning and compatibility

Use a patch release for compatible defect or security fixes, a minor release for compatible user-visible additions, and a major release for intentionally incompatible CLI, exit-code, or JSON-report-contract changes. Documentation-only changes normally need no release. Preserve `schema_version: 1` unless an intentional compatibility decision introduces a new documented schema version. Treat CLI flags and exit codes as public behavior.

## Release preparation

From a clean checkout of the candidate commit, run:

```bash
cargo fmt --check
cargo test --locked
cargo build --release --locked --bin revoketrace
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo audit --deny warnings
RUSTDOCFLAGS="-Dwarnings" cargo doc --workspace --no-deps --locked
git diff --check
```

Run the release binary's `help`, `version`, and the documented offline example. Check expected classifications and exit codes, JSON determinism, output-overwrite behavior, and `inspect`'s non-authentication boundary. Build the mdBook with the version configured by CI and verify important internal and public links.

Before publication, inspect existing tags and release metadata, record the exact source commit, confirm CI on that commit, and obtain maintainer authorization. If publishing a binary, record its target and build command, calculate and recheck SHA-256, and state that an unsigned checksum checks bytes rather than publisher identity. Never move a published version tag, silently replace published assets, publish a crate when `publish = false`, or claim a checksum authenticates a publisher.

v1.0.0 is a historical source release. Its tag and release assets must remain unchanged. Later documentation on `main` is not automatically part of that tagged source archive.

## Future contributor work

Create issues only for real, scoped work with testable acceptance criteria and evidence links. Keep dependencies explicit and check for duplicates. Do not assume approval by Drips Wave, GrantFox, or another program; verify the program's current rules and project approval before advertising a contributor program or broad public backlog.
