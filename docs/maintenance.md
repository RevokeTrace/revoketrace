# Maintenance and release procedure

RevokeTrace is a small, local, read-only Rust CLI. Maintenance should preserve that boundary and leave an honest, reviewable history.

## Routine work

Reproduce a reported behavior with the smallest safe input, record the exact command and result, and classify it as a reproducible bug, duplicate, unsupported request, blocked investigation, or documented limitation. A valid fix gets a focused regression test that checks the actual failure or classification boundary. Do not create speculative issues, fabricated fixtures, or work merely to expand a backlog.

Review pull requests against [CONTRIBUTING.md](../CONTRIBUTING.md), [scope](scope.md), and [security policy](../SECURITY.md). Pay particular attention to provenance, classification precedence, XDR/key identity, numeric bounds, network and file limits, report output paths, workflow changes, dependencies, release metadata, and any wording that could turn a forecast into an approval claim. Keep one commit per genuine logical unit; do not rewrite published history or add artificial splits, AI co-author trailers, or attribution footers.

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
