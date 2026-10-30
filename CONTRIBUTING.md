# Contributing to RevokeTrace

RevokeTrace is a single-repository, free, read-only Rust CLI and forecasting engine. Contributions must preserve the evidence and safety boundaries in [docs/scope.md](docs/scope.md) and [docs/cli.md](docs/cli.md).

## Before you start

You need:

- Git.
- Rust 1.97.1. The pinned toolchain is declared in [rust-toolchain.toml](rust-toolchain.toml) and is selected automatically by rustup.
- `curl` for the optional live Testnet command. Offline analysis and the test suite do not require network access.

After a clean clone:

```bash
rustup show active-toolchain
cargo build --locked --bin revoketrace
cargo test --locked
```

Run the CLI locally with:

```bash
cargo run --locked --bin revoketrace -- help
```

## Required checks

Before opening a pull request, run:

```bash
cargo fmt --check
cargo test --locked
cargo build --locked --bin revoketrace
cargo clippy --all-targets --all-features --locked -- -D warnings
git diff --check
```

The repository also uses these useful local checks:

```bash
cargo audit --deny warnings
RUSTDOCFLAGS="-Dwarnings" cargo doc --workspace --no-deps --locked
```

The current GitHub Actions job enforces formatting, locked tests, the binary build, and strict Clippy. It does not currently enforce `cargo audit` or rustdoc, so do not describe those checks as CI requirements.

## Tests and fixtures

Add a regression test for every behavior change. Keep synthetic protocol cases in [fixtures/cap0038](fixtures/cap0038/) and label them as synthetic. Do not present a synthetic fixture as a live ledger observation.

The stored Testnet capture in [fixtures/live-testnet-discovery.json](fixtures/live-testnet-discovery.json) is historical caller-supplied evidence. Preserve its provenance and do not combine it with a current live response as though they were one snapshot.

For CLI changes, verify both the human-readable output and stable JSON output when relevant. Check exit codes, malformed input, missing evidence, contradictory evidence, bounded input sizes, and report file safety. Preserve the distinction between `UNVERIFIED_FORECAST`, `SUPPORTED_BLOCKED`, `INCONCLUSIVE`, and `UNSUPPORTED`.

## Protocol evidence

Protocol behavior must be checked against the pinned Stellar Core reference and the relevant CAP specifications. The current reference and verification matrix are recorded in [research/phase4c-protocol-verification.md](research/phase4c-protocol-verification.md). Cite the exact source file, commit, CAP, or independently obtained ledger evidence supporting a new protocol claim.

Separate source-code verification, real network evidence, stored network-response captures, and synthetic fixtures. Do not invent a live result, a transaction hash, complete ledger coverage, or a successful transaction outcome. Caller-supplied snapshots and reports remain untrusted data.

## Commits, branches, and pull requests

Create a focused branch from the latest `main`. Use one commit per genuine logical unit of work. Implement the unit, run its relevant checks, inspect the staged diff, commit it, and push that commit immediately. Do not create artificial commit splits, batch unrelated changes, rewrite merged history, or add AI co-author trailers or attribution footers.

Pull requests should explain the user-visible change, list verification commands and results, identify evidence provenance, and call out remaining limitations. Do not add a website, backend, database, indexer, dashboard, signing, broadcasting, dependency-update bot, or unnecessary dependency as part of a normal contribution.

## Issues and security-sensitive changes

Use a regular issue for reproducible bugs, documentation errors, and focused feature proposals. Include the commit, command, input description, expected result, and actual result. Do not file speculative or duplicate issues.

For security-sensitive changes, read [SECURITY.md](SECURITY.md) first. Do not disclose exploit details in a public issue or pull request. Reviewers should pay particular attention to provenance handling, classification precedence, file and network input bounds, XDR identity checks, and the rule that no forecast is transaction approval.
