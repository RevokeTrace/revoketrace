## Summary

Describe the focused change and why it is needed.

## Verification

- [ ] `cargo fmt --check`
- [ ] `cargo test --locked`
- [ ] `cargo build --locked --bin revoketrace`
- [ ] `cargo clippy --all-targets --all-features --locked -- -D warnings`
- [ ] `git diff --check`
- [ ] Documentation and internal links were checked when applicable.

## Evidence and safety

- [ ] Protocol claims cite the pinned Stellar Core source and relevant CAP specifications.
- [ ] Real network evidence, stored captures, and synthetic fixtures are clearly distinguished.
- [ ] The change preserves bounded discovery, fail-closed classification, and the read-only boundary.
- [ ] No private keys, credentials, signing, broadcasting, or transaction-success claims were added.
- [ ] No AI co-author trailers or attribution footers were added.

## Review notes

List known limitations, compatibility concerns, or follow-up work that is outside this pull request.
