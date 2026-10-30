# Maintenance and releases

[v1.0.0](https://github.com/RevokeTrace/revoketrace/releases/tag/v1.0.0) is a published, source-distributed release from immutable commit `9b0e10121a4413d07e6323bd351a6ed4680279bb`. No independently verified downloadable binary is claimed by that release. Documentation improvements on `main` are not automatically part of the tagged source archive.

Maintainers review dependencies manually, preserve locked builds, and require explicit compatibility review for Rust, generated XDR, or Stellar protocol-source changes. A release candidate needs a clean checkout, locked build and test checks, strict Clippy, audit and rustdoc checks, CLI smoke tests, link checks, CI review, and maintainer approval before publication.

Published tags and release assets must never be moved or silently replaced. A SHA-256 checksum can verify a downloaded binary's bytes but does not authenticate its publisher.

For the complete maintenance, versioning, and release process, see [Maintenance and release procedure](https://github.com/RevokeTrace/revoketrace/blob/main/docs/maintenance.md).
