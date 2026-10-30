# Security policy

RevokeTrace is read-only software for bounded Stellar evidence analysis. It does not store private keys, sign transactions, construct transaction envelopes, broadcast transactions, or provide an authoritative transaction-success preflight.

## What to report

Please report issues that could cause, for example:

- Caller-controlled snapshots or reports to be treated as complete authoritative ledger evidence.
- A malformed or contradictory RPC, XDR, JSON, or report input to produce an unsafe classification or crash.
- Bounded input limits to be bypassed in a way that causes denial of service or unbounded allocation.
- Credentials to be accepted in endpoints or written to reports.
- Output handling to overwrite an unintended file or follow a symbolic link.
- A protocol or provenance claim to be presented as stronger evidence than the implementation has verified.

Uncertainty caused by bounded discovery, current-tip-only RPC evidence, incomplete multi-operation sponsorship context, or the lack of a live forced-redemption fixture is documented project scope. These limitations are not themselves vulnerabilities unless the software claims that they are resolved.

## How to report privately

GitHub private vulnerability reporting was checked for this repository on
2026-10-30 and is enabled. Use the repository's GitHub Security tab and choose
**Report a vulnerability**. Do not disclose exploit details, proof-of-concept
code, credentials, or sensitive inputs in a public issue or pull request.

If the GitHub form is temporarily unavailable or you cannot access it, ask a
maintainer through a public message to provide a private channel without
including technical details. The repository does not publish a security email
address. If no private channel is available, withhold the details until one is
provided.

Please include the affected commit, the smallest private reproduction you can provide, the expected and observed behavior, and the possible impact once a private channel is available.

## Trust boundaries

Treat all of the following as untrusted unless the implementation explicitly derives and verifies the relevant property:

- Offline snapshots, capture-artifact metadata, manifests, and saved reports.
- Horizon candidate enumeration.
- Stellar RPC JSON responses and decoded XDR.
- Network, ledger, sequence, sponsorship, and authority claims supplied by callers.
- Input and output file paths.

`UNVERIFIED_FORECAST` is a modeled result with evidence limitations, not transaction approval. `SUPPORTED_BLOCKED` is a modeled blocker, not proof of every network precondition. `COMPLETE_AUTHORITATIVE_LEDGER` cannot be derived from caller-supplied snapshots by `analyze` or `live`, and `SUPPORTED_SAFE` is not emitted. A crafted saved report may contain an authority label, but `inspect` validates an envelope only and does not authenticate, recompute, or promote that report as evidence.

## Disclosure

Do not publish exploit details until maintainers have had a reasonable opportunity to investigate and coordinate a fix. This policy does not promise a response time. Security fixes must preserve the read-only architecture and the fail-closed evidence boundary.
