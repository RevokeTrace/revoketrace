# Security policy

RevokeTrace is read-only software for bounded Stellar evidence analysis. It does not store private keys, sign transactions, construct transaction envelopes, broadcast transactions, or provide an authoritative transaction-success preflight.

## Supported versions

The only published release is [v1.0.0](https://github.com/RevokeTrace/revoketrace/releases/tag/v1.0.0), distributed as source. Security fixes are made on `main`. This policy does not promise backports, a patch timeline, or support for any other version.

## Security properties

- No private-key custody: the program never asks for, reads, or stores a secret key or seed.
- No wallet or account authentication: there is no login, session, or signing prompt.
- No transaction signing, envelope construction, or broadcast. Live mode only reads from the endpoints you give it.
- No server, database, or background service. Everything runs in one local process.

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

`UNVERIFIED_FORECAST` is a modeled result with evidence limitations, not transaction approval. `SUPPORTED_BLOCKED` is a modeled blocker, not proof of every network precondition. `COMPLETE_AUTHORITATIVE_LEDGER` cannot be derived from caller-supplied snapshots by `analyze` or `live`, and `SUPPORTED_SAFE` is not emitted. A crafted saved report may contain an authority label, but `inspect` validates an envelope only and does not authenticate, recompute, or promote that report as evidence. `inspect` output labels every copied value as an unverified saved claim.

## Input and network trust

- **Offline input.** An offline snapshot is whatever the caller supplies. The program checks that it is internally consistent (matching ledger sequences, canonical pool IDs, a manifest digest that matches its own pool list). It cannot check that the snapshot matches the real ledger, and a consistent forgery passes those checks. Offline results are therefore `UNVERIFIED_FORECAST` at best.
- **Horizon and RPC.** Live mode trusts the Horizon and Stellar RPC endpoints you choose. The only protection for their responses is TLS: endpoints must use `https://`, except that plain `http://` is accepted for `localhost`, `127.0.0.1`, and `[::1]`. A compromised or dishonest provider can return a self-consistent but false ledger view.
- **Network identity.** The caller-supplied network passphrase must equal the Testnet passphrase, but the program does not ask the RPC server which network it serves. An endpoint on another network would not be detected.
- **Ledger consistency and provenance.** The adapter requires the ledger header, entries, and discovery manifest to agree on one ledger sequence, retries a bounded number of times if the ledger advances, and fails closed otherwise. It decodes and checks XDR, canonical pool IDs, and requested-key identity. This shows internal consistency. It does not authenticate the ledger against validators, and bounded current-tip discovery is not exhaustive or historical.
- **Protocol versions.** Only protocol versions 18 to 29 are evaluated. Others are refused. The version the RPC reports is checked before the ledger header is decoded, and the decoded header must report the same version. See the [protocol support decision](research/protocol-support-decision.md).
- **Saved reports.** `inspect` reads a caller-supplied file. It does not authenticate the file or recompute the forecast, so any field, including an authority label, can be edited. Its output states this, and its exit code follows the saved label. Do not treat an inspected report, or the JSON that `inspect` prints, as a result RevokeTrace produced.
- **Endpoint URLs in reports.** Live reports record the Horizon and RPC URLs verbatim. Validation rejects user information, query strings, and fragments but cannot detect a secret in the URL path. Use public endpoints that need no key in the URL.
- **The `curl` executable.** Live mode runs the `curl` found on `PATH`, so a different `curl` earlier on `PATH` is trusted. It is started with `-q`, so no `.curlrc` or `CURL_HOME` configuration is read. `curl` itself is limited to `https` (or `http` for loopback hosts), requires TLS 1.2 or later, and never follows redirects. Any HTTP status outside 200 to 299 is a network failure and the response body is not used. Proxy and CA environment variables such as `HTTPS_PROXY` and `SSL_CERT_FILE` are honored, because they belong to the operator's environment.

## Resource bounds and filesystem safety

- Input files and standard input are limited to 8 MiB, and collections to 10,000 items. A single HTTP response is limited to 16 MiB. An RPC `getLedgerEntries` batch is limited to 200 keys, and ledger capture is attempted at most 3 times. Each request has a timeout of 1 to 300 seconds.
- Reports are written to a newly created temporary file in the destination directory and then installed. Without `--force`, installation cannot replace an existing file, including one created concurrently. Symbolic-link output paths and directories are refused. With `--force`, a non-symbolic-link destination is replaced. Portable standard-library calls cannot make that check and the replacement one atomic step, so the output directory must be trusted when `--force` is used (see [the CLI reference](docs/cli.md)).
- If the process is killed while writing, the destination is not left partially written, but a hidden temporary file named `.NAME.revoketrace-PID-N.tmp` can remain and must be removed by hand. This was reasoned from the code and not tested by killing a process.

## Dependency scanning

CI runs `cargo audit --deny warnings` with a pinned `cargo-audit` version. On 2026-10-30 a local run against 1,395 advisories exited 0. This detects known advisories in `Cargo.lock` only. It does not review dependency source code, and the project does not use automated dependency-update bots.

## Independent audit status

No independent third-party security audit of RevokeTrace has taken place. The project has automated tests, CI, `cargo audit`, and agent-assisted source review. None of these is an independent external audit or a certification, and none should be cited as one.

## Disclosure

Do not publish exploit details until maintainers have had a reasonable opportunity to investigate and coordinate a fix. This policy does not promise a response time. Security fixes must preserve the read-only architecture and the fail-closed evidence boundary.
