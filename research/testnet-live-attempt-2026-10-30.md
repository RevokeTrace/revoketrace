# Testnet live run attempt, 2026-10-30

Status: **BLOCKED**. No live Testnet evidence was obtained. This record exists so that nobody reads the absence of a result as a pass.

## What was attempted

One run of `revoketrace live` with the documented command, using the release build of the source commit below. It was not repeated. No transaction was signed or submitted, because the CLI cannot do either.

| Item | Value |
| --- | --- |
| Date and time (UTC) | 2026-10-30T22:11:24Z |
| Network | Stellar Testnet, passphrase `Test SDF Network ; September 2015` |
| Source commit | `0b9729b758b1ca7a0762f2572dea6de5632f0896` (branch `claude/sharp-dijkstra-epoli6-evidence`, local) |
| Rust | `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)` |
| Binary | `revoketrace 1.0.0`, built with `cargo build --release --locked --bin revoketrace` |
| Horizon endpoint | `https://horizon-testnet.stellar.org` (no credentials) |
| RPC endpoint | `https://soroban-testnet.stellar.org` (no credentials, never reached) |
| Target ledger and protocol version | None obtained |
| Request timeout | 15 seconds |

Exact command:

```bash
revoketrace live \
  --network-passphrase 'Test SDF Network ; September 2015' \
  --horizon-url https://horizon-testnet.stellar.org \
  --rpc-url https://soroban-testnet.stellar.org \
  --operation SetTrustLineFlags \
  --source-account GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG \
  --trustor GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB \
  --asset-code FLUTTER \
  --asset-issuer GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG \
  --before-flags 1 --after-flags 0 \
  --tx-source-account GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG \
  --sequence 42 --operation-index 0 --timeout-secs 15
```

The accounts and asset are the ones in the stored fixture `fixtures/live-testnet-discovery.json`. They are public Testnet identifiers, not secrets.

## Result

| Item | Value |
| --- | --- |
| Exit code | 50 (live network/RPC failure) |
| Standard output | Empty |
| Standard error | `error: live evidence acquisition failed: transport error: curl get exited with status exit status: 56` |
| Evidence classification | None produced |
| Forecast classification | None produced |

## Cause

The failure is in the execution environment, not in RevokeTrace, the endpoint, or the input.

- The sandbox sends outbound HTTPS through a policy proxy. The proxy status endpoint logged `gateway answered 403 to CONNECT (policy denial or upstream failure)` for `horizon-testnet.stellar.org:443` at 2026-10-30T22:11:24Z, and for `horizon-testnet.stellar.org:443` and `soroban-testnet.stellar.org:443` earlier at 21:36:56Z while probing with `curl`.
- `curl` exit status 56 means a failure receiving network data, which matches a refused tunnel.
- Horizon is the first request in the live flow, so the RPC endpoint was never contacted.
- This was classified as an endpoint-egress block. It is not an input error (the arguments were accepted), a protocol-compatibility result (no header was read), or an RPC outage (no RPC request was made).

To obtain a real run, someone with access must allow `horizon-testnet.stellar.org` and `soroban-testnet.stellar.org` in the environment's network policy, or run the same command on a machine with open egress, then record the result in a new dated file.

The attempt used the transport as it was before PR #17, which has since been hardened (`-q`, protocol limits, no redirects, HTTP status checks). The failure happened while opening the connection, before any of that applies, so the result is not affected, but a new run should use the current `main`.

## What this record does and does not show

It shows that a transport failure fails closed: exit code 50, no output, no report, and no partial forecast. That behavior is also covered by mock-transport tests, which are not live evidence.

It does not show any live behavior of the adapter, any property of the current Testnet ledger, or any protocol version. The only real Testnet evidence in the repository is the stored capture and the flag-only operation recorded in [Phase 4C](phase4c-protocol-verification.md).

Even a successful run would not show that every affected pool was discovered, that history is complete, that a future transaction would succeed, that multi-operation sponsorship is verified, or that every CAP-0038 redemption effect was observed live.
