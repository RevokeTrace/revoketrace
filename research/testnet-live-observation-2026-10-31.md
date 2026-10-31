# Bounded Testnet observation, 2026-10-31

> **Provenance note:** The 19:35 observation and 20:16 PR #20 CLI output were not retained as raw process files. The 20:16 stdout was transcribed incorrectly and is withdrawn; those CLI results are reported history only. The separately retained RPC response from 20:16 and a fresh 20:42 CLI capture from PR head `9a419eb` are documented below as distinct evidence.

At 2026-10-31T19:35:52Z, the release binary built from `3a7e762973cb4e3c3277e18fe0014037c437ca4e` completed a read-only `live` request against public Testnet endpoints. Rust and Cargo were 1.97.1; the CLI reported `revoketrace 1.0.0`. No transaction was submitted.

The command used `https://horizon-testnet.stellar.org`, `https://soroban-testnet.stellar.org`, the Testnet passphrase, and the public FLUTTER issuer/trustor from `fixtures/live-testnet-discovery.json`. It requested `SetTrustLineFlags`, flags 1 to 0, transaction source equal to the issuer, sequence 42, operation index 0, and a 15-second timeout. These operation values are hypothetical inputs, not observed transaction context.

The CLI exited **10** and printed a Live Testnet bounded discovery report. It recorded ledger and entries sequence **5490344**, evidence classification `BOUNDED_CURRENT_TIP_RPC`, forecast classification `UNVERIFIED_FORECAST`, and forced-pool-redemption transition. The reported base reserve was 5,000,000 stroops. Two candidate pool IDs were reconciled: `00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46` and `078ff7f339a3a1c950812bd143431498f880082e0ebdb95fb348a5b87693465c`. Modeled withdrawals were 700,000,000/514,506,217 and 4,980,000,000/4,980,000,000 stroops respectively. The report forecast pool deletion for both and four claimable balances, with trustor subentries -4 and sponsoring +4. Standard error was empty. Its warning was `W_UNVERIFIED_DISCOVERY`; limitations explicitly stated that discovery is bounded and the forecast is not transaction preflight.

The original summary reported that a separate read-only RPC `getLatestLedger` request immediately afterward returned **protocolVersion 29** and ledger **5490345**, one ledger later. Its response body was not retained, so those values are reported historical observations, not independently reproducible provider evidence. They were not the exact header from the CLI capture. Although the implementation checks RPC protocol metadata before XDR decoding and requires the decoded header version and ledger sequence to agree, the unretained summary cannot establish that validation for ledger 5490344. The separate request did not independently reproduce that earlier header.

The initial bounded RPC hostname probe was reported to have timed out during DNS resolution after 12 seconds, while Horizon returned HTTP 200. The probe command and output were not retained, so this is a reported diagnostic rather than independently auditable output. The subsequent CLI request and RPC request were reported to have completed. This was described as a transient lookup failure, not evidence that Testnet was unavailable.

The historical fixture and this observation use different ledger states. Matching pool IDs and modeled withdrawal amounts do not prove that the stored fixture was current, that every affected pool was discovered, or that a real forced redemption occurred. The prior real operation fixture is clawback-only. Claimable-balance IDs in this forecast depend on caller-supplied hypothetical sequence and operation index. No result here verifies transaction success or complete multi-operation sponsorship behavior. The October 30 blocked attempt remains a separate historical record.

## Earlier PR #20 observation (reported summary; transcript withdrawn)

A read-only run was reported at `2026-10-31T20:16:16.596771Z` from source commit `963453caa98039477ef88897d8b9da017dd8c379`. The earlier draft gave CLI ledger and entries sequence **5490828**, `BOUNDED_CURRENT_TIP_RPC`, `UNVERIFIED_FORECAST`, transition `forced pool redemption`, exit **10**, and empty stderr. However, the draft's purported stdout was manually transcribed into Markdown and no original byte-preserved stdout or stderr exists in the repository. Its issuer line contained a 50-character identity while the fixture and command use the 56-character issuer. The report renderer formats the issuer directly from `report.operation.asset.issuer` in `src/report.rs`; the mismatch is a documentation transcription error, not a confirmed implementation defect. The old stdout transcript has been removed and those result details remain reported historical values only, not independently reproducible evidence.

### Previously retained separate RPC response

At `2026-10-31T20:16:37.354704Z` to `2026-10-31T20:16:38.406182Z`, a separate read-only `getLatestLedger` request returned curl exit 0, HTTP 200, protocol version **29**, and ledger **5490831**. The full response body remains in [the retained JSON artifact](evidence/testnet-getLatestLedger-2026-10-31T201637Z.json), 159,464 bytes, SHA-256 `fa009bc79f84a8de9bd492ceca9cd450559ee657d3280c6b2ee85a71adcdf327`. The corrected digest was calculated with `sha256sum` on the unchanged file. This provider response is separate from both CLI runs; it is not a CLI header, and it predates the fresh capture below by about 26 minutes.

The read-only request command was: `curl -q --silent --show-error --max-time 15 --proto '=https' --proto-redir '=https' --header 'Content-Type: application/json' --data-raw '{"jsonrpc":"2.0","id":1,"method":"getLatestLedger"}' --write-out $'\nHTTP_STATUS:%{http_code}\n' https://soroban-testnet.stellar.org`.

The read-only request used:

```bash
curl -q --silent --show-error --max-time 15 --proto '=https' --proto-redir '=https' \
  --header 'Content-Type: application/json' \
  --data-raw '{"jsonrpc":"2.0","id":1,"method":"getLatestLedger"}' \
  --write-out $'\nHTTP_STATUS:%{http_code}\n' \
  https://soroban-testnet.stellar.org
```

### Historical network diagnostic

An earlier summary reported an initial RPC hostname DNS timeout after 12 seconds and Horizon HTTP 200, followed by successful requests. The command and diagnostic output were not retained. These are reported historical diagnostics only. In the fresh capture below the CLI completed its bounded Horizon/RPC flow; its text output does not expose per-request status codes or raw provider responses.

## Fresh fixture-derived capture from PR #20 head, 2026-10-31

The release binary was built from current PR head `9a419ebf74194359db45b79fb274e58d29c4e4de` with `cargo build --release --locked --bin revoketrace`. The build completed successfully. The binary reported `revoketrace 1.0.0`; toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)`.

Before network access, a local check confirmed one FLUTTER trustline, trustline owner equal to fixture trustor, issuer equal to source account and asset issuer, and both 56-character account identities present in the fixture. The CLI parsed those operation inputs before a deliberately invalid network passphrase was rejected with exit 40; it rejects that passphrase before constructing the live adapter. No network request was made by this local validation. The live command's account arguments were loaded from `fixtures/live-testnet-discovery.json`.

`SetTrustLineFlags`, flags `1` to `0`, transaction source equal to the issuer, sequence `42`, and operation index `0` are hypothetical caller-supplied operation context. No transaction was signed or submitted.

### Exact live command

The following Bash command uses valid single-backslash line continuations. Its arguments match the captured `argv` in the linked metadata artifact.

```bash
./target/release/revoketrace live \
  --network-passphrase 'Test SDF Network ; September 2015' \
  --horizon-url https://horizon-testnet.stellar.org \
  --rpc-url https://soroban-testnet.stellar.org \
  --operation SetTrustLineFlags \
  --source-account GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG \
  --trustor GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB \
  --asset-code FLUTTER \
  --asset-issuer GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG \
  --before-flags 1 \
  --after-flags 0 \
  --tx-source-account GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG \
  --sequence 42 \
  --operation-index 0 \
  --timeout-secs 15
```

| Item | Captured value |
| --- | --- |
| Start (UTC) | `2026-10-31T20:42:44.631326Z` |
| End (UTC) | `2026-10-31T20:42:54.901405Z` |
| Source commit | `9a419ebf74194359db45b79fb274e58d29c4e4de` |
| CLI version | `revoketrace 1.0.0` |
| CLI ledger and entries sequence | **5491146** |
| Evidence classification | `BOUNDED_CURRENT_TIP_RPC` |
| Forecast classification | `UNVERIFIED_FORECAST` |
| Exit code | **10**, valid warning-bearing forecast |
| Standard error | Empty (0 bytes) |

The process output is retained byte-for-byte: [stdout artifact](evidence/revoketrace-live-2026-10-31T204244Z.stdout.txt), SHA-256 `846d3b9e173006949eeb0553b44f308cfd2af3a0c5ad2e3e5af414aacc81c243` (2473 bytes); [stderr artifact](evidence/revoketrace-live-2026-10-31T204244Z.stderr.txt), SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (0 bytes); [capture metadata](evidence/revoketrace-live-2026-10-31T204244Z.capture.json) contains the exact argv, command, timestamps, toolchain, exit code, and hashes. The raw stdout renders the fixture issuer `GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG` exactly. Its full report records two affected pools, the modeled withdrawals and claimable balances, warning `W_UNVERIFIED_DISCOVERY`, and bounded-discovery limitations.

The separate 20:16 RPC response at ledger 5490831 is earlier than this CLI ledger 5491146 and must not be used as its exact header or as the protocol version for this capture. The CLI's human-readable output does not print the protocol version.

This capture is one bounded current-tip forecast. It does not establish exhaustive or historical discovery, an executed forced redemption, transaction success, full multi-operation sponsorship behavior, protocol support beyond 18 to 29, or program approval. The October 30 blocked-attempt record remains unchanged.
