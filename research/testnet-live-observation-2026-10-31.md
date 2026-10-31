# Bounded Testnet observation, 2026-10-31

> **Provenance note:** The first observation below was recorded as a summary. Its original CLI stdout/stderr, exact invoked command transcript, standalone RPC response, and DNS-probe output were not retained. Treat those details as reported historical observations, not independently reproducible artifacts. A new capture from the PR #20 head, with its actual CLI output and a separate retained RPC response, is recorded at the end of this file.

At 2026-10-31T19:35:52Z, the release binary built from `3a7e762973cb4e3c3277e18fe0014037c437ca4e` completed a read-only `live` request against public Testnet endpoints. Rust and Cargo were 1.97.1; the CLI reported `revoketrace 1.0.0`. No transaction was submitted.

The command used `https://horizon-testnet.stellar.org`, `https://soroban-testnet.stellar.org`, the Testnet passphrase, and the public FLUTTER issuer/trustor from `fixtures/live-testnet-discovery.json`. It requested `SetTrustLineFlags`, flags 1 to 0, transaction source equal to the issuer, sequence 42, operation index 0, and a 15-second timeout. These operation values are hypothetical inputs, not observed transaction context.

The CLI exited **10** and printed a Live Testnet bounded discovery report. It recorded ledger and entries sequence **5490344**, evidence classification `BOUNDED_CURRENT_TIP_RPC`, forecast classification `UNVERIFIED_FORECAST`, and forced-pool-redemption transition. The reported base reserve was 5,000,000 stroops. Two candidate pool IDs were reconciled: `00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46` and `078ff7f339a3a1c950812bd143431498f880082e0ebdb95fb348a5b87693465c`. Modeled withdrawals were 700,000,000/514,506,217 and 4,980,000,000/4,980,000,000 stroops respectively. The report forecast pool deletion for both and four claimable balances, with trustor subentries -4 and sponsoring +4. Standard error was empty. Its warning was `W_UNVERIFIED_DISCOVERY`; limitations explicitly stated that discovery is bounded and the forecast is not transaction preflight.

The original summary reported that a separate read-only RPC `getLatestLedger` request immediately afterward returned **protocolVersion 29** and ledger **5490345**, one ledger later. Its response body was not retained, so those values are reported historical observations, not independently reproducible provider evidence. They were not the exact header from the CLI capture. Although the implementation checks RPC protocol metadata before XDR decoding and requires the decoded header version and ledger sequence to agree, the unretained summary cannot establish that validation for ledger 5490344. The separate request did not independently reproduce that earlier header.

The initial bounded RPC hostname probe was reported to have timed out during DNS resolution after 12 seconds, while Horizon returned HTTP 200. The probe command and output were not retained, so this is a reported diagnostic rather than independently auditable output. The subsequent CLI request and RPC request were reported to have completed. This was described as a transient lookup failure, not evidence that Testnet was unavailable.

The historical fixture and this observation use different ledger states. Matching pool IDs and modeled withdrawal amounts do not prove that the stored fixture was current, that every affected pool was discovered, or that a real forced redemption occurred. The prior real operation fixture is clawback-only. Claimable-balance IDs in this forecast depend on caller-supplied hypothetical sequence and operation index. No result here verifies transaction success or complete multi-operation sponsorship behavior. The October 30 blocked attempt remains a separate historical record.

## Reproducible recapture from PR #20, 2026-10-31

This is a separate observation, not a reconstruction of the earlier output. It was run from source commit `963453caa98039477ef88897d8b9da017dd8c379` (`phase7-testnet-evidence`) using the release binary built from that checkout with `cargo build --release --locked --bin revoketrace`. The installed toolchain was `rustc 1.97.1 (8bab26f4f 2026-07-14)` and `cargo 1.97.1 (c980f4866 2026-06-30)`; the binary reported `revoketrace 1.0.0`.

Before network access, a local fixture check confirmed that the single FLUTTER trustline owner is the fixture trustor, its issuer equals the fixture source account and asset issuer, and both identities exist in the fixture account list. The CLI's local parser validated those operation identities before rejecting a deliberately invalid network passphrase with exit 40; the parser rejects that passphrase before creating the live adapter. This validation request made no network call. The identities for the live invocation below were loaded directly from `fixtures/live-testnet-discovery.json`, not manually typed into the executable invocation.

The following transaction fields are hypothetical caller inputs, not a submitted or observed transaction: `SetTrustLineFlags`, flags `1` to `0`, transaction source equal to the issuer, sequence `42`, operation index `0`. The account and asset identities are public Testnet fixture identifiers. No credentials were used and no transaction was signed or submitted.

### Live CLI capture

| Item | Captured value |
| --- | --- |
| Execution start (UTC) | `2026-10-31T20:16:16.596771Z` |
| Execution end (UTC) | `2026-10-31T20:16:22.722517Z` |
| Source commit | `963453caa98039477ef88897d8b9da017dd8c379` |
| Binary | `revoketrace 1.0.0`, release build |
| Endpoints | `https://horizon-testnet.stellar.org`; `https://soroban-testnet.stellar.org` |
| Timeout | 15 seconds per request, as configured for the CLI |
| Exit code | **10**, valid forecast with warnings (not a transport or command failure) |
| Standard error | Empty |

Exact sanitized command, as invoked (identities were read from the tracked fixture):

```bash
./target/release/revoketrace live \\
  --network-passphrase 'Test SDF Network ; September 2015' \\
  --horizon-url https://horizon-testnet.stellar.org \\
  --rpc-url https://soroban-testnet.stellar.org \\
  --operation SetTrustLineFlags \\
  --source-account GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG \\
  --trustor GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB \\
  --asset-code FLUTTER \\
  --asset-issuer GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG \\
  --before-flags 1 \\
  --after-flags 0 \\
  --tx-source-account GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG \\
  --sequence 42 \\
  --operation-index 0 \\
  --timeout-secs 15
```

Captured standard output (verbatim):

```text
RevokeTrace Forecast Report
============================
Mode: Live Testnet bounded discovery
Requested authorization change: SetTrustLineFlags
Asset: FLUTTER issued by GBYEWT4YXA5QJPJDYFESK6T23OJGUFHUZNFVZLWMOJG4IOTUEG
Trustor: GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB
Flags: 1 -> 0
Network: Test SDF Network ; September 2015
Ledger evidence: ledger 5490828 (entries 5490828)
Evidence classification: BOUNDED_CURRENT_TIP_RPC
Forecast classification: UNVERIFIED_FORECAST (not a successful transaction preflight)
Transition: forced pool redemption
Base reserve: 5000000 stroops

Affected liquidity pools: 2
- Pool 00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46 (owner GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB)
  Expected redemption: asset A 700000000 stroops; asset B 514506217 stroops
  Pool deletion forecast: yes
  Expected claimable balances: 2
    - FLUTTER: 514506217 stroops, sponsor GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB, clawback disabled, ID 114bfb2ee7a904f48b7adee94797b61dfb17d74ebe0aed2b13030b4fd57b2986
    - SDK: 700000000 stroops, sponsor GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB, clawback disabled, ID d9209dd88b6227cb963d0c0575861e34f20539987e15f9516714bfd7d29bc5da
- Pool 078ff7f339a3a1c950812bd143431498f880082e0ebdb95fb348a5b87693465c (owner GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB)
  Expected redemption: asset A 4980000000 stroops; asset B 4980000000 stroops
  Pool deletion forecast: yes
  Expected claimable balances: 2
    - FLUTTER: 4980000000 stroops, sponsor GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB, clawback disabled, ID 609d41867c9991c17f984e83c93dc23f500d9173d51d80281b8cda819d641ef4
    - XLM: 4980000000 stroops, sponsor GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB, clawback disabled, ID 7b5cb5352068ba6d5343954ca5993114a4d861ea0d3efc86a88368f8274d51fc

Reserve and sponsorship effects:
- GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB: subentries -4, sponsoring +4, sponsored +0, reserve units +0 (reserve effect 0 stroops)

Warnings:
- [W_UNVERIFIED_DISCOVERY] forecast is internally consistent but discovery is not independently verified

Errors:
- None.

Evidence limitations:
- UNVERIFIED_FORECAST is not a successful transaction preflight and does not certify transaction execution
- live discovery is bounded to the enumerated candidate set and does not prove complete ledger coverage
```

Standard error was captured as the empty string. Exit code 10 is the CLI's documented warning-bearing forecast result. The CLI generated the formatted forecast, classifications, pool redemptions, claimable-balance IDs, account deltas, warning, and limitations from acquired evidence plus the hypothetical operation context. The output's ledger sequence and bounded evidence label describe the CLI acquisition at ledger `5490828`; the provider response bodies used by that acquisition were not separately retained.

### Separate `getLatestLedger` provider response

At `2026-10-31T20:16:37.354704Z` to `2026-10-31T20:16:38.406182Z`, a separate read-only JSON-RPC request to `https://soroban-testnet.stellar.org` completed with curl exit 0 and HTTP status 200. Its request command was:

```bash
curl -q --silent --show-error --max-time 15 --proto '=https' --proto-redir '=https' \\
  --header 'Content-Type: application/json' \\
  --data-raw '{"jsonrpc":"2.0","id":1,"method":"getLatestLedger"}' \\
  --write-out '\nHTTP_STATUS:%{http_code}\n' \\
  https://soroban-testnet.stellar.org
```

The complete response body is retained in [the raw JSON artifact](evidence/testnet-getLatestLedger-2026-10-31T201637Z.json), 159,464 bytes, SHA-256 `fa009bc79f84a8de9bd492ceca9d450559ee657d3280c6b2ee85a71adcdf327`. The provider's JSON fields were `result.sequence: 5490831` and `result.protocolVersion: 29`. This was three ledgers after CLI ledger `5490828`; it is a separate latest-ledger response, not the CLI's captured header, and is not used to relabel the CLI ledger. No HTTP headers were retained.

### Network diagnostics and evidence classes

- The earlier note's DNS timeout and Horizon HTTP 200 are historical reported diagnostics; their exact probe command/output and headers were not retained. They are not reproduced by this recapture.
- The new `live` command completed against the configured Horizon and RPC endpoints and emitted the report above. The CLI did not expose per-request HTTP status or raw provider bodies in its human output, so none are asserted here.
- The separate RPC call's HTTP 200 and JSON values are directly retained as the provider response artifact. They establish only what that endpoint returned for this separate request at the recorded time.
- Account identities, the asset, flags, transaction source, sequence, and operation index were caller inputs, with operation details explicitly hypothetical. Ledger and entry sequences, candidate/pool state, and reserve information came through the live adapter's provider acquisition; the displayed forecast and classification were generated by RevokeTrace.

This recapture does not establish exhaustive or historical pool discovery, a real forced-redemption execution, transaction success, full multi-operation sponsorship behavior, support for protocols beyond 18 to 29, or approval by any external program. The October 30 blocked attempt remains unchanged.
