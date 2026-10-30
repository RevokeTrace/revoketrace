# Commands and reports

| Command | Purpose |
| --- | --- |
| `analyze` | Evaluate a caller-supplied offline snapshot |
| `live` | Acquire bounded current-tip Testnet evidence and forecast |
| `inspect` | Read a saved report envelope without authenticating it; output is labelled as unverified caller-supplied data |
| `version` | Print CLI version |
| `help` | Display usage |

Reports use JSON schema version `1` with report type `revoketrace.forecast`. Equivalent validated inputs produce deterministic JSON output.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Command completed, not transaction approval |
| 10 | Valid forecast with warnings, typically `UNVERIFIED_FORECAST` |
| 20 | Inconclusive or contradictory evidence |
| 30 | Unsupported operation or protocol |
| 40 | Invalid input |
| 50 | Live transport or RPC failure |
| 60 | Safe report-output failure |
| 70 | Internal failure |

For flags, options, file safety, complete schema fields and examples, use the [canonical CLI reference](https://github.com/RevokeTrace/revoketrace/blob/main/docs/cli.md). That document is maintained alongside the implementation.
