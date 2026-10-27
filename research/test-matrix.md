# Phase 1 test matrix

| ID | Scenario | Expected classification | Expected protocol effect | Phase |
| --- | --- | --- | --- | --- |
| T01 | Fully authorized -> maintain-liabilities-only | `SUPPORTED_SAFE` | Flags change; no pool redemption | 2 offline + 4 live |
| T02 | Maintain-liabilities-only -> unauthorized | `SUPPORTED_SAFE` or `SUPPORTED_BLOCKED` | Redemption path; possible low reserve | 2 offline + 4 live |
| T03 | Fully authorized -> unauthorized | same as T02 | Redemption path | 2 offline + 4 live |
| T04 | Pool share redemption with both nonzero outputs and non-issuer owner | `SUPPORTED_SAFE` | Delete pool-share trustline; 2 claimable balances | 2 offline |
| T05 | Valid pool, one constituent issued by owner | `SUPPORTED_SAFE` | Exactly 1 claimable balance | 2 offline |
| T06 | Valid pool, revoked-asset withdrawal floors to zero and other asset is issued by owner | `SUPPORTED_SAFE` | 0 claimable balances | 2 offline |
| T06a | Nonzero total shares with zero reserve | `INCONCLUSIVE` | Arithmetic-only edge case; not accepted as ledger-reachable | 2 offline |
| T07 | Owner is issuer of one constituent | `SUPPORTED_SAFE` | Skip that asset's claimable balance | 2 offline |
| T08 | Unsponsored pool trustline | `SUPPORTED_SAFE` | Trustor sponsors outputs after deletion | 2 offline |
| T09 | Sponsored pool trustline | `SUPPORTED_SAFE` | Existing sponsor sponsors outputs | 2 offline |
| T10 | Active sponsorship sandwich with insufficient replacement sponsor balance | `SUPPORTED_BLOCKED` | Low reserve failure | 2 offline |
| T10a | Unsponsored trustline plus ambiguous active sponsorship context | `INCONCLUSIVE` | Refuse unsupported sponsorship inference | 2 offline |
| T11 | Active sponsorship sandwich over `UINT32_MAX` accounting limit | `SUPPORTED_BLOCKED` | Too-many-sponsoring failure | 2 offline |
| T12 | Missing one affected pool trustline or incomplete discovery manifest | `INCONCLUSIVE` | No SAFE result | 2 offline |
| T13 | Mixed ledger sequences or stale entries | `INCONCLUSIVE` | No SAFE result | 2/3 |
| T14 | Unsupported Soroban SAC authorization or CAP-0077 freeze | `UNSUPPORTED` | No Classic prediction | 2 |
| T15 | Exact reserve boundary | `SUPPORTED_SAFE` / blocked at one stroop below | Reserve delta is checked with integers | 2 offline |
| T16 | Overflow/negative/duplicate/malformed XDR | `UNSUPPORTED` or `INCONCLUSIVE` | Refuse input | 2/5 |

The two non-negotiable regression tests are T01 and T02: changing `AUTHORIZED_FLAG` to `AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG` must not redeem, while removing maintain-liabilities authorization must enter the redemption path.
