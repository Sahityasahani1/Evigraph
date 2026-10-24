# Validator ablation

Each incident was run once with the real model. 'Without validator' means every claim the model
proposed would be shipped. 'With validator' means only claims that pass the checks are shipped.

| Incident | Proposed | Accepted | Rejected | Summary withheld | Problems caught |
|---|---|---|---|---|---|
| INC-0009 | 5 | 3 | 2 | no | attacker called a victim x2 |

## Totals

- Incidents: 1
- Claims proposed by the model: 5
- Faithfulness WITHOUT validator (claims that satisfy every rule): 60%
- Claims the validator rejected: 2
- Faithfulness WITH validator: 100% of shipped claims satisfy every rule (by construction)
- Model summaries withheld for failing verification: 0 of 1

Problems caught, by type:
- attacker called a victim: 2

## How to read this

- Faithfulness here means provenance: IDs, IPs, numbers and roles are grounded in the data the agent was shown.
- It does not prove a claim is correct. A rejected claim may have been true, and an accepted claim can still be wrong.
- The validator's cost is the rejected claims. Its benefit is that none of the invented IDs, IPs or numbers above reach the report.