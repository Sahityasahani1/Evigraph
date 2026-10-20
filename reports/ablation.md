# Validator ablation

Each incident was run once with the real model. 'Without validator' means every claim the model
proposed would be shipped. 'With validator' means only claims that pass the checks are shipped.

| Incident | Proposed | Accepted | Rejected | Summary withheld | Problems caught |
|---|---|---|---|---|---|
| INC-0009 | 1 | 1 | 0 | no | none |
| INC-0001 | 1 | 1 | 0 | no | none |
| INC-0002 | 1 | 1 | 0 | no | none |
| INC-0003 | 1 | 1 | 0 | no | none |
| INC-0004 | 1 | 1 | 0 | no | none |
| INC-0005 | 1 | 1 | 0 | no | none |
| INC-0006 | 1 | 1 | 0 | no | none |
| INC-0007 | 1 | 1 | 0 | no | none |
| INC-0008 | 1 | 1 | 0 | yes | none |

## Totals

- Incidents: 9
- Claims proposed by the model: 9
- Faithfulness WITHOUT validator (claims that satisfy every rule): 100%
- Claims the validator rejected: 0
- Faithfulness WITH validator: 100% of shipped claims satisfy every rule (by construction)
- Model summaries withheld for failing verification: 1 of 9

Problems caught, by type:

## How to read this

- Faithfulness here means provenance: IDs, IPs, numbers and roles are grounded in the data the agent was shown.
- It does not prove a claim is correct. A rejected claim may have been true, and an accepted claim can still be wrong.
- The validator's cost is the rejected claims. Its benefit is that none of the invented IDs, IPs or numbers above reach the report.