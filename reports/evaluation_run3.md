# Agent evaluation

Model: llama3.2:3b. LLM runs per scenario: 3.

| Scenario | Stage order | ATT&CK top-1 | ATT&CK top-5 | Pivot | Key hosts | Findings accepted | Summary accepted | Avg s |
|---|---|---|---|---|---|---|---|---|
| INC-E1 SSH brute force | yes | 100% | 100% | yes | 100% | 3/3 | 3/3 | 32 |
| INC-E2 Brute force then scan (pivot) | yes | 100% | 100% | yes | 100% | 3/3 | 3/3 | 38 |
| INC-E3 DDoS on web server | yes | 100% | 100% | yes | 100% | 17/17 | 0/3 | 89 |
| INC-E4 Data exfiltration | yes | 100% | 100% | yes | 100% | 3/3 | 3/3 | 31 |
| INC-E5 Botnet beaconing | yes | 100% | 100% | yes | 100% | 8/11 | 3/3 | 50 |
| INC-E6 SQL injection | yes | 100% | 100% | yes | 100% | 3/3 | 3/3 | 28 |

## Overall
- Stage order correct: 6/6
- ATT&CK top-1: 100%, top-5: 100%
- Pivot answer correct: 6/6
- Key hosts reaching the model: 100%
- Findings accepted: 37/40 (rejected = caught hallucinations: 3)
- Summaries accepted: 15/18
- Unparseable model outputs: 0/18
- Mean seconds per report: 45
- Rejection reasons seen: cites flows never shown to the agent, contains numbers not in the data

Limitation: the verifier checks provenance (every ID, IP and number was shown to the
agent), not direction or causality. Review summaries by hand for those errors.