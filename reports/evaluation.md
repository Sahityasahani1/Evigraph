# Agent evaluation

Model: llama3.2:3b. LLM runs per scenario: 0.

| Scenario | Stage order | ATT&CK top-1 | ATT&CK top-5 | Pivot | Key hosts | Findings accepted | Summary accepted | Avg s |
|---|---|---|---|---|---|---|---|---|
| INC-E1 SSH brute force | yes | 100% | 100% | yes | 100% | - | - | - |
| INC-E2 Brute force then scan (pivot) | yes | 100% | 100% | yes | 100% | - | - | - |
| INC-E3 DDoS on web server | yes | 100% | 100% | yes | 100% | - | - | - |
| INC-E4 Data exfiltration | yes | 100% | 100% | yes | 100% | - | - | - |
| INC-E5 Botnet beaconing | yes | 100% | 100% | yes | 100% | - | - | - |
| INC-E6 SQL injection | yes | 100% | 100% | yes | 100% | - | - | - |

## Overall
- Stage order correct: 6/6
- ATT&CK top-1: 100%, top-5: 100%
- Pivot answer correct: 6/6
- Key hosts reaching the model: 100%