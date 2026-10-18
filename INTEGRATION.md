# LLM Forensic Agent: integration guide (Member 3)

## What it does
Given an incident from the detector, the agent investigates with tools (flow lookups, MITRE ATT&CK search) and
returns an evidence-cited report. Every flow ID, ATT&CK ID, IP and number the model writes is checked in code
against what it was actually shown; failures are rejected or withheld and reported.

## Requirements
- Ollama running locally, with: `ollama pull llama3.2:3b` and `ollama pull nomic-embed-text`
- `pip install ollama pandas pyarrow pydantic numpy pytest`
- ATT&CK data: `python -m src.agent.ingest_attack`, then build the index (see `attack_rag.py`)

## How to call it (the only file others should import: `src/agent/api.py`)
```python
from src.agent.api import load_agent, list_incidents, investigate
agent = load_agent("path/to/flows.parquet", "path/to/incident_cases.json")
list_incidents(agent)                   # [{incident_id, severity_score, alert_count, ...}]
result = investigate(agent, "INC-001")  # JSON-serialisable dict, about 30-90 s per incident
```
`result` keys: `incident_id, error, severity_score, start, end, alert_count, host_count, report_markdown,
summary, summary_withheld_reason, timeline, cross_stage_hosts, attack_matches, findings, rejected_findings`.
If `error` is not null, nothing else is reliable. `summary` may be null (see `summary_withheld_reason`).
A ready-made example result is in `reports/INC-UNSW.json`.

## Inputs (contract: `src/agent/contract.py`)
- Incidents JSON: `{"incidents": [{incident_id, severity_score (0-1), hosts, alerts: [{alert_id, flow_id,
  timestamp, src_ip, dst_ip, src_port, dst_port, protocol, predicted_class, risk_score (0-1)}]}]}`
- Flow table (CSV or Parquet): at least the columns in `FLOW_COLUMNS`; `flow_id` unique; `label` is never shown to the agent.
- Every alert's `flow_id` must exist in the flow table.

## Current status and limits
- Until Member 2's real detector output arrives, `data/standin/` holds incidents built from the test split's labels
  (`python -m src.agent.make_standin_incidents`). It acts as a perfect detector, so results are optimistic.
- `summary` and `findings` are written by a small local model: verified as grounded, but they can still get
  roles and directions wrong. Show them labelled as AI-generated; treat `timeline` and `cross_stage_hosts`
  (computed by code) as authoritative.
- Backdoor/Fuzzers/Exploits labels are vague, so ATT&CK mappings for them are shortlists.
- Data files are git-ignored (`data/raw`, `data/standin`); get them from Member 2.

## Tests
`python -m pytest tests -q` (Ollama is needed only for the real runs, not for the tests)