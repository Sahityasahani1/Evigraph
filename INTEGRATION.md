# Integration guide: LLM Forensic Analyst Agent (Member 3)

This agent reads detector alerts and flow data, then produces an incident report in which every model claim is checked against evidence. The frontend only needs **one function**: `investigate()` in `src/agent/api.py`.

## 1. Requirements

- Python 3.10+ with the project's `.venv` active, and `pip install -r requirements.txt`
- [Ollama](https://ollama.com) running locally, with these models pulled:
```
  ollama pull llama3.2:3b
  ollama pull nomic-embed-text
```
  The default model is `llama3.2:3b`. The optional model `llama3.1:8b` is slower and not clearly better (`ollama pull llama3.1:8b`).
- The ATT&CK index. If it is missing, build it once:
```
  python -c "from src.agent.attack_rag import build_index; build_index()"
```

## 2. How to call it

```python
from src.agent.api import load_agent, list_incidents, investigate

agent = load_agent(
    flows_path="data/raw/processed/benchmark_test_flows.parquet",
    incidents_path="data/raw/member3_benchmark_test_incidents.json",
    model="llama3.2:3b",
)

list_incidents(agent)                 # incidents available to investigate
result = investigate(agent, "INC-0009")   # JSON-serialisable dict
```

Load the agent **once** and reuse it. `investigate()` takes about a minute on the 3B model, so run it in a background thread or task and show a loading state.

Command line (also writes `reports/<id>.json` and `reports/<id>.md`):

```
python -m src.agent.api INC-0009 --incidents data\raw\member3_benchmark_test_incidents.json
```

Optional flags: `--flows PATH`, `--out reports`, `--model NAME`.
Defaults: flows `data/raw/processed/benchmark_test_flows.parquet`, incidents `data/standin/incident_cases.json`.

### Mock mode (no Ollama, no data files)

To build the UI without running the model, change one import line:

    from src.agent.mock import load_agent, list_incidents, investigate   # mock
    # from src.agent.api import load_agent, list_incidents, investigate  # real

The mock serves saved reports from `src/agent/mock_data/` (currently INC-0009). The response shape is identical. `load_agent` accepts and ignores the same arguments.

## 3. What `investigate()` returns

| Key | What it is | How to show it |
|---|---|---|
| `incident_id` | The incident ID | Header |
| `error` | `None`, or a message if the incident was not found | Show the error and stop |
| `severity_score`, `start`, `end`, `alert_count`, `host_count` | Overview numbers | Overview card |
| `factual_summary` | Summary **written by code** from the alerts | **Show first. Reliable.** |
| `host_roles` | Hosts grouped by role: `compromised`, `infra`, `attackers`, `victims` (each has `hosts` and `total`) | Reliable. Good for a graph or table. |
| `timeline` | Attack stages in time order, with ranked sources and targets | Reliable |
| `cross_stage_hosts` | Hosts whose role changed between stages, with a `pattern` | Reliable |
| `attack_matches` | Top ATT&CK candidates per stage | Reliable. It is a shortlist, not a single answer. |
| `summary` | Model-written executive summary, or `None` | Show under an **"AI-generated, may contain errors"** label |
| `summary_withheld_reason` | Why `summary` is `None` (failed verification) | Optional small note |
| `findings` | Model findings that passed verification (claim, flow IDs, technique ID) | Under the same AI label |
| `rejected_findings` | Findings that failed verification, with reasons | Optional "rejected" panel |
| `report_markdown` | The full report as Markdown | Render or offer as download |

**Trust rule for the UI:** treat `factual_summary`, `host_roles`, `timeline`, `cross_stage_hosts` and `attack_matches` as authoritative (computed by code). Treat `summary` and `findings` as AI-generated.

Sample response: `reports/INC-0009.json`.

## 4. Input contract

- **Incidents file** (`IncidentCases` JSON): incidents, each with alerts (source and destination IP, predicted class, flow ID, timestamp, risk). Exact fields are in `src/agent/contract.py`.
- The loader drops `BENIGN` alerts and recomputes each incident's host list.
- **Flows file** (CSV or Parquet): the flow table columns are listed in `FLOW_COLUMNS` in `src/agent/contract.py`. Only `src/agent/flow_store.py` knows these columns.
- The hidden `label` column is never shown to the agent, to keep evaluation fair.

## 5. Real data

The agent works with Member 2's real incident file (`member3_benchmark_test_incidents.json`) and flows (`benchmark_test_flows.parquet`). His detector output looks label-derived (no misses), so results are optimistic.

For quick tests without his data, `python -m src.agent.make_standin_incidents` builds stand-in incidents into `data/standin/` from the test labels (a "perfect detector"). `data/raw/` and `data/standin/` are git-ignored.

## 6. How the verification works

1. Code gathers the facts: stages, ranked hosts, host roles, and ATT&CK search results.
2. The LLM proposes findings and a summary.
3. Code checks every claim: flow IDs and ATT&CK IDs must have been shown to the agent, IPs must belong to the incident, numbers must appear in the data, and "compromised" may only be said of internal hosts that sent attack traffic.
4. Code builds the final report. Failed claims are listed as rejected, not hidden.

## 7. Known limits (please keep these visible in the UI or docs)

- The verifier proves **provenance** (the claim is grounded in data the agent saw). It does **not** prove direction, causality or correctness. "Accepted" does not mean "correct". This is why model text is labelled AI-generated.
- The 3B model can still pick a weak flow as evidence or word a role loosely. The 8B model is not clearly better.
- ATT&CK mapping is a shortlist. Vague classes (Backdoor, Fuzzers, Exploits) map poorly, so look at the top 5, not only the first.
- Member 2's incidents are grouped by dominant class, which splits multi-stage attacks. For example, the APT attack is split across INC-0008 and INC-0009, so the role-change section is empty for INC-0009.
- Flow IDs in the dataset encode the label (a leak risk). Opaque IDs would be better.
- The data contains 200 BENIGN alerts (dropped by the loader) and `src_port` = 0 in places.

## 8. Tests

```
python -m pytest tests -q
```

Expected: **83 passed** (a real-file test is skipped if the data is absent).