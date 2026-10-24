# Integration guide for the frontend (Member 4)

The LLM Forensic Analyst Agent turns detector alerts into an incident report. The frontend needs
**three functions** from `src/agent/api.py`. There is also a **mock mode** so you can build the UI
without Ollama or any data files.

This branch (`feature/llm-agent-rag`) already contains `main`, Member 1 (`rehan`), Member 4
(`integration-clean`) and the agent. The agent files are Member 4's versions plus one extra rule
file, `src/agent/victim_rule.py`.

---

## 1. Quick start with mock mode (no setup)

Change one import line. Everything else in your code stays the same when you switch to the real agent.

```python
from src.agent.mock import load_agent, list_incidents, investigate    # mock: instant, no Ollama
# from src.agent.api import load_agent, list_incidents, investigate   # real agent

agent = load_agent()
incidents = list_incidents(agent)            # list for the incident picker
result = investigate(agent, "INC-0009")      # dict for the report view
```

The mock serves saved real reports from `src/agent/mock_data/` (INC-0009 and INC-0001). For an
unknown ID the mock returns `{"incident_id": ..., "error": "..."}`.

For the exact shape of a full response, open `src/agent/mock_data/INC-0009.json`. If the mock file and
this guide ever disagree, the mock file is right.

The dashboard has its own demo switch: `VITE_USE_MOCK=true` in `frontend/.env.local` shows prepared
demo data without calling the backend (see section 6).

---

## 2. The real agent

### Requirements
- Python 3.10+, the project `.venv`, and `pip install -r requirements.txt`.
  `requirements.txt` does not list every package yet. If you get `No module named ...`, run:
```
  pip install typer pydantic-settings hypothesis dpkt networkx
  pip install fastapi uvicorn xgboost duckdb psutil pyyaml scikit-learn
```
  (`torch` is only needed for the GNN detector and its tests.)
- [Ollama](https://ollama.com) running locally, with the models pulled:
```
  ollama pull llama3.2:3b
  ollama pull nomic-embed-text
```
- The ATT&CK index. If it is missing, build it once:
```
  python -c "from src.agent.attack_rag import build_index; build_index()"
```
- Data files (git-ignored, ask Member 2/3 for them):
  - flows: `data/raw/processed/benchmark_test_flows.parquet`
  - incidents: `data/raw/member3_benchmark_test_incidents.json`

### Usage
```python
from src.agent.api import load_agent, list_incidents, investigate

agent = load_agent(
    flows_path="data/raw/processed/benchmark_test_flows.parquet",
    incidents_path="data/raw/member3_benchmark_test_incidents.json",
    model="llama3.2:3b",          # optional; this is the default
)
list_incidents(agent)
result = investigate(agent, "INC-0009")
```

Rules for the UI:
- **Load the agent once** at startup and reuse it.
- **`investigate()` takes about 1 minute** on the 3B model. Run it in a background thread or task and show a loading state.
- **Run one investigation at a time.** Ollama is a single local model, so queue requests.
- If `result["error"]` is not `None`, show the message and stop.

### Command line (writes `reports/<id>.json` and `reports/<id>.md`)
```
python -m src.agent.api INC-0009 --incidents data\raw\member3_benchmark_test_incidents.json
```
Optional flags: `--flows PATH`, `--out reports`, `--model NAME`.

---

## 3. `list_incidents(agent)`: for the incident picker

Returns a list, most severe first:
```json
[{"incident_id": "INC-0009", "severity_score": 0.9194, "alert_count": 4100, "host_count": 9,
  "classes": {"C2-Heartbeat": 2000, "HTTPS-Exfiltration": 2000, "Lateral-SMB-Relay": 100}}]
```
Severity bands: **>= 0.8 high, >= 0.5 medium, below that low**.

---

## 4. `investigate(agent, incident_id)`: what you get back

A plain, JSON-serialisable dict.

### Reliable fields (computed by code, show prominently)
| Key | Contents |
|---|---|
| `incident_id`, `error` | ID, and `None` unless something went wrong |
| `severity_score`, `start`, `end`, `alert_count`, `host_count` | Overview. `start` and `end` are ISO timestamps |
| `factual_summary` | One short paragraph written by code. **Show this first.** |
| `host_roles` | `{"compromised": {...}, "infra": {...}, "attackers": {...}, "victims": {...}}`. Each value is `{"hosts": [top IPs], "total": N}` |
| `timeline` | Attack stages in time order. Each stage has `attack_class`, `first_seen`, `last_seen`, `alert_count`, `sources` (senders), `targets` (receivers), `distinct_sources`, `distinct_targets`, `first_flow_id`, `last_flow_id` |
| `cross_stage_hosts` | Hosts whose role changed between stages: `host_ip`, `pattern`, and `stages` (role per stage). Often empty |
| `attack_matches` | MITRE ATT&CK **candidates** per attack class. A shortlist, **not one answer**, and **not confirmed**. The exact shape is the one in the mock JSON and in `frontend/docs/API_CONTRACT.md` |

What the role keys mean:
- `compromised`: internal hosts that sent attack traffic (possibly compromised)
- `infra`: external servers that received traffic from internal hosts (possible attacker infrastructure)
- `attackers`: external hosts that sent attack traffic
- `victims`: internal hosts that received attack traffic (targets)

`cross_stage_hosts[].pattern` is `target_then_source` (possible compromise) or `source_then_target`
(possible callback or reused infrastructure).

### Status fields (new in this branch)
| Key | Contents |
|---|---|
| `reasoning_status` | `available` when the model answered, `degraded` when Ollama could not be reached. In degraded mode the report still contains all the code-written facts |
| `reasoning_error` | The reason, when `reasoning_status` is `degraded` |
| `retrieval_status` | Whether the ATT&CK index was available (for example `unavailable` when the index is missing) |
| `run_info` | Model name, model digest, seed and context size used for the run (also written to `reports/agent_audit.jsonl`) |

Show a small banner when `reasoning_status` is `degraded`, so the analyst knows the AI part is missing.

### AI-generated fields (show under a clear label)
| Key | Contents |
|---|---|
| `summary` | Model-written executive summary, or `None` if it failed verification |
| `summary_withheld_reason` | Why `summary` is `None` (for example "contains numbers not in the data") |
| `findings` | Findings that passed verification: `claim`, `flow_ids`, `technique_id` |
| `rejected_findings` | Findings that failed verification, with the reasons. Optional panel; see the sample file for the shape |

### Everything else
| Key | Contents |
|---|---|
| `report_markdown` | The whole report as Markdown (render it, or offer it as a download) |
| `briefing` | The raw evidence the agent was shown, kept for the evidence drill-down |

---

## 5. How to display it (suggested)

1. **Header:** incident ID, severity badge (high / medium / low), time span, alert and host counts.
2. **Summary card:** `factual_summary`.
3. **Timeline:** one row per stage with class, time range, alert count, senders and receivers.
4. **Host roles:** four groups (compromised, attacker infrastructure, attackers, targets), with "and N more" when `total` exceeds the list.
5. **ATT&CK:** per stage, the first match emphasised and the other candidates shown as alternatives, labelled "candidate, not confirmed".
6. **AI section, clearly labelled "AI-generated, may contain errors":** `summary` and `findings`. If `summary` is `None`, show the withheld reason in small text.
7. **Optional:** a "Rejected claims" panel, and a download button for `report_markdown`.

**Please do not present AI text as fact.** The verifier checks that a claim is grounded in the data the
agent was shown. It does not check that the claim is correct. "Accepted" does not mean "correct".

---

## 6. The HTTP backend and dashboard

The repo now includes a backend: `frontend/api/server.py` (FastAPI, app object `app`). It calls the
agent. Its endpoints are listed in `frontend/docs/API_CONTRACT.md`:

| Method | Path | Use |
|---|---|---|
| GET | `/incidents`, `/incidents/{incident_id}` | Prepared incidents |
| GET / POST | `/incidents/{incident_id}/report` | Report for a prepared incident |
| POST | `/investigations` | Upload a CSV, Parquet or PCAP file; returns a queued job |
| GET | `/investigations/{job_id}` | Poll the job status |
| GET | `/investigations/{job_id}/incidents/{incident_id}/report` | Report for a fresh incident |
| GET | `/investigations/{job_id}/incidents/{incident_id}/evidence/{flow_id}` | Open a cited flow |
| GET | `/health` | Liveness check |

Start the backend from the project root:
```
uvicorn frontend.api.server:app --port 8000
```
Start the dashboard in a second window:
```
cd frontend
npm install
npm run dev
```
Copy `frontend/.env.example` to `frontend/.env.local`. `VITE_USE_MOCK=true` shows prepared demo data;
`false` calls the backend at `VITE_BACKEND_URL` (default `http://localhost:8000`).

Because `investigate` takes about a minute, the backend runs it as a job and the dashboard polls it.

---

## 7. Known limits (keep these visible)

- The verifier proves provenance, not direction or correctness. For example, a claim that an attacker server was "targeted" passed until a specific rule was added (`src/agent/victim_rule.py`). See `docs/agent_eval.md`.
- The 3B model usually proposes only one finding per incident. The 8B model (`--model llama3.1:8b`) gives more but is several times slower.
- ATT&CK mapping is a shortlist. Vague classes (Backdoor, Fuzzers, Exploits) map poorly.
- Member 2's incidents are grouped by dominant class, which splits multi-stage attacks. The APT attack is split across INC-0008 and INC-0009, so `cross_stage_hosts` is empty for INC-0009.
- Member 2's detector output looks label-derived, so results are optimistic.
- Without Ollama the agent runs in degraded mode: facts and timeline are present, the AI summary and findings are not.

---

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| Connection refused / cannot reach Ollama | Start Ollama (open the Ollama app, or run `ollama serve`). Until then the report is `degraded` |
| `404 model not found` | `ollama pull llama3.2:3b` (and `nomic-embed-text`) |
| Missing ATT&CK index error | `python -c "from src.agent.attack_rag import build_index; build_index()"` |
| File not found for flows or incidents | Check the paths in section 2. These files are git-ignored |
| `error` says the incident is unknown | Use an ID from `list_incidents()` |
| `No module named ...` | Install the missing package (section 2) |
| Want to build the UI without any of this | Use mock mode (section 1) |
| `frontend/README.md` talks about an "OS Resource Dashboard" | That file is unrelated to EviGraph. Use section 6 of this guide |

## 9. Tests

Run the suite without the slow live-Ollama test:
```
python -m pytest tests -q --continue-on-collection-errors --timeout=120 -k "not retrieve_cited_flow"
```
The agent's own tests (all should pass):
```
python -m pytest tests/test_report.py tests/test_api.py tests/test_agent_rag.py tests/test_mock.py tests/test_audit.py tests/test_injection.py tests/test_ablation.py -q
```
Known failures in the full run, not caused by the agent:
- `tests/test_real_classes.py`: calls `_stage_query()` with old arguments (needs updating).
- `test_investigation_pipeline.py::...retrieve_cited_flow`: expects `degraded` but returns `available` when Ollama is running; also slow.
- Two Zeek tests: expect `None` where pandas gives `NaN` (Member 1).
- `test_courtroom_auditor.py`: needs a generated report first.
- `test_gnn_detector.py`: needs `torch`.
