# Integration guide for the frontend (Member 4)

The LLM Forensic Analyst Agent turns detector alerts into an incident report. The frontend needs
**three functions** from `src/agent/api.py`. There is also a **mock mode** so you can build the UI
today without Ollama or any data files.

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

The mock serves saved real reports from `src/agent/mock_data/` (INC-0009 and INC-0001). The response
shape is identical to the real agent. For an unknown ID the mock returns `{"incident_id": ..., "error": "..."}`.

For the exact shape of a full response, open `src/agent/mock_data/INC-0009.json`.

---

## 2. The real agent

### Requirements
- Python 3.10+, the project `.venv`, and `pip install -r requirements.txt`
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
| `attack_matches` | MITRE ATT&CK candidates per attack class, as `{class: {"matches": [{id, name, tactics}, ...]}}`. A top-5 shortlist, **not one answer** |

What the role keys mean:
- `compromised`: internal hosts that sent attack traffic (possibly compromised)
- `infra`: external servers that received traffic from internal hosts (possible attacker infrastructure)
- `attackers`: external hosts that sent attack traffic
- `victims`: internal hosts that received attack traffic (targets)

`cross_stage_hosts[].pattern` is `target_then_source` (possible compromise) or `source_then_target`
(possible callback or reused infrastructure).

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

---

## 5. How to display it (suggested)

1. **Header:** incident ID, severity badge (high / medium / low), time span, alert and host counts.
2. **Summary card:** `factual_summary`.
3. **Timeline:** one row per stage with class, time range, alert count, senders and receivers.
4. **Host roles:** four groups (compromised, attacker infrastructure, attackers, targets), with "and N more" when `total` exceeds the list.
5. **ATT&CK:** per stage, the first match emphasised and the other candidates shown as alternatives.
6. **AI section, clearly labelled "AI-generated, may contain errors":** `summary` and `findings`. If `summary` is `None`, show the withheld reason in small text.
7. **Optional:** a "Rejected claims" panel, and a download button for `report_markdown`.

**Please do not present AI text as fact.** The verifier checks that a claim is grounded in the data the
agent was shown. It does not check that the claim is correct. "Accepted" does not mean "correct".

---

## 6. Optional: wrap it in an HTTP endpoint

The repo does not include a web server. If your frontend needs HTTP, this FastAPI sketch is an example
only and is untested:

```python
from fastapi import FastAPI
from src.agent.api import load_agent, list_incidents, investigate

app = FastAPI()
agent = load_agent("data/raw/processed/benchmark_test_flows.parquet",
                   "data/raw/member3_benchmark_test_incidents.json")

@app.get("/incidents")
def incidents():
    return list_incidents(agent)

@app.get("/incidents/{incident_id}")
def incident(incident_id: str):
    return investigate(agent, incident_id)
```
Because `investigate` takes about a minute, either run it in a worker or cache results per incident ID.

---

## 7. Known limits (keep these visible)

- The verifier proves provenance, not direction or correctness. For example, a claim that an attacker server was "targeted" passed until a specific rule was added. See `docs/agent_eval.md`.
- The 3B model usually proposes only one finding per incident. The 8B model (`--model llama3.1:8b`) gives more but is several times slower.
- ATT&CK mapping is a shortlist. Vague classes (Backdoor, Fuzzers, Exploits) map poorly.
- Member 2's incidents are grouped by dominant class, which splits multi-stage attacks. The APT attack is split across INC-0008 and INC-0009, so `cross_stage_hosts` is empty for INC-0009.
- Member 2's detector output looks label-derived, so results are optimistic.

---

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| Connection refused / cannot reach Ollama | Start Ollama (open the Ollama app, or run `ollama serve`) |
| `404 model not found` | `ollama pull llama3.2:3b` (and `nomic-embed-text`) |
| Missing ATT&CK index error | `python -c "from src.agent.attack_rag import build_index; build_index()"` |
| File not found for flows or incidents | Check the paths in section 2. These files are git-ignored |
| `error` says the incident is unknown | Use an ID from `list_incidents()` |
| Want to build the UI without any of this | Use mock mode (section 1) |

## 9. Tests

```
python -m pytest tests -q
```
Expected: **102 passed** (a real-file test is skipped if the data files are absent).