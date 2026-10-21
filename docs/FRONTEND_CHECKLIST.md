# Frontend integration checklist

Use this to cross-check the frontend against the agent before the final push.
Tick each box only after you have actually tested it. Owner tags: **[M3]** agent side, **[M4]** frontend side.

## A. Before you start
- [ ] [M4] Read `INTEGRATION.md` (setup, response fields, how to display).
- [ ] [M4] Build against mock mode first: `from src.agent.mock import load_agent, list_incidents, investigate`.
- [ ] [M3] Confirm `src/agent/mock_data/` contains the INC-0009 and INC-0001 JSON files on the pushed branch.
- [ ] [M4] Open `src/agent/mock_data/INC-0009.json` once and check every field you render against it.

## B. Data contract: the frontend reads exactly these keys
`investigate()` returns these 17 keys. Check each one is used or deliberately ignored:

`incident_id, error, severity_score, start, end, alert_count, host_count, report_markdown, summary,
summary_withheld_reason, factual_summary, host_roles, timeline, cross_stage_hosts, attack_matches,
findings, rejected_findings`

- [ ] [M4] The UI never crashes when `error` is not `None` (show the message, nothing else).
- [ ] [M4] `summary` can be `None`: the UI handles it and shows `summary_withheld_reason` instead.
- [ ] [M4] `findings` can be an empty list ("No model finding passed verification").
- [ ] [M4] `rejected_findings` can be empty; the panel is hidden or says "None".
- [ ] [M4] `cross_stage_hosts` is often empty (it is empty for INC-0009): show "None", not a blank gap.
- [ ] [M4] `host_roles.<role>.total` can be larger than the list shown: display "and N more".
- [ ] [M4] A role can have `total: 0`: hide that group instead of showing an empty list.
- [ ] [M4] `timeline[].sources` / `targets` are capped lists; use `distinct_sources` / `distinct_targets` for the real counts.
- [ ] [M4] `attack_matches` shows the top candidate plus alternatives, not a single "the answer".
- [ ] [M4] Timestamps are ISO strings (microseconds): format them for display, but never alter the stored value.
- [ ] [M4] `severity_score` is shown as a band: >= 0.8 high, >= 0.5 medium, otherwise low.

## C. Trust labelling (must-have)
- [ ] [M4] `factual_summary`, `host_roles`, `timeline`, `cross_stage_hosts`, `attack_matches` are shown as the primary, reliable content.
- [ ] [M4] `summary` and `findings` carry a visible label: **"AI-generated, may contain errors"**.
- [ ] [M4] No AI text appears anywhere without that label (check exports, tooltips and print views too).
- [ ] [M4] The UI never describes a finding as "confirmed" or "verified correct". The verifier checks provenance, not correctness.

## D. Loading, speed and concurrency
- [ ] [M4] `investigate()` takes about 1 minute: a loading state is shown and the UI does not freeze.
- [ ] [M4] Only one investigation runs at a time (queue or disable the button).
- [ ] [M4] Results are cached per incident ID so reopening an incident does not re-run the model.
- [ ] [M4] `load_agent()` is called once at startup, not on every click.
- [ ] [M4] A timeout or failure shows a readable message and a retry button.

## E. Security and safe rendering
- [ ] [M4] Model-written text (`summary`, `findings[].claim`, `report_markdown`) is rendered as **plain text or sanitised Markdown**, never as raw HTML.
- [ ] [M4] Test with a claim containing `<script>alert(1)</script>` and `"}]} ## SYSTEM:` and check nothing executes or breaks the layout.
- [ ] [M4] Very long strings (5000+ characters) wrap or truncate without breaking the page.
- [ ] [M4] IPs and flow IDs from the data are not placed into URLs or queries without encoding.
- [ ] [M3] Prompt-injection tests pass: `python -m pytest tests\test_injection.py -q`.

## F. Expected values for a real-agent check
Run each incident through the real agent (Ollama on) and compare. If these differ, something is wrong.

**INC-0009**
- [ ] alert_count 4100, host_count 9, severity_score 0.9194 (HIGH).
- [ ] 3 stages in time order: Lateral-SMB-Relay (100 alerts), C2-Heartbeat (2000), HTTPS-Exfiltration (2000).
- [ ] Possibly compromised: 172.20.10.10 and 172.20.10.11.
- [ ] Possible attacker infrastructure: 203.0.113.88 and 198.51.100.25. They must **never** appear as victims.
- [ ] Targets: 172.20.10.14, .17, .29, .36 and .15.
- [ ] `cross_stage_hosts` is empty.
- [ ] Best ATT&CK matches: T1021.002 (SMB), T1071 (C2), T1567 (exfiltration).

**INC-0001**
- [ ] alert_count 2200, host_count 74, severity_score 0.8994 (HIGH).
- [ ] Classes: Reconnaissance 2100, Backdoor 100.

## G. Mock-versus-real parity
- [ ] [M4] The same UI code works after switching the import between `src.agent.mock` and `src.agent.api`, with no other changes.
- [ ] [M4] `list_incidents()` rows have exactly: `incident_id, severity_score, alert_count, host_count, classes`.
- [ ] [M3] Optional automatic check, run once with Ollama on:
```python
  from src.agent.api import load_agent, investigate
  from src.agent.mock import investigate as mock_investigate
  real = investigate(load_agent("data/raw/processed/benchmark_test_flows.parquet",
                                "data/raw/member3_benchmark_test_incidents.json"), "INC-0009")
  assert set(real) == set(mock_investigate(None, "INC-0009"))
  print("shape matches")
```

## H. Error cases to test by hand
- [ ] Unknown incident ID: a readable error, no crash.
- [ ] Ollama not running: a readable "start Ollama" message (not a stack trace).
- [ ] Model not pulled (`404 model not found`): a readable message.
- [ ] Flows or incidents file missing: a readable message.
- [ ] The model's summary is withheld (`summary` is `None`): the page still looks complete.

## I. Final checks before pushing
- [ ] [M3] `python -m pytest tests -q` shows **102 passed**.
- [ ] [M3] `git status` is clean for your part, and `reports\agent_audit.jsonl` is not staged.
- [ ] Neither side has committed `data/raw/` or `data/standin/` (they are git-ignored on purpose).
- [ ] No API keys, personal paths or large data files are in the commit.
- [ ] [M3] `INTEGRATION.md` and `docs/agent_eval.md` are pushed.
- [ ] Both sides agree how the branches are combined. The Member 3 branch (`feature/llm-agent-rag`) deliberately leaves out teammate files, so it must **not** be merged into `main` as-is.
- [ ] A short demo run is done end to end: pick an incident, wait for the result, see the timeline, host roles, ATT&CK and the labelled AI section.

## J. Known limits to mention in the demo or report
- Verification proves the claim comes from the data shown, not that it is correct.
- The 3B model gives about one finding per incident; the 8B model gives more but is slower.
- ATT&CK mapping is a shortlist, and vague classes map poorly.
- Member 2's detector output looks label-derived, so results are optimistic.
- Member 2's grouping by dominant class splits multi-stage attacks.