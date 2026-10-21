# LLM Forensic Analyst Agent: evaluation (Member 3)

## What was built
For each incident the agent works in two layers.

1. **Code computes the facts**: attack stages in time order, ranked senders and receivers, hosts whose role changed
   between stages, and host roles (internal senders = possibly compromised, external receivers = possible attacker
   infrastructure, internal receivers = targets). It also retrieves ATT&CK techniques (RAG over 706 techniques).
2. **The LLM writes text, and code verifies it.** The model proposes findings and a summary. Every flow ID, ATT&CK ID,
   IP and number must come from data the agent was actually shown, and role claims must match the computed roles.
   The final report is assembled by code. A model claim that fails is listed as rejected, not softened.

The code-computed sections are the reliable part. The model's summary and findings are labelled AI-generated.

## Setup
- Data: Member 2's incident file (9 incidents, INC-0001 to INC-0009) and test flows. His detector output looks
  label-derived (no misses), so results are optimistic.
- Models: `llama3.2:3b` (default) and `llama3.1:8b` (comparison), temperature 0, seed 0, context 8192.
- One run per incident (temperature 0 with a fixed seed gives near-identical repeats).
- Tests: 102 unit tests, including 6 prompt-injection tests.
- Reproduce the ablation: `python -m src.agent.ablation [--model NAME] [--ids ...] [--limit N]`.

## Results

| Run | Incidents | Claims proposed | Rejected by validator | Summaries withheld |
|---|---|---|---|---|
| 3B, all incidents | 9 | 9 (1 per incident) | 0 | 1 (INC-0008) |
| 8B, before the role-direction rule | 3 | 15 | 0 | 0 |
| 8B, with the role-direction rule, INC-0009 | 1 | 5 | 2 | 0 |
| 8B, with the role-direction rule, INC-0008 and INC-0001 | 2 | 10 | 0 | 0 |

- **3B:** the model proposed only one finding per incident although the prompt asks for 3 to 6, so recall is low.
  For INC-0008 its summary contained the number 13, which is not in the data. The validator withheld it and the
  code-written summary was shown instead.
- **8B, INC-0009, hand-checked against the timeline:**
  - The executive summary was fully correct.
  - Of 5 findings, 3 were correct. 2 were wrong in direction: they said the attacker servers 203.0.113.88 and
    198.51.100.25 were "targeted by the attackers". They passed the provenance checks.
  - A rule was added: attacker-side hosts may not be called targets or victims. On re-run both claims were
    rejected, and the 3 accepted claims are correct.
  - Faithfulness (claims that satisfy every rule) was 60% without the validator and 100% of shipped claims with it.
- **8B, INC-0008 and INC-0001 (rule in place):** 10 claims proposed, none rejected, no summary withheld. These
  claims were not hand-checked, so the validator only shows that none broke a rule, not that they are correct.
  Across all three 8B incidents, 15 claims were proposed and 2 were rejected, both on INC-0009.
- **Earlier 8B run (before host roles were put into the prompt):** the model also called the external attacker
  servers "possibly compromised" and the summary was withheld for shortened timestamps. Giving the model the
  code-computed host roles removed most of those errors. The roles in the prompt did more than rejection did.

## What the verifier does and does not prove
- It proves **provenance**: IDs, IPs and numbers are grounded in data the agent saw, and role words match the computed roles.
- It does **not** prove direction, causality or correctness in general. The two wrong-direction claims above passed
  until a specific rule was added. The new rule is wording-based and closes the errors seen, not every phrasing.
- On most runs the validator rejected nothing. It acts as a safety net, and most of the improvement came from
  putting the code-computed roles into the prompt.
- A harmless-looking injected sentence that cites a real flow can still be accepted. The injection tests show the
  real incident, the computed sections and the evidence checks cannot be removed by injected text.

## Limits and honest caveats
- Hand-checking covered one incident (INC-0009). The other 8B findings are accepted but not hand-verified.
- 9 incidents from a label-derived detector is a small, optimistic sample.
- ATT&CK mapping accuracy against Member 4's lab `truth.yaml` was not evaluated. Mapping is a top-5 shortlist.
  Vague classes (Backdoor, Fuzzers, Exploits) map poorly.
- Member 2's grouping by dominant class splits multi-stage attacks (the APT attack is split across INC-0008 and
  INC-0009), so the role-change section is empty for INC-0009.
- Flow IDs in the dataset encode the label (a leak risk); opaque IDs would be better.

## Differences from the original spec
- No Chroma: numpy cosine search over the ATT&CK embeddings (same idea).
- No `chat()` and no per-sentence `kind` objects. The agent produces one verified report per incident.
- No QueryAPI: a FlowStore adapter reads the flow table directly. The hidden `label` column is never shown.
- Evidence gathering is forced by code (every logged call is `"forced": true`), so the model cannot skip or choose tools.
  The tool loop is capped at 8 steps. There are no SQL or write tools.
- The audit log (`reports/agent_audit.jsonl`) records each tool call with a hash of the call record (not of the
  tool output), plus the model name and digest. The seed is fixed on the report calls; the tool loop uses temperature 0.
- Port and protocol claims are not checked against the cited flows.
- A mock mode (`src/agent/mock.py`) lets the frontend run without Ollama.