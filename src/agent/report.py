"""Verified reporting: the LLM proposes findings and a summary, code checks every one, code writes the report."""
import json
import re

from pydantic import BaseModel, Field, ValidationError

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
FLOW_RE = re.compile(r"\bflw_\d+\b")
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
NUM_RE = re.compile(r"\d+(?:\.\d+)?")


class Finding(BaseModel):
    claim: str
    flow_ids: list[str] = Field(default_factory=list)
    technique_id: str | None = None


class FindingList(BaseModel):
    findings: list[Finding]


class Summary(BaseModel):
    summary: str


FINDINGS_PROMPT = """You are a network forensic analyst. From the incident data provided, propose 3 to 6 findings.
Return JSON only: {"findings": [{"claim": str, "flow_ids": [str], "technique_id": str or null}]}

Rules:
- Each claim is ONE short factual sentence supported by the data. Use the word "possibly" for anything inferred.
- flow_ids: one or more flow IDs copied exactly from the data (first_flow_id, last_flow_id, or top_alerts_by_risk). Never invent IDs.
- technique_id: ONE ATT&CK ID copied from attack_matches for the stage the claim is about, or null.
- Mention IP addresses only if they appear in the data.
- cross_stage_hosts lists hosts that appear in several stages, with a pattern. If a host has pattern target_then_source, include a finding that it was possibly compromised. Call a host a target only if the data lists it as a target, and a source only if the data lists it as a source.
- Do not repeat a claim."""

SUMMARY_PROMPT = """You write an executive summary of a network security incident for a manager.
Return JSON only: {"summary": str}

Rules:
- One sentence per attack stage, in time order, using each stage's OWN start and end times from the timeline. Never use the whole incident's time span for a single stage.
- Then one sentence on which host matters most and why. Base it only on the section "Hosts whose role changed across stages": call a host a target only if the report lists it as a target, and a source only if the report lists it as a source. Never invent roles such as "initial target".
- Use only facts, names and numbers that appear in the report you are given. Add nothing new.
- Say "possibly" for anything that is an inference."""

MEANING = {
    "target_then_source": "possible compromise",
    "source_then_target": "possible callback or reused infrastructure",
}


def _numbers(text: str) -> set[str]:
    """Numbers in a text, ignoring those inside IPs, flow IDs and ATT&CK IDs."""
    stripped = TECH_RE.sub(" ", FLOW_RE.sub(" ", IP_RE.sub(" ", text)))
    return set(NUM_RE.findall(stripped))


def text_problems(text, tools, known_ips, source_text, flow_ids=(), technique_ids=()):
    """Everything in `text` must come from what the agent was actually shown."""
    problems = []
    unseen = {x for x in list(flow_ids) + FLOW_RE.findall(text) if x not in tools.evidence}
    if unseen:
        problems.append(f"cites flows never shown to the agent: {sorted(unseen)}")
    techs = [t for t in technique_ids if t] + TECH_RE.findall(text)
    bad_t = {t for t in techs if t not in tools.techniques_seen}
    if bad_t:
        problems.append(f"cites ATT&CK IDs not in the search results: {sorted(bad_t)}")
    bad_ip = {ip for ip in IP_RE.findall(text) if ip not in known_ips}
    if bad_ip:
        problems.append(f"mentions IPs not in this incident: {sorted(bad_ip)}")
    bad_n = _numbers(text) - _numbers(source_text)
    if bad_n:
        problems.append(f"contains numbers not in the data: {sorted(bad_n)}")
    return problems


def validate_findings(findings, tools, known_ips, source_text=""):
    accepted, rejected = [], []
    for f in findings:
        problems = text_problems(
            f.claim, tools, known_ips, source_text, f.flow_ids, [f.technique_id]
        )
        if not f.flow_ids:
            problems.insert(0, "cites no flow_id")
        if problems:
            rejected.append({"finding": f, "problems": problems})
        else:
            accepted.append(f)
    return accepted, rejected


def _band(score: float) -> str:
    return "HIGH" if score >= 0.8 else "MEDIUM" if score >= 0.5 else "LOW"


def _hosts_text(hosts, distinct):
    text = ", ".join(hosts)
    extra = distinct - len(hosts)
    return f"{text} and {extra} more" if extra > 0 else text


def build_report(briefing, accepted, rejected, summary=None, summary_note=None) -> str:
    inc = briefing["incident"]
    stages = inc["stages_in_time_order"]
    L = [f"# Incident report: {inc['incident_id']}"]
    if summary:
        L += ["", "## Executive summary (model-written, verified)", summary]
    elif summary_note:
        L += ["", "## Executive summary", f"- Withheld: {summary_note}"]

    L += ["", "## Overview"]
    L.append(f"- Severity: {inc['severity_score']} ({_band(inc['severity_score'])}; "
             "bands: >=0.8 high, >=0.5 medium)")
    L.append(f"- Time span: {inc['start']} to {inc['end']}")
    L.append(f"- Alerts: {inc['alert_count']} across {inc['host_count']} hosts")

    L += ["", "## Timeline (from detector alerts)"]
    for i, s in enumerate(stages, 1):
        src = _hosts_text(s["sources"], s.get("distinct_sources", len(s["sources"])))
        dst = _hosts_text(s["targets"], s.get("distinct_targets", len(s["targets"])))
        L.append(f"{i}. {s['first_seen']} to {s['last_seen']}: {s['attack_class']}, "
                 f"{s['alert_count']} alerts, from {src} to {dst} "
                 f"[{s['first_flow_id']}, {s['last_flow_id']}]")

    sources = {h["host_ip"] for h in inc["top_alert_sources"]}
    targets = {h["host_ip"] for h in inc["top_alert_targets"]}
    pivots = sorted(sources & targets)
    L += ["", "## Possible pivot hosts"]
    if pivots:
        for p in pivots:
            L.append(f"- {p} was both a target and a source of alerts (possible compromise and "
                     "lateral movement). Check the timeline above for the order.")
    else:
        L.append("- None: no host appears as both a target and a source of alerts.")

    L += ["", "## Hosts whose role changed across stages (computed from the alerts)"]
    changed = [h for h in inc.get("cross_stage_hosts", []) if h["pattern"] in MEANING]
    if changed:
        for h in changed:
            roles = ", then ".join(f"{s['role']} in {s['stage']}" for s in h["stages"])
            L.append(f"- {h['host_ip']}: {roles} ({MEANING[h['pattern']]})")
    else:
        L.append("- None: no host changed role between stages.")

    L += ["", "## Key hosts"]
    for ip, s in briefing["host_summaries"].items():
        if "error" in s:
            continue
        L.append(f"- {ip}: source of {s['flows_as_source']} flows "
                 f"({s['unique_destination_hosts']} destination hosts, "
                 f"{s['unique_destination_ports']} destination ports), "
                 f"destination of {s['flows_as_destination']} flows")

    L += ["", "## ATT&CK mapping (best search match per stage)"]
    for cls, res in briefing["attack_matches"].items():
        m = res["matches"]
        if m:
            others = ", ".join(x["id"] for x in m[1:])
            L.append(f"- {cls}: {m[0]['id']} {m[0]['name']} "
                     f"(tactic: {', '.join(m[0]['tactics'])}); other candidates: {others}")

    L += ["", "## Analyst findings (each verified against retrieved evidence)"]
    if not accepted:
        L.append("- No model finding passed verification.")
    for f in accepted:
        tech = f" ({f.technique_id})" if f.technique_id else ""
        L.append(f"- {f.claim}{tech} [{', '.join(f.flow_ids)}]")

    L += ["", "## Verification summary",
          f"- Findings proposed: {len(accepted) + len(rejected)}, "
          f"accepted: {len(accepted)}, rejected: {len(rejected)}"]
    for r in rejected:
        L.append(f"  - REJECTED: \"{r['finding'].claim}\" ({'; '.join(r['problems'])})")
    return "\n".join(L)


def _summarise(agent, base_report, known_ips):
    resp = agent.chat(
        model=agent.model,
        messages=[{"role": "system", "content": SUMMARY_PROMPT},
                  {"role": "user", "content": "Report:\n" + base_report}],
        format=Summary.model_json_schema(),
        options={"temperature": 0, "num_ctx": 8192},
    )
    try:
        text = Summary.model_validate_json(resp.message.content).summary.strip()
    except (ValidationError, ValueError):
        return None, "model output could not be parsed"
    if not text:
        return None, "model returned an empty summary"
    problems = text_problems(text, agent.tools, known_ips, base_report)
    if problems:
        return None, "failed verification: " + "; ".join(problems)
    return text, None


def generate_report(agent, incident_id: str) -> dict:
    tools = agent.tools
    tools.evidence.clear()  # evidence is tracked per incident
    tools.techniques_seen.clear()
    calls: list[dict] = []
    briefing, err = agent._gather(incident_id, calls)
    if err:
        return {"report": None, "error": err, "tool_calls": calls}

    source = json.dumps(briefing, separators=(",", ":"), default=str)
    resp = agent.chat(
        model=agent.model,
        messages=[{"role": "system", "content": FINDINGS_PROMPT},
                  {"role": "user", "content": "Incident data:\n" + source}],
        format=FindingList.model_json_schema(),
        options={"temperature": 0, "num_ctx": 8192},
    )
    parse_error = False
    try:
        findings = FindingList.model_validate_json(resp.message.content).findings
    except (ValidationError, ValueError):
        findings, parse_error = [], True

    known_ips = set(tools.incidents[incident_id].hosts)
    accepted, rejected = validate_findings(findings, tools, known_ips, source)

    base = build_report(briefing, accepted, rejected)
    summary, summary_note = _summarise(agent, base, known_ips)
    return {
        "report": build_report(briefing, accepted, rejected, summary, summary_note),
        "error": None, "accepted": accepted, "rejected": rejected,
        "summary": summary, "summary_note": summary_note,
        "parse_error": parse_error, "tool_calls": calls,
    }


if __name__ == "__main__":
    import sys
    import time
    from pathlib import Path

    from src.agent.agent import build_agent

    incident = sys.argv[1] if len(sys.argv) > 1 else "INC-001"
    t0 = time.time()
    result = generate_report(build_agent(), incident)
    print(result["report"] or result["error"])
    if result["report"]:
        Path("reports").mkdir(exist_ok=True)
        Path(f"reports/{incident}.md").write_text(result["report"], encoding="utf-8")
    print(f"\n({time.time() - t0:.0f}s)")