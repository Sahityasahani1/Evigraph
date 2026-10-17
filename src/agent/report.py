"""Verified reporting: the LLM proposes findings, code checks every one, code writes the report."""
import json
import re

from pydantic import BaseModel, Field, ValidationError

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
FLOW_RE = re.compile(r"\bflw_\d+\b")
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


class Finding(BaseModel):
    claim: str
    flow_ids: list[str] = Field(default_factory=list)
    technique_id: str | None = None


class FindingList(BaseModel):
    findings: list[Finding]


FINDINGS_PROMPT = """You are a network forensic analyst. From the incident data provided, propose 3 to 6 findings.
Return JSON only: {"findings": [{"claim": str, "flow_ids": [str], "technique_id": str or null}]}

Rules:
- Each claim is ONE short factual sentence supported by the data. Use the word "possibly" for anything inferred.
- flow_ids: one or more flow IDs copied exactly from the data (first_flow_id, last_flow_id, or top_alerts_by_risk). Never invent IDs.
- technique_id: ONE ATT&CK ID copied from attack_matches for the stage the claim is about, or null.
- Mention IP addresses only if they appear in the data.
- If a host was first attacked and later attacked others, include a finding about it.
- Do not repeat a claim."""


def validate_findings(findings, tools, known_ips):
    """Accept a finding only if everything it cites was actually shown to the agent."""
    accepted, rejected = [], []
    for f in findings:
        problems = []
        if not f.flow_ids:
            problems.append("cites no flow_id")
        unseen = {x for x in f.flow_ids + FLOW_RE.findall(f.claim) if x not in tools.evidence}
        if unseen:
            problems.append(f"cites flows never shown to the agent: {sorted(unseen)}")
        techs = ([f.technique_id] if f.technique_id else []) + TECH_RE.findall(f.claim)
        bad_t = {t for t in techs if t not in tools.techniques_seen}
        if bad_t:
            problems.append(f"cites ATT&CK IDs not in the search results: {sorted(bad_t)}")
        bad_ip = {ip for ip in IP_RE.findall(f.claim) if ip not in known_ips}
        if bad_ip:
            problems.append(f"mentions IPs not in this incident: {sorted(bad_ip)}")
        if problems:
            rejected.append({"finding": f, "problems": problems})
        else:
            accepted.append(f)
    return accepted, rejected


def _band(score: float) -> str:
    return "HIGH" if score >= 0.8 else "MEDIUM" if score >= 0.5 else "LOW"


def build_report(briefing: dict, accepted: list, rejected: list) -> str:
    inc = briefing["incident"]
    stages = inc["stages_in_time_order"]
    L = [f"# Incident report: {inc['incident_id']}", "", "## Overview"]
    L.append(f"- Severity: {inc['severity_score']} ({_band(inc['severity_score'])}; "
             "bands: >=0.8 high, >=0.5 medium)")
    L.append(f"- Time span: {inc['start']} to {inc['end']}")
    L.append(f"- Alerts: {inc['alert_count']} across {inc['host_count']} hosts")

    L += ["", "## Timeline (from detector alerts)"]
    for i, s in enumerate(stages, 1):
        L.append(f"{i}. {s['first_seen']} to {s['last_seen']}: {s['attack_class']}, "
                 f"{s['alert_count']} alerts, {', '.join(s['sources'])} -> {', '.join(s['targets'])} "
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


def generate_report(agent, incident_id: str) -> dict:
    tools = agent.tools
    tools.evidence.clear()  # evidence is tracked per incident
    tools.techniques_seen.clear()
    calls: list[dict] = []
    briefing, err = agent._gather(incident_id, calls)
    if err:
        return {"report": None, "error": err, "tool_calls": calls}

    user = "Incident data:\n" + json.dumps(briefing, separators=(",", ":"), default=str)
    resp = agent.chat(
        model=agent.model,
        messages=[{"role": "system", "content": FINDINGS_PROMPT},
                  {"role": "user", "content": user}],
        format=FindingList.model_json_schema(),
        options={"temperature": 0, "num_ctx": 8192},
    )
    parse_error = False
    try:
        findings = FindingList.model_validate_json(resp.message.content).findings
    except (ValidationError, ValueError):
        findings, parse_error = [], True

    known_ips = set(tools.incidents[incident_id].hosts)
    accepted, rejected = validate_findings(findings, tools, known_ips)
    return {
        "report": build_report(briefing, accepted, rejected), "error": None,
        "accepted": accepted, "rejected": rejected,
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