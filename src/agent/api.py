"""The ONE entry point other team members call. Everything else in src/agent is internal."""
import json
from pathlib import Path

from src.agent.agent import ForensicAgent
from src.agent.attack_rag import AttackKnowledge
from src.agent.contract import load_incidents
from src.agent.flow_store import FlowStore
from src.agent.report import generate_report
from src.agent.tools import ForensicTools


def load_agent(flows_path, incidents_path, model="llama3.2:3b") -> ForensicAgent:
    tools = ForensicTools(FlowStore(flows_path), load_incidents(incidents_path), AttackKnowledge())
    return ForensicAgent(tools, model=model)


def list_incidents(agent) -> list[dict]:
    return agent.tools.list_incidents()["incidents"]


def investigate(agent, incident_id: str) -> dict:
    """Investigate one incident. The result is plain JSON-serialisable data for the dashboard."""
    result = generate_report(agent, incident_id)
    if result["error"]:
        return {"incident_id": incident_id, "error": result["error"]}
    briefing, _ = agent._gather(incident_id, [])
    inc = briefing["incident"]
    return {
        "incident_id": incident_id,
        "error": None,
        "severity_score": inc["severity_score"],
        "start": inc["start"],
        "end": inc["end"],
        "alert_count": inc["alert_count"],
        "host_count": inc["host_count"],
        "report_markdown": result["report"],
        "summary": result["summary"],
        "summary_withheld_reason": result["summary_note"],
        "timeline": inc["stages_in_time_order"],
        "cross_stage_hosts": inc.get("cross_stage_hosts", []),
        "attack_matches": {c: r["matches"] for c, r in briefing["attack_matches"].items()},
        "findings": [f.model_dump() for f in result["accepted"]],
        "rejected_findings": [
            {"finding": r["finding"].model_dump(), "problems": r["problems"]}
            for r in result["rejected"]
        ],
    }


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Investigate one incident and save JSON + Markdown.")
    default_flows = (
        "data/processed/benchmark_test_flows.parquet"
        if Path("data/processed/benchmark_test_flows.parquet").exists()
        else "data/raw/processed/benchmark_test_flows.parquet"
    )
    default_incidents = (
        "outputs/member3_benchmark_test_incidents.json"
        if Path("outputs/member3_benchmark_test_incidents.json").exists()
        else "data/standin/incident_cases.json"
    )
    ap.add_argument("incident_id", help="Incident ID to investigate")
    ap.add_argument("--flows", default=default_flows)
    ap.add_argument("--incidents", default=default_incidents)
    ap.add_argument("--out", default="reports")
    ap.add_argument("--model", default="llama3.2:3b")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(exist_ok=True)
    result = investigate(load_agent(args.flows, args.incidents, args.model), args.incident_id)
    (out / f"{args.incident_id}.json").write_text(json.dumps(result, indent=1, default=str), encoding="utf-8")
    if result.get("report_markdown"):
        (out / f"{args.incident_id}.md").write_text(result["report_markdown"], encoding="utf-8")
    print(result.get("report_markdown") or result["error"])