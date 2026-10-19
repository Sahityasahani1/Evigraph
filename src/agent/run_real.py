"""Run the agent on the stand-in incidents over Member 2's real TEST flows."""
import argparse
import json
from pathlib import Path

from src.agent.agent import ForensicAgent
from src.agent.attack_rag import AttackKnowledge
from src.agent.contract import load_incidents
from src.agent.flow_store import FlowStore
from src.agent.report import generate_report
from src.agent.tools import ForensicTools


def _encode(o):
    return o.model_dump() if hasattr(o, "model_dump") else str(o)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("incident_id")
    ap.add_argument("--llm", action="store_true")
    args = ap.parse_args()

    flows_path = (
        Path("data/processed/benchmark_test_flows.parquet")
        if Path("data/processed/benchmark_test_flows.parquet").exists()
        else Path("data/raw/processed/benchmark_test_flows.parquet")
    )
    incidents_path = (
        Path("outputs/member3_benchmark_test_incidents.json")
        if Path("outputs/member3_benchmark_test_incidents.json").exists()
        else Path("data/standin/incident_cases.json")
    )
    tools = ForensicTools(
        FlowStore(flows_path),
        load_incidents(incidents_path),
        AttackKnowledge(),
    )
    agent = ForensicAgent(tools)

    briefing, err = agent._gather(args.incident_id, [])
    if err:
        print("ERROR:", err)
        return
    inc = briefing["incident"]
    print(f"{args.incident_id}: {inc['alert_count']} alerts, {inc['host_count']} hosts, "
          f"severity {inc['severity_score']}")
    print("\nStages in time order:")
    for s in inc["stages_in_time_order"]:
        print("  ", s)
    print("\nTop sources:", inc["top_alert_sources"][:4])
    print("Top targets:", inc["top_alert_targets"][:4])
    print("Cross-stage hosts:")
    for h in inc.get("cross_stage_hosts", []):
        print("  ", h)
    print("Hosts looked up in full:", list(briefing["host_summaries"]))
    print("\nATT&CK matches per stage:")
    for cls, res in briefing["attack_matches"].items():
        print(f"  {cls}: {[m['id'] for m in res.get('matches', [])]}")

    if args.llm:
        r = generate_report(agent, args.incident_id)
        print("\nSUMMARY:", r["summary"] or f"(withheld: {r['summary_note']})")
        print("ACCEPTED:", json.dumps(r["accepted"], default=_encode, indent=1))
        print("REJECTED:", json.dumps(r["rejected"], default=_encode, indent=1))


if __name__ == "__main__":
    main()