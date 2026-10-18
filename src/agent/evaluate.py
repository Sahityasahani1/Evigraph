"""Score the agent on scenarios with known answers: deterministic checks plus repeated LLM runs."""
import argparse
import json
import time
from pathlib import Path

from src.agent.agent import ForensicAgent
from src.agent.attack_rag import AttackKnowledge
from src.agent.contract import load_incidents
from src.agent.flow_store import FlowStore
from src.agent.report import generate_report
from src.agent.tools import ForensicTools

EVAL = Path("data/eval")


def deterministic(agent, incident_id, truth):
    """Checks that need no LLM: what the code hands to the model must be right."""
    briefing, _ = agent._gather(incident_id, [])
    inc = briefing["incident"]
    stages = [s["attack_class"] for s in inc["stages_in_time_order"]]
    top1 = top5 = 0
    for cls, prefixes in truth["attack_families"].items():
        ids = [m["id"] for m in briefing["attack_matches"].get(cls, {}).get("matches", [])]
        top1 += bool(ids) and ids[0].startswith(tuple(prefixes))
        top5 += any(i.startswith(tuple(prefixes)) for i in ids)
    n = len(truth["attack_families"])
    sources = {h["host_ip"] for h in inc["top_alert_sources"]}
    targets = {h["host_ip"] for h in inc["top_alert_targets"]}
    seen_hosts = set(briefing["host_summaries"])
    return {
        "stage_order": stages == truth["stage_order"],
        "top1": top1 / n,
        "top5": top5 / n,
        "pivot": sorted(sources & targets) == sorted(truth["pivot_hosts"]),
        "key_hosts": len(set(truth["key_hosts"]) & seen_hosts) / len(truth["key_hosts"]),
    }


def llm_runs(agent, incident_id, runs):
    out = []
    for _ in range(runs):
        t0 = time.time()
        r = generate_report(agent, incident_id)
        out.append({
            "proposed": len(r["accepted"]) + len(r["rejected"]),
            "accepted": len(r["accepted"]),
            "summary_ok": r["summary"] is not None,
            "summary_note": r["summary_note"],
            "parse_error": r["parse_error"],
            "rejections": [p for x in r["rejected"] for p in x["problems"]],
            "seconds": time.time() - t0,
            "summary_text": r["summary"],
            "accepted_findings": r["accepted"],
            "rejected_findings": r["rejected"],
        })
    return out


def render(rows, args) -> str:
    n = len(rows)
    runs_per = 0 if args.no_llm else args.runs
    L = ["# Agent evaluation", "", f"Model: {args.model}. LLM runs per scenario: {runs_per}.", "",
         "| Scenario | Stage order | ATT&CK top-1 | ATT&CK top-5 | Pivot | Key hosts | Findings accepted | Summary accepted | Avg s |",
         "|---|---|---|---|---|---|---|---|---|"]
    all_runs = []
    for iid, title, d, runs in rows:
        all_runs += runs
        if runs:
            acc, prop = sum(r["accepted"] for r in runs), sum(r["proposed"] for r in runs)
            fnd = f"{acc}/{prop}"
            summ = f"{sum(r['summary_ok'] for r in runs)}/{len(runs)}"
            secs = f"{sum(r['seconds'] for r in runs) / len(runs):.0f}"
        else:
            fnd = summ = secs = "-"
        L.append(f"| {iid} {title} | {'yes' if d['stage_order'] else 'NO'} | {d['top1']:.0%} | "
                 f"{d['top5']:.0%} | {'yes' if d['pivot'] else 'NO'} | {d['key_hosts']:.0%} | "
                 f"{fnd} | {summ} | {secs} |")
    L += ["", "## Overall",
          f"- Stage order correct: {sum(d['stage_order'] for _, _, d, _ in rows)}/{n}",
          f"- ATT&CK top-1: {sum(d['top1'] for _, _, d, _ in rows) / n:.0%}, "
          f"top-5: {sum(d['top5'] for _, _, d, _ in rows) / n:.0%}",
          f"- Pivot answer correct: {sum(d['pivot'] for _, _, d, _ in rows)}/{n}",
          f"- Key hosts reaching the model: {sum(d['key_hosts'] for _, _, d, _ in rows) / n:.0%}"]
    if all_runs:
        prop = sum(r["proposed"] for r in all_runs)
        acc = sum(r["accepted"] for r in all_runs)
        reasons = sorted({p.split(":")[0] for r in all_runs for p in r["rejections"]})
        L += [f"- Findings accepted: {acc}/{prop} (rejected = caught hallucinations: {prop - acc})",
              f"- Summaries accepted: {sum(r['summary_ok'] for r in all_runs)}/{len(all_runs)}",
              f"- Unparseable model outputs: {sum(r['parse_error'] for r in all_runs)}/{len(all_runs)}",
              f"- Mean seconds per report: {sum(r['seconds'] for r in all_runs) / len(all_runs):.0f}",
              f"- Rejection reasons seen: {', '.join(reasons) or 'none'}",
              "",
              "Limitation: the verifier checks provenance (every ID, IP and number was shown to the",
              "agent), not direction or causality. Review summaries by hand for those errors."]
    return "\n".join(L)


def _encode(o):
    """Let json.dumps handle pydantic objects (Finding etc.)."""
    return o.model_dump() if hasattr(o, "model_dump") else str(o)


def save_json(rows):
    Path("reports").mkdir(exist_ok=True)
    Path("reports/evaluation.json").write_text(
        json.dumps([{"incident": i, "title": t, "deterministic": d, "runs": r} for i, t, d, r in rows],
                   indent=1, default=_encode),
        encoding="utf-8",
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--model", default="llama3.2:3b")
    args = ap.parse_args()

    truth = json.loads((EVAL / "ground_truth.json").read_text(encoding="utf-8"))
    tools = ForensicTools(
        FlowStore(EVAL / "flows.csv"),
        load_incidents(EVAL / "incident_cases.json"),
        AttackKnowledge(),
    )
    agent = ForensicAgent(tools, model=args.model)

    rows = []
    for iid, t in truth.items():
        d = deterministic(agent, iid, t)
        runs = [] if args.no_llm else llm_runs(agent, iid, args.runs)
        rows.append((iid, t["title"], d, runs))
        save_json(rows)  # saved after every scenario, so a late crash loses nothing
        print(f"done {iid} {t['title']}", flush=True)

    text = render(rows, args)
    Path("reports").mkdir(exist_ok=True)
    Path("reports/evaluation.md").write_text(text, encoding="utf-8")
    print("\n" + text)


if __name__ == "__main__":
    main()