"""Ablation: what does the validator catch?
Runs the real model on each incident and compares the model's raw output (no validator)
with what the validator lets through. Writes reports/ablation.md and reports/ablation.json."""
import argparse
import json
import time
from collections import Counter
from pathlib import Path

from src.agent.api import list_incidents, load_agent
from src.agent.report import generate_report

CATEGORIES = [
    ("cites no flow_id", "no citation"),
    ("flows never shown", "invented flow ID"),
    ("ATT&CK IDs not", "invented ATT&CK ID"),
    ("IPs not in this incident", "invented IP"),
    ("numbers not in", "invented number"),
    ("compromised", "wrong 'compromised' role"),
]


def categorise(problems) -> Counter:
    counts = Counter()
    for problem in problems:
        for key, label in CATEGORIES:
            if key in problem:
                counts[label] += 1
                break
    return counts


def run_ablation(agent, incident_ids, out=None) -> list[dict]:
    rows = []
    for incident_id in incident_ids:
        t0 = time.time()
        r = generate_report(agent, incident_id)
        if r["error"]:
            rows.append({"incident_id": incident_id, "error": r["error"]})
        else:
            problems = [p for x in r["rejected"] for p in x["problems"]]
            rows.append({
                "incident_id": incident_id,
                "proposed": len(r["accepted"]) + len(r["rejected"]),
                "accepted": len(r["accepted"]),
                "rejected": len(r["rejected"]),
                "parse_error": r["parse_error"],
                "summary_withheld": r["summary"] is None,
                "summary_note": r["summary_note"],
                "problems": dict(categorise(problems)),
                "seconds": round(time.time() - t0),
            })
        if out:  # save after every incident so a crash loses nothing
            save(rows, out)
    return rows


def summarise(rows) -> dict:
    ok = [r for r in rows if not r.get("error")]
    proposed = sum(r["proposed"] for r in ok)
    accepted = sum(r["accepted"] for r in ok)
    problems = Counter()
    for r in ok:
        problems.update(r["problems"])
    return {
        "incidents": len(ok),
        "proposed": proposed,
        "accepted": accepted,
        "rejected": proposed - accepted,
        "faithfulness_without_validator": (accepted / proposed) if proposed else None,
        "summaries_withheld": sum(1 for r in ok if r["summary_withheld"]),
        "problems": dict(problems),
    }


def to_markdown(rows) -> str:
    s = summarise(rows)
    pct = (f"{100 * s['faithfulness_without_validator']:.0f}%"
           if s["faithfulness_without_validator"] is not None else "n/a")
    L = ["# Validator ablation", "",
         "Each incident was run once with the real model. 'Without validator' means every claim the model",
         "proposed would be shipped. 'With validator' means only claims that pass the checks are shipped.", "",
         "| Incident | Proposed | Accepted | Rejected | Summary withheld | Problems caught |",
         "|---|---|---|---|---|---|"]
    for r in rows:
        if r.get("error"):
            L.append(f"| {r['incident_id']} | error: {r['error']} | | | | |")
            continue
        probs = ", ".join(f"{k} x{v}" for k, v in r["problems"].items()) or "none"
        L.append(f"| {r['incident_id']} | {r['proposed']} | {r['accepted']} | {r['rejected']} | "
                 f"{'yes' if r['summary_withheld'] else 'no'} | {probs} |")
    L += ["", "## Totals", "",
          f"- Incidents: {s['incidents']}",
          f"- Claims proposed by the model: {s['proposed']}",
          f"- Faithfulness WITHOUT validator (claims that satisfy every rule): {pct}",
          f"- Claims the validator rejected: {s['rejected']}",
          "- Faithfulness WITH validator: 100% of shipped claims satisfy every rule (by construction)",
          f"- Model summaries withheld for failing verification: {s['summaries_withheld']} of {s['incidents']}",
          "", "Problems caught, by type:"]
    for k, v in s["problems"].items():
        L.append(f"- {k}: {v}")
    L += ["", "## How to read this", "",
          "- Faithfulness here means provenance: IDs, IPs, numbers and roles are grounded in the data the agent was shown.",
          "- It does not prove a claim is correct. A rejected claim may have been true, and an accepted claim can still be wrong.",
          "- The validator's cost is the rejected claims. Its benefit is that none of the invented IDs, IPs or numbers above reach the report."]
    return "\n".join(L)


def save(rows, out) -> None:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(
        json.dumps({"rows": rows, "summary": summarise(rows)}, indent=2, default=str), encoding="utf-8")
    out.with_suffix(".md").write_text(to_markdown(rows), encoding="utf-8")


def main():
    p = argparse.ArgumentParser(description="Validator on/off ablation")
    p.add_argument("--flows", default="data/raw/processed/benchmark_test_flows.parquet")
    p.add_argument("--incidents", default="data/raw/member3_benchmark_test_incidents.json")
    p.add_argument("--model", default="llama3.2:3b")
    p.add_argument("--ids", nargs="*", help="only these incident IDs")
    p.add_argument("--limit", type=int, help="only the first N incidents")
    p.add_argument("--out", default="reports/ablation")
    args = p.parse_args()

    agent = load_agent(args.flows, args.incidents, model=args.model)
    ids = args.ids or [row["incident_id"] for row in list_incidents(agent)]
    if args.limit:
        ids = ids[: args.limit]
    rows = run_ablation(agent, ids, out=args.out)
    print(to_markdown(rows))


if __name__ == "__main__":
    main()