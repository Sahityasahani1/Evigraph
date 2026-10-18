"""STAND-IN for Member 2's detector: builds incidents from the TEST split's ground-truth labels.

This acts as a PERFECT detector (no misses, no false alarms), so results are optimistic.
Replace it with Member 2's real alerts and incidents as soon as they arrive.
The agent never sees `label`: labels only decide which flows become alerts and what
predicted_class says. Risk scores are random placeholders in 0.85 to 0.99.
"""
import json
import random
from pathlib import Path

import pandas as pd

from src.agent.contract import load_incidents

FLOWS = Path("data/raw/processed/benchmark_test_flows.parquet")
OUT = Path("data/standin")
NAMES = {
    "evd_apt_c2_capture": "INC-APT",
    "evd_ddos2019_capture": "INC-DDOS",
    "evd_unsw_nb15_capture": "INC-UNSW",
}


def main() -> None:
    rng = random.Random(21)
    df = pd.read_parquet(FLOWS)
    df = df[df["label"] != "BENIGN"].sort_values("timestamp")

    incidents = []
    for evidence_id, name in NAMES.items():
        part = df[df["evidence_id"] == evidence_id]
        if part.empty:
            continue
        alerts = [
            {
                "alert_id": f"alr_{r.flow_id}",
                "flow_id": r.flow_id,
                "timestamp": r.timestamp.isoformat(),
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "src_port": int(r.src_port),
                "dst_port": int(r.dst_port),
                "protocol": int(r.protocol),
                "predicted_class": r.label,
                "risk_score": round(rng.uniform(0.85, 0.99), 3),
            }
            for r in part.itertuples()
        ]
        hosts = sorted({a["src_ip"] for a in alerts} | {a["dst_ip"] for a in alerts})
        risks = [a["risk_score"] for a in alerts]
        classes = {a["predicted_class"] for a in alerts}
        severity = (0.40 * max(risks) + 0.30 * sum(risks) / len(risks)
                    + 0.15 * min(1.0, len(hosts) / 5) + 0.15 * min(1.0, len(classes) / 3))
        incidents.append({"incident_id": name, "severity_score": round(min(severity, 1.0), 3),
                          "hosts": hosts, "alerts": alerts})

    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "incident_cases.json"
    path.write_text(json.dumps({"incidents": incidents}), encoding="utf-8")

    # Prove the output follows the contract
    for inc in load_incidents(path).incidents:
        counts: dict[str, int] = {}
        for a in inc.alerts:
            counts[a.predicted_class] = counts.get(a.predicted_class, 0) + 1
        print(f"{inc.incident_id}: {len(inc.alerts)} alerts, {len(inc.hosts)} hosts, "
              f"severity {inc.severity_score}, classes {counts}")


if __name__ == "__main__":
    main()