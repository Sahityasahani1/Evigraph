"""Create a small FAKE dataset that follows contract.py (for development and tests only)."""
import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

from src.agent.contract import FLOW_COLUMNS

OUT = Path("data/sample")
T0 = datetime(2026, 1, 10, 9, 0, 0)


def main() -> None:
    rng = random.Random(7)
    flows: list[dict] = []

    def add(ts, src, dst, sport, dport, label, dur, fwd, bwd, lenf, lenb, syn=0, rst=0, proto=6):
        row = {
            "flow_id": f"flw_{len(flows) + 1:06d}",
            "evidence_id": "sample_capture_001",
            "timestamp": ts.isoformat(),
            "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
            "protocol": proto, "flow_duration": dur,
            "tot_fwd_pkts": fwd, "tot_bwd_pkts": bwd,
            "tot_len_fwd_pkts": lenf, "tot_len_bwd_pkts": lenb,
            "flow_iat_mean": round(dur / max(fwd + bwd - 1, 1), 1),
            "syn_flag_cnt": syn, "rst_flag_cnt": rst, "label": label,
        }
        flows.append(row)
        return row

    # 1) Normal traffic: workstations talk to a DNS server and a web server
    for _ in range(200):
        ts = T0 + timedelta(seconds=rng.uniform(0, 3600))
        src = f"10.0.0.{rng.randint(10, 60)}"
        if rng.random() < 0.5:
            add(ts, src, "10.0.0.2", rng.randint(40000, 60000), 53, "BENIGN",
                rng.randint(500, 5000), 1, 1, 70, 120, proto=17)
        else:
            add(ts, src, "10.0.0.9", rng.randint(40000, 60000), 443, "BENIGN",
                rng.randint(50000, 900000), rng.randint(5, 40), rng.randint(5, 60),
                rng.randint(500, 4000), rng.randint(2000, 90000), syn=1)

    # 2) SSH brute force: external attacker -> server 10.0.0.5 (INC-001, stage 1)
    inc1 = []
    for i in range(40):
        ts = T0 + timedelta(minutes=20, seconds=3 * i)
        inc1.append(add(ts, "203.0.113.50", "10.0.0.5", rng.randint(40000, 60000), 22,
                        "SSH-Patator", rng.randint(900000, 2500000), rng.randint(8, 12),
                        rng.randint(6, 9), rng.randint(900, 1400), rng.randint(900, 1500),
                        syn=1, rst=rng.randint(0, 1)))

    # 3) Hacked server scans its neighbours (INC-001, stage 2: lateral movement)
    for i in range(60):
        ts = T0 + timedelta(minutes=24, milliseconds=500 * i)
        inc1.append(add(ts, "10.0.0.5", f"10.0.0.{rng.randint(1, 254)}", rng.randint(40000, 60000),
                        rng.choice([21, 22, 23, 25, 80, 110, 139, 443, 445, 3306, 3389, 8080]),
                        "PortScan", rng.randint(100, 900), 1, 0, 60, 0, syn=1, rst=1))

    # 4) Large upload to an outside address (INC-002: possible data theft)
    inc2 = []
    for i in range(3):
        ts = T0 + timedelta(minutes=50, seconds=20 * i)
        inc2.append(add(ts, "10.0.0.9", "198.51.100.7", rng.randint(40000, 60000), 443,
                        "Infiltration", 20_000_000, 9000, 400, 25_000_000, 30_000, syn=1))

    flows.sort(key=lambda r: r["timestamp"])

    def build_incident(inc_id, rows, lo, hi):
        alerts = [
            {
                "alert_id": f"alr_{inc_id}_{i + 1:03d}",
                "flow_id": r["flow_id"], "timestamp": r["timestamp"],
                "src_ip": r["src_ip"], "dst_ip": r["dst_ip"],
                "src_port": r["src_port"], "dst_port": r["dst_port"],
                "protocol": r["protocol"], "predicted_class": r["label"],
                "risk_score": round(rng.uniform(lo, hi), 3),
            }
            for i, r in enumerate(rows)
        ]
        hosts = sorted({a["src_ip"] for a in alerts} | {a["dst_ip"] for a in alerts})
        risks = [a["risk_score"] for a in alerts]
        classes = {a["predicted_class"] for a in alerts}
        severity = (0.40 * max(risks) + 0.30 * sum(risks) / len(risks)
                    + 0.15 * min(1.0, len(hosts) / 5) + 0.15 * min(1.0, len(classes) / 3))
        return {"incident_id": inc_id, "severity_score": round(min(severity, 1.0), 3),
                "hosts": hosts, "alerts": alerts}

    cases = {"incidents": [
        build_incident("INC-001", inc1, 0.85, 0.99),
        build_incident("INC-002", inc2, 0.70, 0.80),
    ]}

    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "sample_flows.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FLOW_COLUMNS)
        w.writeheader()
        w.writerows(flows)
    (OUT / "sample_incident_cases.json").write_text(json.dumps(cases, indent=1), encoding="utf-8")
    print(f"Wrote {len(flows)} flows and {len(cases['incidents'])} incidents to {OUT}")


if __name__ == "__main__":
    main()