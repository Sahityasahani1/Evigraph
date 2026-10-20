"""Create a FAKE multi-scenario dataset with known answers, for evaluating the agent."""
import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

from src.agent.contract import FLOW_COLUMNS

OUT = Path("data/eval")
T0 = datetime(2026, 2, 1, 9, 0, 0)
PORTS = [21, 22, 23, 25, 80, 110, 139, 443, 445, 3306, 3389, 8080]


def main() -> None:
    rng = random.Random(11)
    flows: list[dict] = []

    def add(ts, src, dst, dport, label, dur, fwd, bwd, lenf, lenb, syn=1, rst=0, proto=6):
        row = {
            "flow_id": f"flw_{len(flows) + 1:06d}", "evidence_id": "eval_capture_001",
            "timestamp": ts.isoformat(), "src_ip": src, "dst_ip": dst,
            "src_port": rng.randint(40000, 60000), "dst_port": dport, "protocol": proto,
            "flow_duration": dur, "tot_fwd_pkts": fwd, "tot_bwd_pkts": bwd,
            "totlen_fwd_pkts": lenf, "totlen_bwd_pkts": lenb,
            "flow_iat_mean": round(dur / max(fwd + bwd - 1, 1), 1),
            "syn_flag_cnt": syn, "rst_flag_cnt": rst, "label": label,
        }
        flows.append(row)
        return row

    # Normal traffic
    for _ in range(300):
        ts = T0 + timedelta(seconds=rng.uniform(0, 3600))
        src = f"10.0.0.{rng.randint(10, 60)}"
        if rng.random() < 0.5:
            add(ts, src, "10.0.0.2", 53, "BENIGN", rng.randint(500, 5000), 1, 1, 70, 120, syn=0, proto=17)
        else:
            add(ts, src, "10.0.0.9", 443, "BENIGN", rng.randint(50000, 900000), rng.randint(5, 40),
                rng.randint(5, 60), rng.randint(500, 4000), rng.randint(2000, 90000))

    scenarios: dict[str, dict] = {}

    def scenario(iid, title, rows, risk, stage_order, families, pivots, key_hosts):
        scenarios[iid] = {"rows": rows, "risk": risk, "truth": {
            "title": title, "stage_order": stage_order, "attack_families": families,
            "pivot_hosts": pivots, "key_hosts": key_hosts}}

    # E1: SSH brute force only
    rows = [add(T0 + timedelta(minutes=5, seconds=4 * i), "203.0.113.10", "10.0.0.5", 22, "SSH-Patator",
                rng.randint(900000, 2500000), rng.randint(8, 12), rng.randint(6, 9),
                rng.randint(900, 1400), rng.randint(900, 1500), rst=rng.randint(0, 1)) for i in range(30)]
    scenario("INC-E1", "SSH brute force", rows, (0.85, 0.99), ["SSH-Patator"],
             {"SSH-Patator": ["T1110"]}, [], ["203.0.113.10", "10.0.0.5"])

    # E2: SSH brute force, then the hacked server scans the network (pivot)
    rows = [add(T0 + timedelta(minutes=10, seconds=3 * i), "203.0.113.20", "10.0.0.6", 22, "SSH-Patator",
                rng.randint(900000, 2500000), rng.randint(8, 12), rng.randint(6, 9),
                rng.randint(900, 1400), rng.randint(900, 1500), rst=rng.randint(0, 1)) for i in range(20)]
    rows += [add(T0 + timedelta(minutes=12, milliseconds=500 * i), "10.0.0.6", f"10.0.0.{rng.randint(100, 200)}",
                 rng.choice(PORTS), "PortScan", rng.randint(100, 900), 1, 0, 60, 0, rst=1) for i in range(40)]
    scenario("INC-E2", "Brute force then scan (pivot)", rows, (0.85, 0.99), ["SSH-Patator", "PortScan"],
             {"SSH-Patator": ["T1110"], "PortScan": ["T1046", "T1595"]}, ["10.0.0.6"],
             ["203.0.113.20", "10.0.0.6"])

    # E3: DDoS from six external sources against the web server
    rows = [add(T0 + timedelta(minutes=20, milliseconds=200 * i), f"198.51.100.{11 + i % 6}", "10.0.0.9", 80,
                "DDoS", rng.randint(2000, 8000), 300, 0, 40000, 0) for i in range(60)]
    scenario("INC-E3", "DDoS on web server", rows, (0.85, 0.99), ["DDoS"],
             {"DDoS": ["T1498", "T1499"]}, [], ["10.0.0.9"])

    # E4: large upload to an external address
    rows = [add(T0 + timedelta(minutes=30, seconds=20 * i), "10.0.0.31", "198.51.100.77", 443, "Infiltration",
                20_000_000, 9000, 400, 30_000_000, 30_000) for i in range(4)]
    scenario("INC-E4", "Data exfiltration", rows, (0.70, 0.80), ["Infiltration"],
             {"Infiltration": ["T1048", "T1041", "T1567", "T1030"]}, [], ["10.0.0.31", "198.51.100.77"])

    # E5: botnet beaconing every 20 seconds
    rows = [add(T0 + timedelta(minutes=40, seconds=20 * i), "10.0.0.44", "198.51.100.99", 8080, "Bot",
                300_000, 3, 2, 200, 150) for i in range(25)]
    scenario("INC-E5", "Botnet beaconing", rows, (0.85, 0.99), ["Bot"],
             {"Bot": ["T1071", "T1095", "T1571", "T1573", "T1090", "T1102"]}, [],
             ["10.0.0.44", "198.51.100.99"])

    # E6: SQL injection against the web server
    rows = [add(T0 + timedelta(minutes=50, seconds=5 * i), "203.0.113.30", "10.0.0.9", 80,
                "Web Attack - Sql Injection", 400_000, 10, 8, 1500, 6000) for i in range(15)]
    scenario("INC-E6", "SQL injection", rows, (0.85, 0.99), ["Web Attack - Sql Injection"],
             {"Web Attack - Sql Injection": ["T1190"]}, [], ["203.0.113.30", "10.0.0.9"])

    def build_incident(iid, rows, risk):
        alerts = [
            {"alert_id": f"alr_{iid}_{i + 1:03d}", "flow_id": r["flow_id"], "timestamp": r["timestamp"],
             "src_ip": r["src_ip"], "dst_ip": r["dst_ip"], "src_port": r["src_port"],
             "dst_port": r["dst_port"], "protocol": r["protocol"], "predicted_class": r["label"],
             "risk_score": round(rng.uniform(*risk), 3)}
            for i, r in enumerate(rows)
        ]
        hosts = sorted({a["src_ip"] for a in alerts} | {a["dst_ip"] for a in alerts})
        risks = [a["risk_score"] for a in alerts]
        classes = {a["predicted_class"] for a in alerts}
        severity = (0.40 * max(risks) + 0.30 * sum(risks) / len(risks)
                    + 0.15 * min(1.0, len(hosts) / 5) + 0.15 * min(1.0, len(classes) / 3))
        return {"incident_id": iid, "severity_score": round(min(severity, 1.0), 3),
                "hosts": hosts, "alerts": alerts}

    cases = {"incidents": [build_incident(i, s["rows"], s["risk"]) for i, s in scenarios.items()]}
    truth = {i: s["truth"] for i, s in scenarios.items()}

    flows.sort(key=lambda r: r["timestamp"])
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "flows.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FLOW_COLUMNS)
        w.writeheader()
        w.writerows(flows)
    (OUT / "incident_cases.json").write_text(json.dumps(cases, indent=1), encoding="utf-8")
    (OUT / "ground_truth.json").write_text(json.dumps(truth, indent=1), encoding="utf-8")
    print(f"Wrote {len(flows)} flows, {len(cases['incidents'])} incidents to {OUT}")


if __name__ == "__main__":
    main()