from src.agent.contract import IncidentCases, load_incidents
from src.agent.flow_store import FlowStore
from src.agent.tools import ForensicTools


class FakeKB:
    def search(self, query, k=5):
        return []


def _alert(n, src, dst, cls):
    return {"alert_id": f"a{n}", "flow_id": f"f{n}",
            "timestamp": f"2026-01-01T00:{n // 60:02d}:{n % 60:02d}", "src_ip": src,
            "dst_ip": dst, "src_port": 1000, "dst_port": 80, "protocol": 6,
            "predicted_class": cls, "risk_score": 0.9}


def _tools_for(alerts):
    hosts = sorted({a["src_ip"] for a in alerts} | {a["dst_ip"] for a in alerts})
    cases = IncidentCases.model_validate({"incidents": [
        {"incident_id": "X", "severity_score": 0.5, "hosts": hosts, "alerts": alerts}]})
    return ForensicTools(None, cases, FakeKB())


def test_pivot_host_is_target_then_source():
    tools = ForensicTools(FlowStore("data/sample/sample_flows.csv"),
                          load_incidents("data/sample/sample_incident_cases.json"), FakeKB())
    inc = tools.get_incident("INC-001")
    row = next(h for h in inc["cross_stage_hosts"] if h["host_ip"] == "10.0.0.5")
    assert [s["role"] for s in row["stages"]] == ["target", "source"]
    assert row["pattern"] == "target_then_source"


def test_stage_sources_are_ranked_by_alerts_not_alphabetically():
    alerts, n = [], 0
    for src, count in [("10.0.0.1", 1), ("10.0.0.2", 1), ("10.0.0.3", 1),
                       ("10.0.0.4", 1), ("10.0.0.5", 1), ("10.0.0.6", 5)]:
        for _ in range(count):
            n += 1
            alerts.append(_alert(n, src, "192.168.0.1", "SYN-Flood"))
    stage = _tools_for(alerts).get_incident("X")["stages_in_time_order"][0]
    assert stage["sources"][0] == "10.0.0.6"
    assert stage["distinct_sources"] == 6


def test_revealing_patterns_are_ranked_above_busy_hosts():
    alerts, n = [], 0
    for cls in ("Recon", "Backdoor"):
        for k in range(1, 13):  # twelve busy hosts that act the same way in both stages
            for _ in range(5):
                n += 1
                alerts.append(_alert(n, f"1.1.1.{k}", "9.9.9.9", cls))
    n += 1
    alerts.append(_alert(n, "1.1.1.99", "10.0.0.7", "Recon"))     # 10.0.0.7 is scanned ...
    n += 1
    alerts.append(_alert(n, "10.0.0.7", "1.1.1.99", "Backdoor"))  # ... then sends backdoor traffic
    rows = _tools_for(alerts).get_incident("X")["cross_stage_hosts"]
    assert rows[0]["host_ip"] == "10.0.0.7" and rows[0]["pattern"] == "target_then_source"
    assert rows[1]["host_ip"] == "1.1.1.99" and rows[1]["pattern"] == "source_then_target"