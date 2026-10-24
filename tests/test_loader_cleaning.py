import json

import pytest

from src.agent.contract import load_incidents
from src.agent.flow_store import FlowStore

REAL = "data/raw/member3_benchmark_test_incidents.json"


def _alert(n, src, dst, cls):
    return {"alert_id": f"a{n}", "flow_id": f"f{n}", "timestamp": "2026-11-02 15:00:00",
            "src_ip": src, "dst_ip": dst, "src_port": 0, "dst_port": 80, "protocol": 6,
            "predicted_class": cls, "risk_score": 0.9}


def _write(tmp_path, alerts, hosts):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"incidents": [
        {"incident_id": "X", "severity_score": 0.5, "hosts": hosts, "alerts": alerts}]}))
    return p


def test_benign_alerts_dropped_and_hosts_recomputed(tmp_path):
    alerts = [_alert(1, "1.1.1.1", "2.2.2.2", "C2-Heartbeat"),
              _alert(2, "3.3.3.3", "2.2.2.2", "BENIGN"),
              _alert(3, "1.1.1.1", "4.4.4.4", "C2-Heartbeat")]
    inc = load_incidents(_write(tmp_path, alerts, ["1.1.1.1"])).incidents[0]
    assert [a.predicted_class for a in inc.alerts] == ["C2-Heartbeat", "C2-Heartbeat"]
    assert set(inc.hosts) == {"1.1.1.1", "2.2.2.2", "4.4.4.4"}


def test_incident_with_only_benign_alerts_is_removed(tmp_path):
    p = _write(tmp_path, [_alert(1, "1.1.1.1", "2.2.2.2", "BENIGN")], ["1.1.1.1"])
    assert load_incidents(p).incidents == []


@pytest.mark.skipif(not __import__("pathlib").Path(REAL).exists(), reason="Member 2's file not present")
def test_real_incidents_are_clean_and_point_to_real_flows():
    cases = load_incidents(REAL)
    store = FlowStore("data/raw/processed/benchmark_test_flows.parquet")
    assert len(cases.incidents) == 9
    for inc in cases.incidents:
        assert all(a.predicted_class != "BENIGN" for a in inc.alerts)
        assert all(store.has_flow(a.flow_id) for a in inc.alerts)
        assert {a.src_ip for a in inc.alerts} <= set(inc.hosts)