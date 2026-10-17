import pytest

from src.agent.contract import load_incidents
from src.agent.flow_store import FlowStore
from src.agent.tools import ForensicTools


class FakeKB:
    def search(self, query, k=5):
        return [{"id": "T1110", "name": "Brute Force", "tactics": ["credential-access"], "score": 0.9}]


@pytest.fixture()
def tools():
    store = FlowStore("data/sample/sample_flows.csv")
    cases = load_incidents("data/sample/sample_incident_cases.json")
    return ForensicTools(store, cases, FakeKB())


def test_list_incidents(tools):
    ids = [i["incident_id"] for i in tools.list_incidents()["incidents"]]
    assert ids == ["INC-001", "INC-002"]


def test_incident_stages_are_in_time_order(tools):
    r = tools.get_incident("INC-001")
    assert [s["attack_class"] for s in r["stages_in_time_order"]] == ["SSH-Patator", "PortScan"]
    assert r["alert_count"] == 100


def test_unknown_incident_returns_error_not_crash(tools):
    assert "error" in tools.get_incident("INC-999")


def test_attacker_host_summary(tools):
    s = tools.host_summary("203.0.113.50")
    assert s["flows_as_source"] == 40
    assert s["unique_destination_hosts"] == 1
    assert s["top_destination_ports"] == {"22": 40}


def test_compromised_host_looks_like_a_scanner(tools):
    s = tools.host_summary("10.0.0.5")
    assert s["flows_as_destination"] >= 40  # received the brute force
    assert s["flows_as_source"] == 60  # then scanned out
    assert s["unique_destination_ports"] >= 8


def test_unknown_host_returns_error(tools):
    assert "error" in tools.host_summary("192.0.2.99")


def test_flow_limit_is_enforced(tools):
    r = tools.get_flows("203.0.113.50", limit=1000)
    assert r["returned"] == 25 and r["total_matching"] == 40


def test_time_window_filters(tools):
    assert tools.get_flows("203.0.113.50", end_time="2026-01-10T09:10:00")["total_matching"] == 0
    assert tools.get_flows("203.0.113.50", start_time="not a time")["error"]


def test_ground_truth_label_is_hidden(tools):
    for f in tools.get_flows("203.0.113.50", limit=5)["flows"]:
        assert "label" not in f


def test_evidence_registry_tracks_only_what_was_shown(tools):
    assert tools.evidence == set()
    r = tools.get_incident("INC-001")
    shown = {a["flow_id"] for a in r["top_alerts_by_risk"]}
    assert shown <= tools.evidence
    assert "flw_999999" not in tools.evidence

def test_incident_names_the_real_attacker_and_the_pivot_host(tools):
    r = tools.get_incident("INC-001")
    sources = [h["host_ip"] for h in r["top_alert_sources"]]
    targets = [h["host_ip"] for h in r["top_alert_targets"]]
    assert "203.0.113.50" in sources  # external attacker must not be cut off
    assert "10.0.0.5" in sources and "10.0.0.5" in targets  # target first, then source


def test_search_records_techniques_shown(tools):
    assert tools.techniques_seen == set()
    tools.search_attack_knowledge("many failed SSH logins")
    assert tools.techniques_seen == {"T1110"}