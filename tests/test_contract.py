import csv

import pytest
from pydantic import ValidationError

from src.agent.contract import FLOW_COLUMNS, Alert, load_incidents

CASES = "data/sample/sample_incident_cases.json"
FLOWS = "data/sample/sample_flows.csv"


@pytest.fixture(scope="module")
def flows():
    with open(FLOWS, encoding="utf-8") as f:
        return {r["flow_id"]: r for r in csv.DictReader(f)}


def test_sample_incidents_follow_contract():
    cases = load_incidents(CASES)
    assert len(cases.incidents) == 2


def test_flow_table_has_expected_columns(flows):
    first = next(iter(flows.values()))
    assert list(first.keys()) == FLOW_COLUMNS


def test_flow_ids_are_unique():
    with open(FLOWS, encoding="utf-8") as f:
        ids = [r["flow_id"] for r in csv.DictReader(f)]
    assert len(ids) == len(set(ids))


def test_every_alert_points_to_a_real_matching_flow(flows):
    for inc in load_incidents(CASES).incidents:
        for a in inc.alerts:
            assert a.flow_id in flows, f"{a.alert_id} cites missing flow {a.flow_id}"
            f = flows[a.flow_id]
            assert (a.src_ip, a.dst_ip) == (f["src_ip"], f["dst_ip"])
            assert (a.src_port, a.dst_port) == (int(f["src_port"]), int(f["dst_port"]))


def test_incident_hosts_cover_all_alert_hosts():
    for inc in load_incidents(CASES).incidents:
        for a in inc.alerts:
            assert a.src_ip in inc.hosts and a.dst_ip in inc.hosts


def test_bad_risk_score_is_rejected():
    with pytest.raises(ValidationError):
        Alert(alert_id="a", flow_id="f", timestamp="2026-01-10T09:00:00", src_ip="1.1.1.1",
              dst_ip="2.2.2.2", src_port=1, dst_port=2, protocol=6,
              predicted_class="x", risk_score=1.5)


def test_missing_flow_id_is_rejected():
    with pytest.raises(ValidationError):
        Alert(alert_id="a", timestamp="2026-01-10T09:00:00", src_ip="1.1.1.1",
              dst_ip="2.2.2.2", src_port=1, dst_port=2, protocol=6,
              predicted_class="x", risk_score=0.9)