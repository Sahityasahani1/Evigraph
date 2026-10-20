import json

from src.agent.mock import investigate, list_incidents, load_agent

KEYS = {
    "incident_id", "error", "severity_score", "start", "end", "alert_count", "host_count",
    "report_markdown", "summary", "summary_withheld_reason", "factual_summary", "host_roles",
    "timeline", "cross_stage_hosts", "attack_matches", "findings", "rejected_findings",
}


def test_mock_returns_the_full_response_shape():
    r = investigate(load_agent(), "INC-0009")
    assert set(r) == KEYS
    assert r["error"] is None
    assert r["factual_summary"]


def test_mock_is_json_serialisable():
    json.dumps(investigate(load_agent(), "INC-0009"))


def test_mock_lists_incidents():
    ids = [row["incident_id"] for row in list_incidents(load_agent())]
    assert "INC-0009" in ids


def test_mock_unknown_incident_gives_an_error():
    r = investigate(load_agent(), "INC-NOPE")
    assert "Unknown incident" in r["error"]



def test_mock_list_rows_match_the_real_shape():
    row = list_incidents(load_agent())[0]
    assert set(row) == {"incident_id", "severity_score", "alert_count", "host_count", "classes"}
    assert row["classes"]["C2-Heartbeat"] == 2000