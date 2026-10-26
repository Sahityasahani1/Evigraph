from unittest.mock import patch
import json
from pathlib import Path
import pytest
from fastapi import HTTPException
from frontend.api.server import (
    get_incident_countermeasures,
    get_investigation_countermeasures,
    INVESTIGATION_ROOT,
)


def test_get_incident_countermeasures_valid():
    """Verify countermeasures are generated for a valid incident with advisory notice and guidance."""
    res = get_incident_countermeasures("INC-0001")
    assert res["incident_id"] == "INC-0001"
    assert res["status"] == "advisory"
    assert "advisory" in res["advisory_notice"].lower()
    assert res["simulation_run"] is False
    assert res["containment_actions_count"] > 0
    assert len(res["actions"]) > 0

    first = res["actions"][0]
    assert first["rule_id"].startswith("RULE-INC-0001")
    assert "target_attacker" in first
    assert "target_victim" in first
    assert "destination_port" in first
    assert "protocol" in first
    assert "rationale" in first

    # Verify blast radius information is included
    assert "victim_blast_radius" in first
    blast = first["victim_blast_radius"]
    assert "blast_radius_score" in blast
    assert "impact_level" in blast
    assert "recommended_approach" in blast

    # Verify synthesized commands across platforms
    commands = first["synthesized_commands"]
    assert "linux_iptables" in commands
    assert "windows_powershell" in commands

    # Verify verification and rollback guidance
    assert "verification_guidance" in first
    assert "rollback_guidance" in first
    assert "iptables" in first["verification_guidance"]["linux_iptables"]
    assert "iptables" in first["rollback_guidance"]["linux_iptables"]


def test_get_incident_countermeasures_mock_incident():
    """Verify countermeasures are generated for mock-derived incident (INC-0009)."""
    res = get_incident_countermeasures("INC-0009")
    assert res["incident_id"] == "INC-0009"
    assert res["status"] == "advisory"
    assert res["containment_actions_count"] == 3
    assert len(res["actions"]) == 3

    rule_ids = [a["rule_id"] for a in res["actions"]]
    assert "RULE-INC-0009-01" in rule_ids
    assert any(a["target_attacker"] == "172.20.10.10" for a in res["actions"])


def test_get_incident_countermeasures_unknown_incident():
    """Verify unknown incident raises 404 HTTPException."""
    with pytest.raises(HTTPException) as exc_info:
        get_incident_countermeasures("INC-NONEXISTENT-999")
    assert exc_info.value.status_code == 404
    assert "not found" in str(exc_info.value.detail).lower()


def test_get_incident_countermeasures_engine_error():
    """Verify engine failure raises 500 HTTPException."""
    with patch(
        "src.mitigation.countermeasure_engine.CountermeasureEngine.plan_incident_countermeasures",
        side_effect=RuntimeError("Graph min-cut optimization failed"),
    ):
        with pytest.raises(HTTPException) as exc_info:
            get_incident_countermeasures("INC-0001")
        assert exc_info.value.status_code == 500
        assert "Countermeasure synthesis failed" in str(exc_info.value.detail)


def test_get_investigation_countermeasures_fresh_job():
    """Verify fresh investigation incident countermeasures can be fetched."""
    # Find any completed investigation job with an incident_cases.json
    cases_files = list(INVESTIGATION_ROOT.glob("*/incident_cases.json"))
    if not cases_files:
        pytest.skip("No pre-existing investigation jobs to test")

    sample_cases = json.loads(cases_files[0].read_text(encoding="utf-8"))
    incidents = sample_cases.get("incidents", [])
    if not incidents:
        pytest.skip("No incidents in sample job")

    job_id = cases_files[0].parent.name
    incident_id = incidents[0]["incident_id"]

    res = get_investigation_countermeasures(job_id=job_id, incident_id=incident_id)
    assert res["incident_id"] == incident_id
    assert res["status"] == "advisory"
    assert len(res["actions"]) > 0
