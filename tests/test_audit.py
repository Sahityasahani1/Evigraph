import json

try:
    from tests.test_report import make_agent, one
except ImportError:
    from test_report import make_agent, one

from src.agent.report import generate_report


def test_every_run_is_written_to_an_audit_log(tmp_path):
    log = tmp_path / "audit.jsonl"
    r = generate_report(make_agent(one("The host 10.0.0.5 was possibly compromised.")),
                        "INC-001", audit_path=log)
    lines = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == len(r["tool_calls"]) + 1
    assert all("sha256" in x for x in lines[:-1])
    assert lines[-1]["event"] == "report_generated"
    assert lines[-1]["incident_id"] == "INC-001"


def test_report_records_the_model_and_settings():
    r = generate_report(make_agent(one("The host 10.0.0.5 was possibly compromised.")), "INC-001")
    assert "## Run information" in r["report"]
    assert "temperature 0, seed 0" in r["report"]
    assert r["run_info"]["model"]