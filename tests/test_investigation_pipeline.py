import csv
import json
import threading
import time
from pathlib import Path

import pandas as pd
import pytest

from src.agent.api import investigate, load_agent
from src.agent.attack_rag import AttackKnowledge
from src.agent.flow_store import FlowStore
from src.agent.report import Finding, validate_findings
from src.investigation_pipeline import run_investigation_pipeline


def write_flow_csv(path: Path) -> list[str]:
    rows = []
    classes = ["PortScan", "SSH-Patator", "Lateral-SMB-Relay", "HTTPS-Exfiltration"]
    start = pd.Timestamp("2026-10-15T09:00:00Z")
    for index, attack_class in enumerate(classes):
        rows.append({
            "flow_id": f"flw_fixture_{index:03d}",
            "evidence_id": "capture-fixture",
            "timestamp": (start + pd.Timedelta(seconds=index * 30)).isoformat(),
            "src_ip": "203.0.113.7" if index < 2 else "10.0.0.5",
            "dst_ip": "10.0.0.5" if index < 2 else "10.0.0.9" if index == 2 else "203.0.113.8",
            "src_port": 40000 + index,
            "dst_port": [443, 22, 445, 443][index],
            "protocol": 6,
            "label": "BENIGN",
            "flow_duration": 10 + index,
        })
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return [row["flow_id"] for row in rows]


class FixedDetector:
    feature_columns = ["flow_duration"]
    optimal_threshold = 0.5

    def __init__(self, model_name):
        self.model_name = model_name

    def load(self, _model_dir):
        return None

    def score_flows(self, _features, metadata):
        scored = metadata.copy()
        scored["risk_score"] = [0.9, 0.92, 0.94, 0.96]
        scored["predicted_class"] = [
            "PortScan", "SSH-Patator", "Lateral-SMB-Relay", "HTTPS-Exfiltration"
        ]
        scored["is_alert"] = True
        return scored


def run_fixed_pipeline(tmp_path, monkeypatch):
    import src.investigation_pipeline as pipeline

    source = tmp_path / "flows.csv"
    flow_ids = write_flow_csv(source)
    monkeypatch.setattr(pipeline, "BaselineDetector", FixedDetector)
    result = run_investigation_pipeline(source, tmp_path / "job")
    return source, flow_ids, result


def test_supported_flow_input_builds_fresh_incident_and_preserves_evidence(
    tmp_path, monkeypatch
):
    source, flow_ids, result = run_fixed_pipeline(tmp_path, monkeypatch)
    cases = json.loads(Path(result["cases_path"]).read_text(encoding="utf-8"))
    incident = cases["incidents"][0]

    assert result["input_format"] == "csv"
    assert result["flows_scored"] == 4
    assert result["alerts"] == 4
    assert result["incident_count"] == 1
    assert cases["provenance"]["inference_source"] == "fresh"
    assert cases["provenance"]["labels_used_for_inference"] is False
    assert cases["provenance"]["merkle_root"] == cases["merkle_root"]
    assert len(cases["merkle_root"]) == 64
    assert result["merkle_certificate_path"]
    assert Path(result["merkle_certificate_path"]).is_file()
    assert incident["evidence_flow_ids"] == flow_ids
    assert incident["source_sha256"] == result["source_sha256"]
    assert [alert["evidence_id"] for alert in incident["alerts"]] == ["capture-fixture"] * 4
    assert incident["primary_attack_chain"]
    assert all(edge.get("merkle_verified") for edge in incident["subgraph"]["edges"])
    assert all(step["observed"] for step in incident["primary_attack_chain"])
    assert all(step["interpretation_status"] == "inferred" for step in incident["primary_attack_chain"])

    scored = pd.read_parquet(result["flows_path"])
    assert "label" not in scored.columns
    assert scored["source_sha256"].eq(result["source_sha256"]).all()


def test_report_validation_and_job_api_can_retrieve_cited_flow(tmp_path, monkeypatch):
    source, flow_ids, result = run_fixed_pipeline(tmp_path, monkeypatch)
    cases = json.loads(Path(result["cases_path"]).read_text(encoding="utf-8"))
    incident_id = cases["incidents"][0]["incident_id"]
    agent = load_agent(result["flows_path"], result["cases_path"])
    # Keep this test focused on graceful degraded reporting regardless of whether
    # a developer has built the live ATT&CK vector index locally.
    agent.tools.kb = AttackKnowledge(index_path=tmp_path / "missing-attack-index.npz")
    briefing, error = agent._gather(incident_id, [])
    assert error is None

    good, bad = validate_findings(
        [
            Finding(claim="Observed network activity.", flow_ids=[flow_ids[0]]),
            Finding(claim="Unverified network activity.", flow_ids=["flw_not_in_case"]),
        ],
        agent.tools,
        set(agent.tools.incidents[incident_id].hosts),
        source_text=json.dumps(briefing, default=str),
    )
    assert len(good) == 1
    assert len(bad) == 1
    assert "never shown" in " ".join(bad[0]["problems"])

    agent.chat = lambda **_kwargs: (_ for _ in ()).throw(ConnectionError("offline test"))
    report = investigate(agent, incident_id)
    assert report["error"] is None
    assert report["reasoning_status"] == "degraded"
    assert "local reasoning model unavailable" in report["report_markdown"]
    assert flow_ids[0] in report["report_markdown"]
    assert report["retrieval_status"] == "unavailable"

    import frontend.api.server as server

    job_id = "job"
    monkeypatch.setattr(server, "INVESTIGATION_ROOT", tmp_path)
    monkeypatch.setitem(server._investigation_jobs, job_id, {
        "job_id": job_id,
        "status": "running",
        "model_type": "xgb",
    })
    monkeypatch.setattr(server, "run_investigation_pipeline", lambda *_a, **_kw: result)
    server._run_investigation_job(job_id, source, tmp_path / "job", "xgb")
    assert server._investigation_jobs[job_id]["status"] == "completed"
    api_report = server.get_investigation_report(job_id, incident_id)
    assert api_report["footer"]["input_sha256"] == result["source_sha256"]
    assert api_report["footer"]["merkle_root"] == cases["merkle_root"]
    assert api_report["reasoning_status"] == "degraded"
    assert api_report["validation"]["valid"] == len(api_report["sentences"])
    assert api_report["validation"]["total"] == len(api_report["sentences"])
    assert api_report["validation"]["rejected"] == 0
    evidence = server.get_investigation_evidence(job_id, incident_id, flow_ids[0])
    assert evidence["flow_id"] == flow_ids[0]
    assert evidence["evidence_id"] == "capture-fixture"
    assert evidence["source_sha256"] == result["source_sha256"]
    assert evidence["merkle_root"] == cases["merkle_root"]
    assert evidence["merkle_verified"] is True
    assert evidence["merkle_proof"]["flow_id"] == flow_ids[0]
    assert evidence["flow"]["timestamp"]


def test_fallback_citation_validation_checks_stage_and_flow_resolution():
    from frontend.api.server import _validate_fallback_citations

    class FlowLookup:
        def get_flow(self, flow_id):
            return {} if flow_id == "flow-present" else None

    incident = {
        "evidence_flow_ids": ["flow-present"],
        "alerts": [{"flow_id": "flow-present"}],
    }
    normalized = {
        "stages": [{
            "stage_id": "INC-TEST-stage-1",
            "evidence": [{"flow_id": "flow-present"}],
        }],
    }
    sentences = [
        {"stage_id": "INC-TEST-stage-1", "evidence_ids": ["flow-present"]},
        {"stage_id": "INC-TEST-stage-2", "evidence_ids": ["flow-present"]},
        {"stage_id": "INC-TEST-stage-1", "evidence_ids": ["flow-missing"]},
    ]

    assert _validate_fallback_citations(sentences, incident, normalized, FlowLookup()) == {
        "valid": 1,
        "total": 3,
        "rejected": 2,
    }


def test_invalid_input_and_missing_detector_artifact_are_explicit(tmp_path, monkeypatch):
    unsupported = tmp_path / "capture.json"
    unsupported.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported input format"):
        run_investigation_pipeline(unsupported, tmp_path / "invalid-job")

    source = tmp_path / "flows.csv"
    write_flow_csv(source)
    import src.investigation_pipeline as pipeline

    missing_models = tmp_path / "missing-models"
    monkeypatch.setattr(pipeline, "MODELS_DIR", missing_models)
    with pytest.raises(FileNotFoundError, match="xgboost_baseline.joblib"):
        run_investigation_pipeline(source, tmp_path / "missing-model-job")


def test_fresh_loader_deduplicates_rows_without_ids_and_keeps_missing_features(tmp_path):
    from src.investigation_pipeline import _detector_features, _load_flows

    source = tmp_path / "flows-with-duplicates.csv"
    source.write_text(
        "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,flow_duration\n"
        "2026-10-15T09:00:00Z,10.0.0.1,10.0.0.2,40000,443,6,12\n"
        "2026-10-15T09:00:00Z,10.0.0.1,10.0.0.2,40000,443,6,12\n"
        "2026-10-15T09:01:00Z,10.0.0.1,10.0.0.3,40001,443,6,\n",
        encoding="utf-8",
    )

    flows = _load_flows(source, "a" * 64)
    assert len(flows) == 2
    assert flows["flow_id"].is_unique
    features = _detector_features(flows, ["flow_duration"])
    assert features["flow_duration"].tolist() == [12.0, 0.0]


def test_fresh_feature_normalizer_rejects_malformed_nonempty_values():
    from src.investigation_pipeline import _detector_features

    with pytest.raises(ValueError, match="non-numeric values"):
        _detector_features(pd.DataFrame({"flow_duration": ["not-a-number"]}), ["flow_duration"])


@pytest.mark.parametrize(
    "metadata",
    [
        {"src_ip": "", "src_port": 40000, "dst_port": 443, "protocol": 6},
        {"src_ip": "not-an-ip", "src_port": 40000, "dst_port": 443, "protocol": 6},
        {"src_ip": "10.0.0.1", "src_port": 70000, "dst_port": 443, "protocol": 6},
        {"src_ip": "10.0.0.1", "src_port": 40000, "dst_port": 443, "protocol": 6.5},
    ],
)
def test_fresh_loader_rejects_invalid_endpoint_and_transport_metadata(tmp_path, metadata):
    from src.investigation_pipeline import _load_flows

    source = tmp_path / "invalid-metadata.csv"
    row = {
        "timestamp": "2026-10-15T09:00:00Z",
        "src_ip": metadata["src_ip"],
        "dst_ip": "10.0.0.2",
        "src_port": metadata["src_port"],
        "dst_port": metadata["dst_port"],
        "protocol": metadata["protocol"],
        "flow_duration": 12,
    }
    pd.DataFrame([row]).to_csv(source, index=False)
    with pytest.raises(ValueError, match="invalid|missing|range|integer|malformed"):
        _load_flows(source, "b" * 64)


def test_prepared_incident_demo_route_remains_available():
    from src.agent.mock import investigate as mock_investigate, load_agent as mock_load_agent

    prepared = mock_investigate(mock_load_agent(), "INC-0009")
    assert prepared["incident_id"] == "INC-0009"
    assert prepared.get("timeline")


def test_upload_validation_and_nonblocking_job_progress(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    import frontend.api.server as server

    monkeypatch.setattr(server, "INVESTIGATION_ROOT", tmp_path / "jobs")
    entered = threading.Event()
    release = threading.Event()

    def fail_after_progress(_input_path, _output_dir, model_type, progress):
        assert model_type == "xgb"
        progress("Scoring fixture flows", 50)
        entered.set()
        assert release.wait(timeout=5)
        raise ValueError("fixture model artifact is missing")

    monkeypatch.setattr(server, "run_investigation_pipeline", fail_after_progress)
    with TestClient(server.app) as client:
        unsupported = client.post(
            "/investigations",
            content=b"{}",
            headers={"X-Filename": "flows.json", "Content-Type": "application/octet-stream"},
        )
        assert unsupported.status_code == 415
        assert "PCAPNG" in unsupported.json()["detail"]

        accepted = client.post(
            "/investigations",
            content=b"flow data",
            headers={"X-Filename": "flows.csv", "Content-Type": "application/octet-stream"},
        )
        assert accepted.status_code == 202
        job_id = accepted.json()["job_id"]
        assert entered.wait(timeout=5)
        running = client.get(f"/investigations/{job_id}")
        assert running.json()["status"] == "running"
        assert running.json()["stage"] == "Scoring fixture flows"
        assert running.json()["progress"] == 50
        release.set()
        for _ in range(100):
            failed = client.get(f"/investigations/{job_id}").json()
            if failed["status"] == "failed":
                break
            time.sleep(0.01)
        assert failed["status"] == "failed"
        assert "fixture model artifact is missing" in failed["error"]
    release.set()
