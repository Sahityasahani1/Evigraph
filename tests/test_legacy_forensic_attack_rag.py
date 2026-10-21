import json

from src.agent.attack_rag import AttackKnowledge, TECHNIQUES
from src.agent.forensic_agent import ForensicAgent


class FixedKnowledge:
    status = "available"
    error = None

    def __init__(self, matches=None):
        self.matches = matches or []
        self.queries = []

    def search(self, query, k=5):
        self.queries.append(query)
        return self.matches[:k]


def make_case(tmp_path):
    path = tmp_path / "incident_cases.json"
    path.write_text(json.dumps({
        "incidents": [{
            "incident_id": "INC-TEST",
            "incident_score": 0.8,
            "suspected_entry_point": "203.0.113.4",
            "affected_hosts": ["10.0.0.5"],
            "attack_classes": ["SSH-Patator"],
            "total_alerts": 2,
            "duration_seconds": 60,
            "evidence_files": ["capture-001"],
            "evidence_flow_ids": ["flw_ssh_001", "flw_ssh_002"],
            "subgraph": {"edges": [
                {
                    "edge_id": "flw_ssh_001",
                    "source": "203.0.113.4",
                    "target": "10.0.0.5",
                    "timestamp": "2026-10-20T10:00:00Z",
                    "dst_port": 22,
                    "protocol": 6,
                    "risk_score": 0.91,
                    "predicted_class": "SSH-Patator",
                    "is_alert": True,
                },
                {
                    "edge_id": "flw_ssh_002",
                    "source": "203.0.113.4",
                    "target": "10.0.0.5",
                    "timestamp": "2026-10-20T10:01:00Z",
                    "dst_port": 22,
                    "protocol": 6,
                    "risk_score": 0.89,
                    "predicted_class": "SSH-Patator",
                    "is_alert": True,
                },
            ]},
        }],
    }), encoding="utf-8")
    return path


def test_legacy_pipeline_reports_retrieved_candidate_with_grounding(tmp_path):
    knowledge = FixedKnowledge([{
        "id": "T1110",
        "name": "Brute Force",
        "tactics": ["credential-access"],
        "score": 0.92,
        "source_url": "https://attack.mitre.org/techniques/T1110",
    }])
    agent = ForensicAgent(make_case(tmp_path), attack_knowledge=knowledge)

    report = agent._generate_report_deterministic()

    assert "T1110" in report
    assert "Brute Force" in report
    assert "relevance 0.92" in report
    assert "inferred, not confirmed" in report
    assert "flw_ssh_001" in report and "capture-001" in report
    assert "destination port 22" in knowledge.queries[0]


def test_legacy_pipeline_returns_unsupported_when_retrieval_is_empty(tmp_path):
    agent = ForensicAgent(make_case(tmp_path), attack_knowledge=FixedKnowledge())

    report = agent._generate_report_deterministic()

    assert "no result; mapping unsupported" in report
    assert "T0000" not in report


def test_legacy_pipeline_reports_exact_missing_index_without_static_mapping(tmp_path):
    index = tmp_path / "missing-attack-index.npz"
    knowledge = AttackKnowledge(TECHNIQUES, index)
    agent = ForensicAgent(make_case(tmp_path), attack_knowledge=knowledge)

    report = agent._generate_report_deterministic()

    assert "retrieval unavailable" in report
    assert str(index) in report
    assert "T0000" not in report
    assert "| Inferred:" not in report
