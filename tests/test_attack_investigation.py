from types import SimpleNamespace as NS

import numpy as np
import pytest

from src.agent.agent import ForensicAgent
from src.agent import attack_rag
from src.agent.api import investigate
from src.agent.attack_rag import AttackKnowledge, TECHNIQUES
from src.agent.attack_rag import AttackKnowledgeUnavailableError
from src.agent.contract import load_incidents
from src.agent.flow_store import FlowStore
from src.agent.report import Finding, build_report, validate_findings
from src.agent.tools import ForensicTools


class FixedKnowledge:
    status = "available"
    error = None

    def search(self, query, k=5):
        if "failed SSH" in query or "SSH" in query:
            return [{
                "id": "T1110",
                "name": "Brute Force",
                "tactics": ["credential-access"],
                "score": 0.91,
                "score_semantics": "cosine_similarity",
                "source_url": "https://attack.mitre.org/techniques/T1110",
            }]
        return []


def make_agent(kb=None):
    tools = ForensicTools(
        FlowStore("data/sample/sample_flows.csv"),
        load_incidents("data/sample/sample_incident_cases.json"),
        kb or FixedKnowledge(),
    )
    def chat(**kwargs):
        system = kwargs["messages"][0]["content"]
        content = (
            '{"summary":"Host 203.0.113.50 attacked 10.0.0.5."}'
            if "executive summary" in system else '{"findings":[]}'
        )
        return NS(message=NS(content=content, tool_calls=None))

    return ForensicAgent(tools, chat_fn=chat)


def test_existing_retriever_searches_technique_corpus_and_returns_source(tmp_path, monkeypatch):
    index = tmp_path / "test-index.npz"
    np.savez(index, vectors=np.array([[1.0, 0.0]], dtype=np.float32), ids=["T1110"])
    monkeypatch.setattr(
        attack_rag,
        "_embed",
        lambda texts: np.array([[1.0, 0.0]], dtype=np.float32),
    )
    knowledge = AttackKnowledge(TECHNIQUES, index)

    matches = knowledge.search("failed SSH login attempts", k=1)

    assert knowledge.status == "available"
    assert matches[0]["id"] == "T1110"
    assert matches[0]["name"] == "Brute Force"
    assert matches[0]["source_url"] == "https://attack.mitre.org/techniques/T1110"
    assert matches[0]["score"] == 1.0
    assert matches[0]["score_semantics"] == "cosine_similarity"


def test_search_preserves_candidate_and_keeps_stage_flows_as_query_context():
    agent = make_agent()
    briefing, error = agent._gather("INC-001", [])

    assert error is None
    result = briefing["attack_matches"]["SSH-Patator"]
    match = result["matches"][0]
    assert result["status"] == "available"
    assert result["mapping_status"] == "retrieved_candidate"
    assert match["id"] == "T1110"
    assert match["name"] == "Brute Force"
    assert match["source_url"] == "https://attack.mitre.org/techniques/T1110"
    assert match["retrieval_similarity"] == 0.91
    assert "score" not in match
    assert match["score_semantics"] == "cosine_similarity"
    assert result["query_context_flow_ids"]
    assert match["candidate_evidence"] == {
        "status": "none_available", "flow_ids": [], "event_ids": [], "reason": None,
    }
    assert match["candidate_status"] == "retrieved_candidate"
    assert match["review_status"] == "not_reviewed"
    assert "No technique-specific evidence available. This candidate requires analyst review." == match["assessment"]
    assert not agent.tools.technique_evidence
    report = build_report(briefing, [], [])
    assert "ATT&CK retrieval candidates (inferred, not confirmed)" in report
    assert "candidate-specific evidence references: none" in report
    assert "No technique-specific evidence available. This candidate requires analyst review." in report
    assert "stage query context flows (not technique-specific evidence)" in report


def test_empty_retrieval_is_explicit_and_unsupported():
    class EmptyKnowledge(FixedKnowledge):
        def search(self, query, k=5):
            return []

    agent = make_agent(EmptyKnowledge())
    briefing, error = agent._gather("INC-001", [])

    assert error is None
    result = briefing["attack_matches"]["SSH-Patator"]
    assert result["status"] == "no_matches"
    assert result["mapping_status"] == "unsupported"
    assert result["matches"] == []


def test_missing_index_returns_explicit_unavailable_status(tmp_path):
    index = tmp_path / "missing-attack-index.npz"
    knowledge = AttackKnowledge(TECHNIQUES, index)
    agent = make_agent(knowledge)
    inc = agent.tools.get_incident("INC-001")
    stage = next(s for s in inc["stages_in_time_order"] if s["attack_class"] == "SSH-Patator")

    result = agent.tools.search_attack_knowledge(
        query="failed SSH login attempts",
        attack_class="SSH-Patator",
        flow_ids=stage["flow_ids"],
        incident_id="INC-001",
    )

    assert result["status"] == "unavailable"
    assert result["matches"] == []
    assert str(index) in result["error"]


def test_api_returns_degraded_retrieval_state_when_index_is_missing(tmp_path):
    index = tmp_path / "missing-attack-index.npz"
    result = investigate(
        make_agent(AttackKnowledge(TECHNIQUES, index)),
        "INC-001",
    )

    assert result["error"] is None
    assert result["retrieval_status"] == "unavailable"
    stage = result["attack_matches"]["SSH-Patator"]
    assert stage["status"] == "unavailable"
    assert str(index) in stage["error"]
    assert "retrieval unavailable" in result["report_markdown"]


def test_embedding_service_disconnect_degrades_investigation(tmp_path, monkeypatch):
    index = tmp_path / "available-index.npz"
    np.savez(index, vectors=np.array([[1.0, 0.0]], dtype=np.float32), ids=["T1110"])

    def disconnected(_texts):
        raise ConnectionError("Ollama is not reachable")

    monkeypatch.setattr(attack_rag, "_embed", disconnected)
    knowledge = AttackKnowledge(TECHNIQUES, index)
    agent = make_agent(knowledge)

    briefing, error = agent._gather("INC-001", [])

    assert error is None
    assert knowledge.status == "unavailable"
    result = briefing["attack_matches"]["SSH-Patator"]
    assert result["status"] == "unavailable"
    assert result["matches"] == []
    assert "Ollama is not reachable" in result["error"]


def test_incompatible_query_embedding_degrades_retrieval(tmp_path, monkeypatch):
    index = tmp_path / "available-index.npz"
    np.savez(index, vectors=np.array([[1.0, 0.0, 0.0]], dtype=np.float32), ids=["T1110"])
    monkeypatch.setattr(
        attack_rag,
        "_embed",
        lambda _texts: np.array([[1.0, 0.0]], dtype=np.float32),
    )
    knowledge = AttackKnowledge(TECHNIQUES, index)

    with pytest.raises(AttackKnowledgeUnavailableError, match="incompatible"):
        knowledge.search("SSH password guessing", k=1)
    assert knowledge.status == "unavailable"


def test_corrupt_attack_index_is_reported_as_unavailable(tmp_path):
    index = tmp_path / "corrupt-index.npz"
    index.write_bytes(b"not a numpy archive")

    knowledge = AttackKnowledge(TECHNIQUES, index)

    assert knowledge.status == "unavailable"
    assert "Invalid ATT&CK vector index" in knowledge.error


def test_retrieved_candidate_without_stage_evidence_remains_unverified_candidate():
    agent = make_agent()
    result = agent.tools.search_attack_knowledge(
        query="failed SSH login attempts",
        attack_class="SSH-Patator",
    )

    assert result["status"] == "available"
    assert result["mapping_status"] == "retrieved_candidate"
    assert result["matches"][0]["candidate_status"] == "retrieved_candidate"
    assert result["matches"][0]["candidate_evidence"]["flow_ids"] == []
    assert "T1110" in agent.tools.techniques_seen


def test_finding_technique_must_be_grounded_by_its_cited_flows():
    agent = make_agent()
    briefing, error = agent._gather("INC-001", [])
    assert error is None
    ssh = briefing["attack_matches"]["SSH-Patator"]
    ssh_flow = ssh["query_context_flow_ids"][0]
    other_stage = next(
        stage for stage in briefing["incident"]["stages_in_time_order"]
        if stage["attack_class"] != "SSH-Patator"
    )
    unrelated_flow = other_stage["flow_ids"][0]
    finding = Finding(
        claim="A brute-force-like SSH stage was detected.",
        flow_ids=[unrelated_flow],
        technique_id="T1110",
    )

    accepted, rejected = validate_findings(
        [finding],
        agent.tools,
        set(agent.tools.incidents["INC-001"].hosts),
        source_text="A brute-force-like SSH stage was detected.",
    )

    assert not accepted
    assert "not grounded" in rejected[0]["problems"][-1]
    assert not agent.tools.technique_evidence.get("T1110")


def test_only_explicit_candidate_evidence_links_are_accepted():
    class EvidenceKnowledge(FixedKnowledge):
        def search(self, query, k=5):
            return [{
                "id": "T1110", "name": "Brute Force", "tactics": ["credential-access"],
                "score": 0.91, "score_semantics": "cosine_similarity",
                "candidate_evidence": {
                    "flow_ids": [valid_flow_id, "unrelated-flow"],
                    "event_ids": [valid_event_id, "unrelated-event"],
                    "reason": "Explicitly linked source record.",
                },
            }]

    agent = make_agent()
    incident = agent.tools.get_incident("INC-001")
    ssh_stage = next(s for s in incident["stages_in_time_order"] if s["attack_class"] == "SSH-Patator")
    valid_flow_id = ssh_stage["flow_ids"][0]
    valid_event_id = agent.tools.store.get_flow(valid_flow_id).get("evidence_id")
    if not valid_event_id:
        # The fixture has no event ID; test flow-level provenance without inventing one.
        EvidenceKnowledge.search = lambda self, query, k=5: [{
            "id": "T1110", "name": "Brute Force", "tactics": ["credential-access"],
            "score": 0.91, "score_semantics": "cosine_similarity",
            "candidate_evidence": {
                "flow_ids": [valid_flow_id, "unrelated-flow"],
                "event_ids": ["unrelated-event"],
                "reason": "Explicitly linked source record.",
            },
        }]
    agent.tools.kb = EvidenceKnowledge()
    result = agent.tools.search_attack_knowledge(
        "failed SSH login attempts", "SSH-Patator", ssh_stage["flow_ids"], "INC-001",
    )
    evidence = result["matches"][0]["candidate_evidence"]
    assert evidence["flow_ids"] == [valid_flow_id]
    assert evidence["event_ids"] == ([valid_event_id] if valid_event_id else [])
    assert result["matches"][0]["candidate_status"] == "evidence_linked_candidate"
    assert agent.tools.technique_evidence["T1110"] == {valid_flow_id}
