import pytest

from src.agent.agent import _stage_query
from src.agent.attack_rag import INDEX, AttackKnowledge


def _ollama_available() -> bool:
    try:
        import ollama
        ollama.list()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not INDEX.exists() or not _ollama_available(),
    reason="ATT&CK index not built or Ollama embedding service unavailable",
)

EXPECTED = {
    "DNS-Amplification": ("T1498.002",),
    "NTP-Reflection": ("T1498.002",),
    "SYN-Flood": ("T1499.001", "T1498.001"),
    "Exploits": ("T1210", "T1190"),
    "Fuzzers": ("T1595.002", "T1190"),
    "Reconnaissance": ("T1595", "T1046"),
    "C2-Heartbeat": ("T1071", "T1095", "T1571"),
    "HTTPS-Exfiltration": ("T1041", "T1048", "T1567"),
    "Lateral-SMB-Relay": ("T1021.002", "T1557.001", "T1570"),
}

DUMMY_INCIDENT = {
    "incident_id": "INC-0001",
    "severity_score": 0.85,
}

DUMMY_STAGE = {
    "first_seen": "2026-10-15T09:00:00Z",
    "last_seen": "2026-10-15T09:10:00Z",
    "alert_count": 5,
    "evidence": [],
}


@pytest.fixture(scope="module")
def kb():
    return AttackKnowledge()


@pytest.mark.parametrize("cls", EXPECTED)
def test_right_family_in_top_5(kb, cls):
    ids = [m["id"] for m in kb.search(_stage_query(cls, DUMMY_INCIDENT, DUMMY_STAGE), 5)]
    assert any(i.startswith(EXPECTED[cls]) for i in ids), f"{cls}: got {ids}"


def test_backdoor_still_returns_a_shortlist(kb):
    # Backdoor is ambiguous by nature; we only require that the agent gets 5 candidates.
    assert len(kb.search(_stage_query("Backdoor", DUMMY_INCIDENT, DUMMY_STAGE), 5)) == 5
