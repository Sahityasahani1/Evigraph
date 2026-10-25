import functools
import pytest

from src.agent.attack_rag import EMBED_MODEL, INDEX, AttackKnowledge


@functools.cache
def _ollama_available() -> bool:
    try:
        import ollama
    except ImportError:
        return False
    try:
        response = ollama.embed(model=EMBED_MODEL, input="availability check")
    except (ollama.RequestError, ollama.ResponseError, ConnectionError):
        return False
    return bool(response.embeddings)


pytestmark = pytest.mark.skipif(not INDEX.exists(), reason="index not built")
requires_ollama = pytest.mark.skipif(
    not _ollama_available(),
    reason="Ollama embedding service unavailable",
)


@pytest.fixture(scope="module")
def kb():
    return AttackKnowledge()


def top_ids(kb, query, k=5):
    return [r["id"] for r in kb.search(query, k)]


def has_prefix(ids, *prefixes):
    return any(i.startswith(p) for i in ids for p in prefixes)


def test_exact_lookup(kb):
    assert kb.get("T1110")["name"] == "Brute Force"


def test_unknown_id_is_rejected(kb):
    assert kb.get("T9999") is None


@requires_ollama
def test_brute_force(kb):
    assert has_prefix(top_ids(kb, "many failed SSH login attempts from one IP"), "T1110")


@requires_ollama
def test_port_scan(kb):
    ids = top_ids(kb, "one host sending connection attempts to many ports on many hosts")
    assert has_prefix(ids, "T1046", "T1595")


@requires_ollama
def test_denial_of_service(kb):
    ids = top_ids(kb, "flood of traffic overwhelming a server so it becomes unavailable")
    assert has_prefix(ids, "T1498", "T1499")


@requires_ollama
def test_exfiltration(kb):
    ids = top_ids(kb, "large outbound data transfer to an external server")
    assert has_prefix(ids, "T1048", "T1041", "T1567", "T1030")


@requires_ollama
def test_dns_tunnelling(kb):
    ids = top_ids(kb, "DNS queries with long encoded subdomains used to hide data")
    assert has_prefix(ids, "T1071.004", "T1572", "T1048")
