import pytest

from src.agent.ingest_attack import RAW, load_techniques

pytestmark = pytest.mark.skipif(not RAW.exists(), reason="ATT&CK file not downloaded")


@pytest.fixture(scope="module")
def by_id():
    return {t["id"]: t for t in load_techniques()}


def test_enough_techniques(by_id):
    assert len(by_id) > 400


def test_no_duplicate_ids():
    ids = [t["id"] for t in load_techniques()]
    assert len(ids) == len(set(ids))


def test_brute_force_is_credential_access(by_id):
    assert "credential-access" in by_id["T1110"]["tactics"]


def test_techniques_our_attacks_need(by_id):
    # port scan, brute force, DoS, exfiltration, DNS tunnelling, lateral movement
    for tid in ["T1046", "T1595", "T1110", "T1498", "T1048", "T1572", "T1071.004", "T1021"]:
        assert tid in by_id, f"{tid} missing"