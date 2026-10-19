import csv
import json

import pytest

from src.agent.agent import ForensicAgent
from src.agent.contract import load_incidents
from src.agent.evaluate import EVAL, deterministic
from src.agent.flow_store import FlowStore
from src.agent.tools import ForensicTools

pytestmark = pytest.mark.skipif(
    not (EVAL / "ground_truth.json").exists(), reason="run make_eval_data first"
)


class FakeKB:
    def search(self, query, k=5):
        return [{"id": "T1110", "name": "Brute Force", "tactics": ["credential-access"], "score": 0.9}]


@pytest.fixture(scope="module")
def setup():
    truth = json.loads((EVAL / "ground_truth.json").read_text(encoding="utf-8"))
    tools = ForensicTools(
        FlowStore(EVAL / "flows.csv"), load_incidents(EVAL / "incident_cases.json"), FakeKB()
    )
    return truth, tools, ForensicAgent(tools)


def test_ground_truth_covers_every_incident(setup):
    truth, tools, _ = setup
    assert set(truth) == set(tools.incidents)


def test_every_alert_points_to_a_real_flow(setup):
    _, tools, _ = setup
    with open(EVAL / "flows.csv", encoding="utf-8") as f:
        ids = {r["flow_id"] for r in csv.DictReader(f)}
    for inc in tools.incidents.values():
        assert all(a.flow_id in ids for a in inc.alerts)


def test_key_hosts_exist_in_their_incident(setup):
    truth, tools, _ = setup
    for iid, t in truth.items():
        assert set(t["key_hosts"]) <= set(tools.incidents[iid].hosts)


def test_answer_key_matches_generated_data(setup):
    truth, _, agent = setup
    for iid, t in truth.items():
        d = deterministic(agent, iid, t)
        assert d["stage_order"], f"{iid}: stage order differs from the answer key"
        assert d["pivot"], f"{iid}: pivot hosts differ from the answer key"