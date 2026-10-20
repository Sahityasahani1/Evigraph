import json
from types import SimpleNamespace as NS

from src.agent.agent import ForensicAgent
from src.agent.api import investigate, list_incidents
from src.agent.contract import load_incidents
from src.agent.flow_store import FlowStore
from src.agent.tools import ForensicTools


class FakeKB:
    def search(self, query, k=5):
        return [{"id": "T1110", "name": "Brute Force", "tactics": ["credential-access"], "score": 0.9}]


def make():
    tools = ForensicTools(FlowStore("data/sample/sample_flows.csv"),
                          load_incidents("data/sample/sample_incident_cases.json"), FakeKB())

    def chat(**kw):
        system = kw["messages"][0]["content"]
        out = ('{"summary": "Host 203.0.113.50 attacked 10.0.0.5."}'
               if "executive summary" in system else '{"findings": []}')
        return NS(message=NS(content=out, tool_calls=None))

    return ForensicAgent(tools, chat_fn=chat)


def test_investigate_returns_json_serialisable_result():
    r = investigate(make(), "INC-001")
    json.dumps(r)
    assert r["error"] is None and r["report_markdown"] and r["timeline"]


def test_unknown_incident_returns_error_not_crash():
    assert investigate(make(), "NOPE")["error"]


def test_list_incidents():
    assert {i["incident_id"] for i in list_incidents(make())} == {"INC-001", "INC-002"}