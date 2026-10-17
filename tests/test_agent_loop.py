from types import SimpleNamespace as NS

from src.agent.agent import ForensicAgent
from src.agent.contract import load_incidents
from src.agent.flow_store import FlowStore
from src.agent.tools import ForensicTools


class FakeKB:
    def search(self, query, k=5):
        return [{"id": "T1110", "name": "Brute Force", "tactics": ["credential-access"], "score": 0.9}]


def make_tools():
    return ForensicTools(
        FlowStore("data/sample/sample_flows.csv"),
        load_incidents("data/sample/sample_incident_cases.json"),
        FakeKB(),
    )


def tool_call(name, **args):
    return NS(message=NS(content="", tool_calls=[NS(function=NS(name=name, arguments=args))]))


def final(text):
    return NS(message=NS(content=text, tool_calls=None))


def scripted(*responses):
    it = iter(responses)
    return lambda **kwargs: next(it)


def test_loop_runs_tool_then_returns_final_answer():
    agent = ForensicAgent(make_tools(), chat_fn=scripted(
        tool_call("get_incident", incident_id="INC-001"), final("done")))
    r = agent.investigate("INC-001", playbook=False)
    assert r["final"] == "done" and r["error"] is None
    assert [c["tool"] for c in r["tool_calls"]] == ["get_incident"]
    assert agent.tools.evidence  # the tool result was recorded as evidence


def test_unknown_tool_does_not_crash():
    agent = ForensicAgent(make_tools(), chat_fn=scripted(tool_call("delete_everything"), final("ok")))
    assert agent.investigate("INC-001")["final"] == "ok"


def test_bad_arguments_do_not_crash():
    agent = ForensicAgent(make_tools(), chat_fn=scripted(
        tool_call("get_incident", wrong_name="x"), final("ok")))
    assert agent.investigate("INC-001")["final"] == "ok"


def test_step_limit_stops_endless_loop():
    endless = lambda **kwargs: tool_call("list_incidents")
    r = ForensicAgent(make_tools(), max_steps=3, chat_fn=endless).investigate("INC-001")
    assert r["final"] is None and "max steps" in r["error"] and r["steps"] == 3

def test_playbook_gathers_evidence_before_model_speaks():
    seen = {}

    def chat(**kwargs):
        seen["messages"] = kwargs["messages"]
        return final("summary")

    agent = ForensicAgent(make_tools(), chat_fn=chat)
    r = agent.investigate("INC-001")
    names = [c["tool"] for c in r["tool_calls"]]
    assert names[0] == "get_incident"
    assert "host_summary" in names and names.count("search_attack_knowledge") == 2
    assert "203.0.113.50" in seen["messages"][1]["content"]  # the real attacker is visible
    assert agent.tools.techniques_seen == {"T1110"}  # FakeKB only ever returns T1110


def test_playbook_unknown_incident_never_calls_the_model():
    def chat(**kwargs):
        raise AssertionError("model should not be called")

    r = ForensicAgent(make_tools(), chat_fn=chat).investigate("INC-999")
    assert r["final"] is None and r["error"]


def test_playbook_gathers_evidence_before_model_speaks():
    seen = {}

    def chat(**kwargs):
        seen["messages"] = kwargs["messages"]
        return final("summary")

    agent = ForensicAgent(make_tools(), chat_fn=chat)
    r = agent.investigate("INC-001")
    names = [c["tool"] for c in r["tool_calls"]]
    assert names[0] == "get_incident"
    assert "host_summary" in names and names.count("search_attack_knowledge") == 2
    assert "203.0.113.50" in seen["messages"][1]["content"]  # the real attacker is visible
    assert agent.tools.techniques_seen == {"T1110"}  # FakeKB only ever returns T1110


def test_playbook_unknown_incident_never_calls_the_model():
    def chat(**kwargs):
        raise AssertionError("model should not be called")

    r = ForensicAgent(make_tools(), chat_fn=chat).investigate("INC-999")
    assert r["final"] is None and r["error"]


def test_free_mode_makes_no_forced_calls():
    agent = ForensicAgent(make_tools(), chat_fn=scripted(final("hi")))
    assert agent.investigate("INC-001", playbook=False)["tool_calls"] == []