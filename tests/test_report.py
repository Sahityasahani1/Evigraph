import json
from types import SimpleNamespace as NS

from src.agent.agent import ForensicAgent
from src.agent.contract import load_incidents
from src.agent.flow_store import FlowStore
from src.agent.report import FLOW_RE, generate_report
from src.agent.tools import ForensicTools


class FakeKB:
    def search(self, query, k=5):
        return [{"id": "T1110", "name": "Brute Force", "tactics": ["credential-access"], "score": 0.9}]


def make_agent(build, summary=None):
    tools = ForensicTools(
        FlowStore("data/sample/sample_flows.csv"),
        load_incidents("data/sample/sample_incident_cases.json"),
        FakeKB(),
    )

    def chat(**kwargs):
        system = kwargs["messages"][0]["content"]
        content = kwargs["messages"][1]["content"]
        if "executive summary" in system:
            out = summary(content) if summary else "not json"
        else:
            out = build(content)
        text = out if isinstance(out, str) else json.dumps(out)
        return NS(message=NS(content=text, tool_calls=None))

    return ForensicAgent(tools, chat_fn=chat)

def one(claim, flow_ids=None, technique_id=None):
    return lambda c: {"findings": [{
        "claim": claim,
        "flow_ids": FLOW_RE.findall(c)[:1] if flow_ids is None else flow_ids,
        "technique_id": technique_id,
    }]}


def test_grounded_finding_is_accepted():
    r = generate_report(make_agent(one("203.0.113.50 repeatedly targeted 10.0.0.5.", None, "T1110")), "INC-001")
    assert len(r["accepted"]) == 1 and not r["rejected"]


def test_invented_flow_id_is_rejected():
    r = generate_report(make_agent(one("203.0.113.50 attacked 10.0.0.5.", ["flw_999999"])), "INC-001")
    assert not r["accepted"] and "never shown" in r["rejected"][0]["problems"][0]


def test_technique_not_in_search_results_is_rejected():
    r = generate_report(make_agent(one("A brute force took place.", None, "T1210")), "INC-001")
    assert not r["accepted"] and "ATT&CK" in r["rejected"][0]["problems"][0]


def test_technique_id_hidden_in_claim_text_is_rejected():
    r = generate_report(make_agent(one("This matches T1001 data obfuscation.")), "INC-001")
    assert not r["accepted"]


def test_unknown_ip_in_claim_is_rejected():
    r = generate_report(make_agent(one("Traffic went to 8.8.8.8.")), "INC-001")
    assert not r["accepted"] and "IPs" in r["rejected"][0]["problems"][0]


def test_finding_without_evidence_is_rejected():
    r = generate_report(make_agent(one("Something happened.", [])), "INC-001")
    assert not r["accepted"] and "no flow_id" in r["rejected"][0]["problems"][0]


def test_garbage_model_output_still_gives_a_factual_report():
    r = generate_report(make_agent(lambda c: "this is not json"), "INC-001")
    assert r["parse_error"] and not r["accepted"]
    assert "## Timeline" in r["report"] and "203.0.113.50" in r["report"]


def test_report_flags_the_pivot_host_without_the_model():
    r = generate_report(make_agent(lambda c: {"findings": []}), "INC-001")
    assert "Possible pivot hosts" in r["report"]
    assert "10.0.0.5 was both a target and a source" in r["report"]


def test_unknown_incident_returns_error():
    r = generate_report(make_agent(lambda c: {"findings": []}), "INC-999")
    assert r["report"] is None and r["error"]


def test_evidence_does_not_leak_between_incidents():
    agent = make_agent(lambda c: {"findings": []})
    generate_report(agent, "INC-001")
    r = generate_report(agent, "INC-002")
    assert "SSH-Patator" not in r["report"]

NO_FINDINGS = lambda c: {"findings": []}


def test_grounded_summary_is_shown():
    good = lambda c: {"summary": "Host 203.0.113.50 brute-forced 10.0.0.5, which then scanned other hosts."}
    r = generate_report(make_agent(NO_FINDINGS, good), "INC-001")
    assert r["summary"] and "## Executive summary (model-written, verified)" in r["report"]


def test_summary_with_invented_number_is_withheld():
    bad = lambda c: {"summary": "Host 203.0.113.50 sent 500000 packets to 10.0.0.5."}
    r = generate_report(make_agent(NO_FINDINGS, bad), "INC-001")
    assert r["summary"] is None and "Withheld" in r["report"]


def test_summary_with_unknown_ip_is_withheld():
    bad = lambda c: {"summary": "Traffic went to 8.8.8.8 after the attack."}
    r = generate_report(make_agent(NO_FINDINGS, bad), "INC-001")
    assert r["summary"] is None and "IPs" in r["summary_note"]


def test_unparseable_summary_is_withheld():
    r = generate_report(make_agent(NO_FINDINGS), "INC-001")  # fake returns "not json"
    assert r["summary"] is None and "could not be parsed" in r["summary_note"]


def test_finding_with_invented_number_is_rejected():
    r = generate_report(make_agent(one("203.0.113.50 sent 9999 packets.")), "INC-001")
    assert not r["accepted"] and "numbers" in r["rejected"][0]["problems"][0]



def test_report_lists_role_changes_from_the_alerts():
    r = generate_report(make_agent(NO_FINDINGS), "INC-001")
    assert "10.0.0.5: target in" in r["report"] and "then source in" in r["report"]



def test_report_has_code_written_summary_and_roles():
    r = generate_report(make_agent(NO_FINDINGS), "INC-001")
    assert "## Summary of the alerts (computed by code)" in r["report"]
    assert "10.0.0.5" in r["factual_summary"] and "203.0.113.50" in r["factual_summary"]


def test_finding_calling_attacker_server_compromised_is_rejected():
    r = generate_report(make_agent(one("The host 203.0.113.50 was possibly compromised.")), "INC-001")
    assert not r["accepted"] and "compromised" in r["rejected"][0]["problems"][0]


def test_finding_about_an_internal_sender_may_say_compromised():
    r = generate_report(make_agent(one("The host 10.0.0.5 was possibly compromised.")), "INC-001")
    assert r["accepted"]


def test_finding_calling_the_attacker_server_a_target_is_rejected():
    r = generate_report(make_agent(one("The host 203.0.113.50 was targeted by the attackers.")), "INC-001")
    assert not r["accepted"] and "attacker-side" in r["rejected"][0]["problems"][0]


def test_finding_about_an_internal_host_may_use_the_word_targets():
    r = generate_report(make_agent(one("The host 10.0.0.5 sent traffic to several targets.")), "INC-001")
    assert r["accepted"]


def test_finding_saying_the_attacker_was_targeted_is_rejected_in_either_wording():
    r = generate_report(make_agent(one("The attackers targeted 203.0.113.50.")), "INC-001")
    assert not r["accepted"] and "attacker-side" in r["rejected"][0]["problems"][0]