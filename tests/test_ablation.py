try:
    from tests.test_report import make_agent, one
except ImportError:
    from test_report import make_agent, one

from src.agent.ablation import categorise, run_ablation, summarise


def test_problems_are_sorted_into_types():
    counts = categorise(["cites no flow_id", "mentions IPs not in this incident: ['1.2.3.4']",
                         "contains numbers not in the data: ['9']"])
    assert counts["no citation"] == 1 and counts["invented IP"] == 1 and counts["invented number"] == 1


def test_ablation_counts_what_the_validator_rejects():
    rows = run_ablation(make_agent(one("The host 203.0.113.50 was possibly compromised.")), ["INC-001"])
    assert rows[0]["proposed"] == 1 and rows[0]["rejected"] == 1
    assert rows[0]["problems"]["wrong 'compromised' role"] >= 1


def test_summary_computes_faithfulness_without_validator():
    rows = [{"incident_id": "A", "proposed": 4, "accepted": 3, "rejected": 1,
             "summary_withheld": True, "problems": {"invented IP": 1}},
            {"incident_id": "B", "proposed": 2, "accepted": 1, "rejected": 1,
             "summary_withheld": False, "problems": {"invented number": 1}}]
    s = summarise(rows)
    assert s["proposed"] == 6 and s["accepted"] == 4
    assert abs(s["faithfulness_without_validator"] - 4 / 6) < 1e-9
    assert s["summaries_withheld"] == 1