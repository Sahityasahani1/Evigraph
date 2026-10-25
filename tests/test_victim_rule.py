import pytest

from src.agent.victim_rule import attacker_side_problem, called_victim


def test_attacker_side_host_labelled_as_victim_or_target_is_rejected():
    """Verify that attacker-side infrastructure incorrectly labelled as target/victim is rejected."""
    attacker_ip = "203.0.113.50"
    attacker_side = {attacker_ip}

    # Case 1: Passive wording ("was targeted")
    claim_passive = f"The host {attacker_ip} was targeted by the attackers."
    assert called_victim(claim_passive, attacker_ip) is True
    problem_passive = attacker_side_problem(claim_passive, [attacker_ip], attacker_side)
    assert problem_passive is not None
    assert "calls attacker-side hosts targets or victims" in problem_passive
    assert attacker_ip in problem_passive

    # Case 2: Active objective wording ("attackers targeted <ip>")
    claim_active = f"The attackers targeted {attacker_ip}."
    assert called_victim(claim_active, attacker_ip) is True
    problem_active = attacker_side_problem(claim_active, [attacker_ip], attacker_side)
    assert problem_active is not None
    assert "calls attacker-side hosts targets or victims" in problem_active
    assert attacker_ip in problem_active

    # Case 3: Explicit victim label ("was a victim")
    claim_victim = f"Server {attacker_ip} was a victim of exfiltration."
    assert called_victim(claim_victim, attacker_ip) is True
    problem_victim = attacker_side_problem(claim_victim, [attacker_ip], attacker_side)
    assert problem_victim is not None
    assert "calls attacker-side hosts targets or victims" in problem_victim


def test_attacker_side_host_as_source_or_valid_victim_is_accepted():
    """Verify that valid role descriptions do not flag attacker-side problems."""
    attacker_ip = "203.0.113.50"
    victim_ip = "10.0.0.5"
    attacker_side = {attacker_ip}

    # Attacker host correctly acting as attacker/source
    claim_valid_attack = f"{attacker_ip} attacked {victim_ip}."
    assert called_victim(claim_valid_attack, attacker_ip) is False
    assert attacker_side_problem(claim_valid_attack, [attacker_ip, victim_ip], attacker_side) is None

    # Victim host correctly called target/victim
    claim_valid_target = f"{victim_ip} was targeted by {attacker_ip}."
    assert called_victim(claim_valid_target, attacker_ip) is False
    assert attacker_side_problem(claim_valid_target, [attacker_ip, victim_ip], attacker_side) is None
