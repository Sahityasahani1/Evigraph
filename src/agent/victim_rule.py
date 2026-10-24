"""Rule: attacker-side hosts (attacker servers or attackers) may not be called targets or victims."""
import re

_FILLER = r"(?:(?:a|an|the|also|possibly|likely|then|repeatedly|been|being)\s+)*"


def called_victim(claim: str, ip: str) -> bool:
    """True if the claim says this host was the target or victim (not that it targeted someone)."""
    p = re.escape(ip)
    passive = rf"{p}\s+(?:was|were|is|are)\s+{_FILLER}(?:targeted|attacked|breached|victims?|targets?)\b"
    obj = rf"\b(?:targeted|attacked|breached)\s+(?:the\s+)?(?:host\s+|server\s+)?{p}"
    return bool(re.search(passive, claim, re.IGNORECASE) or re.search(obj, claim, re.IGNORECASE))


def attacker_side_problem(claim, ips_in_claim, attacker_side):
    """A problem string if the claim calls an attacker-side host a target or victim, else None."""
    if not attacker_side:
        return None
    wrong = sorted({ip for ip in ips_in_claim if ip in attacker_side and called_victim(claim, ip)})
    if wrong:
        return ("calls attacker-side hosts targets or victims "
                f"(they are attacker servers or attackers): {wrong}")
    return None