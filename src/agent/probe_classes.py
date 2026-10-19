"""Show what ATT&CK retrieval returns for each attack class, using the agent's REAL queries."""
from src.agent.agent import _stage_query
from src.agent.attack_rag import AttackKnowledge

CLASSES = [
    "DNS-Amplification", "NTP-Reflection", "SYN-Flood", "Backdoor", "Exploits",
    "Fuzzers", "Reconnaissance", "C2-Heartbeat", "HTTPS-Exfiltration", "Lateral-SMB-Relay",
]

kb = AttackKnowledge()
for cls in CLASSES:
    print(f"\n{cls}  <-  {_stage_query(cls)}")
    for m in kb.search(_stage_query(cls), 5):
        print(f"  {m['id']:<10} {m['name']:<40} {m['score']:.2f}")