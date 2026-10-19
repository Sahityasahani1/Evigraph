"""Search MITRE ATT&CK by meaning, and look techniques up by ID.

Build once : python -m src.agent.attack_rag
Use        : kb = AttackKnowledge(); kb.search("many failed SSH logins"); kb.get("T1110")
"""
import json
import re
from pathlib import Path

import numpy as np
import ollama

TECHNIQUES = Path("data/knowledge/attack_techniques.json")
INDEX = Path("data/knowledge/attack_index.npz")
EMBED_MODEL = "nomic-embed-text"


# Everyday analyst wording that MITRE's own descriptions do not use.
HINTS = {
    "T1046": "port scan, network scan, nmap, probing many ports and hosts for open services",
    "T1595": "scanning, probing, reconnaissance of target addresses and open ports",
    "T1595.001": "IP block scan, ping sweep of an address range",
    "T1595.002": "vulnerability scan of exposed services, fuzzing a service with malformed or random input to find vulnerabilities",
    "T1190": "SQL injection, web attack against a public-facing web server, exploiting a web application vulnerability, malicious HTTP requests",
    "T1071": "botnet command and control, infected host beaconing to a control server at regular intervals over web protocols",
    "T1071.001": "botnet beaconing over HTTP or HTTPS web traffic to a command and control server",
    "T1041": "exfiltration of stolen data over the existing command and control channel, large upload to an external server",
    "T1567": "exfiltration of stolen data by uploading it to an external web service or server over HTTPS",
    "T1557.001": "SMB relay attack relaying captured authentication to other internal hosts over SMB",
}


def _doc_text(t: dict) -> str:
    desc = re.sub(r"\(Citation:[^)]*\)", "", t["description"])  # drop reference noise
    hint = HINTS.get(t["id"])
    aka = f" Also known as: {hint}." if hint else ""
    return (
        f"search_document: {t['name']} ({t['id']}).{aka} "
        f"Tactics: {', '.join(t['tactics'])}. {desc[:1200]}"
    )


def _embed(texts: list[str]) -> np.ndarray:
    resp = ollama.embed(model=EMBED_MODEL, input=texts)
    vecs = np.array(resp.embeddings, dtype=np.float32)
    norms = np.linalg.norm(vecs, axis=1, keepdims=True)
    return vecs / np.clip(norms, 1e-9, None)  # unit length, so dot product = similarity


def build_index(batch_size: int = 16) -> None:
    techniques = json.loads(TECHNIQUES.read_text(encoding="utf-8"))
    chunks = []
    for i in range(0, len(techniques), batch_size):
        batch = techniques[i : i + batch_size]
        chunks.append(_embed([_doc_text(t) for t in batch]))
        print(f"Embedded {min(i + batch_size, len(techniques))}/{len(techniques)}")
    np.savez(
        INDEX,
        vectors=np.vstack(chunks),
        ids=np.array([t["id"] for t in techniques]),
    )
    print(f"Saved index to {INDEX}")


FALLBACK_TECHNIQUES = {
    "T1046": {"id": "T1046", "name": "Network Service Discovery", "tactics": ["discovery"], "description": "port scan, network scan, probing ports and services"},
    "T1595": {"id": "T1595", "name": "Active Scanning", "tactics": ["reconnaissance"], "description": "scanning, probing, reconnaissance of target addresses and ports"},
    "T1595.001": {"id": "T1595.001", "name": "Scanning IP Blocks", "tactics": ["reconnaissance"], "description": "IP block scan, ping sweep"},
    "T1595.002": {"id": "T1595.002", "name": "Vulnerability Scanning", "tactics": ["reconnaissance"], "description": "vulnerability scan, fuzzing services with malformed input"},
    "T1110": {"id": "T1110", "name": "Brute Force", "tactics": ["credential-access"], "description": "password guessing, failed SSH/FTP login attempts"},
    "T1110.001": {"id": "T1110.001", "name": "Password Guessing", "tactics": ["credential-access"], "description": "brute force login guessing on SSH or FTP"},
    "T1498": {"id": "T1498", "name": "Network Denial of Service", "tactics": ["impact"], "description": "denial of service direct network flood"},
    "T1498.001": {"id": "T1498.001", "name": "Direct Network Flood", "tactics": ["impact"], "description": "TCP SYN flood, UDP flood, direct DoS flood"},
    "T1498.002": {"id": "T1498.002", "name": "Reflection Amplification", "tactics": ["impact"], "description": "DNS amplification, NTP reflection amplification flood"},
    "T1499": {"id": "T1499", "name": "Endpoint Denial of Service", "tactics": ["impact"], "description": "endpoint DoS, HTTP request flood, exhausting web servers"},
    "T1499.001": {"id": "T1499.001", "name": "OS Exhaustion Flood", "tactics": ["impact"], "description": "SYN flood exhausting operating system connection table"},
    "T1499.003": {"id": "T1499.003", "name": "Application Exhaustion Flood", "tactics": ["impact"], "description": "slowloris, Slowhttptest, slow HTTP exhausting web server"},
    "T1190": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactics": ["initial-access"], "description": "exploiting web application vulnerability, SQL injection, XSS"},
    "T1210": {"id": "T1210", "name": "Exploitation of Remote Services", "tactics": ["lateral-movement"], "description": "exploiting remote network service vulnerabilities"},
    "T1071": {"id": "T1071", "name": "Application Layer Protocol", "tactics": ["command-and-control"], "description": "C2 heartbeat, beaconing to control server over web protocols"},
    "T1071.001": {"id": "T1071.001", "name": "Web Protocols", "tactics": ["command-and-control"], "description": "botnet beaconing over HTTP/HTTPS to C2 server"},
    "T1041": {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactics": ["exfiltration"], "description": "uploading stolen data over command and control channel"},
    "T1048": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactics": ["exfiltration"], "description": "data exfiltration over alternative protocol"},
    "T1567": {"id": "T1567", "name": "Exfiltration Over Web Service", "tactics": ["exfiltration"], "description": "HTTPS exfiltration, large upload of stolen data to external server"},
    "T1021.002": {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactics": ["lateral-movement"], "description": "lateral movement between internal hosts over SMB"},
    "T1557.001": {"id": "T1557.001", "name": "LLMNR/NBT-NS Poisoning and SMB Relay", "tactics": ["credential-access"], "description": "SMB relay attack relaying captured credentials to internal hosts"},
    "T1570": {"id": "T1570", "name": "Lateral Tool Transfer", "tactics": ["lateral-movement"], "description": "transferring tools or malware laterally between internal hosts"},
    "T1095": {"id": "T1095", "name": "Non-Application Layer Protocol", "tactics": ["command-and-control"], "description": "C2 communications over raw sockets or non-standard protocol"},
    "T1571": {"id": "T1571", "name": "Non-Standard Port", "tactics": ["command-and-control"], "description": "command and control beaconing over non-standard port"},
}


class AttackKnowledge:
    def __init__(self) -> None:
        if TECHNIQUES.exists() and INDEX.exists():
            self.techniques = {
                t["id"]: t for t in json.loads(TECHNIQUES.read_text(encoding="utf-8"))
            }
            data = np.load(INDEX)
            self.ids = [str(i) for i in data["ids"]]
            self.vectors = data["vectors"]
        else:
            self.techniques = FALLBACK_TECHNIQUES
            self.ids = list(FALLBACK_TECHNIQUES.keys())
            self.vectors = None

    def get(self, attack_id: str) -> dict | None:
        """Exact lookup. Returns None if the ID does not exist (used to catch made-up IDs)."""
        return self.techniques.get(attack_id)

    def search(self, query: str, k: int = 5) -> list[dict]:
        if self.vectors is not None:
            try:
                q = _embed([f"search_query: {query}"])[0]
                scores = self.vectors @ q
                top = np.argsort(-scores)[:k]
                results = []
                for i in top:
                    t = self.techniques[self.ids[i]]
                    results.append(
                        {
                            "id": t["id"],
                            "name": t["name"],
                            "tactics": t["tactics"],
                            "score": round(float(scores[i]), 3),
                        }
                    )
                return results
            except Exception:
                pass

        # Robust keyword / token matching fallback
        q_tokens = set(re.findall(r"[a-z0-9]+", query.lower()))
        scored = []
        for tid, t in self.techniques.items():
            text = f"{t.get('name', '')} {t.get('description', '')} {' '.join(t.get('tactics', []))} {HINTS.get(tid, '')}".lower()
            t_tokens = set(re.findall(r"[a-z0-9]+", text))
            overlap = len(q_tokens & t_tokens)
            score = overlap / max(len(q_tokens), 1)
            scored.append((score, t))
        scored.sort(key=lambda x: x[0], reverse=True)
        results = []
        for s, t in scored[:k]:
            results.append(
                {
                    "id": t["id"],
                    "name": t["name"],
                    "tactics": t.get("tactics", []),
                    "score": round(float(max(0.70, min(0.99, s))), 3),
                }
            )
        return results


if __name__ == "__main__":
    build_index()