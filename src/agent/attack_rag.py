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
    "T1595.002": "vulnerability scan of exposed services",
    "T1190": "SQL injection, web attack against a public-facing web server, exploiting a web application vulnerability, malicious HTTP requests",
    "T1071": "botnet command and control, infected host beaconing to a control server at regular intervals over web protocols",
    "T1071.001": "botnet beaconing over HTTP or HTTPS web traffic to a command and control server",
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


class AttackKnowledge:
    def __init__(self) -> None:
        self.techniques = {
            t["id"]: t for t in json.loads(TECHNIQUES.read_text(encoding="utf-8"))
        }
        data = np.load(INDEX)
        self.ids = [str(i) for i in data["ids"]]
        self.vectors = data["vectors"]

    def get(self, attack_id: str) -> dict | None:
        """Exact lookup. Returns None if the ID does not exist (used to catch made-up IDs)."""
        return self.techniques.get(attack_id)

    def search(self, query: str, k: int = 5) -> list[dict]:
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


if __name__ == "__main__":
    build_index()