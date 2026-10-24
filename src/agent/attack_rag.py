"""Search MITRE ATT&CK by meaning, and look techniques up by ID.

Build once : python -m src.agent.attack_rag
Use        : kb = AttackKnowledge(); kb.search("many failed SSH logins"); kb.get("T1110")
"""
import json
import re
from pathlib import Path

import numpy as np
import ollama

KNOWLEDGE_DIR = Path(__file__).resolve().parents[2] / "data" / "knowledge"
TECHNIQUES = KNOWLEDGE_DIR / "attack_techniques.json"
INDEX = KNOWLEDGE_DIR / "attack_index.npz"
EMBED_MODEL = "nomic-embed-text"


class AttackKnowledgeUnavailableError(RuntimeError):
    """The existing ATT&CK embedding index or embedding service is unavailable."""


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

ATTACK_CLASS_DESCRIPTIONS = {
    "ssh patator": "repeated failed SSH login attempts guessing passwords (brute force)",
    "ftp patator": "repeated failed FTP login attempts guessing passwords (brute force)",
    "portscan": "port scan probing many ports and hosts for open services",
    "dos hulk": "denial of service flood of HTTP requests overwhelming a web server",
    "dos goldeneye": "denial of service flood of HTTP requests overwhelming a web server",
    "dos slowloris": "slow HTTP connections exhausting a web server (denial of service)",
    "dos slowhttptest": "slow HTTP connections exhausting a web server (denial of service)",
    "ddos": "distributed denial of service flood of traffic from many sources",
    "bot": "infected host repeatedly beaconing to a command and control server over web protocols",
    "infiltration": "large outbound data transfer to an external server (data exfiltration)",
    "web attack brute force": "repeated login attempts guessing passwords on a web application",
    "web attack xss": "cross-site scripting attack against a web application",
    "web attack sql injection": "SQL injection exploiting a vulnerability in a public-facing web application",
    "heartbleed": "exploiting a vulnerability in a public-facing service to leak memory",
    "dns amplification": "DNS amplification reflection flood of large DNS responses sent to a victim",
    "ntp reflection": "NTP reflection amplification flood sent to a victim",
    "syn flood": "TCP SYN flood denial of service against a server",
    "backdoor": "backdoor giving persistent remote access to a compromised host",
    "exploits": "exploiting a vulnerability in a network service for remote code execution",
    "fuzzers": "fuzzing a network service with malformed or random input to discover exploitable vulnerabilities",
    "reconnaissance": "port scanning and probing many hosts and ports to discover open network services",
    "c2 heartbeat": "infected host repeatedly beaconing to a command and control server at regular intervals",
    "https exfiltration": "large upload of stolen data to an external server over HTTPS, exfiltration over web services",
    "lateral smb relay": "lateral movement between internal hosts over SMB, relaying captured credentials, SMB relay",
}


def describe_attack_class(attack_class: str) -> str:
    """Return analyst wording for a detector label, without asserting a technique."""
    normalized = re.sub(r"[^a-z0-9]+", " ", attack_class.lower()).strip()
    return ATTACK_CLASS_DESCRIPTIONS.get(
        normalized, f"{attack_class} network activity"
    )


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
    INDEX.parent.mkdir(parents=True, exist_ok=True)
    np.savez(
        INDEX,
        vectors=np.vstack(chunks),
        ids=np.array([t["id"] for t in techniques]),
    )
    print(f"Saved index to {INDEX}")


class AttackKnowledge:
    def __init__(
        self,
        techniques_path: Path = TECHNIQUES,
        index_path: Path = INDEX,
    ) -> None:
        self.techniques_path = Path(techniques_path)
        self.index_path = Path(index_path)
        self.techniques = {
            t["id"]: t
            for t in json.loads(self.techniques_path.read_text(encoding="utf-8"))
        }
        self.ids: list[str] = []
        self.vectors = np.empty((0, 0), dtype=np.float32)
        self.status = "unavailable"
        self.error: str | None = None
        if not self.index_path.is_file():
            self.error = (
                f"ATT&CK vector index not found at {self.index_path}. "
                "Build the existing index with `python -m src.agent.attack_rag` "
                f"after starting Ollama with the `{EMBED_MODEL}` model."
            )
            return

        try:
            with np.load(self.index_path, allow_pickle=False) as data:
                self.ids = [str(i) for i in data["ids"]]
                self.vectors = np.asarray(data["vectors"], dtype=np.float32)
        except (OSError, ValueError, KeyError, EOFError) as exc:
            self.error = f"Invalid ATT&CK vector index at {self.index_path}: {exc}"
            return
        if (
            self.vectors.ndim != 2
            or len(self.ids) != len(self.vectors)
            or not self.ids
            or not np.isfinite(self.vectors).all()
        ):
            self.error = f"Invalid ATT&CK vector index at {self.index_path}."
            return
        unknown_ids = sorted(set(self.ids) - set(self.techniques))
        if unknown_ids:
            self.error = (
                f"ATT&CK vector index at {self.index_path} references unknown "
                f"technique IDs: {unknown_ids[:10]}."
            )
            return
        self.status = "available"

    def get(self, attack_id: str) -> dict | None:
        """Exact lookup. Returns None if the ID does not exist (used to catch made-up IDs)."""
        return self.techniques.get(attack_id)

    def search(self, query: str, k: int = 5) -> list[dict]:
        if self.status != "available":
            raise AttackKnowledgeUnavailableError(self.error or "ATT&CK retrieval is unavailable.")
        if k < 0:
            raise ValueError("k must be zero or greater.")
        if not query.strip() or k == 0:
            return []
        try:
            query_vectors = _embed([f"search_query: {query}"])
        except (ollama.RequestError, ollama.ResponseError, ConnectionError) as exc:
            self.status = "unavailable"
            self.error = (
                f"ATT&CK embedding service unavailable for model `{EMBED_MODEL}`: {exc}"
            )
            raise AttackKnowledgeUnavailableError(self.error) from exc
        if (
            query_vectors.ndim != 2
            or query_vectors.shape[0] != 1
            or query_vectors.shape[1] != self.vectors.shape[1]
            or not np.isfinite(query_vectors).all()
        ):
            self.status = "unavailable"
            self.error = (
                f"ATT&CK query embedding is incompatible with vector index at {self.index_path}."
            )
            raise AttackKnowledgeUnavailableError(self.error)
        q = query_vectors[0]
        scores = self.vectors @ q
        top = np.argsort(-scores)[: min(k, len(scores))]
        results = []
        for i in top:
            t = self.techniques[self.ids[i]]
            results.append(
                {
                    "id": t["id"],
                    "name": t["name"],
                    "tactics": t["tactics"],
                    "score": round(float(scores[i]), 3),
                    "score_semantics": "cosine_similarity",
                    "source_url": t.get("url"),
                }
            )
        return results


if __name__ == "__main__":
    build_index()
