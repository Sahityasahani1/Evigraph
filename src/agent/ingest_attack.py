"""Turn MITRE's raw ATT&CK catalogue into a small, clean file the agent can search.

Input : data/knowledge/enterprise-attack.json   (big STIX file from MITRE)
Output: data/knowledge/attack_techniques.json   (one short record per technique)
"""
import json
from pathlib import Path

RAW = Path("data/knowledge/enterprise-attack.json")
OUT = Path("data/knowledge/attack_techniques.json")


def load_techniques(raw_path: Path = RAW) -> list[dict]:
    with open(raw_path, encoding="utf-8") as f:
        bundle = json.load(f)

    techniques = []
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        attack_id, url = None, None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                url = ref.get("url")
                break
        if not attack_id:
            continue

        tactics = [
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        techniques.append(
            {
                "id": attack_id,
                "name": obj["name"],
                "tactics": tactics,
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                "description": obj.get("description", "").strip(),
                "url": url,
            }
        )

    techniques.sort(key=lambda t: t["id"])
    return techniques


def main():
    techniques = load_techniques()
    OUT.write_text(json.dumps(techniques, indent=1), encoding="utf-8")
    print(f"Saved {len(techniques)} techniques to {OUT}")


if __name__ == "__main__":
    main()