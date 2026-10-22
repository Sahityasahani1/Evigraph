"""
EviGraph Forensic Citation Validator (Member 3 / Downstream Defense)
Adheres to PRD FR-7.4 & TRD Section 6:
- Scans LLM forensic reports for evidence citation tags [E:<flow_id>]
- Cross-references citations against immutable case bundle (outputs/incident_cases.json)
- Computes Citation Faithfulness Score (target: >= 95%)
- Flags or suppresses ungrounded or hallucinated statements
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple

class CitationValidator:
    """
    Validates that every factual statement in forensic agent reports cites
    verifiable, authentic flow evidence from Member 2's incident cases.
    """
    # Regex to capture [E:flw_...] or [Evidence: flw_...]
    CITATION_REGEX = re.compile(r"\[(?:E|Evidence):\s*([a-zA-Z0-9_\-]+)\]")

    def __init__(self, incident_cases_path: Optional[Path] = None):
        self.incident_cases_path = incident_cases_path
        self.evidence_index: Dict[str, Dict[str, Any]] = {}
        self.valid_flow_ids: Set[str] = set()
        if incident_cases_path and Path(incident_cases_path).exists():
            self.load_evidence_index(incident_cases_path)

    def load_evidence_index(self, incident_cases_path: Path):
        """Loads incident cases JSON and indexes all evidence flows and edges."""
        with open(incident_cases_path, "r") as f:
            data = json.load(f)

        self.evidence_index.clear()
        self.valid_flow_ids.clear()

        for incident in data.get("incidents", []):
            inc_id = incident.get("incident_id")
            # Index flows listed in evidence_flow_ids
            for fid in incident.get("evidence_flow_ids", []):
                self.valid_flow_ids.add(fid)
                if fid not in self.evidence_index:
                    self.evidence_index[fid] = {
                        "incident_id": inc_id,
                        "source": incident.get("suspected_entry_point"),
                        "attack_classes": incident.get("attack_classes", [])
                    }

            # Index edge details from the extracted subgraph
            subgraph = incident.get("subgraph", {})
            for edge in subgraph.get("edges", []):
                eid = edge.get("edge_id")
                if eid:
                    self.valid_flow_ids.add(eid)
                    self.evidence_index[eid] = {
                        "incident_id": inc_id,
                        "source": edge.get("source"),
                        "target": edge.get("target"),
                        "timestamp": edge.get("timestamp"),
                        "dst_port": edge.get("dst_port"),
                        "protocol": edge.get("protocol"),
                        "risk_score": edge.get("risk_score"),
                        "predicted_class": edge.get("predicted_class")
                    }

    def validate_report(self, report_text: str) -> Dict[str, Any]:
        """
        Validates the entire report text:
        - Extracts all citation tags
        - Verifies each against the evidence index
        - Returns verification metrics and breakdown
        """
        citations = self.CITATION_REGEX.findall(report_text)
        total_citations = len(citations)
        
        verified_citations = []
        hallucinated_citations = []

        for cid in citations:
            if cid in self.valid_flow_ids:
                verified_citations.append(cid)
            else:
                hallucinated_citations.append(cid)

        unique_citations = set(citations)
        unique_verified = set(verified_citations)
        unique_hallucinated = set(hallucinated_citations)

        faithfulness = (
            (len(verified_citations) / total_citations * 100.0) 
            if total_citations > 0 else 0.0
        )

        passed = faithfulness >= 95.0 and total_citations > 0

        result = {
            "total_citations": total_citations,
            "unique_citations_count": len(unique_citations),
            "verified_count": len(verified_citations),
            "hallucinated_count": len(hallucinated_citations),
            "citation_faithfulness_pct": round(faithfulness, 2),
            "passed_threshold": passed,
            "verified_flow_ids": list(unique_verified),
            "hallucinated_flow_ids": list(unique_hallucinated),
        }
        return result

    def format_validation_summary(self, result: Dict[str, Any]) -> str:
        """Renders a readable summary table of citation verification."""
        status = "PASSED (Faithful)" if result["passed_threshold"] else "FAILED (Insufficient / Hallucinated)"
        lines = [
            "=" * 60,
            "   EVIGRAPH CITATION VALIDATOR REPORT",
            "=" * 60,
            f"Status                   : {status}",
            f"Total Evidence Citations : {result['total_citations']}",
            f"Unique Citations         : {result['unique_citations_count']}",
            f"Verified Evidence Flows  : {result['verified_count']}",
            f"Hallucinated Flow IDs    : {result['hallucinated_count']}",
            f"Faithfulness Score       : {result['citation_faithfulness_pct']}% (Target: >= 95%)",
            "=" * 60
        ]
        if result["hallucinated_flow_ids"]:
            lines.append("Flagged Hallucinations: " + ", ".join(result["hallucinated_flow_ids"]))
        return "\n".join(lines)
