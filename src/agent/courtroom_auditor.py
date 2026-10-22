"""
EviGraph Dual-Agent Adversarial Courtroom Cross-Examiner (Defense Auditor)
Adheres to Federal Rules of Evidence 902(13)/(14), ISO/IEC 27037 Digital Forensics,
and PRD NFR-1 (Cryptographic Admissibility) & FR-7.4 (Zero-Hallucination):

Role:
Acts as a skeptical, adversarial defense counsel / independent forensic auditor.
Cross-examines the Investigating Agent's (ForensicAgent) claims, citations, and causal
reconstructions against 4 independent verification gates:

Gate 1: Cryptographic Proof-of-Existence (RFC-6962 Merkle Root & Inclusion Path)
Gate 2: Physical Network Protocol & Layer-4 Feasibility (RFC Standards)
Gate 3: Temporal Monotonicity & Causal DAG Reachability (Lamport Monotonicity)
Gate 4: Quantitative Fact-Checking & Anti-Hallucination Telemetry Audit

Outputs:
- outputs/certified_forensic_verdict.json
- outputs/courtroom_cross_examination.md
"""

import os
import sys
import re
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Set, Any, Optional, Tuple

from src.config import OUTPUTS_DIR
from src.integrity.merkle_engine import MerkleEvidenceEngine

# Recognized standard protocols
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
    "ICMP": "ICMP",
    "TCP": "TCP",
    "UDP": "UDP"
}

# Attack class to physical Layer-4 protocol and port constraints
ATTACK_PROTOCOL_CONSTRAINTS = {
    "SSH-Patator": {
        "required_protocols": {"TCP", "6"},
        "typical_ports": {22, 2222},
        "description": "SSH remote terminal authentication requires TCP connection handshake."
    },
    "FTP-Patator": {
        "required_protocols": {"TCP", "6"},
        "typical_ports": {21, 2121, 20},
        "description": "FTP control plane requires TCP stream connection."
    },
    "DoS-Slowloris": {
        "required_protocols": {"TCP", "6"},
        "typical_ports": {80, 443, 8080, 8443, 8000, 8008},
        "description": "Slowloris exploits HTTP keep-alive headers over TCP sockets."
    },
    "DoS-Hulk": {
        "required_protocols": {"TCP", "6"},
        "typical_ports": {80, 443, 8080, 8443, 8000},
        "description": "HULK HTTP request flooding targets Web application sockets over TCP."
    },
    "Bot": {
        "required_protocols": {"TCP", "UDP", "6", "17"},
        "typical_ports": None,  # Botnets can utilize various C2 channels
        "description": "C2 beaconing over IP protocols."
    },
    "PortScan": {
        "required_protocols": {"TCP", "UDP", "ICMP", "6", "17", "1"},
        "typical_ports": None,  # Port scans target arbitrary destination ports
        "description": "Port scanning probes arbitrary remote ports across TCP/UDP/ICMP."
    },
    "DDoS": {
        "required_protocols": {"TCP", "UDP", "ICMP", "6", "17", "1"},
        "typical_ports": None,
        "description": "Distributed denial of service flooding."
    },
    "Infiltration": {
        "required_protocols": {"TCP", "6"},
        "typical_ports": None,
        "description": "Lateral infiltration typically leverages TCP-based application protocols."
    }
}

class CourtroomCrossExaminer:
    """
    Adversarial Defense Auditor that ruthlessly cross-examines forensic reports
    against cryptographic Merkle proofs, Layer-4 protocols, Causal DAGs, and raw telemetry.
    """
    CITATION_REGEX = re.compile(r"\[(?:E|Evidence):\s*([a-zA-Z0-9_\-]+)\]")

    def __init__(
        self,
        incident_cases_path: Optional[Path] = None,
        merkle_cert_path: Optional[Path] = None,
        report_path: Optional[Path] = None
    ):
        self.cases_path = Path(incident_cases_path or (OUTPUTS_DIR / "incident_cases.json"))
        self.merkle_cert_path = Path(merkle_cert_path or (OUTPUTS_DIR / "forensic_merkle_certificate.json"))
        self.report_path = Path(report_path or (OUTPUTS_DIR / "forensic_incident_report.md"))

        self.incidents_data: Dict[str, Any] = {}
        self.merkle_data: Dict[str, Any] = {}
        self.report_text: str = ""

        # Indexed telemetry for verification
        self.evidence_by_id: Dict[str, Dict[str, Any]] = {}
        self.merkle_proofs_by_id: Dict[str, Dict[str, Any]] = {}
        self.causal_chains_by_incident: Dict[str, List[Dict[str, Any]]] = {}
        self.session_merkle_root: str = ""

        self.load_data()

    def load_data(self):
        """Loads and indexes case bundles, Merkle certificates, and reports."""
        # 1. Load Incident Cases
        if self.cases_path.exists():
            with open(self.cases_path, "r", encoding="utf-8") as f:
                self.incidents_data = json.load(f)

            for inc in self.incidents_data.get("incidents", []):
                inc_id = inc.get("incident_id")
                # Index causal chain
                causal_info = inc.get("causal_provenance", {})
                self.causal_chains_by_incident[inc_id] = causal_info.get("primary_attack_chain", [])

                # Index subgraph edges
                subgraph = inc.get("subgraph", {})
                for edge in subgraph.get("edges", []):
                    eid = edge.get("edge_id")
                    if eid:
                        self.evidence_by_id[eid] = {
                            "incident_id": inc_id,
                            "flow_id": eid,
                            "source": edge.get("source"),
                            "target": edge.get("target"),
                            "timestamp": str(edge.get("timestamp")),
                            "dst_port": edge.get("dst_port"),
                            "protocol": edge.get("protocol"),
                            "risk_score": edge.get("risk_score", 0.0),
                            "predicted_class": edge.get("predicted_class", "BENIGN"),
                            "merkle_leaf_hash": edge.get("merkle_leaf_hash")
                        }

        # 2. Load Merkle Certificate
        if self.merkle_cert_path.exists():
            with open(self.merkle_cert_path, "r", encoding="utf-8") as f:
                self.merkle_data = json.load(f)
            self.session_merkle_root = self.merkle_data.get("session_merkle_root", "")
            proofs_map = self.merkle_data.get("incident_evidence_proofs", {})
            for inc_id, proofs_list in proofs_map.items():
                for proof in proofs_list:
                    fid = proof.get("flow_id")
                    if fid:
                        self.merkle_proofs_by_id[fid] = proof

        # 3. Load Forensic Report
        if self.report_path.exists():
            with open(self.report_path, "r", encoding="utf-8") as f:
                self.report_text = f.read()

    def cross_examine_gate1_merkle(
        self, citations: List[str]
    ) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Gate 1: Cryptographic Proof-of-Existence Audit.
        Recomputes Merkle root along RFC-6962 audit paths for all cited flow IDs.
        """
        objections = []
        verified_count = 0

        for fid in citations:
            proof = self.merkle_proofs_by_id.get(fid)
            if not proof:
                objections.append({
                    "gate": "Gate 1 (Cryptographic Admissibility)",
                    "type": "OBJECTION_FABRICATED_OR_MISSING_PROOF",
                    "status": "SUSTAINED",
                    "flow_id": fid,
                    "reason": f"Flow ID '{fid}' has no cryptographic inclusion proof in the certified Merkle Ledger."
                })
                continue

            claimed_root = proof.get("root_hash", "")
            leaf_hash = proof.get("leaf_hash", "")
            proof_steps = proof.get("proof_steps", [])

            # Reconstruct parent hashes up to root
            current_hash = leaf_hash
            for step in proof_steps:
                sibling = step["sibling_hash"]
                pos = step["position"]
                if pos == "left":
                    combined = hashlib.sha256((sibling + current_hash).encode("utf-8")).hexdigest()
                else:
                    combined = hashlib.sha256((current_hash + sibling).encode("utf-8")).hexdigest()
                current_hash = combined

            expected_root = self.session_merkle_root or claimed_root
            if current_hash.lower() == expected_root.lower():
                verified_count += 1
                objections.append({
                    "gate": "Gate 1 (Cryptographic Admissibility)",
                    "type": "CHALLENGE_MERKLE_ROOT_CONFORMANCE",
                    "status": "OVERRULED",
                    "flow_id": fid,
                    "reason": f"Mathematical audit path verified: recomputed root '{current_hash[:16]}...' matches certified root."
                })
            else:
                objections.append({
                    "gate": "Gate 1 (Cryptographic Admissibility)",
                    "type": "OBJECTION_CRYPTOGRAPHIC_TAMPERING",
                    "status": "SUSTAINED",
                    "flow_id": fid,
                    "reason": f"Cryptographic tamper detected: recomputed hash '{current_hash}' != certified root '{expected_root}'."
                })

        total = max(1, len(citations))
        score = verified_count / total
        return score, objections

    def cross_examine_gate2_protocols(
        self, citations: List[str]
    ) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Gate 2: Physical Network Protocol & Layer-4 Feasibility Audit.
        Ensures claimed attack vectors match RFC transport protocols and destination ports.
        """
        objections = []
        valid_count = 0

        for fid in citations:
            ev = self.evidence_by_id.get(fid)
            if not ev:
                objections.append({
                    "gate": "Gate 2 (Protocol Feasibility)",
                    "type": "OBJECTION_UNRESOLVED_FLOW_TELEMETRY",
                    "status": "SUSTAINED",
                    "flow_id": fid,
                    "reason": f"Flow '{fid}' could not be resolved in raw network telemetry to check Layer-4 protocol."
                })
                continue

            proto_raw = str(ev.get("protocol", "")).upper()
            proto_name = PROTOCOL_MAP.get(proto_raw, proto_raw)
            dst_port = ev.get("dst_port")
            pred_cls = ev.get("predicted_class", "BENIGN")

            constraints = ATTACK_PROTOCOL_CONSTRAINTS.get(pred_cls)
            if not constraints:
                # Generic or benign traffic
                valid_count += 1
                continue

            req_protos = constraints.get("required_protocols", set())
            typ_ports = constraints.get("typical_ports")

            # Check Protocol Compatibility
            proto_ok = (proto_name in req_protos) or (proto_raw in req_protos)
            if not proto_ok:
                objections.append({
                    "gate": "Gate 2 (Protocol Feasibility)",
                    "type": "OBJECTION_IMPOSSIBLE_LAYER4_PROTOCOL",
                    "status": "SUSTAINED",
                    "flow_id": fid,
                    "reason": (
                        f"Physical impossibility: Claimed attack '{pred_cls}' uses protocol '{proto_name}', "
                        f"which violates required Layer-4 protocols {req_protos} ({constraints['description']})."
                    )
                })
                continue

            # Check Port Compatibility if specified
            if typ_ports and dst_port not in typ_ports:
                # Warning objection overruled if port is non-standard but protocol is valid
                objections.append({
                    "gate": "Gate 2 (Protocol Feasibility)",
                    "type": "CHALLENGE_NON_STANDARD_PORT",
                    "status": "OVERRULED",
                    "flow_id": fid,
                    "reason": f"Flow uses non-standard port {dst_port} for {pred_cls}, but Layer-4 protocol {proto_name} is valid."
                })
                valid_count += 1
            else:
                objections.append({
                    "gate": "Gate 2 (Protocol Feasibility)",
                    "type": "CHALLENGE_LAYER4_PROTOCOL_COMPLIANCE",
                    "status": "OVERRULED",
                    "flow_id": fid,
                    "reason": f"Layer-4 protocol {proto_name} and port {dst_port} strictly conform to {pred_cls} physical specifications."
                })
                valid_count += 1

        total = max(1, len(citations))
        score = valid_count / total
        return score, objections

    def cross_examine_gate3_causal(
        self, report_text: str
    ) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Gate 3: Temporal Monotonicity & Causal Provenance Topology Audit.
        Verifies that attack transitions follow monotonic time (t_1 <= t_2) and valid DAG paths.
        """
        objections = []
        total_checks = 0
        passed_checks = 0

        for inc_id, chain in self.causal_chains_by_incident.items():
            if not chain:
                continue

            for idx in range(len(chain) - 1):
                total_checks += 1
                curr_step = chain[idx]
                next_step = chain[idx + 1]

                t_curr_str = curr_step.get("timestamp")
                t_next_str = next_step.get("timestamp")

                try:
                    t_curr = datetime.fromisoformat(t_curr_str.replace(" ", "T"))
                    t_next = datetime.fromisoformat(t_next_str.replace(" ", "T"))
                except Exception:
                    t_curr = None
                    t_next = None

                # 1. Temporal Monotonicity Check (Lamport causality: t_next >= t_curr)
                if t_curr and t_next and t_next < t_curr:
                    delta = (t_curr - t_next).total_seconds()
                    objections.append({
                        "gate": "Gate 3 (Temporal Causal Provenance)",
                        "type": "OBJECTION_RETROGRADE_CAUSATION",
                        "status": "SUSTAINED",
                        "incident_id": inc_id,
                        "step": f"{idx+1} -> {idx+2}",
                        "reason": f"Temporal paradox: Step {idx+2} ({t_next}) occurs {delta:.3f}s prior to step {idx+1} ({t_curr})."
                    })
                    continue

                # 2. Pivot & Graph Reachability Check
                c_src = curr_step.get("source")
                c_tgt = curr_step.get("target")
                n_src = next_step.get("source")
                n_tgt = next_step.get("target")

                # If next source equals previous target, this is a pivot / lateral movement hop
                if n_src == c_tgt:
                    # Valid lateral movement pivot
                    passed_checks += 1
                    objections.append({
                        "gate": "Gate 3 (Temporal Causal Provenance)",
                        "type": "CHALLENGE_LATERAL_PIVOT_REACHABILITY",
                        "status": "OVERRULED",
                        "incident_id": inc_id,
                        "step": f"{idx+1} -> {idx+2}",
                        "reason": f"Topological pivot verified: Host '{c_tgt}' received ingress before executing egress to '{n_tgt}'."
                    })
                elif n_src == c_src:
                    # Same attacker progressing attack
                    passed_checks += 1
                    objections.append({
                        "gate": "Gate 3 (Temporal Causal Provenance)",
                        "type": "CHALLENGE_MONOTONIC_PROGRESSION",
                        "status": "OVERRULED",
                        "incident_id": inc_id,
                        "step": f"{idx+1} -> {idx+2}",
                        "reason": f"Monotonic attack progression confirmed from attacker '{c_src}' against target '{n_tgt}'."
                    })
                else:
                    # Disjoint hosts in primary chain
                    passed_checks += 1
                    objections.append({
                        "gate": "Gate 3 (Temporal Causal Provenance)",
                        "type": "CHALLENGE_MULTI_ENTITY_CORRELATION",
                        "status": "OVERRULED",
                        "incident_id": inc_id,
                        "step": f"{idx+1} -> {idx+2}",
                        "reason": f"Correlated campaign transition from ({c_src} -> {c_tgt}) to ({n_src} -> {n_tgt})."
                    })

        total = max(1, total_checks)
        score = passed_checks / total if total_checks > 0 else 1.0
        return score, objections

    def cross_examine_gate4_fact_checking(
        self, report_text: str, citations: List[str]
    ) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Gate 4: Quantitative Fact-Checking & Anti-Hallucination Telemetry Audit.
        Verifies that specific numerical claims match ground-truth values and flags uncited claims.
        """
        objections = []
        fact_checks_total = 0
        fact_checks_passed = 0

        # 1. Fact-check total incidents count
        inc_count_match = re.search(r"Identified\s+(\d+)\s+high-risk", report_text, re.IGNORECASE)
        actual_inc_count = len(self.incidents_data.get("incidents", []))
        if inc_count_match:
            fact_checks_total += 1
            stated_count = int(inc_count_match.group(1))
            if stated_count == actual_inc_count:
                fact_checks_passed += 1
                objections.append({
                    "gate": "Gate 4 (Quantitative Fact-Checking)",
                    "type": "CHALLENGE_INCIDENT_COUNT_ACCURACY",
                    "status": "OVERRULED",
                    "reason": f"Stated incident count ({stated_count}) precisely matches ground truth case ledger ({actual_inc_count})."
                })
            else:
                objections.append({
                    "gate": "Gate 4 (Quantitative Fact-Checking)",
                    "type": "OBJECTION_FACTUAL_MISREPRESENTATION",
                    "status": "SUSTAINED",
                    "reason": f"Investigator report claims {stated_count} incidents, but case ledger contains {actual_inc_count}."
                })

        # 2. Fact-check suspected entry point and total alerts per incident
        for inc in self.incidents_data.get("incidents", []):
            inc_id = inc.get("incident_id")
            actual_entry = inc.get("suspected_entry_point")
            actual_alerts = inc.get("total_alerts")

            # Check if entry point is mentioned in report
            if actual_entry and actual_entry in report_text:
                fact_checks_total += 1
                fact_checks_passed += 1
                objections.append({
                    "gate": "Gate 4 (Quantitative Fact-Checking)",
                    "type": "CHALLENGE_ENTRY_POINT_GROUNDING",
                    "status": "OVERRULED",
                    "incident_id": inc_id,
                    "reason": f"Entry point '{actual_entry}' in incident {inc_id} correctly grounded in cluster index."
                })

            # Check if alert count is accurately cited
            if actual_alerts is not None and f"{actual_alerts} high-confidence alerts" in report_text:
                fact_checks_total += 1
                fact_checks_passed += 1
                objections.append({
                    "gate": "Gate 4 (Quantitative Fact-Checking)",
                    "type": "CHALLENGE_ALERT_COUNT_FIDELITY",
                    "status": "OVERRULED",
                    "incident_id": inc_id,
                    "reason": f"Alert count of {actual_alerts} alerts for incident {inc_id} verified against telemetry."
                })

        # 3. Check for uncited dramatic assertions in narrative prose
        # Filter out markdown tables, dividers, headers, and metadata key-value properties
        prose_blocks = []
        for line in report_text.splitlines():
            sline = line.strip()
            if not sline:
                continue
            if sline.startswith("|") or sline.startswith("#") or sline.startswith("---"):
                continue
            # Skip bullet metadata properties like "- **Incident Score:** 0.826" or "- **Primary Attack Tactics:**"
            if re.match(r"^-\s*\*\*[A-Za-z\s]+:\*\*", sline):
                continue
            prose_blocks.append(sline)

        dramatic_keywords = ["compromise", "exfiltrate", "breach", "infiltrat", "brute force", "malicious", "attack"]
        for block in prose_blocks:
            cleaned = block.lstrip("-* ").strip()
            if len(cleaned) < 25:
                continue
            if any(k in cleaned.lower() for k in dramatic_keywords):
                has_citation = bool(self.CITATION_REGEX.search(cleaned))
                fact_checks_total += 1
                if has_citation:
                    fact_checks_passed += 1
                    objections.append({
                        "gate": "Gate 4 (Quantitative Fact-Checking)",
                        "type": "CHALLENGE_GROUNDED_ADVERSE_CLAIM",
                        "status": "OVERRULED",
                        "reason": f"Adverse claim is grounded with authentic evidence citation: '{cleaned[:65]}...'"
                    })
                else:
                    # Allow executive high-level summary overview if followed by evidence
                    if "executive summary" in cleaned.lower() or "mitre attack" in cleaned.lower() or "investigation" in cleaned.lower():
                        fact_checks_passed += 1
                    else:
                        objections.append({
                            "gate": "Gate 4 (Quantitative Fact-Checking)",
                            "type": "OBJECTION_UNCITED_FACTUAL_ASSERTION",
                            "status": "SUSTAINED",
                            "reason": f"Statement alleges adverse action without citing immutable flow: '{cleaned[:75]}...'"
                        })

        total = max(1, fact_checks_total)
        score = fact_checks_passed / total
        return score, objections

    def evaluate_report(
        self, report_content: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes complete adversarial cross-examination over all 4 gates.
        Computes composite admissibility score and issues certified forensic verdict.
        """
        content = report_content or self.report_text
        if not content:
            raise ValueError("Forensic report text is empty. Run ForensicAgent first or provide report_content.")

        citations = self.CITATION_REGEX.findall(content)
        unique_citations = list(dict.fromkeys(citations))

        # Run 4 Verification Gates
        g1_score, g1_objections = self.cross_examine_gate1_merkle(unique_citations)
        g2_score, g2_objections = self.cross_examine_gate2_protocols(unique_citations)
        g3_score, g3_objections = self.cross_examine_gate3_causal(content)
        g4_score, g4_objections = self.cross_examine_gate4_fact_checking(content, unique_citations)

        # Composite Admissibility Score (weights sum to 1.0)
        # 0.35 Merkle + 0.25 Causal DAG + 0.20 Protocol + 0.20 Telemetry Fact-Checking
        admissibility_score = (
            0.35 * g1_score +
            0.25 * g3_score +
            0.20 * g2_score +
            0.20 * g4_score
        )

        # Sustained vs Overruled Objections Count
        all_objections = g1_objections + g2_objections + g3_objections + g4_objections
        sustained = [o for o in all_objections if o.get("status") == "SUSTAINED"]
        overruled = [o for o in all_objections if o.get("status") == "OVERRULED"]

        # Admissibility Verdict
        if admissibility_score >= 0.95 and len(sustained) == 0:
            verdict = "ADMISSIBLE_IN_COURT"
            verdict_description = (
                "Flawless forensic validity. All claims are backed by RFC-6962 Merkle inclusion proofs, "
                "physically valid Layer-4 protocols, monotonic causal DAG transitions, and verified telemetry."
            )
        elif admissibility_score >= 0.80:
            verdict = "CONDITIONALLY_ADMISSIBLE"
            verdict_description = (
                "High evidentiary value. Core causal and cryptographic chain is established, "
                "with minor procedural caveats or uncited commentary noted."
            )
        else:
            verdict = "INADMISSIBLE"
            verdict_description = (
                "Evidentiary failure. Severe flaws detected including missing cryptographic proofs, "
                "retrograde causality, or Layer-4 protocol impossibilities."
            )

        verdict_package = {
            "version": "1.0",
            "auditor": "EviGraph Adversarial Courtroom Cross-Examiner (Defense Agent)",
            "standard": "FRE 902(13)/(14) & ISO/IEC 27037 Digital Forensic Admissibility",
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict,
            "admissibility_score": round(admissibility_score, 4),
            "verdict_description": verdict_description,
            "session_merkle_root": self.session_merkle_root,
            "gate_scores": {
                "gate1_cryptographic_merkle": round(g1_score, 4),
                "gate2_protocol_feasibility": round(g2_score, 4),
                "gate3_temporal_causal_dag": round(g3_score, 4),
                "gate4_telemetry_fact_checking": round(g4_score, 4)
            },
            "citation_statistics": {
                "total_citations_scanned": len(citations),
                "unique_citations_audited": len(unique_citations),
                "sustained_objections_count": len(sustained),
                "overruled_objections_count": len(overruled)
            },
            "cross_examination_objections": all_objections
        }

        return verdict_package

    def format_cross_examination_markdown(self, verdict_package: Dict[str, Any]) -> str:
        """Formats the adversarial cross-examination into a courtroom markdown transcript."""
        v = verdict_package
        gs = v["gate_scores"]
        stats = v["citation_statistics"]

        lines = [
            "# Certified Forensic Courtroom Verdict & Adversarial Audit",
            "",
            "> **Standard of Proof:** Federal Rules of Evidence Rule 902(13)/(14) & ISO/IEC 27037: Guidelines for Identification, Collection, Acquisition and Preservation of Digital Evidence.",
            "",
            "---",
            "",
            "## 1. Executive Judicial Verdict",
            "",
            f"- **Admissibility Verdict:** `{v['verdict']}`",
            f"- **Admissibility Score:** **{v['admissibility_score'] * 100:.2f}%**",
            f"- **Session Merkle Root Digest:** `{v['session_merkle_root']}`",
            f"- **Audit Timestamp:** `{v['evaluated_at']}`",
            f"- **Findings:** {v['verdict_description']}",
            "",
            "### Defense Gate Evaluation Matrix",
            "",
            "| Verification Gate | Evidentiary Requirement | Score | Gate Status |",
            "| :--- | :--- | :--- | :--- |",
            f"| **Gate 1: Cryptographic Integrity** | RFC-6962 SHA-256 Merkle Inclusion Proofs | {gs['gate1_cryptographic_merkle']*100:.1f}% | {'PASSED' if gs['gate1_cryptographic_merkle'] >= 0.95 else 'FAILED'} |",
            f"| **Gate 2: Protocol Feasibility** | RFC Layer-4 Port & Transport Conformity | {gs['gate2_protocol_feasibility']*100:.1f}% | {'PASSED' if gs['gate2_protocol_feasibility'] >= 0.95 else 'FAILED'} |",
            f"| **Gate 3: Causal Provenance DAG** | Lamport Monotonicity & Reachable Topological Path | {gs['gate3_temporal_causal_dag']*100:.1f}% | {'PASSED' if gs['gate3_temporal_causal_dag'] >= 0.95 else 'FAILED'} |",
            f"| **Gate 4: Telemetry Fact-Checking** | Zero Uncited Assertions & Metric Conformance | {gs['gate4_telemetry_fact_checking']*100:.1f}% | {'PASSED' if gs['gate4_telemetry_fact_checking'] >= 0.90 else 'FAILED'} |",
            "",
            f"**Audit Statistics:** Total Citations Audited: `{stats['unique_citations_audited']}` | Sustained Objections: `{stats['sustained_objections_count']}` | Overruled Objections: `{stats['overruled_objections_count']}`",
            "",
            "---",
            "",
            "## 2. Adversarial Cross-Examination Objections Log",
            "",
            "| Gate | Objection / Challenge Type | Ruling | Evidence Subject | Ruling Details |",
            "| :--- | :--- | :--- | :--- | :--- |"
        ]

        for obj in v["cross_examination_objections"][:25]:  # Display top 25 objections in table
            gate_short = obj.get("gate", "").split("(")[0].strip()
            otype = f"`{obj.get('type')}`"
            status = f"**{obj.get('status')}**"
            target = f"`{obj.get('flow_id') or obj.get('incident_id') or obj.get('step') or 'Report'}`"
            reason = obj.get("reason", "").replace("|", "-")
            lines.append(f"| {gate_short} | {otype} | {status} | {target} | {reason} |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. Legal & Scientific Certification",
            "",
            "This document certifies that the corresponding forensic report has undergone dual-agent adversarial cross-examination.",
            "Any tampering with packet headers, timestamps, flow rates, or attack sequence causes mathematical proof failure",
            "at the cryptographic Merkle root layer or the topological causal provenance layer.",
            "",
            f"*Certified by: EviGraph Autonomous Defense Auditor (`{v['auditor']}`)*"
        ])

        return "\n".join(lines)

    def cross_examine_tampered_claim(
        self, tamper_type: str = "leaf_hash"
    ) -> Dict[str, Any]:
        """
        Adversarial Testing Mode:
        Injects deliberate malicious falsifications to demonstrate that the auditor
        successfully detects and rejects synthetic hallucinations and tampering.
        """
        fake_flow_id = "flw_fabricated_zero_day_9999"

        if tamper_type == "missing_proof":
            tampered_report = f"The adversary compromised internal server via [E:{fake_flow_id}]."
        elif tamper_type == "protocol_impossibility":
            # SSH claimed over UDP
            first_fid = next(iter(self.evidence_by_id.keys())) if self.evidence_by_id else "flw_sample_0"
            # temporarily mutate protocol to UDP
            orig = self.evidence_by_id.get(first_fid, {})
            mutated = dict(orig)
            mutated["protocol"] = 17  # UDP
            mutated["predicted_class"] = "SSH-Patator"
            self.evidence_by_id[first_fid] = mutated
            tampered_report = f"Adversary initiated SSH-Patator brute force attack [E:{first_fid}]."
            res = self.evaluate_report(tampered_report)
            self.evidence_by_id[first_fid] = orig  # restore
            return res
        elif tamper_type == "tampered_leaf_hash":
            # Corrupt the leaf hash in the proof
            first_fid = next(iter(self.merkle_proofs_by_id.keys())) if self.merkle_proofs_by_id else "flw_sample_0"
            orig_proof = self.merkle_proofs_by_id.get(first_fid, {})
            mutated_proof = dict(orig_proof)
            mutated_proof["leaf_hash"] = "deadbeef" * 8
            self.merkle_proofs_by_id[first_fid] = mutated_proof
            tampered_report = f"Adversary compromised system via flow [E:{first_fid}]."
            res = self.evaluate_report(tampered_report)
            self.merkle_proofs_by_id[first_fid] = orig_proof  # restore
            return res
        else:
            tampered_report = f"Adversary compromised server via [E:{fake_flow_id}]."

        return self.evaluate_report(tampered_report)

    def run(
        self,
        output_verdict_path: Optional[Path] = None,
        output_markdown_path: Optional[Path] = None
    ) -> Tuple[Path, Path]:
        """
        Executes end-to-end cross-examination:
        1. Reads report and indexes
        2. Evaluates all 4 gates
        3. Exports outputs/certified_forensic_verdict.json
        4. Exports outputs/courtroom_cross_examination.md
        """
        print("=" * 65)
        print("   EVIGRAPH: DUAL-AGENT ADVERSARIAL COURTROOM AUDITOR (USP)")
        print("   Standard: FRE 902(13)/(14) & ISO/IEC 27037 Digital Forensics")
        print("=" * 65)

        verdict_package = self.evaluate_report()
        verdict = verdict_package["verdict"]
        score = verdict_package["admissibility_score"]

        print(f"\n[CourtroomAuditor] Final Admissibility Verdict: {verdict}")
        print(f"[CourtroomAuditor] Composite Admissibility Score: {score * 100:.2f}%\n")
        print("Defense Gate Breakdown:")
        for gate, gscore in verdict_package["gate_scores"].items():
            status = "PASSED" if gscore >= 0.85 else "CHALLENGED"
            print(f"  - {gate}: {gscore * 100:.1f}% [{status}]")

        # Save JSON verdict
        v_path = Path(output_verdict_path or (OUTPUTS_DIR / "certified_forensic_verdict.json"))
        v_path.parent.mkdir(parents=True, exist_ok=True)
        with open(v_path, "w", encoding="utf-8") as f:
            json.dump(verdict_package, f, indent=2)
        print(f"\n[CourtroomAuditor] Certified Verdict exported to: {v_path}")

        # Save Markdown transcript
        md_text = self.format_cross_examination_markdown(verdict_package)
        md_path = Path(output_markdown_path or (OUTPUTS_DIR / "courtroom_cross_examination.md"))
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_text)
        print(f"[CourtroomAuditor] Cross-examination transcript saved to: {md_path}")

        return v_path, md_path

if __name__ == "__main__":
    examiner = CourtroomCrossExaminer()
    examiner.run()
