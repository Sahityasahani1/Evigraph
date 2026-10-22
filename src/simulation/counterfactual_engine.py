"""
EviGraph Counterfactual "What-If" Resilience Simulator
Core USP for Security Architects, Red Teams & Threat Modelers:
- Applies causal counterfactual perturbations over the Temporal Causal DAG G_causal
- Simulates hypothetical defense interventions:
    * Port Closures / Protocol Filtering (e.g. "What if Port 22 was blocked?")
    * Host Isolation / Zero-Trust Microsegmentation (e.g. "What if Host B was segmented?")
    * Early Perimeter Termination (e.g. "What if Reconnaissance was dropped?")
- Recomputes topological dynamic programming reachability on the perturbed graph
- Calculates the Defensive Resilience Index (DRI in [0.0, 1.0]):
    DRI = 1.0 - (Perturbed Severity / Baseline Severity)
- Identifies Single Points of Failure (SPOF) in defense architectures
- Generates outputs/counterfactual_simulation_results.json and outputs/resilience_simulation_report.md
"""

import os
import sys
import json
import networkx as nx
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Set, Any, Optional, Tuple

from src.config import OUTPUTS_DIR
from src.causal_provenance import CausalProvenanceEngine, STAGE_RANKS

class CounterfactualResilienceSimulator:
    """
    Simulates counterfactual security policy interventions over Causal Provenance DAGs.
    Evaluates defensive resilience, attack extinction, and single-points-of-failure.
    """
    def __init__(self, incident_cases_path: Optional[Path] = None):
        self.cases_path = Path(incident_cases_path or (OUTPUTS_DIR / "incident_cases.json"))
        self.causal_engine = CausalProvenanceEngine()
        self.incidents_data: Dict[str, Any] = {}
        self.incident_dags: Dict[str, nx.DiGraph] = {}
        self.load_data()

    def load_data(self):
        """Loads incident cases and reconstructs NetworkX causal DAGs for each incident."""
        if not self.cases_path.exists():
            return

        with open(self.cases_path, "r", encoding="utf-8") as f:
            self.incidents_data = json.load(f)

        for inc in self.incidents_data.get("incidents", []):
            inc_id = inc.get("incident_id")
            subgraph = inc.get("subgraph", {})
            edges = subgraph.get("edges", [])
            # Reconstruct causal DAG using CausalProvenanceEngine
            dag = self.causal_engine.build_causal_dag(edges)
            self.incident_dags[inc_id] = dag

    @staticmethod
    def calculate_chain_severity(chain: List[Dict[str, Any]]) -> float:
        """
        Computes the cumulative impact severity of an attack chain.
        Severity = sum(risk_score * stage_rank).
        """
        severity = 0.0
        for step in chain:
            risk = float(step.get("risk_score", 0.5))
            stage = step.get("attack_stage", "Reconnaissance")
            rank = STAGE_RANKS.get(stage, 1)
            severity += risk * rank
        return round(severity, 4)

    def simulate_policy_intervention(
        self,
        incident_id: str,
        intervention_type: str,
        parameter: Any,
        policy_name: str
    ) -> Dict[str, Any]:
        """
        Simulates a specific counterfactual intervention on the incident's Causal DAG:
        - 'BLOCK_PORT': removes edges where dst_port == parameter
        - 'ISOLATE_HOST': removes nodes where source or target == parameter
        - 'FILTER_STAGE': removes nodes where attack_stage == parameter
        - 'SEVER_EDGE': removes specific flow_id
        """
        base_dag = self.incident_dags.get(incident_id)
        if not base_dag or base_dag.number_of_nodes() == 0:
            return {
                "policy_name": policy_name,
                "incident_id": incident_id,
                "status": "ERROR_NO_DAG",
                "resilience_index": 0.0
            }

        # 1. Baseline Attack Chain & Severity
        base_chain = self.causal_engine.extract_primary_attack_chain(base_dag)
        base_severity = self.calculate_chain_severity(base_chain)
        if base_severity == 0.0:
            base_severity = 1.0

        # 2. Clone DAG and apply counterfactual perturbation
        perturbed_dag = base_dag.copy()
        removed_elements = []

        if intervention_type == "BLOCK_PORT":
            target_port = int(parameter)
            nodes_to_remove = [
                n for n, data in perturbed_dag.nodes(data=True)
                if data.get("dst_port") == target_port
            ]
            for n in nodes_to_remove:
                perturbed_dag.remove_node(n)
                removed_elements.append(n)

        elif intervention_type == "ISOLATE_HOST":
            target_host = str(parameter)
            nodes_to_remove = [
                n for n, data in perturbed_dag.nodes(data=True)
                if data.get("source") == target_host or data.get("target") == target_host
            ]
            for n in nodes_to_remove:
                perturbed_dag.remove_node(n)
                removed_elements.append(n)

        elif intervention_type == "FILTER_STAGE":
            target_stage = str(parameter)
            nodes_to_remove = [
                n for n, data in perturbed_dag.nodes(data=True)
                if data.get("attack_stage") == target_stage
            ]
            for n in nodes_to_remove:
                perturbed_dag.remove_node(n)
                removed_elements.append(n)

        elif intervention_type == "SEVER_EDGE":
            target_fid = str(parameter)
            if perturbed_dag.has_node(target_fid):
                perturbed_dag.remove_node(target_fid)
                removed_elements.append(target_fid)

        # 3. Recalculate attack chain through perturbed DAG
        residual_chain = self.causal_engine.extract_primary_attack_chain(perturbed_dag)
        residual_severity = self.calculate_chain_severity(residual_chain)

        # 4. Compute Defensive Resilience Index (DRI)
        # DRI = 1.0 - (residual / baseline)
        dri = max(0.0, min(1.0, 1.0 - (residual_severity / base_severity)))
        dri = round(dri, 4)

        attack_extinguished = (len(residual_chain) == 0 or residual_severity == 0.0)
        is_spof = (dri >= 0.99)  # Single Point of Failure in attack path

        return {
            "policy_name": policy_name,
            "incident_id": incident_id,
            "intervention_type": intervention_type,
            "parameter": parameter,
            "baseline_steps_count": len(base_chain),
            "baseline_severity": base_severity,
            "residual_steps_count": len(residual_chain),
            "residual_severity": residual_severity,
            "defensive_resilience_index": dri,
            "attack_extinguished": attack_extinguished,
            "single_point_of_failure": is_spof,
            "elements_severed_count": len(removed_elements),
            "residual_attack_chain": residual_chain
        }

    def run_comprehensive_simulation_suite(self) -> Dict[str, Any]:
        """
        Executes a comprehensive counterfactual simulation suite across all incidents.
        Simulates standard defensive configurations:
        - Zero-Trust Port Filtering (blocking individual attacked ports)
        - Perimeter Reconnaissance Filtering
        - Pivot Host Quarantine
        """
        simulations = []

        for inc in self.incidents_data.get("incidents", []):
            inc_id = inc.get("incident_id")
            entry_point = inc.get("suspected_entry_point")
            dag = self.incident_dags.get(inc_id)
            if not dag:
                continue

            # Identify unique ports and stages in this incident
            ports_in_incident = set()
            stages_in_incident = set()
            for _, data in dag.nodes(data=True):
                p = data.get("dst_port")
                if p:
                    ports_in_incident.add(int(p))
                s = data.get("attack_stage")
                if s:
                    stages_in_incident.add(s)

            # Scenario 1: Port Filtering for each major port
            for p in sorted(list(ports_in_incident))[:4]:
                sim = self.simulate_policy_intervention(
                    incident_id=inc_id,
                    intervention_type="BLOCK_PORT",
                    parameter=p,
                    policy_name=f"Firewall Policy: Block Port {p}"
                )
                simulations.append(sim)

            # Scenario 2: Drop Reconnaissance Stage at Boundary
            if "Reconnaissance" in stages_in_incident:
                sim = self.simulate_policy_intervention(
                    incident_id=inc_id,
                    intervention_type="FILTER_STAGE",
                    parameter="Reconnaissance",
                    policy_name="Boundary Defense: Drop Inbound Reconnaissance Probes"
                )
                simulations.append(sim)

            # Scenario 3: Immediate Quarantine of Suspected Entry Point
            if entry_point:
                sim = self.simulate_policy_intervention(
                    incident_id=inc_id,
                    intervention_type="ISOLATE_HOST",
                    parameter=entry_point,
                    policy_name=f"Zero-Trust Policy: Quarantine Entry Host {entry_point}"
                )
                simulations.append(sim)

        # Calculate average resilience across simulated policies
        avg_dri = (
            sum(s["defensive_resilience_index"] for s in simulations) / len(simulations)
            if simulations else 0.0
        )
        spof_count = sum(1 for s in simulations if s["single_point_of_failure"])

        results_package = {
            "version": "1.0",
            "generator": "EviGraph Counterfactual Resilience Simulator",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_incidents_simulated": len(self.incident_dags),
            "total_counterfactual_scenarios": len(simulations),
            "average_defensive_resilience_index": round(avg_dri, 4),
            "discovered_single_points_of_failure": spof_count,
            "simulations": simulations
        }

        return results_package

    def format_simulation_report_markdown(self, results_package: Dict[str, Any]) -> str:
        """Formats the simulation results into an architectural resilience report."""
        pkg = results_package
        sims = pkg["simulations"]

        lines = [
            "# EviGraph Counterfactual Resilience & Threat Modeling Report",
            "",
            "> **Proactive Defense Modeling:** Simulates counterfactual security policy interventions on Causal Provenance DAGs to quantify Defensive Resilience and uncover Single Points of Failure (SPOF).",
            "",
            "---",
            "",
            "## 1. Executive Resilience Summary",
            "",
            f"- **Simulation Timestamp:** `{pkg['generated_at']}`",
            f"- **Total Scenarios Evaluated:** `{pkg['total_counterfactual_scenarios']}`",
            f"- **Average Defensive Resilience Index (DRI):** **{pkg['average_defensive_resilience_index']*100:.2f}%**",
            f"- **Single Points of Failure (SPOF) Identified:** `{pkg['discovered_single_points_of_failure']}`",
            "",
            "### Counterfactual Policy Performance Matrix",
            "",
            "| Incident | Evaluated Policy Name | Intervention | Parameter | Baseline Sev | Residual Sev | DRI Score | Attack Extinguished? | SPOF? |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
        ]

        for s in sims:
            inc = s["incident_id"]
            p_name = s["policy_name"]
            itype = s["intervention_type"]
            param = str(s["parameter"])
            b_sev = f"{s['baseline_severity']:.1f}"
            r_sev = f"{s['residual_severity']:.1f}"
            dri = f"{s['defensive_resilience_index']*100:.1f}%"
            ext = "**YES**" if s["attack_extinguished"] else "No"
            spof = "**CRITICAL CHOKEPOINT**" if s["single_point_of_failure"] else "Redundant Path"

            lines.append(f"| `{inc}` | {p_name} | `{itype}` | `{param}` | {b_sev} | {r_sev} | **{dri}** | {ext} | {spof} |")

        lines.extend([
            "",
            "---",
            "",
            "## 2. Key Architectural Recommendations & Choke Points",
            ""
        ])

        spof_sims = [s for s in sims if s["single_point_of_failure"]]
        if spof_sims:
            lines.append("### Highest Leverage Defensive Controls (100% Extinction)")
            for sp in spof_sims[:5]:
                lines.append(
                    f"- **{sp['policy_name']}** ({sp['incident_id']}): Applying `{sp['intervention_type']}` on `{sp['parameter']}` "
                    f"completely eliminates {sp['baseline_steps_count']} attack progression steps, achieving a Defensive Resilience Index of **{sp['defensive_resilience_index']*100:.1f}%**."
                )
        else:
            lines.append("No single control extinguished the attack completely; layered defense-in-depth is required across perimeter and internal segmentation.")

        lines.extend([
            "",
            "---",
            "",
            "## 3. Mathematical Methodology",
            "",
            "- **Graph Perturbation:** For each policy rule $P$, edges matching the condition are pruned from $G_{\\text{causal}}$.",
            "- **Topological Dynamic Programming:** The primary attack chain is re-derived over remaining causal paths.",
            "- **Defensive Resilience Index (DRI):**",
            "  $$\\text{DRI} = 1.0 - \\frac{\\text{Severity}(G_{\\text{perturbed}})}{\\text{Severity}(G_{\\text{baseline}})}$$",
            "  where $\\text{Severity} = \\sum_{s} \\text{RiskScore}(s) \\times \\text{StageRank}(s)$."
        ])

        return "\n".join(lines)

    def run(
        self,
        output_results_path: Optional[Path] = None,
        output_report_path: Optional[Path] = None
    ) -> Tuple[Path, Path]:
        """Executes the simulation suite and writes artifacts."""
        print("=" * 65)
        print("   EVIGRAPH: COUNTERFACTUAL WHAT-IF RESILIENCE SIMULATOR (USP)")
        print("   Topological Perturbation & Defensive Resilience Index (DRI)")
        print("=" * 65)

        results = self.run_comprehensive_simulation_suite()
        n_scenarios = results["total_counterfactual_scenarios"]
        avg_dri = results["average_defensive_resilience_index"]

        print(f"\n[ResilienceSimulator] Simulated {n_scenarios} counterfactual defense policies")
        print(f"[ResilienceSimulator] Average Defensive Resilience Index (DRI): {avg_dri * 100:.2f}%")
        print(f"[ResilienceSimulator] Critical Defense Chokepoints (SPOF): {results['discovered_single_points_of_failure']}")

        # Save JSON results
        j_path = Path(output_results_path or (OUTPUTS_DIR / "counterfactual_simulation_results.json"))
        j_path.parent.mkdir(parents=True, exist_ok=True)
        with open(j_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"[ResilienceSimulator] Results JSON saved to: {j_path}")

        # Save Markdown Report
        md_text = self.format_simulation_report_markdown(results)
        md_path = Path(output_report_path or (OUTPUTS_DIR / "resilience_simulation_report.md"))
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_text)
        print(f"[ResilienceSimulator] Architectural report saved to: {md_path}")

        return j_path, md_path

if __name__ == "__main__":
    sim = CounterfactualResilienceSimulator()
    sim.run()
