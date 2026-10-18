"""
EviGraph Member 3 Test Split Exporter
Scores benchmark_test_flows.parquet and exports incidents and alerts
in the exact schema requested by the LLM Forensic Agent team.
"""

import json
import pandas as pd
from pathlib import Path
from sklearn.metrics import classification_report

from src.data_loader import FlowDataLoader
from src.baseline_detector import BaselineDetector
from src.graph_engine import HostGraphEngine
from src.incident_cluster import IncidentClusterEngine
from src.config import OUTPUTS_DIR

def export_member3_test_data():
    print("=" * 65)
    print("   EVIGRAPH: EXPORTING DETECTOR OUTPUT FOR MEMBER 3 (TEST SPLIT)")
    print("=" * 65)

    loader = FlowDataLoader()
    X_train, y_train, meta_train, X_val, y_val, meta_val, X_test, y_test, meta_test = loader.load_processed_splits("benchmark")

    # Train high-performance baseline on 204k flows
    detector = BaselineDetector(model_name="xgboost_benchmark")
    detector.train(X_train, y_train, X_val, y_val)
    detector.save()

    # Score held-out 68,000 test flows
    scored_test_df = detector.score_flows(X_test, meta_test)

    # Classification report
    print("\n--- Held-Out Test Set Performance per Class ---")
    report = classification_report(y_test, scored_test_df["predicted_class"], output_dict=True, zero_division=0)
    print(classification_report(y_test, scored_test_df["predicted_class"], zero_division=0))

    # Graph construction & Incident clustering
    alerts_df = scored_test_df[scored_test_df["is_alert"] == True].copy()
    graph_engine = HostGraphEngine()
    graph_engine.build_graph_from_flows(scored_test_df)

    incident_engine = IncidentClusterEngine(time_threshold_secs=300)
    incidents = incident_engine.correlate_alerts(alerts_df)
    print(f"\n[IncidentEngine] Correlated alerts into {len(incidents)} distinct incident clusters.")

    # Export rich EviGraph case bundle
    case_bundle_path = incident_engine.export_agent_case_bundle(incidents, graph_engine, output_path=OUTPUTS_DIR / "benchmark_test_cases.json")

    # Format into Member 3's exact requested schema
    with open(case_bundle_path, "r", encoding="utf-8") as f:
        bundled_data = json.load(f)

    member3_incidents = []
    total_alerts_exported = 0

    for inc in bundled_data.get("incidents", []):
        i_id = inc.get("incident_id")
        sev = inc.get("incident_score")
        hosts = inc.get("affected_hosts", [])
        subgraph = inc.get("subgraph", {})

        alerts_list = []
        for idx, edge in enumerate(subgraph.get("edges", [])):
            alerts_list.append({
                "alert_id": f"alt_{i_id}_{idx+1:04d}",
                "flow_id": edge.get("edge_id"),
                "timestamp": str(edge.get("timestamp")),
                "src_ip": edge.get("source"),
                "dst_ip": edge.get("target"),
                "src_port": int(edge.get("src_port", 0)),
                "dst_port": int(edge.get("dst_port", 0)),
                "protocol": int(edge.get("protocol", 6)),
                "predicted_class": edge.get("predicted_class"),
                "risk_score": float(edge.get("risk_score", 0.9))
            })

        total_alerts_exported += len(alerts_list)
        member3_incidents.append({
            "incident_id": i_id,
            "severity_score": sev,
            "hosts": hosts,
            "total_alerts": len(alerts_list),
            "alerts": alerts_list
        })

    # Save to outputs/member3_benchmark_test_incidents.json
    out_path = OUTPUTS_DIR / "member3_benchmark_test_incidents.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"incidents": member3_incidents}, f, indent=2)

    print(f"\n[OK] Exported {len(member3_incidents)} incidents with {total_alerts_exported} alerts to:")
    print(f"     {out_path}")
    print(f"     File size: {out_path.stat().st_size:,} bytes")

    # Also save class performance metrics
    metrics_path = OUTPUTS_DIR / "model_precision_recall_per_class.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[OK] Saved precision/recall metrics to: {metrics_path}")

    return out_path, member3_incidents[0] if member3_incidents else {}

if __name__ == "__main__":
    export_member3_test_data()
