"""
EviGraph Member 2 Pipeline Runner: Detection & Graph Engine
Executes End-to-End:
1. Data Loading & Leak-free Temporal Split
2. XGBoost Baseline Training + Calibrated Risk Scoring
3. Host-Communication Graph Construction
4. Alert Correlation & Incident Clustering
5. Agent JSON Bundle Export (incidents, scores, subgraphs, evidence IDs)
"""

import sys
from pathlib import Path
import json

from src.config import SAMPLES_DATA_DIR, OUTPUTS_DIR
from src.data_loader import FlowDataLoader
from src.baseline_detector import BaselineDetector
from src.graph_engine import HostGraphEngine
from src.incident_cluster import IncidentClusterEngine

def run_pipeline(data_path: Path, max_rows: int = None):
    print("=" * 60)
    print("   EVIGRAPH: MEMBER 2 (DETECTION & GRAPH ENGINE)")
    print("=" * 60)
    
    # 1. Ingestion & Temporal Split
    loader = FlowDataLoader()
    raw_df = loader.load_dataset(data_path, max_rows=max_rows)
    X_train, y_train, meta_train, X_val, y_val, meta_val, X_test, y_test, meta_test = loader.prepare_temporal_split(
        raw_df, train_ratio=0.50, val_ratio=0.20
    )
    
    # 2. Train Baseline Detector (XGBoost)
    detector = BaselineDetector(model_name="xgboost_baseline")
    detector.train(X_train, y_train, X_val, y_val)
    detector.save()
    
    # 3. Score Test Flows & Flag Alerts
    print("\n--- Scoring Network Flows ---")
    scored_test_df = detector.score_flows(X_test, meta_test)
    alerts_df = scored_test_df[scored_test_df["is_alert"] == True].copy()
    print(f"Total Test Flows: {len(scored_test_df)} | Flagged Alerts: {len(alerts_df)}")
    
    # 4. Host Graph Construction
    print("\n--- Building Host Communication Graph ---")
    graph_engine = HostGraphEngine()
    graph_engine.build_graph_from_flows(scored_test_df)
    
    # 5. Alert Correlation & Incident Clustering
    print("\n--- Correlating Alerts & Building Incidents ---")
    incident_engine = IncidentClusterEngine(time_threshold_secs=300)
    incidents = incident_engine.correlate_alerts(alerts_df)
    
    print(f"\n[Summary] Discovered {len(incidents)} Incidents:")
    for inc in incidents:
        print(f"  * {inc['incident_id']} | Score: {inc['incident_score']} | "
              f"Entry: {inc['suspected_entry_point']} | "
              f"Attacks: {', '.join(inc['attack_classes'])} | "
              f"Alerts: {inc['total_alerts']} | "
              f"Hosts: {len(inc['affected_hosts'])}")
        
    # 6. Export Case Bundle for Member 3 (Agent)
    output_file = incident_engine.export_agent_case_bundle(incidents, graph_engine)
    print(f"\n[DONE] Pipeline complete! Hand-off file generated at:\n       {output_file}")
    
    return output_file

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="EviGraph Member 2 Pipeline Runner")
    parser.add_argument("--data", type=str, default=None, help="Path to CSV or Parquet flow dataset")
    parser.add_argument("--max-rows", type=int, default=None, help="Max rows to process (useful for rapid testing)")
    args = parser.parse_args()

    if args.data:
        target_file = Path(args.data)
    else:
        target_file = SAMPLES_DATA_DIR / "sample_cicids2017_flows.csv"
        if not target_file.exists():
            print(f"Sample file not found at {target_file}. Generating sample dataset first...")
            from src.generate_sample_data import generate_flows
            df = generate_flows()
            target_file.parent.mkdir(parents=True, exist_ok=True)
            df.to_csv(target_file, index=False)
            
    run_pipeline(target_file, max_rows=args.max_rows)
