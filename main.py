"""
EviGraph Member 2 Pipeline Runner: Detection & Graph Engine
Executes End-to-End:
1. Data Loading & Leak-free Temporal Split
2. XGBoost Baseline Training OR PyG Edge-GraphSAGE (CUDA-Accelerated / CPU)
3. Platt Risk Probability Calibration
4. Host-Communication Graph Construction
5. Inverted Host Index Alert Correlation & Incident Clustering
6. Member 3 JSON Case Bundle Export (outputs/incident_cases.json)
"""

import sys
from pathlib import Path
import json
from typing import Optional
import pandas as pd
import numpy as np
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score, average_precision_score

from src.config import SAMPLES_DATA_DIR, OUTPUTS_DIR, MODELS_DIR
from src.data_loader import FlowDataLoader
from src.baseline_detector import BaselineDetector
try:
    from src.gnn_detector import GNNDetector
    _gnn_import_error = None
except ImportError as e:  # torch / torch_geometric are optional
    GNNDetector = None
    _gnn_import_error = str(e)
try:
    from src.detectors.autoencoder_detector import AutoencoderDetector
except ImportError:
    AutoencoderDetector = None
from src.detectors.hist_gb_detector import HistGBDetector
try:
    from src.detectors.ensemble_fuser import EnsembleFuser
except ImportError:
    EnsembleFuser = None
from src.graph_engine import HostGraphEngine
from src.incident_cluster import IncidentClusterEngine

def run_pipeline(
    data_path: Optional[Path] = None, 
    max_rows: Optional[int] = None, 
    raw_df: Optional[pd.DataFrame] = None,
    model_type: str = "xgb",
    run_agent: bool = False,
    load_checkpoint: bool = False
):
    print("=" * 60)
    print("   EVIGRAPH: MEMBER 2 (DETECTION & GRAPH ENGINE)")
    print(f"   Architecture: {model_type.upper()}")
    print("=" * 60)
    
    # 1. Ingestion & Temporal Split
    loader = FlowDataLoader()
    if raw_df is None:
        raw_df = loader.load_dataset(data_path, max_rows=max_rows)
        
    X_train, y_train, meta_train, X_val, y_val, meta_val, X_test, y_test, meta_test = loader.prepare_temporal_split(
        raw_df, train_ratio=0.60, val_ratio=0.20, per_class=False
    )
    
    # 2. Train or Load Detector (Ensemble, XGBoost, Autoencoder, HistGB, or GNN)
    if model_type == "ensemble":
        if EnsembleFuser is None:
            raise ImportError("Ensemble detector could not be imported.")
        detector = EnsembleFuser(model_name="ensemble_fuser")
        if load_checkpoint:
            detector.load()
        else:
            print("\n--- Training Tri-Pillar Multi-Model Defense-in-Depth Ensemble ---")
            detector.train(X_train, y_train, X_val, y_val)
            detector.save()
        scored_test_df = detector.score_flows(X_test, meta_test)
    elif model_type == "autoencoder":
        if AutoencoderDetector is None:
            raise ImportError("Autoencoder detector could not be imported.")
        detector = AutoencoderDetector(model_name="autoencoder_detector")
        if load_checkpoint:
            detector.load()
        else:
            print("\n--- Training Unsupervised PyTorch Autoencoder Zero-Day Detector ---")
            detector.train(X_train, y_train, X_val, y_val, epochs=15)
            detector.save()
        scored_test_df = detector.score_flows(X_test, meta_test)
    elif model_type == "histgb":
        detector = HistGBDetector(model_name="hist_gb_detector")
        if load_checkpoint:
            detector.load()
        else:
            print("\n--- Training Scikit-Learn Native HistGradientBoosting Detector ---")
            detector.train(X_train, y_train, X_val, y_val)
            detector.save()
        scored_test_df = detector.score_flows(X_test, meta_test)
    elif model_type == "gnn":
        if GNNDetector is None:
            raise ImportError(
                f"Cannot run GNN detector because required dependencies could not be imported: {_gnn_import_error}. "
                f"Please ensure 'torch' and 'torch_geometric' are installed."
            )
        detector = GNNDetector(model_name="gnn_edge_sage")
        migrated_path = MODELS_DIR / "gnn_edge_sage.migrated-legacy-v2.pt"
        default_path = MODELS_DIR / "gnn_edge_sage.pt"
        checkpoint_path = migrated_path if migrated_path.is_file() else default_path
        if load_checkpoint:
            if not checkpoint_path.exists():
                raise FileNotFoundError(
                    f"GNN checkpoint not found at {checkpoint_path}. Train the model first by running without --load-checkpoint."
                )
            print(f"\n--- Loading PyTorch Geometric Edge-GraphSAGE Detector Checkpoint ---")
            detector.load(checkpoint_path)
        else:
            print("\n--- Training PyTorch Geometric Edge-GraphSAGE Detector ---")
            detector.train(X_train, y_train, meta_train, X_val, y_val, meta_val, epochs=25)
            detector.save(checkpoint_path)
        if detector.migration_metadata:
            print("[GNN Detector] Notice: Migrated legacy checkpoint used; temporal isolation unverified.")
        else:
            detector.validate_inference_split(meta_test)
        scored_test_df = detector.score_flows(X_test, meta_test)
    else:
        detector = BaselineDetector(model_name="xgboost_baseline")
        if load_checkpoint:
            detector.load()
        else:
            print("\n--- Training Multi-Class XGBoost Baseline Detector ---")
            detector.train(X_train, y_train, X_val, y_val)
            detector.save()
        scored_test_df = detector.score_flows(X_test, meta_test)
    
    # 3. Score Test Flows & Flag Alerts
    print("\n--- Scoring Network Flows ---")
    alerts_df = scored_test_df[scored_test_df["is_alert"] == True].copy()
    print(f"Total Test Flows: {len(scored_test_df)} | Flagged Alerts: {len(alerts_df)}")
    
    # Evaluate Held-Out Test Set (PRD Sec 8.1 / TRD Sec 6.1)
    if "label" in meta_test.columns:
        print("\n--- Held-Out Test Set Evaluation ---")
        y_true_binary = (meta_test["label"] != "BENIGN").astype(int)
        y_pred_binary = scored_test_df["is_alert"].astype(int)
        p, r, f1, _ = precision_recall_fscore_support(y_true_binary, y_pred_binary, average="binary", zero_division=0)
        print(f"Detection Results (Threshold = {detector.optimal_threshold}):")
        print(f"   * Precision : {p * 100:.2f}%")
        print(f"   * Recall    : {r * 100:.2f}%")
        print(f"   * F1-Score  : {f1:.4f}")
        if len(np.unique(y_true_binary)) > 1:
            try:
                pr_auc = average_precision_score(y_true_binary, scored_test_df["risk_score"])
                roc_auc = roc_auc_score(y_true_binary, scored_test_df["risk_score"])
                print(f"   * PR-AUC    : {pr_auc:.4f}")
                print(f"   * ROC-AUC   : {roc_auc:.4f}")
            except Exception:
                pass
    
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
    
    # 6.5 Cryptographic Merkle Chain-of-Custody Certification (Milestone 1 USP)
    print("\n--- Constructing Cryptographic Merkle Evidence Ledger ---")
    from src.integrity.merkle_engine import MerkleEvidenceEngine
    merkle_engine = MerkleEvidenceEngine()
    root_hash = merkle_engine.build_tree(scored_test_df)
    merkle_engine.enrich_incident_case_package(output_file)
    cert_file = merkle_engine.export_forensic_certificate(incident_cases_path=output_file)
    print(f"[MerkleEngine] Certified Session Merkle Root: {root_hash}")
    
    # 6.6 Temporal Causal Provenance DAG & Attack FSM (Milestone 2 USP)
    print("\n--- Constructing Temporal Causal Provenance DAGs & MITRE FSM ---")
    from src.causal_provenance import CausalProvenanceEngine
    causal_engine = CausalProvenanceEngine()
    causal_engine.enrich_incident_case_package(output_file)

    # 7. Member 3: Downstream Forensic Reasoning & LLM Agent (RAG)
    if run_agent:
        print("\n" + "=" * 60)
        print("   INVOKING MEMBER 3: FORENSIC AGENT & CITATION VALIDATOR")
        print("=" * 60)
        from src.agent.forensic_agent import ForensicAgent
        agent = ForensicAgent(incident_cases_path=output_file)
        agent.run()

        # 8. Autonomous Surgical Containment & Blast-Radius Engine (USP)
        print("\n" + "=" * 60)
        print("   INVOKING SURGICAL CONTAINMENT & BLAST-RADIUS ENGINE (USP)")
        print("=" * 60)
        from src.mitigation.countermeasure_engine import CountermeasureEngine
        mitigation_engine = CountermeasureEngine(incident_cases_path=output_file)
        mitigation_engine.run()

        # 9. Privacy-Preserving Redacted Proof Engine (USP)
        print("\n" + "=" * 60)
        print("   INVOKING PRIVACY-PRESERVING REDACTED PROOF ENGINE (USP)")
        print("=" * 60)
        from src.integrity.privacy_proofs import PrivacyPreservingProofEngine
        privacy_engine = PrivacyPreservingProofEngine(incident_cases_path=output_file)
        privacy_engine.run()

        # 10. Counterfactual "What-If" Resilience Simulator (USP)
        print("\n" + "=" * 60)
        print("   INVOKING COUNTERFACTUAL WHAT-IF RESILIENCE SIMULATOR (USP)")
        print("=" * 60)
        from src.simulation.counterfactual_engine import CounterfactualResilienceSimulator
        sim_engine = CounterfactualResilienceSimulator(incident_cases_path=output_file)
        sim_engine.run()

    return output_file

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="EviGraph Member 2 Pipeline Runner")
    parser.add_argument("--data", type=str, default=None, help="Path to CSV or Parquet flow dataset, or 'all'")
    parser.add_argument("--model", type=str, default="ensemble", choices=["ensemble", "xgb", "autoencoder", "histgb", "gnn"], help="Detector model architecture: 'ensemble', 'xgb', 'autoencoder', 'histgb', or 'gnn'")
    parser.add_argument("--max-rows", type=int, default=None, help="Max rows to process (useful for rapid testing)")
    parser.add_argument("--load-checkpoint", action="store_true", help="Load existing model checkpoint from models/ instead of retraining")
    parser.add_argument("--agent", action="store_true", help="Automatically trigger Member 3 Forensic Agent, Courtroom Auditor, Containment, Privacy, and Simulator after detection")
    args = parser.parse_args()

    if args.data == "all":
        loader = FlowDataLoader()
        sample_size = args.max_rows  # None loads the complete 2.64M enterprise dataset
        raw_df = loader.load_combined_dataset(max_per_attack=sample_size, benign_per_file=sample_size)
        run_pipeline(raw_df=raw_df, model_type=args.model, run_agent=args.agent, load_checkpoint=args.load_checkpoint)
    elif args.data in ["processed", "preprocessed"]:
        from src.config import PROCESSED_DATA_DIR
        full_proc_path = PROCESSED_DATA_DIR / "benchmark_full_340k.parquet"
        print(f"[Main] Loading archived preprocessed benchmark dataset from: {full_proc_path}")
        raw_df = pd.read_parquet(full_proc_path)
        if args.max_rows and len(raw_df) > args.max_rows:
            sampled_slices = []
            for _, grp in raw_df.groupby("label"):
                n_take = max(20, int(args.max_rows * len(grp) / len(raw_df)))
                sampled_slices.append(grp.head(n_take))
            raw_df = pd.concat(sampled_slices, ignore_index=True)
        run_pipeline(raw_df=raw_df, model_type=args.model, run_agent=args.agent, load_checkpoint=args.load_checkpoint)
    elif args.data in ["new_benchmark", "new", "new_benchmarks"] or (args.data and Path(args.data).is_dir()):
        from src.config import BASE_DIR
        target_dir = Path(args.data) if (args.data and Path(args.data).is_dir()) else (BASE_DIR / "data" / "new_benchmark")
        benchmark_files = sorted(list(target_dir.glob("*.parquet")) + list(target_dir.glob("*.csv")))
        print(f"[Main] Loading external new benchmark datasets from: {target_dir}")
        for bf in benchmark_files:
            print(f"   -> {bf.name}")
        loader = FlowDataLoader()
        raw_df = loader.load_combined_dataset(file_paths=benchmark_files, max_per_attack=args.max_rows, benign_per_file=args.max_rows)
        run_pipeline(raw_df=raw_df, model_type=args.model, run_agent=args.agent, load_checkpoint=args.load_checkpoint)
    elif args.data:
        target_file = Path(args.data)
        run_pipeline(target_file, max_rows=args.max_rows, model_type=args.model, run_agent=args.agent, load_checkpoint=args.load_checkpoint)
    else:
        target_file = SAMPLES_DATA_DIR / "sample_cicids2017_flows.csv"
        if not target_file.exists():
            print(f"Sample file not found at {target_file}. Generating sample dataset first...")
            from src.generate_sample_data import generate_flows
            df = generate_flows()
            target_file.parent.mkdir(parents=True, exist_ok=True)
            df.to_csv(target_file, index=False)
        run_pipeline(target_file, max_rows=args.max_rows, model_type=args.model, run_agent=args.agent, load_checkpoint=args.load_checkpoint)
