# EviGraph Evaluation Protocol

This document defines what EviGraph may and may not claim from a model run. It
is intentionally stricter than the default pipeline, which is optimized for a
fast end-to-end demo on CICIDS2017-derived fixtures.

## 1. Claims allowed by each protocol

| Protocol | What it can support | What it cannot support |
|----------|--------------------|------------------------|
| Per-class temporal split (current default) | "The model separates the classes present in this benchmark." | "The model detects unseen attack families / zero-days." |
| Global temporal split | "The model generalizes forward in time for classes represented in training." | "The model detects families absent from training." |
| Leave-one-family-out (LOFO) | "The model generalizes to a held-out attack family." | "The model generalizes to arbitrary real-world traffic." |
| Group/host holdout | "The model does not memorize a host or campaign." | Anything about unseen protocols or sensors. |
| External dataset | "The model transfers to a different capture." | "The model is universally calibrated." |

The current `FlowDataLoader.prepare_temporal_split(per_class=True)` gives every
attack family its own chronological train/val/test slices. That preserves class
representation, but it also means **every test class was seen during training**.
It is a detection benchmark, not zero-day evidence. The loader now prints an
explicit warning when this mode is used.

## 2. Required splits

### 2.1 Primary benchmark (reported with every release)

1. Sort all flows by timestamp.
2. Cut globally at 60% / 20% / 20% by time.
3. Fit all preprocessing (imputation, scaling, feature selection) on train only.
4. Report the test window and the label distribution in that window.
5. Report any class that appears in validation/test but not in training.

### 2.2 LOFO (required for any zero-day claim)

For each attack family `F` in the taxonomy:

1. Remove all `F` flows from train and validation.
2. Train on the remaining families.
3. Test on the held-out `F` flows plus a time-matched benign sample.
4. Report per-family recall, false-positive rate, and PR-AUC.
5. Report the macro average across families and the worst family.

A single aggregate number is not acceptable; zero-day performance is
family-dependent.

### 2.3 Group/host holdout (required for graph and incident claims)

Split by source host or campaign so that no host/campaign appears in both train
and test. Report the percentage of test hosts seen in training. If it is not
zero, the split is not group-clean.

## 3. Leakage controls

- **Identity leakage:** `flow_id`, IPs, MACs, ports, timestamps, and labels are
  never model features. This is enforced by `METADATA_COLS`.
- **Preprocessing leakage:** fit imputers/scalers/encoders on train only. The
  current `fillna(0)` is a placeholder; median/iterative imputation plus a
  missingness indicator is preferred.
- **Duplicate leakage:** exact duplicates are removed in `clean_dataset`. Before
  reporting, additionally check near-duplicates (same 5-tuple within a short
  window) and report the overlap rate. Deduplicate **within train only** so that
  repeated attack bursts are not silently erased from the test set.
- **Threshold leakage:** tune the alert threshold on a split that is disjoint
  from early stopping, calibration, and meta-learner fitting. The hardened
  `BaselineDetector` and `EnsembleFuser` now do this; keep it that way.
- **Meta-learner leakage:** the stacking model must only see base-model scores
  on rows the base models did not train on. Do not fit the meta-learner on the
  same validation rows used for early stopping.

## 4. Metrics to report

For every run, report at minimum:

- Precision, recall, F1, PR-AUC, ROC-AUC (binary "attack vs benign").
- Per-class recall and support for every attack family.
- False-positive rate at a fixed analyst budget (e.g., alerts per 10k flows or
  per day), not only the max-F1 threshold.
- Calibration: reliability diagram, expected calibration error (ECE), Brier
  score.
- Uncertainty: bootstrap 95% confidence intervals over flows **and** over
  hosts/campaigns (cluster bootstrap).
- Alert volume: number of alerts per hour/day and the incident count produced
  downstream, since incident clustering can amplify or suppress flow-level
  errors.
- Latency: p50/p95 scoring latency per flow and per incident bundle.

A single "100% F1" line on a synthetic fixture is a smoke-test result, not an
evaluation result.

## 5. Reproducibility requirements

Every reported number must be accompanied by:

- `outputs/run_manifest.json` (dataset hash, git commit, library versions,
  model artifact hashes, output hashes);
- the split protocol name and seed;
- the exact dataset version and preprocessing version;
- a fixed threshold policy and calibration method;
- the code commit used for the run.

If the working tree is dirty, the manifest says so. Treat dirty-tree results as
provisional.

## 6. Reporting template

```
Dataset:            <name, version, sha256>
Split:              <per-class temporal | global temporal | LOFO(F) | group>
Train/Val/Test:     <rows, date ranges>
Features:           <count, fit-on-train-only = yes/no>
Model:              <architecture, artifact sha256>
Threshold policy:   <split, target metric, value>
Metrics:            precision / recall / F1 / PR-AUC / ROC-AUC
Per-class recall:   <table>
Calibration:        ECE / Brier
Uncertainty:        <bootstrap CI method and values>
Alert budget:       <FPR at N alerts/day>
Manifest:           outputs/run_manifest.json
Commit:             <git commit, dirty?>
```

## 7. Current status

Implemented:

- Per-class temporal split with an explicit "not zero-day evidence" warning.
- Disjoint early-stop / calibration / threshold / meta-learner slices.
- Hash-based run manifest with provenance warnings.

Not implemented yet:

- Global temporal split as the primary reported protocol.
- LOFO and group/host holdout runners.
- Near-duplicate detection and overlap reporting.
- Calibration/uncertainty reporting in the pipeline output.
- External-dataset evaluation and drift monitoring.

Until those exist, the honest claim is: *"On the included benchmark, using the
stated split, the pipeline achieves X. Generalization to unseen families is not
established."*
