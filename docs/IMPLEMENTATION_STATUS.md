# Data Pipeline and Detector Audit Status

Audit date: 2026-10-25

## Scope and outcome

Compared the current data ingestion, normalization, feature extraction, detector
and evaluation code with `README.md`, `PRD.md`,
[`feature_definitions.md`](./feature_definitions.md), and
[`data_pipeline_architecture.md`](./data_pipeline_architecture.md).

The ingestion routes for CICIDS CSV/Parquet, Zeek logs, and PCAP have focused
parser tests. The detection code contains XGBoost, HistGradientBoosting,
autoencoder, GraphSAGE, and ensemble implementations. The main data split
policy did not match the documented leakage controls, and three PCAP standard
deviations did not match the feature specification. Both discrepancies are
fixed below. This phase also found parser and canonicalization fallbacks that
could invent IP addresses or timestamps, plus a Parquet writer that skipped
schema validation.

## Completed fixes

- **Global temporal splits:** `FlowDataLoader.prepare_temporal_split()` now
  defaults to a single global chronological partition instead of independent
  per-class partitions. The benchmark split exporter uses the same shared
  splitter. Equal timestamps stay in one partition; invalid timestamps and
  insufficient distinct time boundaries fail explicitly. Per-class splitting
  remains available only as an explicit compatibility option.
- **PCAP standard deviations:** Forward/backward packet-length standard
  deviations and flow-IAT standard deviation now use the sample formula
  (`ddof=1`) specified in `feature_definitions.md`; one-or-zero observations
  still return zero.
- Updated the README and data-pipeline architecture documentation to state the
  global split policy.
- **Required identity/time metadata:** Canonicalization now requires real
  `src_ip`/`dst_ip` fields and a valid `ts_start` or `timestamp`; it validates IP
  syntax and rejects missing, malformed, or unparseable values. Fabricated IP
  and fixed-date fallbacks were removed.
- **Parser and flow-ID boundaries:** CICIDS and Zeek ingestion now reject
  missing source metadata fields and invalid timestamps/IPs instead of
  assigning placeholder addresses or epoch timestamps. Flow-ID generation
  also fails when required IP or time metadata is absent or invalid.
- **Storage boundary:** `ParquetStorageEngine.write_parquet()` now validates
  canonicalized rows before writing. Invalid inputs fail before a Parquet file
  or manifest is created. The valid Parquet test fixture now supplies its
  `evidence_id` as required by the canonical schema.

## Validation

Passed:

```text
python -m pytest tests/test_temporal_splits.py tests/data/test_pcap.py tests/data/test_parsers.py tests/test_gnn_detector.py::test_pipeline_temporal_split_has_disjoint_global_time_ranges -q
15 passed

python -m py_compile src/data_loader.py src/export_training_data.py data/parsers/pcap.py
passed

python -m pytest tests/data/test_schema.py tests/data/test_parsers.py tests/data/test_zeek.py tests/data/test_storage_duckdb.py tests/data/test_flow_id.py tests/data/test_pcap.py tests/data/test_host.py tests/data/test_cli.py tests/data/test_determinism.py -q
63 passed, 1 skipped (the optional 10k-row determinism fixture is absent)

python -m py_compile data/schema.py data/storage.py data/flow_id.py data/parsers/cicids.py data/parsers/zeek.py
passed

python -m pytest tests/test_baseline_detector.py -q
4 passed

git diff --check
passed
```

The audit did not rerun the previously passed Auto detector or frontend suites.
No stored `benchmark_*_flows.parquet` split artifacts were present under
`data/processed/`, so regenerated split files were not independently checked.

## Remaining findings, ranked

1. **Detector test coverage is uneven.** The available targeted tests cover
   baseline scoring behavior and GraphSAGE, but there are no direct
   `HistGBDetector` or `EnsembleFuser` tests. Add small deterministic
   train/score/save/load checks, including thresholding and output schema.
2. **Legacy per-class partitioning remains callable.** It is documented as an
   opt-in compatibility mode because it does not ensure disjoint global time
   ranges. Avoid using it for benchmark certification or reported evaluation.

## Best next task

Add direct detector coverage for HistGradientBoosting and ensemble checkpoint
round-trips, and distinguish implementation status from held-out evaluation
evidence in the detector documentation.


## Handover Known Test Failures Resolution (Member 4 Handover)

Date: 2026-10-25

Resolved the known test failures specified in `EviGraph_Handover_Member4.pdf`:

1. **`tests/test_real_classes.py` signature update**:
   - `_stage_query(attack_class, incident, stage)` in `src/agent/agent.py` requires three positional arguments.
   - Updated `test_real_classes.py` with representative incident and stage fixtures (`DUMMY_INCIDENT`, `DUMMY_STAGE`).
   - Added `_ollama_available()` check to guard ATT&CK embedding retrieval when the local Ollama daemon is offline, cleanly skipping tests without raising `TypeError` or socket connection failures.

2. **Investigation pipeline slow Ollama dependency (`tests/test_investigation_pipeline.py`)**:
   - Marked `test_report_validation_and_job_api_can_retrieve_cited_flow` with `@pytest.mark.slow` (registered in `pyproject.toml`).
   - Deterministically mocked `ollama.chat` and `ollama.embed` via `monkeypatch` to simulate offline graceful degradation immediately, reducing test runtime while preserving all assertions on real reporting, Merkle integrity, and evidence retrieval.

3. **Zeek parser test `None` vs pandas `NaN` assertions (`tests/data/test_zeek.py`)**:
   - Updated `test_zeek_conn_tsv_and_null_handling` and `test_zeek_conn_json_and_malformed_tolerance` on `conn_state` assertions to accept either `None` or `pd.isna(r2["conn_state"])` conforming to pandas null column semantics across backends.

### Verification

```text
pytest tests/test_real_classes.py tests/test_investigation_pipeline.py::test_report_validation_and_job_api_can_retrieve_cited_flow tests/data/test_zeek.py
11 passed, 10 skipped, 3 warnings in 17.52s
```


## Environment-Dependent Test Limitation: Async Pipeline Test

Date: 2026-10-25

- **Target**: `tests/test_investigation_pipeline.py::test_upload_validation_and_nonblocking_job_progress`
- **Limitation**: `TestClient` hangs during initialization before any HTTP request, apparently due to Windows sandbox loopback socket restrictions.
- **Test Fix**: The test-only upload request header mismatch was corrected by adding `"X-Detector": "xgb"` to match the mock assertion.
- **Status**: Verification outside this sandbox remains pending.


## Handover Verification & Test Suite Hardening

Date: 2026-10-25

1. **Legacy Sample Fixture Restoration (`data/sample/sample_flows.csv`)**:
   - Regenerated deterministic 303-flow test fixture from `src/agent/make_sample_data.py` logic matching all 103 alerts in `data/sample/sample_incident_cases.json`.
   - Added narrow `.gitignore` whitelist exception `!data/sample/*.csv`.
   - Verified 37/37 passing tests across `tests/test_api.py`, `tests/test_attack_investigation.py`, and `tests/test_report.py`.

2. **ATT&CK RAG Offline Guard (`tests/test_attack_rag.py`)**:
   - Added cached `_ollama_available()` check.
   - Exact dictionary lookup tests (`test_exact_lookup`, `test_unknown_id_is_rejected`) execute offline without daemons.
   - Guarded the 5 semantic search tests with `@requires_ollama` so they cleanly skip when the local Ollama embedding daemon is offline (2 passed, 5 skipped).

3. **Counterfactual Simulation Causal-Chain Test (`tests/test_counterfactual_engine.py`)**:
   - Updated `test_counterfactual_entry_quarantine_removes_host_from_residual_chain` to dynamically extract the entry host from the active causal chain (`primary_chain[0]["source"]`).
   - Verified all 4 tests pass (`4 passed in 24.32s`).

4. **Deferred Items**:
   - **Parked Async Pipeline Test**: `tests/test_investigation_pipeline.py::test_upload_validation_and_nonblocking_job_progress` parked due to Windows sandbox loopback TCP socket restrictions blocking `TestClient` initialization. Header fix `"X-Detector": "xgb"` applied; verification outside sandbox pending.
   - **160-Claim / MITRE Mapping Investigation**: Evaluation of the 160-claim dataset and deep semantic mapping against live ATT&CK vectors deferred, as it requires the live Ollama daemon and held-out benchmark data generation. Core agent retrieval degradation and fallback paths are verified.
