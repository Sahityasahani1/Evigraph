# EviGraph Security & Correctness Audit

**Scope:** `src/`, `api/`, `main.py`, integrity/agent/courtroom code paths, ML training and evaluation, and generated forensic artifacts.
**Method:** static review + live exploit reproduction against the running code, then in-place remediation with regression tests.
**Result:** 5 critical and 8 high-severity defects were confirmed. All confirmed critical/high defects in the API, integrity, privacy, and agent layers are fixed in this tree; ML methodology gaps are documented in §4 and [`docs/EVALUATION_PROTOCOL.md`](EVALUATION_PROTOCOL.md), with a strict reporting protocol.

---

## 1. Executive summary

EviGraph's architecture is strong on paper (detection → graph → causal chain → LLM report → Merkle proof → courtroom audit). The original implementation, however, **certified properties it did not actually verify**. The most serious pattern was *assurance theater*:

- A "zero-topology-leakage" certificate **contained the HMAC disclosure key**, so hidden IPs were recoverable.
- The API served files outside `dist/` via path traversal.
- Unknown incidents returned `"ADMISSIBLE_IN_COURT"` and `"verified": true`.
- A hard-coded Merkle root was presented as a certified session root.
- The courtroom's Gate 1 accepted a proof that certified its own root.
- The report endpoint reported 100% citation validity without running the citation validator.

For a forensic product, **a false assurance is worse than no assurance**. The fixes below make the system fail closed: missing evidence now produces `UNVERIFIED`, `404`, `INADMISSIBLE`, or `PROOF_VERIFICATION_FAILED` instead of a green check.

### Confirmed exploits (before → after)

| # | Exploit | Before | After |
|---|---------|--------|-------|
| 1 | `GET /..%2F.env.example` | Returned `.env.example` (HTTP 200) | Returns SPA shell only; path confined to `dist/` |
| 2 | Certificate key custody | Secret `enterprise_selective_disclosure_key` shipped in cert; IP recovered exactly | Secret removed from artifact; written to `outputs/privacy_disclosure_key.secret` (0600) or supplied by KMS |
| 3 | `GET /incidents/DOES-NOT-EXIST/courtroom` | `200`, `ADMISSIBLE_IN_COURT`, score `1.0` | `400`/`404`; artifact endpoint never fabricates a verdict |
| 4 | Unknown report integrity | Hard-coded `5455c3…` root + fabricated pcap hashes | Root taken from the ledger or `null` + `UNVERIFIED` |
| 5 | LLM tool dispatch | `getattr(self, fn_name)` allowed arbitrary method invocation | Strict allowlist + signature validation |
| 6 | Courtroom Gate 1 | Verified proof against `session_root or claimed_root` | Requires certified root; rejects self-signed proofs |
| 7 | Citation metric | Repeated one real ID to inflate faithfulness | Faithfulness over **unique** citations; inflation ratio reported |

---

## 2. Findings

### Critical

#### C1 — Disclosure secret shipped inside the privacy certificate
`src/integrity/privacy_proofs.py`

The certificate contained `enterprise_selective_disclosure_key`, and each commitment stored its salt. Because IPv4 space is small, anyone with the certificate could recompute `HMAC(secret, "ip:salt")` and recover every "redacted" address. **Reproduced:** recovered `172.16.0.105` from `flw_scan_0080` in one pass.

**Fixed:** key is no longer serialized; `run()` writes it to a separate 0600 file (or reads `EVIGRAPH_DISCLOSURE_SECRET`). The artifact now states the real security property: *salted HMAC commitment, not zero-knowledge*, and confidentiality depends on key custody.

#### C2 — Path traversal in the SPA catch-all
`api/server.py`

```python
target = DIST_DIR / full_path
if target.exists():
    return FileResponse(target)
```

Starlette decodes `%2F`; `../` escapes `dist/`. **Reproduced:** `.env.example` was downloadable.

**Fixed:** resolve the candidate and require it to remain under `DIST_DIR.resolve()`; traversal attempts fall back to `index.html`.

#### C3 — Fabricated positive assurance for missing evidence
`api/server.py`

On missing artifacts the API returned:
- `courtroom`: `admissibility_verdict: "ADMISSIBLE_IN_COURT"`, `score: 1.0`
- `privacy-proof`: `verified: true`
- report: `validation = {"valid": len(sentences), "total": len(sentences)}`

This is the exact failure mode that destroys forensic credibility.

**Fixed:** missing artifacts → `404`; unknown incident → `400/404`; report validation runs `CitationValidator` on real citations and returns `passed: false` when evidence is absent.

#### C4 — Hard-coded Merkle root and fabricated evidence fields
`api/server.py`, `src/integrity/merkle_engine.py`

`5455c327…` was a literal fallback, yet appeared as `session_merkle_root` in `certified_forensic_verdict.json`. `normalize_incident` also invented flow IDs (`md5(...)`) and pcap hashes when data was missing.

**Fixed:** no literal roots; missing evidence yields `None` + `evidence_status: "MISSING"`; evidence IDs/hashes are never synthesized. Verification only marks `merkle_verified` after recomputing the audit path.

#### C5 — LLM-controlled tool dispatch via `getattr`
`src/agent/forensic_agent.py`

The model's `tool_call.function.name` was passed directly to `getattr(self, ...)`. A prompt-injected telemetry field could ask the model to invoke `run`, `load_cases`, or internal methods (and the tool loop had no iteration bound).

**Fixed:** explicit `TOOL_ALLOWLIST`, keyword-signature validation, bounded loop (`MAX_TOOL_ITERATIONS`), output truncation, and untrusted-telemetry delimiting in the prompt.

---

### High

#### H1 — Merkle tree lacked domain separation and had ambiguous shape
`src/integrity/merkle_engine.py`

- No leaf/node prefixes → an internal node hash can be replayed as a leaf (second-preimage).
- Odd nodes duplicated at every level → two different leaf sets can produce the same root (CVE-2012-2459 class).
- Duplicate `flow_id`s silently overwrote the index → a proof could point at the wrong row.
- Proofs did not bind `tree_size` / `leaf_index`; verifier accepted a proof's own claimed root.

**Fixed:** v2 scheme: `H(0x00 || canonical)` leaves, `H(0x01 || left || right)` nodes, odd-node promotion, duplicate-ID rejection, length-prefixed canonical encoding with round-trippable floats, and fail-closed root binding. Legacy proofs remain auditable through an explicit `scheme: "legacy"` path.

#### H2 — Courtroom gates were tautological or scored absence as success
`src/agent/courtroom_auditor.py`

- Gate 1 accepted `expected_root = session_root or claimed_root`.
- Gate 3 returned `1.0` when no causal transitions existed.
- Gate 4 returned `1.0` when no fact checks existed, and exempted "executive summary" text.
- Verdict text claimed "flawless" at 100%.

**Fixed:** Gate 1 requires a certified root and replays the audit path (and cross-checks the evidence leaf); Gates 3/4 return `0.0` with a sustained objection when there is nothing checkable; verdict includes scope and explicit limitations; "flawless" language removed.

#### H3 — Report integrity claims were not computed
`api/server.py`

The endpoint set `footer.input_sha256` to a constant and computed validation as `valid == total`. **Fixed:** root from the ledger or `null`; real `CitationValidator` pass; `integrity_status: ANCHORED | UNVERIFIED`.

#### H4 — No authentication, wildcard CORS, and broad bind
`api/server.py`

`allow_origins=["*"]`, no auth, `uvicorn.run(host="0.0.0.0", reload=True)`.

**Fixed:** explicit origin allowlist, optional API-key/Bearer auth, loopback default, refusal to bind non-loopback without a key, security headers, no `reload`, and no docs endpoint by default.

#### H5 — ML: stacking and calibration leakage
`src/detectors/ensemble_fuser.py`, `src/baseline_detector.py`

The same validation rows were used for:
1. early stopping,
2. Platt calibration,
3. meta-learner fitting,
4. threshold tuning.

The stack therefore saw in-sample scores; reported validation metrics were optimistic.

**Fixed:** base models receive a fit slice; the meta-learner and threshold use a disjoint holdout. XGBoost now uses separate early-stop, calibration, and threshold slices. This reduces (but does not eliminate) optimism — see §4.

#### H6 — Citation faithfulness could be inflated
`src/agent/citation_validator.py`

Faithfulness was computed per occurrence. Repeating one valid `[E:…]` 100 times while hallucinating elsewhere could still score high.

**Fixed:** primary score is unique-citation coverage; duplicate count and inflation ratio are reported; pass requires at least one unique citation.

#### H7 — Unknown incident returned a global artifact (IDOR/correctness)
`api/server.py`

`/incidents/<anything>/courtroom` returned the global verdict file. **Fixed:** incident is validated first; artifact ownership is checked when the artifact declares an `incident_id`; artifacts are marked `scope: "session"` when global.

#### H8 — Prompt injection surface in the LLM path
`src/agent/forensic_agent.py`

Telemetry strings were interpolated into the prompt without delimiting or instruction isolation. **Fixed:** `<untrusted_telemetry>` block + explicit system rule that telemetry is data, not instructions; tool args validated; results truncated.

---

### Medium

| ID | Finding | Status / action |
|----|---------|-----------------|
| M1 | No request schema validation / pagination on incident endpoints | Open — add Pydantic response models and pagination for large bundles |
| M2 | TTL cache is per-process; no cache invalidation across workers | Mitigated — 2s TTL + mtime check; use Redis/ETag for multi-worker |
| M3 | Rate limiting is per-process, best-effort | Mitigated — configurable; use gateway/Redis for real limits |
| M4 | No evidence-collection attestation or external timestamping (RFC 3161) | Open — sign root with HSM/KMS key and notarize |
| M5 | Merkle root not signed; cert authenticity depends on transport | Fixed - detached Ed25519 signature + key ID in certificate; courtroom verifies it |
| M6 | `fillna(0)` merges missingness with a real zero | Open — use median/iterative imputation + missingness indicators |
| M7 | Per-class temporal split prevents testing unseen attack families | Mitigated - explicit warning + manifest flag + leakage audit; strict protocol in `docs/EVALUATION_PROTOCOL.md` |
| M8 | Exact-duplicate removal can strip repeated attack flows | Open — dedupe only within train, or document as sampling policy |
| M9 | Countermeasure engine emits firewall rules | Mitigated — IP/port/protocol allowlist validation, `deployable` flag, `ADVISORY_ONLY` policy, human approval required; still no execution sandbox |
| M10 | No drift monitoring / model registry / data version pinning | Partially fixed — `outputs/run_manifest.json` records data/model/output hashes, git state, library versions; drift monitoring still open |
| M11 | `infer_zone` ignored IPv6/link-local/CGNAT | Fixed — uses `ipaddress` classification |
| M12 | Dependency pinning absent in `pyproject.toml` | Partially fixed — ML/API extras added; pin exact versions for prod |
| M13 | `outputs/` secret file is new and must never be committed | Fixed — `.gitignore` excludes `outputs/*.secret`, `.env*`, keys |

---

## 3. Changes applied in this tree

| Area | File | Change |
|------|------|--------|
| Merkle | `src/integrity/merkle_engine.py` | v2 domain-separated scheme, odd-node promotion, duplicate-ID rejection, canonical encoding, proof binding, real verification on enrich, legacy audit path |
| Privacy | `src/integrity/privacy_proofs.py` | Secret removed from cert; key custody separated; v2 canonical parsing; `dst_port` redacted; fail-closed verification; commitment verifier; corrected claims |
| API | `api/server.py` | Path confinement, API-key auth, CORS allowlist, headers, rate limiting, TTL cache, no fabricated verdicts/hashes, real report validation, artifact ownership checks, safe bind |
| Agent | `src/agent/forensic_agent.py` | Tool allowlist, arg validation, bounded loop, prompt-injection delimiting, real Merkle recomputation |
| Courtroom | `src/agent/courtroom_auditor.py` | Fail-closed gates, certified-root replay, scope/limitations, honest verdict language |
| Citations | `src/agent/citation_validator.py` | Unique-citation faithfulness, inflation metrics, duplicate accounting |
| Mitigation | `src/mitigation/countermeasure_engine.py` | IP/port/protocol validation, non-deployable flag, advisory-only execution policy |
| Reproducibility | `src/integrity/run_manifest.py`, `main.py` | Data/model/output hashes, git state, library versions, explicit provenance warnings |
| ML | `src/baseline_detector.py`, `src/detectors/ensemble_fuser.py` | Disjoint early-stop/calibration/threshold/meta slices |
| Tests | `tests/test_security_hardening.py` | 25 regression tests covering every confirmed exploit and hardening |
| Packaging | `pyproject.toml` | ML/API/agent extras, `src*`/`api*` packages, `httpx` for tests |
| Ops | `.env.server.example`, `.gitignore` | Secret/Auth config template and secret exclusions |

---

## 4. ML evaluation: what still needs to change

The current metrics are **benchmark metrics, not production evidence**. Before claiming zero-day capability or court-grade accuracy:

1. **Global temporal split.** `per_class=True` gives the model the latest 20% of every class, so every test class was seen in training. Add a global cutoff and a leave-one-attack-family-out experiment. Report both.
2. **Near-duplicate control.** CICIDS contains highly similar flows. Deduplicate by 5-tuple/time window (or MinHash) *within train only*, then measure test leakage explicitly.
3. **Group-aware splits.** Split by host/campaign so the same campaign cannot straddle train/test. Report host-overlap rate.
4. **External validation.** Evaluate on a dataset not used for feature engineering (e.g., a newer CICIDS capture, UNSW-NB15, or a lab PCAP). Report dataset-shift degradation.
5. **Calibration and uncertainty.** Report ECE/reliability diagrams, Brier score, and conformal prediction sets. Do not present a single threshold as universal.
6. **Threshold policy.** Tune on a dedicated threshold split (done) and report precision at fixed analyst capacity (alerts/day), not only max-F1.
7. **Drift and monitoring.** Log feature distributions, model hash, dataset hash, and alert-rate per run; alert on PSI/KS drift.
8. **Ablations.** Report each pillar alone and the fused model; report the autoencoder's zero-day recall honestly on held-out families.
9. **Statistical rigor.** Add bootstrap confidence intervals and per-class recall; a single 100% F1 on synthetic sample data is not evidence.
10. **Ground-truth provenance.** The case bundle and eval fixtures must be versioned and hash-pinned; otherwise reported metrics cannot be reproduced.

**Honest claim to make today:** "On the included benchmark, the pipeline achieves X; on held-out families it achieves Y; calibration error is Z." Not "100% court-admissible."

---

## 5. Production roadmap

### Phase 0 (done here) — stop false assurance
Fail-closed API, real crypto verification, secret custody, auth, tests.

### Phase 1 — Evidence integrity
- Ed25519-sign the Merkle root; publish key ID + signature in the cert.
- RFC 3161 timestamp / transparency log anchor.
- Store raw PCAPs immutably (object lock/WORM) and hash them at capture time.
- Chain-of-custody events (collector, hash, transfer, access) in append-only storage.
- Separate collection attestation from analysis; sign both.

### Phase 2 — Detection quality
- Global temporal + group + family-holdout evaluation; publish a benchmark card.
- Conformal prediction for alert uncertainty.
- Drift monitoring and retraining triggers.
- Model registry with dataset/model hashes and approval status.

### Phase 3 — Response safety
- Countermeasure plans require human approval; dry-run + syntax validation; rollback plan.
- Least-privilege execution credentials; no autonomous firewall changes by default.

### Phase 4 — Platform hardening
- OIDC/RBAC (analyst, reviewer, admin), per-incident authorization.
- PostgreSQL/object storage instead of whole-file JSON reloads.
- Structured audit logging with request IDs; immutable security log.
- CI: dependency audit, SAST, secret scanning, container scanning, SBOM.
- Postgres row-level security for multi-tenant forensic data.

---

## 6. How to verify

```powershell
# 1. Security + integrity regression suite
python -m unittest discover -s tests -v

# 2. Regenerate ledger and artifacts
python main.py --agent

# 3. Confirm no secret is shipped
python -c "import json; c=json.load(open('outputs/privacy_preserving_proof_certificate.json')); print('secret_present=', 'enterprise_selective_disclosure_key' in c)"

# 4. Confirm path traversal is dead (should return the SPA shell, not .env)
#    Start the server, then:
#    curl.exe -i "http://127.0.0.1:8000/..%2F.env.example"
```

Expected: 57 tests pass; certificate has no `enterprise_selective_disclosure_key`; `outputs/privacy_disclosure_key.secret` exists locally and is gitignored.

---

## 7. Residual risk statement

After these changes the system can honestly say:

- *"This cited flow existed in the capture and its audit path recomputes to the session root."*
- *"The report was checked against the case bundle; ungrounded citations are reported."*
- *"The API does not expose files outside its build directory and requires a key when configured."*

It still **cannot** say:

- that the capture was complete, untampered at collection time, or produced by a trusted sensor;
- that the ML model generalizes to unseen attack families;
- that a firewall rule is safe to execute;
- that the output is legal advice or a court ruling.

Those require signed collection attestations, external validation, human approval, and counsel — not code alone.
