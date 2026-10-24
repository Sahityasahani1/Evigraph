# EviGraph Dashboard API Contract

The dashboard is a vanilla ES-module application. `src/api/client.js` is the only
module that makes API requests; display components consume the normalized shapes.
The Vite development proxy forwards `/api/*` to the FastAPI service and strips the
`/api` prefix.

## Prepared incidents

| Method | Path | Dashboard use |
| --- | --- | --- |
| `GET` | `/incidents` | Incident list. The current service returns normalized incident objects. |
| `GET` | `/incidents/{incident_id}` | Full incident hosts, stages, embedded evidence references, status, and provenance when present. |
| `GET` or `POST` | `/incidents/{incident_id}/report` | Evidence-linked report claims, validation counts, ATT&CK retrieval results, and provenance. |

Prepared incident records contain embedded `stage.evidence` metadata. There is no
prepared-incident endpoint for looking up the complete raw flow record, so the
dashboard does not invent absent ports, protocol values, or evidence hashes.

## Fresh investigations

| Method | Path | Dashboard use |
| --- | --- | --- |
| `POST` | `/investigations` | Stream a flow CSV/Parquet or PCAP/PCAPNG file. `X-Filename` and `X-Detector` headers identify the file and `xgb`/`gnn` model. Returns a queued job. |
| `GET` | `/investigations/{job_id}` | Poll status, stage, percentage, and final result. |
| `GET` | `/investigations/{job_id}/incidents` | Incident records with fresh inference provenance and model metadata. |
| `GET` | `/investigations/{job_id}/incidents/{incident_id}/report` | Evidence-linked report and ATT&CK retrieval result for the fresh incident. |
| `GET` | `/investigations/{job_id}/incidents/{incident_id}/evidence/{flow_id}` | Retrieve an incident-linked flow, evidence ID, and source-file SHA-256. |
| `GET` | `/health` | API liveness check. |

The dashboard preserves the `flow_id`, timestamp, evidence references, and source
hash returned by these endpoints. A source SHA-256 is an input fingerprint; it is
not shown as a flow-level digest.

## Incident view fields

The normalizer keeps the original fields and canonicalizes tactic names and
timestamps. The UI uses the following fields where present:

- Incident: `incident_id`, `status`, `score`, optional `severity`/`confidence`,
  `start`, `end`, `hosts`, `total_alerts`, `source_sha256`, `inference_source`,
  `detection_model`.
- Host: `id`, `ip`, `role`, `zone`.
- Stage: `stage_id`, `order`, `tactic`, `tactic_id`, `src`, `dst`, `port`,
  `start`, `end`, `confidence`, `observed`, `interpretation_status`, `behavior`,
  `summary`, `evidence`.
- Evidence: `flow_id`, `evidence_id`, `ts`/`timestamp`, flow attributes and
  available hashes.

Unknown fields remain absent in the UI rather than receiving synthetic values.
Incident severity is taken from a returned severity field when present; otherwise
the UI labels the numeric incident score separately and uses score bands only for
the severity filter.

## Report and ATT&CK fields

- Report claims use `sentences[]` with `text`, optional `stage_id`, and
  `evidence_ids[]`; the UI links flow IDs back to the evidence inspector.
- `validation.valid`, `validation.total`, and `validation.rejected` drive the
  displayed validation summary when returned.
- Deterministic fallback claims are counted as valid only when their citations
  belong to that incident stage and resolve to records in the flow store.
- `attack_matches` is rendered as retrieved metadata. Candidate techniques remain
  unconfirmed unless the backend explicitly returns a confirmed mapping. Missing
  evidence references and unavailable retrieval indexes are called out.
- JSON and Markdown exports are generated from the report payload. The backend
  does not expose a PDF export endpoint, so the dashboard does not offer PDF.

## Demo and error behavior

The prepared/mock path remains available through the existing `VITE_USE_MOCK`
configuration and is labeled in the workspace. Fresh investigations are labeled
separately and retain their job ID for evidence/report lookups. API errors are
displayed with retry actions where retry is safe; loading states do not block
incident browsing.

The current backend has no standalone report-validation endpoint, no PDF export,
and no raw-flow lookup for prepared incidents. The dashboard shows those
limitations instead of implying those capabilities exist.
