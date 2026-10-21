# Investigation dashboard checklist

The repository did not contain a standalone frontend checklist with sections
B, C, and E. The following sections map those requested areas to this dashboard
work; statuses below record only checks performed for this implementation.

## B. Incident overview and attack graph — COMPLETE

- [x] Display incident identity, status, score-derived/returned severity,
  confidence when supplied, affected hosts, time range, alert count, and source
  provenance without manufacturing missing values.
- [x] Filter the live incident list by search and severity; select an incident
  to refresh the complete investigation workspace.
- [x] Render returned hosts, zones, and alert-stage relationships in the
  interactive graph. Provide direction, selectable paths/nodes, pan, zoom,
  fit, reset, and keyboard-accessible selection.
- [x] Keep prepared incidents visibly distinct from fresh inference.
- [x] Verify in-browser against prepared INC-0009 and a fresh XGBoost job;
  graph node/edge counts followed each incident's API data.

## C. Timeline, evidence, and ATT&CK — VERIFIED WITH RETRIEVAL LIMITATION

- [x] Order timeline entries by returned timestamps; keep observed flow evidence
  distinct from an inferred stage interpretation. Search and observed/inferred
  filters change the rendered events.
- [x] Synchronize timeline selection, graph highlighting, and the evidence
  inspector in both directions.
- [x] Display only returned flow fields and provenance. Fresh-flow details were
  verified through the investigation evidence endpoint; prepared incidents show
  their embedded evidence and disclose that raw-flow lookup is not available.
- [x] Render ATT&CK candidates, source links, scores, supporting flow
  references, unconfirmed/inferred status, empty results, and retrieval errors
  from the report API response.
- [ ] Verify live technique retrieval from the vector index. The configured
  `data/knowledge/attack_index.npz` is absent, so the real API returned an
  explicit unavailable status; no techniques are fabricated by the UI.

## E. Report review and export — COMPLETE

- [x] Display report claims, available stage associations, evidence citations,
  validation counts, rejected claims, degradation status, and provenance.
- [x] Make report flow citations open the corresponding evidence inspector.
- [x] Provide JSON and Markdown export controls; PDF is omitted because the
  backend exposes no PDF endpoint.
- [x] Verify exported JSON/Markdown formatting and citations with the frontend
  export tests; click both controls in the browser without page errors.
- [x] Verify the live report response for a fresh investigation (160/160 cited
  statements, explicitly deterministic/degraded).

## Verification record

- `npm test` — 25 passed.
- `npm run build` — passed.
- `git diff --check -- frontend` — passed.
- Browser checks — incident search/severity filtering, prepared/fresh labels,
  graph/timeline synchronization, keyboard selection, graph pan/zoom/fit/reset,
  live fresh-flow evidence, report validation, and explicit ATT&CK unavailable
  status.
- Limitation: the integrated browser runner did not emit a download event when
  exercising the browser download controls. Export content/format and citations
  are covered by automated tests; the controls executed without browser page
  errors.
