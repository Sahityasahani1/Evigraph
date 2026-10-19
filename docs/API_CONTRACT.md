# EviGraph Frontend ⇄ Backend Contract (draft v0.1)

Aligned with TRD 3.8 endpoints and 4.2 tables. Agree on this with Members 2 and 3, then change `src/api/mock.js` and `src/api/client.js` only.
All timestamps are ISO-8601 UTC. IDs are stable strings (PRD FR-1.3).

| Method | Path | Returns |
|---|---|---|
| GET | `/incidents` | `[{incident_id, score, start, end, status}]` |
| GET | `/incidents/{id}` | Incident object (below) |
| GET | `/incidents/{id}/evidence` | Not used yet (stage.evidence is embedded for now) |
| POST | `/incidents/{id}/report` | Report object (below) |

## Incident
```json
{
  "incident_id": "INC-0042", "score": 0.93, "status": "open",
  "start": "2026-10-13T14:02:00Z", "end": "2026-10-13T14:32:00Z",
  "hosts": [{ "id": "WEB", "ip": "10.0.1.10", "zone": "DMZ", "role": "Web server" }],
  "stages": [{
    "stage_id": "STG-1", "order": 1,
    "tactic": "Reconnaissance", "tactic_id": "TA0043", "behavior": "scan",
    "src": "ATK", "dst": "WEB", "port": "1-1024",
    "start": "...", "end": "...", "confidence": 0.91, "observed": true,
    "summary": "412 short connections to 412 distinct ports within 3.5 minutes",
    "evidence": [{ "flow_id": "flow_1001", "ts": "...", "pcap_sha256": "..." }],
    "explanation": [{ "feature": "distinct dst ports (412)", "weight": 0.95 }]
  }],
  "background": [{ "src": "WS1", "dst": "WEB" }]
}
```
- `zone` is one of `EXTERNAL | DMZ | INTERNAL` (drives 3D placement). `host.id` is what stages reference in `src`/`dst`.
- `tactic` must match a key in `src/config.js` `TACTIC_COLORS` (unknown tactics get a neutral colour).
- `explanation` text must be observable-only (PRD FR-6.5). The UI escapes all strings.

## Report
```json
{
  "report_id": "RPT-0042", "incident_id": "INC-0042",
  "sentences": [{ "text": "...", "stage_id": "STG-1", "evidence_ids": ["flow_1001"] }],
  "validation": { "valid": 6, "total": 6 },
  "footer": { "input_sha256": "...", "manifest_id": "run_ab12cd34", "attack_version": "v15" }
}
```

## Auth
If the backend uses tokens (TRD 3.8), store one in `localStorage['evigraph_token']`; it is sent as `Authorization: Bearer`.
