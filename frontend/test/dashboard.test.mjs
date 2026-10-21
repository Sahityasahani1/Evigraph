import test from 'node:test';
import assert from 'node:assert/strict';

import {
  attackMappingsHtml,
  evidenceHtml,
  filteredEvents,
  incidentMatches,
  overviewHtml,
  reportHtml,
  timelineEvents,
  observedReplayEvents,
} from '../src/ui/dashboard.js';

const incident = {
  incident_id: 'INC-TEST',
  score: 0.82,
  status: 'Open',
  start: '2026-10-21T09:00:00Z',
  end: '2026-10-21T09:05:00Z',
  source_sha256: 'abc123',
  merkle_root: 'root123',
  hosts: [
    { id: 'source-1', ip: '192.0.2.10', role: 'source', zone: 'EXTERNAL' },
    { id: 'target-1', ip: '10.0.0.5', role: 'server', zone: 'INTERNAL' },
  ],
  total_alerts: 3,
  stages: [{
    stage_id: 'stage-1',
    tactic: 'Lateral Movement',
    tactic_id: 'TA0008',
    src: 'source-1',
    dst: 'target-1',
    port: '445',
    start: '2026-10-21T09:01:00Z',
    observed: true,
    summary: 'Observed SMB activity',
    evidence: [{ flow_id: 'flow-1', ts: '2026-10-21T09:01:00Z', evidence_id: 'evidence-1' }],
  }],
};

test('incident filters use actual incident and host fields', () => {
  assert.equal(incidentMatches(incident, '192.0.2.10', 'high'), true);
  assert.equal(incidentMatches(incident, 'INC-TEST', 'critical'), false);
  assert.equal(incidentMatches(incident, 'not-present', 'all'), false);
});

test('attack replay includes only observed timeline events with cited flow evidence', () => {
  const events = [
    { key: 'seen', observed: true, inferred: false, evidence: { flow_id: 'flow-1' } },
    { key: 'inferred-stage', observed: true, inferred: true, evidence: { flow_id: 'flow-2' } },
    { key: 'unobserved', observed: false, inferred: true, evidence: { flow_id: 'flow-3' } },
    { key: 'no-flow', observed: true, inferred: false, evidence: null },
  ];
  assert.deepEqual(observedReplayEvents(events).map(event => event.key), ['seen']);
});

test('overview labels the available incident score without presenting it as model confidence', () => {
  const html = overviewHtml(incident, 'Prepared incident');
  assert.match(html, /INC-TEST/);
  assert.match(html, /Prepared incident/);
  assert.match(html, /82% incident score/);
  assert.match(html, /82% incident score/);
  assert.match(html, /0\.82 normalized score/);
  assert.match(html, /3<\/strong>/);
});

test('timeline identifies observed versus inferred records and filters real event data', () => {
  const events = timelineEvents({
    stages: [
      { stage_id: 's1', start: '2026-10-21T09:00:00Z', observed: true, interpretation_status: 'inferred', tactic: 'Reconnaissance', summary: 'Observed scan with inferred stage mapping', evidence: [{ flow_id: 'f1', ts: '2026-10-21T09:00:00Z' }] },
      { stage_id: 's2', start: '2026-10-21T09:02:00Z', observed: false, tactic: 'Lateral Movement', summary: 'Inferred path', evidence: [] },
    ],
  });
  assert.equal(events.length, 2);
  assert.equal(filteredEvents(events, 'scan', 'observed').length, 1);
  assert.equal(filteredEvents(events, 'scan', 'inferred').length, 1);
  assert.equal(events[0].observed, true);
  assert.equal(events[0].inferred, true);
  assert.deepEqual(filteredEvents(events, '', 'inferred').map(event => event.stage.stage_id), ['s1', 's2']);
});

test('evidence inspector displays supplied values only and resolves host ids to returned addresses', () => {
  const html = evidenceHtml(
    incident,
    incident.stages[0],
    incident.stages[0].evidence[0],
    null,
    'Prepared incident',
  );
  assert.match(html, /flow-1/);
  assert.match(html, /192\.0\.2\.10/);
  assert.match(html, /10\.0\.0\.5/);
  assert.match(html, /Prepared incident route has no raw-flow lookup endpoint/);
  assert.match(html, /Merkle root/);
  assert.doesNotMatch(html, /Protocol/);
  assert.doesNotMatch(html, /src_port/);
});

test('ATT&CK panel keeps legacy evidence citations off retrieved candidates', () => {
  const html = attackMappingsHtml({
    attack_matches: {
      'Lateral Movement': {
        status: 'available',
        matches: [{ id: 'T1021.002', name: 'SMB/Windows Admin Shares', mapping_status: 'inferred', score: 0.91, evidence_flow_ids: ['flow-1'] }],
      },
      'Command and Control': { status: 'unavailable', error: 'index missing', matches: [] },
      Exfiltration: { status: 'available', matches: [{ id: 'T1041', name: 'Exfiltration Over C2 Channel' }] },
    },
  }, 'loaded');
  assert.match(html, /Retrieved candidate/);
  assert.match(html, /Needs review/);
  assert.match(html, /Candidates are ranked by retrieval similarity\. No technique-specific evidence is available; analyst review is required\./);
  assert.doesNotMatch(html, /data-evidence-flow="flow-1"/);
  assert.match(html, /Retrieval unavailable: index missing/);
  assert.match(html, /not observed activity/);
  assert.doesNotMatch(html, /confidence|probability/i);
});

test('report claims expose citations and explicit unsupported validation state', () => {
  const html = reportHtml({
    incident_id: 'INC-TEST',
    validation: { valid: 1, total: 2, rejected: 1 },
    sentences: [
      { text: 'A claim backed by evidence.', stage_id: 'stage-1', evidence_ids: ['flow-1'] },
      { text: 'A claim without evidence.', stage_id: null, evidence_ids: [] },
    ],
  }, 'loaded', incident);
  assert.match(html, /1\/2 claims supported/);
  assert.match(html, /Evidence · flow-1/);
  assert.match(html, /No evidence reference returned/);
  assert.match(html, /Stage reference not available/);
});
