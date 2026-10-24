import { test } from 'node:test';
import assert from 'node:assert/strict';
import { reportHtml, chainHtml, detailHtml, hoverHtml, capHtml } from '../src/ui/panels.js';

test('report displays retrieved ATT&CK matches as inferred candidates', () => {
  const html = reportHtml(
    { incident_id: 'INC-TEST', stages: [], hosts: [], start: null },
    {
      incident_id: 'INC-TEST',
      validation: { valid: 0, total: 0 },
      sentences: [],
      attack_matches: {
        'Repeated SSH authentication failures': {
          matches: [
            {
              id: 'T1110',
              name: 'Brute Force',
              tactics: ['Credential Access'],
              score: 0.876,
            },
          ],
        },
      },
    },
  );

  assert.match(html, /ATT&amp;CK candidates - inferred/);
  assert.match(html, /not confirmed techniques or observed events/);
  assert.match(html, /T1110/);
  assert.match(html, /Brute Force/);
  assert.match(html, /similarity 0\.876/);
  assert.match(html, /Credential Access/);
});

test('unknown API tactic text is escaped in every incident-stage renderer', () => {
  const tactic = '<img src=x onerror=alert(1)>';
  const incident = {
    incident_id: 'INC-XSS',
    start: '2026-01-01T00:00:00Z',
    durationMin: 1,
    hosts: [
      { id: 'h1', ip: '192.0.2.1', role: 'Host', zone: 'INTERNAL' },
      { id: 'h2', ip: '192.0.2.2', role: 'Host', zone: 'INTERNAL' },
    ],
    stages: [{
      stage_id: 'INC-XSS-stage-1', order: 1, tactic, tactic_id: 'T9999',
      src: 'h1', dst: 'h2', port: '22', confidence: 0.8, observed: true,
      summary: 'Observed test event', explanation: [], evidence: [], t0: 0, t1: 1,
    }],
  };
  const rendered = [
    chainHtml(incident),
    detailHtml(incident, { stage: 'INC-XSS-stage-1' }, 0),
    detailHtml(incident, { host: 'h1' }, 0),
    hoverHtml(incident, { stage: 'INC-XSS-stage-1' }, 0),
    capHtml(incident, incident.stages[0], 'ACTIVE'),
  ];

  for (const html of rendered) {
    assert.ok(!html.includes('<img src=x'), 'untrusted tactic must not create an element');
    assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
  }
});
