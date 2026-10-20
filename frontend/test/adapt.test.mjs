import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { adapt } from '../src/api/adapt.js';
import { headline, hostStatus } from '../src/ui/story.js';
import { overviewHtml, chainHtml } from '../src/ui/panels.js';
import { mockIncident } from '../src/api/mock.js';

describe('Fix 2: Zero-stage Incident Adaptation & Rendering', () => {
  test('adapt handles incident with empty stages without throwing', () => {
    const raw = {
      incident_id: 'INC-ZERO',
      score: 0.75,
      start: '2026-11-02T15:00:00Z',
      end: '2026-11-02T16:00:00Z',
      hosts: [
        { id: '10.0.0.10', ip: '10.0.0.10', role: 'target' },
        { id: '203.0.113.5', ip: '203.0.113.5', role: 'attacker' },
      ],
      stages: [],
      background: [
        { src: '10.0.0.10', dst: '10.0.0.20' },
      ],
    };

    assert.doesNotThrow(() => {
      const res = adapt(raw);
      assert.equal(res.incident_id, 'INC-ZERO');
      assert.deepEqual(res.stages, []);
      assert.equal(res.score, 0.75);
      assert.ok(res.start.endsWith('Z'));
      assert.ok(res.end.endsWith('Z'));
      assert.equal(res.hosts.length, 3); // 2 raw hosts + 1 from background

      // Check host normalization
      const atkHost = res.hosts.find(h => h.ip === '203.0.113.5');
      assert.ok(atkHost);
      assert.equal(atkHost.id, 'ATK');
      assert.equal(atkHost.zone, 'EXTERNAL');

      const targetHost = res.hosts.find(h => h.ip === '10.0.0.10');
      assert.ok(targetHost);
      assert.equal(targetHost.zone, 'INTERNAL');
    });
  });

  test('adapt handles completely empty incident gracefully', () => {
    const res = adapt({ incident_id: 'INC-EMPTY' });
    assert.equal(res.incident_id, 'INC-EMPTY');
    assert.deepEqual(res.stages, []);
    assert.deepEqual(res.hosts, []);
    assert.deepEqual(res.background, []);
    assert.equal(res.score, 0);
    assert.equal(res.start, null);
    assert.equal(res.end, null);
  });

  test('UI components render zero-stage incident without throwing', () => {
    const rawZero = {
      incident_id: 'INC-ZERO-UI',
      score: 0.3,
      hosts: [{ id: '10.0.0.1', ip: '10.0.0.1', role: 'workstation' }],
      stages: [],
    };
    const adapted = adapt(rawZero);

    // Headline
    const hl = headline(adapted);
    assert.ok(hl.includes('INC-ZERO-UI has no recorded attack stages'));

    // Overview HTML
    const oHtml = overviewHtml(adapted, 0);
    assert.ok(oHtml.includes('No entry point detected'));
    assert.ok(oHtml.includes('No attack stages recorded'));

    // Chain HTML
    const cHtml = chainHtml(adapted);
    assert.ok(cHtml.includes('No attack steps recorded'));
  });

  test('adapt preserves normal multi-stage incidents identically', () => {
    const inc0009 = mockIncident('INC-0009');
    const adapted = adapt(inc0009);

    assert.equal(adapted.incident_id, 'INC-0009');
    assert.equal(adapted.stages.length, 3);
    assert.equal(adapted.stages[0].stage_id, 'INC-0009-stage-1');
    assert.equal(adapted.stages[1].stage_id, 'INC-0009-stage-2');
    assert.equal(adapted.stages[2].stage_id, 'INC-0009-stage-3');
    assert.ok(headline(adapted).includes('172.20.10.10'));
  });
});

