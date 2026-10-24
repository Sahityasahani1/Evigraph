import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import { attackMappingsHtml } from '../src/ui/dashboard.js';

test('panel shows candidate-specific evidence and labels cosine score as retrieval similarity', () => {
  const html = attackMappingsHtml({
    attack_matches: {
      'Credential Access': {
        status: 'available',
        matches: [{
          id: 'T1110', name: 'Brute Force', tactics: ['credential-access'],
          score: 0.91, score_semantics: 'cosine_similarity',
          source_url: 'https://attack.mitre.org/techniques/T1110',
          retrieval_reason: 'Ranked by semantic similarity of the stage query.',
          candidate_evidence: { status: 'candidate_specific', flow_ids: ['flow-1'], event_ids: ['event-1'], reason: 'Exact linked record.' },
        }],
      },
    },
  }, 'loaded');

  assert.match(html, /T1110/);
  assert.match(html, /Brute Force/);
  assert.match(html, /Tactic: credential-access/);
  assert.match(html, /Evidence-linked candidate/);
  assert.match(html, /Needs review/);
  assert.match(html, /Retrieval similarity <strong>0\.910<\/strong>/);
  assert.doesNotMatch(html, /confidence|probability/i);
  assert.match(html, /data-evidence-flow="flow-1"/);
  assert.match(html, /event-1/);
  assert.match(html, /Exact linked record\./);
  assert.match(html, /https:\/\/attack\.mitre\.org\/techniques\/T1110/);
  assert.match(html, /<summary>Why this candidate\?<\/summary>/);
  assert.doesNotMatch(html, /<details[^>]*open/);
});

test('legacy incident citations are not reused as candidate evidence', () => {
  const html = attackMappingsHtml({
    attack_matches: {
      'SSH-Patator': {
        status: 'available', evidence_flow_ids: ['incident-flow'],
        matches: [{
          id: 'T1110', name: 'Brute Force', score: 0.91,
          evidence_flow_ids: ['unrelated-candidate-flow'], evidence_ids: ['unrelated-event'],
        }],
      },
    },
  }, 'loaded');

  assert.match(html, /No technique-specific evidence is available\./);
  assert.match(html, /Stage query context only; not technique-specific evidence\./);
  const explanation = 'Candidates are ranked by retrieval similarity. No technique-specific evidence is available; analyst review is required.';
  assert.equal(html.split(explanation).length - 1, 1);
  assert.match(html, /Retrieved by semantic similarity between the stage investigation query and ATT&amp;CK technique text\. No technique-specific evidence is available\./);
  assert.doesNotMatch(html, /data-evidence-flow="(?:incident-flow|unrelated-candidate-flow)"/);
  assert.doesNotMatch(html, /unrelated-event/);
  assert.doesNotMatch(html, /Retrieval similarity:/);
  assert.match(html, /Retrieved candidate/);
  assert.match(html, /Needs review/);
  assert.doesNotMatch(html, /Analyst-confirmed|Analyst-rejected/);
});

test('candidate cards expose collapsed native details and keep all candidates in the panel list', () => {
  const html = attackMappingsHtml({
    attack_matches: {
      'Stage A': { status: 'available', matches: [
        { id: 'T1110', name: 'Brute Force', tactics: ['credential-access'], score: 0.91, score_semantics: 'cosine_similarity' },
        { id: 'T1046', name: 'Network Service Discovery', tactics: ['discovery'], score: 0.82, score_semantics: 'cosine_similarity' },
      ] },
    },
  }, 'loaded');
  assert.match(html, /role="region" aria-label="ATT&amp;CK candidate list"/);
  assert.match(html, /T1110/);
  assert.match(html, /Brute Force/);
  assert.match(html, /credential-access/);
  assert.match(html, /0\.910/);
  assert.match(html, /T1046/);
  assert.match(html, /Network Service Discovery/);
  assert.match(html, /discovery/);
  assert.match(html, /0\.820/);
  assert.equal((html.match(/<details class="attack-candidate-details">/g) ?? []).length, 2);
});

test('candidate list scrolls independently with a narrower-screen height rule', async () => {
  const css = await readFile(new URL('../src/styles.css', import.meta.url), 'utf8');
  assert.match(css, /\.attack-candidate-list\s*\{[^}]*max-height:\s*min\(48vh, 500px\)[^}]*overflow-y:\s*auto/s);
  assert.match(css, /@media\s*\(max-width:\s*700px\)[\s\S]*?\.attack-candidate-list\s*\{\s*max-height:\s*min\(58vh, 500px\)/);
});

test('candidate text and links remain escaped', () => {
  const html = attackMappingsHtml({
    attack_matches: {
      '<img src=x>': { status: 'available', matches: [{
        id: '<script>', name: 'xss & name', tactics: ['<b>'],
        score: 0.5, score_semantics: 'cosine_similarity',
        retrieval_reason: '<svg onload=alert(1)>',
        source_url: 'https://attack.mitre.org/techniques/T0000',
        candidate_evidence: { flow_ids: ['<button>'], reason: '<script>alert(1)</script>' },
      }] },
    },
  }, 'loaded');

  assert.doesNotMatch(html, /<img|<script|<svg|<b>/);
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /&lt;button&gt;/);
});

test('unavailable ATT&CK retrieval remains explicit', () => {
  const html = attackMappingsHtml({
    attack_matches: { 'SSH-Patator': { status: 'unavailable', error: 'index missing', matches: [] } },
  }, 'loaded');
  assert.match(html, /Retrieval unavailable: index missing/);
});
