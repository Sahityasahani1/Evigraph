import test from 'node:test';
import assert from 'node:assert/strict';

import { createReportExport } from '../src/ui/reportExport.js';

const incident = { incident_id: 'INC-42', stages: [] };
const report = {
  incident_id: 'INC-42',
  sentences: [{ text: 'Observed activity.', evidence_ids: ['flow-42'] }],
  validation: { valid: 1, total: 1 },
  footer: { input_sha256: 'abc123', merkle_root: 'root123' },
};

test('JSON export preserves the complete report payload and evidence citations', () => {
  const file = createReportExport(incident, report, 'json');
  assert.equal(file.filename, 'INC-42_investigation.json');
  assert.equal(file.mimeType, 'application/json');
  assert.deepEqual(JSON.parse(file.content), report);
});

test('Markdown export includes evidence citations and uses a markdown filename', () => {
  const file = createReportExport(incident, report, 'md');
  assert.equal(file.filename, 'INC-42_investigation.md');
  assert.equal(file.mimeType, 'text/markdown;charset=utf-8');
  assert.match(file.content, /flow-42/);
  assert.match(file.content, /root123/);
});

test('Markdown export appends fresh run provenance and structured retrieval results', () => {
  const fresh = {
    ...report,
    report_markdown: '# Forensic report\n\nObserved flow evidence [E:observed-flow].\n\n## ATT&CK retrieval candidates (inferred, not confirmed)\n\n- Legacy citation [E:incident-flow].',
    provenance: { inference_source: 'fresh', detector_label: 'gnn_legacy_migrated', input_sha256: 'abc123' },
    retrieval_status: 'available',
    attack_matches: {
      'Credential Access': { status: 'available', evidence_flow_ids: ['incident-flow'], matches: [{ id: 'T1110', name: 'Brute Force', score: 0.91, score_semantics: 'cosine_similarity', evidence_flow_ids: ['incident-flow'] }] },
    },
  };
  const file = createReportExport(incident, fresh, 'md');
  assert.match(file.content, /Inference mode: fresh/);
  assert.match(file.content, /gnn_legacy_migrated/);
  assert.match(file.content, /Merkle root: root123/);
  assert.match(file.content, /Retrieved ATT&CK candidates/);
  assert.match(file.content, /T1110 Brute Force/);
  assert.match(file.content, /not confirmed activity/);
  assert.match(file.content, /Retrieval similarity 0\.91/);
  assert.match(file.content, /No technique-specific evidence available\. This candidate requires analyst review\./);
  assert.match(file.content, /\[E:observed-flow\]/);
  assert.doesNotMatch(file.content, /\[E:incident-flow\]/);
  assert.doesNotMatch(file.content, /(?:confidence|probability)\s*:/i);
});

test('JSON export normalizes candidate review and evidence without reusing incident citations', () => {
  const payload = {
    ...report,
    report_markdown: '# Report\n\nObserved activity [E:flow-42].\n\n## ATT&CK mapping (best search match per stage)\n- T1110 cited [E:incident-flow].',
    attack_matches: {
      'SSH-Patator': {
        status: 'available', mapping_status: 'inferred', evidence_flow_ids: ['incident-flow'],
        matches: [{
          id: 'T1110', name: 'Brute Force', score: 0.91, score_semantics: 'cosine_similarity',
          evidence_flow_ids: ['old-unrelated-flow'], evidence_ids: ['old-unrelated-event'],
        }],
      },
    },
  };
  const output = JSON.parse(createReportExport(incident, payload, 'json').content);
  const result = output.attack_matches['SSH-Patator'];
  const candidate = result.matches[0];
  assert.deepEqual(result.retrieval_query_context.flow_ids, ['incident-flow']);
  assert.equal(Object.hasOwn(result, 'mapping_status'), false);
  assert.deepEqual(candidate.candidate_evidence.flow_ids, []);
  assert.deepEqual(candidate.candidate_evidence.event_ids, []);
  assert.equal(candidate.candidate_status, 'retrieved_candidate');
  assert.equal(candidate.review_status, 'not_reviewed');
  assert.equal(candidate.retrieval_similarity, 0.91);
  assert.equal(candidate.score_semantics, 'cosine_similarity');
  assert.equal(candidate.assessment, 'No technique-specific evidence available. This candidate requires analyst review.');
  assert.deepEqual(output.sentences[0].evidence_ids, ['flow-42']);
  assert.match(output.report_markdown, /Observed activity \[E:flow-42\]/);
  assert.doesNotMatch(output.report_markdown, /\[E:incident-flow\]/);
  assert.match(output.report_markdown, /No technique-specific evidence available/);
});

test('Markdown export includes only explicit candidate-specific references', () => {
  const payload = {
    ...report,
    attack_matches: {
      'Credential Access': { status: 'available', matches: [{
        id: 'T1110', name: 'Brute Force', tactics: ['credential-access'],
        score: 0.8, score_semantics: 'cosine_similarity',
        candidate_evidence: { status: 'candidate_specific', flow_ids: ['candidate-flow'], event_ids: ['candidate-event'], reason: 'Matched explicit record.' },
      }] },
    },
  };
  const content = createReportExport(incident, payload, 'md').content;
  assert.match(content, /evidence-linked candidate/);
  assert.match(content, /Retrieval similarity 0\.8/);
  assert.match(content, /Candidate-specific supporting references: flow candidate-flow, event candidate-event/);
  assert.match(content, /Matched explicit record\./);
  assert.match(content, /not confirmed activity/);
  assert.doesNotMatch(content, /as confirmed|confirmed technique/i);
});

test('PDF and unknown formats fail explicitly because the API has no PDF export', () => {
  assert.throws(() => createReportExport(incident, report, 'pdf'), /Unsupported export format: pdf/);
  assert.throws(() => createReportExport(incident, report, 'csv'), /Unsupported export format: csv/);
});
