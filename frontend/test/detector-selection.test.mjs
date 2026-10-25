import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { overviewHtml } from '../src/ui/dashboard.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

test('frontend/index.html has Auto detector option selected by default and preserves xgb and gnn', () => {
  const html = fs.readFileSync(join(__dirname, '../index.html'), 'utf-8');
  assert.match(
    html,
    /<select id="detector"[^>]*>[\s\S]*?<option value="auto" selected>Auto<\/option>/,
    'Auto option should be present and selected by default in #detector select',
  );
  assert.match(
    html,
    /<option value="xgb">XGBoost<\/option>/,
    'XGBoost manual option must be preserved',
  );
  assert.match(
    html,
    /<option value="gnn">GraphSAGE GNN/,
    'GraphSAGE GNN manual option must be preserved',
  );
});

test('overviewHtml renders selection_reason and fallback_reason when provided', () => {
  const incidentWithAuto = {
    incident_id: 'INC-TEST-01',
    score: 0.85,
    status: 'open',
    hosts: ['10.0.0.1', '10.0.0.2'],
    stages: [],
    detection_model: 'xgb',
    detector_label: 'xgb',
    selection_reason: 'Auto selected XGBoost: input satisfies 31-feature schema.',
    fallback_reason: 'GraphSAGE GNN incompatible: Input missing 4 required features.',
  };

  const html = overviewHtml(incidentWithAuto, 'Fresh inference · XGBoost');
  assert.ok(html.includes('Auto selected XGBoost: input satisfies 31-feature schema.'), 'Should display selection reason');
  assert.ok(html.includes('Fallback: GraphSAGE GNN incompatible: Input missing 4 required features.'), 'Should display fallback reason');
  assert.ok(html.includes('overview-selection-info'), 'Should wrap selection info with overview-selection-info class');
});

test('overviewHtml omits selection info when selection_reason is not present', () => {
  const incidentStandard = {
    incident_id: 'INC-TEST-02',
    score: 0.75,
    status: 'open',
    hosts: ['10.0.0.1'],
    stages: [],
  };

  const html = overviewHtml(incidentStandard, 'Prepared incident');
  assert.ok(!html.includes('overview-selection-info'), 'Should not render selection info container');
  assert.ok(!html.includes('Detector Selection'), 'Should not render detector selection label');
});
