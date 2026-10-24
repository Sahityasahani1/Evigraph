import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { formatReportJson, formatReportMarkdown, downloadFile } from '../src/utils.js';
import { reportHtml } from '../src/ui/panels.js';
import { mockReport, mockIncident } from '../src/api/mock.js';

describe('FR-8.6: Report Review and Export', () => {
  const incidents = ['INC-0001', 'INC-0002', 'INC-0009'];

  test('reportHtml renders clearly visible download action buttons', () => {
    const inc = mockIncident('INC-0009');
    const r = mockReport('INC-0009');
    const html = reportHtml(inc, r);

    assert.ok(html.includes('data-download="json"'), 'Must contain Download JSON button');
    assert.ok(html.includes('data-download="md"'), 'Must contain Download Markdown button');
    assert.ok(html.includes('Download JSON'), 'Must have "Download JSON" text');
    assert.ok(html.includes('Download Markdown'), 'Must have "Download Markdown" text');
  });

  for (const iid of incidents) {
    describe(`Export verification for ${iid}`, () => {
      const inc = mockIncident(iid);
      const r = mockReport(iid);

      test(`formatReportJson produces valid JSON with correct incident_id and citations for ${iid}`, () => {
        const jsonStr = formatReportJson(r);
        const parsed = JSON.parse(jsonStr);

        assert.equal(parsed.incident_id, iid, `JSON incident_id must match ${iid}`);
        assert.ok(Array.isArray(parsed.sentences), 'Must contain sentences array');
        assert.ok(parsed.sentences.length > 0, 'Sentences array must not be empty');
        assert.ok(parsed.validation, 'Must contain validation metadata');
        assert.ok(parsed.footer, 'Must contain footer metadata');

        // Check evidence IDs exist
        const allEv = parsed.sentences.flatMap(s => s.evidence_ids || []);
        assert.ok(allEv.length > 0, 'Must preserve evidence references');

        // Check safe download simulation
        const dl = downloadFile(`${iid}_report.json`, jsonStr, 'application/json');
        assert.equal(dl.filename, `${iid}_report.json`);
      });

      test(`formatReportMarkdown produces valid Markdown with summary, evidence tags, and verification for ${iid}`, () => {
        const md = formatReportMarkdown(inc, r);

        assert.ok(md.includes(`# Incident Report: ${iid}`) || md.includes(`# Incident report: ${iid}`), `Markdown must have header for ${iid}`);
        assert.ok(md.includes('Executive Summary') || md.includes('Executive summary'), 'Markdown must have executive summary section');
        assert.ok(md.includes('Verification') || md.includes('Verification summary'), 'Markdown must have verification info');

        // Check evidence tags [E:... or [flw_... exist
        assert.ok(md.includes('[E:') || md.includes('[flw_'), 'Markdown must preserve evidence tags');

        // Check safe download simulation
        const dl = downloadFile(`${iid}_report.md`, md, 'text/markdown;charset=utf-8');
        assert.equal(dl.filename, `${iid}_report.md`);
      });
    });
  }

  test('Downloaded reports for distinct incidents are strictly independent', () => {
    const r1 = mockReport('INC-0001');
    const r2 = mockReport('INC-0002');
    const r9 = mockReport('INC-0009');

    const json1 = JSON.parse(formatReportJson(r1));
    const json2 = JSON.parse(formatReportJson(r2));
    const json9 = JSON.parse(formatReportJson(r9));

    assert.notEqual(json1.incident_id, json2.incident_id);
    assert.notEqual(json2.incident_id, json9.incident_id);
    assert.notEqual(json1.incident_id, json9.incident_id);

    assert.equal(json1.incident_id, 'INC-0001');
    assert.equal(json2.incident_id, 'INC-0002');
    assert.equal(json9.incident_id, 'INC-0009');
  });

  test('formatReportJson and formatReportMarkdown throw meaningful errors on empty input', () => {
    assert.throws(() => formatReportJson(null), /Cannot export empty report/);
    assert.throws(() => formatReportJson({}), /Cannot export empty report/);
    assert.throws(() => formatReportMarkdown(null, null), /Cannot export empty report/);
    assert.throws(() => formatReportMarkdown(null, {}), /Cannot export empty report/);
    assert.throws(() => formatReportMarkdown(null, 'not an object'), /Cannot export empty report/);
  });
});

