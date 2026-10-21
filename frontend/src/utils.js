import { NO_TECHNIQUE_EVIDENCE, normalizeAttackMatches } from './attackCandidates.js';

// Everything derived from traffic is untrusted (TRD design principle 5): always escape before innerHTML.
export const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const clockAt = (startIso, minutes) => {
  if (!startIso || minutes == null || isNaN(Number(minutes))) return '';
  const parsed = Date.parse(startIso);
  if (isNaN(parsed)) return '';
  try {
    return new Date(parsed + Number(minutes) * 60000).toISOString().slice(11, 19) + ' UTC';
  } catch {
    return '';
  }
};

// Format report as clean JSON string preserving all metadata, citations, and validation
export function formatReportJson(report) {
  if (!report || typeof report !== 'object' || Object.keys(report).length === 0) {
    throw new Error('Cannot export empty report');
  }

  const normalizedReport = { ...report };
  if (Object.hasOwn(report, 'attack_matches')) {
    normalizedReport.attack_matches = normalizeAttackMatches(report.attack_matches);
    if (typeof report.report_markdown === 'string' && report.report_markdown.trim()) {
      const baseMarkdown = withoutExistingAttackSection(report.report_markdown.trim());
      normalizedReport.report_markdown = `${baseMarkdown}\n\n${attackMatchesMarkdown(report.attack_matches)}`;
    }
  }
  return JSON.stringify(normalizedReport, null, 2);
}

function attackMatchesMarkdown(attackMatches) {
  const mappings = Object.entries(normalizeAttackMatches(attackMatches ?? {}));
  const lines = ['## Retrieved ATT&CK candidates (not confirmed activity)'];
  if (!mappings.length) {
    lines.push('- No ATT&CK retrieval results were returned.');
    return lines.join('\n');
  }
  for (const [stage, result] of mappings) {
    const matches = result.matches ?? [];
    if (!matches.length) {
      lines.push(`- ${stage}: ${result.status === 'unavailable' ? `retrieval unavailable${result.error ? `: ${result.error}` : ''}` : 'no candidate returned; mapping unsupported'}.`);
      continue;
    }
    for (const match of matches) {
      const tacticValues = Array.isArray(match.tactics) ? match.tactics : (match.tactic ? [match.tactic] : []);
      const tactic = tacticValues.length ? `; tactic ${tacticValues.join(', ')}` : '';
      const status = match.candidate_status === 'evidence_linked_candidate'
        ? 'evidence-linked candidate; analyst review not recorded'
        : 'retrieved candidate; analyst review not recorded';
      const similarity = match.retrieval_similarity !== null
        ? `; Retrieval similarity ${match.retrieval_similarity}` : '';
      const candidateEvidence = match.candidate_evidence;
      const evidenceRefs = [
        ...candidateEvidence.flow_ids.map(id => `flow ${id}`),
        ...candidateEvidence.event_ids.map(id => `event ${id}`),
      ];
      const evidence = evidenceRefs.length
        ? `Candidate-specific supporting references: ${evidenceRefs.join(', ')}${candidateEvidence.reason ? ` (${candidateEvidence.reason})` : ''}.`
        : NO_TECHNIQUE_EVIDENCE;
      const source = match.source_url ? `; source ${match.source_url}` : '';
      lines.push(`- ${stage}: **${match.id || 'Technique ID unavailable'} ${match.name || ''}** (${status}${tactic}${similarity}${source}). ${match.retrieval_reason} ${evidence}`);
    }
  }
  return lines.join('\n');
}

function withoutExistingAttackSection(markdown) {
  const lines = markdown.split(/\r?\n/);
  const start = lines.findIndex(line => /^## ATT&CK (?:retrieval candidates|mapping)\b/i.test(line));
  if (start < 0) return markdown.trim();
  let end = lines.findIndex((line, index) => index > start && /^## /.test(line));
  if (end < 0) end = lines.length;
  lines.splice(start, end - start);
  return lines.join('\n').trim();
}

// Format report as clean GitHub-flavored Markdown
export function formatReportMarkdown(inc, report) {
  if (!report || typeof report !== 'object' || Object.keys(report).length === 0) {
    throw new Error('Cannot export empty report');
  }

  if (
    report.report_markdown &&
    typeof report.report_markdown === 'string' &&
    report.report_markdown.trim()
  ) {
    const provenance = report.provenance ?? {};
    const footer = report.footer ?? {};
    const citations = [...new Set((report.sentences ?? []).flatMap(item => item.evidence_ids ?? []))];
    const lines = [
      '',
      '## Structured provenance and retrieval details',
      `- Inference mode: ${provenance.inference_source || 'not provided'}`,
      `- Detector: ${provenance.detector_label || provenance.detector || 'not provided'}`,
      `- Input SHA-256: ${footer.input_sha256 || provenance.input_sha256 || 'not recorded'}`,
      `- Merkle root: ${footer.merkle_root || provenance.merkle_root || 'not recorded'}`,
      `- ATT&CK retrieval status: ${report.retrieval_status || 'not provided'}`,
      `- Observed evidence flow references in report claims: ${citations.length ? citations.map(id => `[E:${id}]`).join(', ') : 'none returned'}`,
      '',
    ];
    const baseMarkdown = withoutExistingAttackSection(report.report_markdown.trim());
    lines.push(attackMatchesMarkdown(report.attack_matches));
    lines.push('', 'Report conclusions and their validation status are shown above. Retrieval similarity is not confidence or confirmation of adversary behavior.');
    return `${baseMarkdown}\n\n${lines.join('\n').trim()}`;
  }

  const iid = report.incident_id || inc?.incident_id || 'Unknown';
  const v = report.validation;

  const verificationSummary = v
    ? `- Findings proposed: ${v.total}, accepted: ${v.valid}, rejected: ${v.rejected}`
    : '- Verification details unavailable in the report data.';

  const summary =
    report.summary ||
    (report.summary_withheld_reason
      ? `(Summary withheld: ${report.summary_withheld_reason})`
      : report.factual_summary) ||
    `Forensic investigation report for incident ${iid}.`;

  const lines = [
    `# Incident Report: ${iid}`,
    '',
    '## Executive Summary',
    summary,
    '',
    '## Verification & Integrity',
    verificationSummary,
    `- Input Fingerprint: ${report.footer?.input_sha256 || 'not recorded'}`,
    `- Merkle Root: ${report.footer?.merkle_root || 'not recorded'}`,
    `- Run Manifest: ${report.footer?.manifest_id || 'not recorded'}`,
    `- MITRE ATT&CK Version: ${report.footer?.attack_version || 'not recorded'}`,
    '',
    '## Timeline & Findings',
  ];

  (report.sentences || []).forEach((s, i) => {
    const tags = (s.evidence_ids || []).map(id => `[E:${id}]`).join(' ');
    lines.push(`${i + 1}. ${s.text}${tags ? ' ' + tags : ''}`);
  });

  if ((report.rejected_findings || []).length) {
    lines.push('', '## Rejected Claims');
    report.rejected_findings.forEach(rf => {
      const claim = rf.finding?.claim || rf.claim || 'Unverified claim';
      const reason =
        (rf.problems || []).join('; ') || 'Unsupported evidence reference';
      lines.push(`- **Rejected:** ${claim} (Reason: ${reason})`);
    });
  }

  lines.push('', attackMatchesMarkdown(report.attack_matches));
  lines.push('', 'Retrieved ATT&CK candidates are suggestions and are not observed activity.');

  return lines.join('\n');
}

// Safe client-side file download helper (works in browser; returns descriptor in node)
export function downloadFile(filename, content, mimeType = 'text/plain;charset=utf-8') {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return { filename, content, mimeType };
  }
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return { filename, size: blob.size };
}
