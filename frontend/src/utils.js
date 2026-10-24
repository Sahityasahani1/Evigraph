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

  return JSON.stringify(report, null, 2);
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
    return report.report_markdown.trim();
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
