import { formatReportJson, formatReportMarkdown } from '../utils.js';

export function createReportExport(incident, report, format) {
  const incidentId = incident?.incident_id || report?.incident_id || 'incident';
  if (format === 'json') {
    return {
      filename: `${incidentId}_investigation.json`,
      content: formatReportJson(report),
      mimeType: 'application/json',
    };
  }
  if (format === 'md') {
    return {
      filename: `${incidentId}_investigation.md`,
      content: formatReportMarkdown(incident, report),
      mimeType: 'text/markdown;charset=utf-8',
    };
  }
  throw new Error(`Unsupported export format: ${format}`);
}
