import { esc } from '../utils.js';
import { normalizeAttackMatches } from '../attackCandidates.js';

const numeric = value => value !== null && value !== undefined && value !== '' && Number.isFinite(Number(value));
const severityOf = (score, supplied) => {
  const label = String(supplied ?? '').trim().toLowerCase();
  if (['critical', 'high', 'medium', 'low'].includes(label)) return label;
  if (label === 'severe') return 'critical';
  if (!numeric(score)) return 'unknown';
  if (Number(score) >= 0.9) return 'critical';
  if (Number(score) >= 0.75) return 'high';
  if (Number(score) >= 0.5) return 'medium';
  return 'low';
};

export const severity = severityOf;
export const severityLabel = score => severityOf(score).toUpperCase();

export function incidentMatches(incident, search, level) {
  const query = search.trim().toLowerCase();
  const matchesSeverity = level === 'all' || severityOf(incident.score, incident.severity) === level;
  const searchable = [
    incident.incident_id,
    incident.status,
    ...(incident.hosts ?? []).flatMap(host => [host.id, host.ip, host.role]),
  ].join(' ').toLowerCase();
  return matchesSeverity && (!query || searchable.includes(query));
}

export function mergeIncidents(existingList = [], incomingList = [], { isFresh = false } = {}) {
  const incoming = incomingList.map(incident => ({
    ...incident,
    _sourceKey: incident._sourceKey || (
      incident.inference_source === 'fresh' && incident.investigation_job_id
        ? `fresh:${incident.investigation_job_id}:${incident.incident_id}`
        : incident.incident_id
    ),
  }));

  if (isFresh) {
    const incomingJobIds = new Set(incoming.map(i => i.investigation_job_id).filter(Boolean));
    const incomingShaModels = new Set(
      incoming
        .filter(i => i.source_sha256)
        .map(i => `${i.source_sha256}:${i.detection_model || i.detector_label || ''}`)
    );
    const incomingIds = new Set(incoming.map(i => i.incident_id));

    const preserved = existingList.filter(item => {
      if (item.investigation_job_id && incomingJobIds.has(item.investigation_job_id)) return false;
      if (item.inference_source === 'fresh' && item.source_sha256) {
        const key = `${item.source_sha256}:${item.detection_model || item.detector_label || ''}`;
        if (incomingShaModels.has(key)) return false;
      }
      if (item.inference_source !== 'fresh' && incomingIds.has(item.incident_id)) return false;
      if (incoming.some(inc => inc._sourceKey === item._sourceKey)) return false;
      return true;
    });

    return [...incoming, ...preserved];
  }

  const existingFresh = existingList.filter(item => item.inference_source === 'fresh');
  const freshIds = new Set(existingFresh.map(i => i.incident_id));

  const filteredIncoming = incoming.filter(item => !freshIds.has(item.incident_id));

  const seen = new Set();
  const result = [];
  for (const item of [...existingFresh, ...filteredIncoming]) {
    const key = item._sourceKey || item.incident_id;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(item);
    }
  }
  return result;
}

export function incidentCardHtml(incident, selectedId) {
  const level = severityOf(incident.score, incident.severity);
  const sourceKey = incident._sourceKey || incident.incident_id;
  const hostCount = incident.hosts?.length;
  const isFresh = incident.inference_source === 'fresh';
  const status = isFresh
    ? (incident.detector_label ? `Fresh · ${incident.detector_label.toUpperCase()}` : 'Fresh inference')
    : (incident.status || 'Status unavailable');
  return `<button class="incident-item ${sourceKey === selectedId ? 'selected' : ''}" type="button" data-incident="${esc(sourceKey)}" aria-current="${sourceKey === selectedId ? 'true' : 'false'}">
    <span class="incident-item-top"><span class="severity-dot severity-${level}"></span><strong>${esc(incident.incident_id)}</strong><span class="severity-label severity-text-${level}">${level}</span></span>
    <span class="incident-item-meta">${esc(status)}<span>${hostCount == null ? 'Hosts unavailable' : `${hostCount} hosts`}</span></span>
    <span class="incident-item-time">${esc(formatTime(incident.start))}</span>
  </button>`;
}

export function overviewHtml(incident, sourceLabel) {
  const level = severityOf(incident.score, incident.severity);
  const dates = incident.start || incident.end
    ? `${formatDateTime(incident.start)} <span aria-hidden="true">→</span> ${formatDateTime(incident.end)}`
    : 'Time range unavailable';
  const status = incident.status || 'Status unavailable';
  const alertCount = numeric(incident.total_alerts) ? Number(incident.total_alerts).toLocaleString() : '—';
  const confidence = numeric(incident.confidence)
    ? `${(Number(incident.confidence) * 100).toFixed(0)}%`
    : numeric(incident.score) ? `${(Number(incident.score) * 100).toFixed(0)}% incident score` : 'Not provided';
  const observedCount = (incident.stages ?? []).filter(stage => stage.observed).length;
  const inferredCount = (incident.stages ?? []).filter(stage => stage.interpretation_status === 'inferred' || stage.observed === false).length;
  const summary = incident.summary || incident.factual_summary || (incident.stages ?? []).map(stage => stage.summary).filter(Boolean).slice(0, 2).join(' ');
  return `<div class="overview-top">
    <div class="overview-identity">
      <div class="overview-titleline"><span class="severity-pill severity-bg-${level}">${level}</span><span class="source-pill">${esc(sourceLabel)}</span><span class="status-pill"><i></i>${esc(status)}</span></div>
      <h2>${esc(incident.incident_id)} <span class="overview-subtitle">Investigation</span></h2>
      <p class="overview-summary">${summary ? esc(summary) : 'No incident summary was provided by the API.'}</p>
      ${incident.selection_reason ? `<div class="overview-selection-info"><strong>Detector:</strong> ${esc(incident.detector_label || incident.detection_model || '')} · <em>${esc(incident.selection_reason)}</em>${incident.fallback_reason ? ` (Fallback: ${esc(incident.fallback_reason)})` : ''}</div>` : ''}
    </div>
    <div class="overview-confidence"><span class="eyebrow">CONFIDENCE / SCORE</span><strong>${esc(confidence)}</strong><span>${numeric(incident.score) ? `${Number(incident.score).toFixed(2)} normalized score` : 'No confidence or score returned'}</span></div>
  </div>
  <div class="metric-strip">
    <div class="metric"><span class="metric-label">Affected hosts</span><strong>${incident.hosts?.length ?? '—'}</strong><span>${incident.hosts?.length == null ? 'Not returned' : 'in incident graph'}</span></div>
    <div class="metric"><span class="metric-label">Alert count</span><strong>${alertCount}</strong><span>${alertCount === '—' ? 'Not returned' : 'correlated alerts'}</span></div>
    <div class="metric metric-time"><span class="metric-label">Time range</span><strong>${dates}</strong><span>${(incident.stages ?? []).length} reported stages · ${observedCount} with observed evidence · ${inferredCount} inferred mappings</span></div>
    <div class="metric"><span class="metric-label">Input SHA-256</span><strong class="hash-value">${incident.source_sha256 ? esc(incident.source_sha256) : 'Not available'}</strong><span>${incident.source_sha256 ? 'source provenance recorded' : 'not returned by this API route'}</span></div>
  </div>`;
}

export function timelineEvents(incident) {
  const events = [];
  for (const stage of incident.stages ?? []) {
    const evidence = stage.evidence ?? [];
    const inferred = stage.interpretation_status === 'inferred' || stage.observed === false || !evidence.length;
    if (!evidence.length) {
      events.push({
        key: `${stage.stage_id}:stage`,
        stage,
        evidence: null,
        timestamp: stage.start || null,
        observed: false,
        inferred,
      });
      continue;
    }
    for (const [index, item] of evidence.entries()) {
      events.push({
        key: `${stage.stage_id}:${item.flow_id ?? index}`,
        stage,
        evidence: item,
        timestamp: item.ts || stage.start || null,
        observed: stage.observed !== false,
        inferred,
      });
    }
  }
  return events.sort((a, b) => timeValue(a.timestamp) - timeValue(b.timestamp));
}

// Replay is restricted to timeline records that cite an observed flow.
export const observedReplayEvents = events => events.filter(event =>
  event.observed && !event.inferred && Boolean(event.evidence?.flow_id),
);

export function filteredEvents(events, query, kind) {
  const q = query.trim().toLowerCase();
  return events.filter(event => {
    const isObserved = event.observed;
    if (kind === 'observed' && !isObserved) return false;
    if (kind === 'inferred' && !event.inferred) return false;
    const searchable = [
      event.timestamp,
      event.stage.tactic,
      event.stage.tactic_id,
      event.stage.summary,
      event.stage.src,
      event.stage.dst,
      event.stage.port,
      event.evidence?.flow_id,
    ].join(' ').toLowerCase();
    return !q || searchable.includes(q);
  });
}

export function eventButtonHtml(event, selectedKey) {
  const { stage, evidence } = event;
  const observedLabel = event.observed ? 'Observed evidence' : 'No cited flow';
  const inferenceBadge = event.inferred ? '<span class="event-kind kind-inferred">Inferred stage</span>' : '';
  const selected = event.key === selectedKey;
  return `<button type="button" class="timeline-event ${selected ? 'selected' : ''}" data-event-key="${esc(event.key)}" data-stage="${esc(stage.stage_id)}" data-flow="${esc(evidence?.flow_id ?? '')}" aria-pressed="${selected}">
    <span class="timeline-time">${esc(formatTime(event.timestamp))}</span>
    <span class="timeline-marker ${event.observed ? 'marker-observed' : 'marker-inferred'}" aria-hidden="true"></span>
    <span class="timeline-event-body"><span class="timeline-event-heading"><strong>${esc(stage.tactic || 'Unclassified activity')}</strong><span class="event-kind ${event.observed ? 'kind-observed' : 'kind-inferred'}">${observedLabel}</span></span>
      ${inferenceBadge}
      <span class="timeline-route">${esc(stage.src || 'Source unavailable')} <span aria-hidden="true">→</span> ${esc(stage.dst || 'Destination unavailable')}${stage.port ? ` · port ${esc(stage.port)}` : ''}</span>
      <span class="timeline-summary">${esc(stage.summary || 'No event summary returned.')}</span>
      <span class="timeline-flow">${evidence?.flow_id ? `Flow ${esc(evidence.flow_id)}` : 'No flow reference returned'}${stage.tactic_id ? ` · ${esc(stage.tactic_id)}` : ''}</span>
    </span>
  </button>`;
}

export function evidenceHtml(incident, stage, evidence, retrieved, sourceLabel) {
  if (!stage) return `<div class="empty-state"><span class="empty-icon">⌖</span><strong>Select a graph relationship or timeline event</strong><p>Available flow and alert details will appear here.</p></div>`;
  const display = retrieved?.flow || evidence || {};
  const fields = [
    ['Flow ID', display.flow_id],
    ['Evidence ID', display.evidence_id],
    ['Timestamp', display.timestamp || display.ts],
    ['Source', display.src_ip || display.source],
    ['Source port', display.src_port],
    ['Destination', display.dst_ip || display.destination],
    ['Reported port(s)', display.dst_port || stage.port],
    ['Protocol', display.protocol],
    ['Input SHA-256', display.source_sha256 || display.pcap_sha256 || incident.source_sha256],
    ['Merkle leaf hash', retrieved?.merkle_leaf_hash || display.merkle_leaf_hash || display.sha256],
    ['Merkle root', retrieved?.merkle_root || incident.merkle_root],
    ['Merkle verification', (retrieved?.merkle_verified ?? display.merkle_verified) === true ? 'Verified (RFC 6962 inclusion proof valid)' : (retrieved?.merkle_verified ?? display.merkle_verified) === false ? 'Unverified / No inclusion proof' : ((retrieved?.merkle_leaf_hash || display.merkle_leaf_hash) ? 'Verified inclusion proof available' : undefined)],
    ['Detector class', stage.behavior],
    ['Alert details', stage.summary],
  ];
  const rows = fields.filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([label, value]) => `<div class="evidence-field"><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('');
  const status = stage.interpretation_status === 'inferred' || stage.observed === false
    ? '<span class="event-kind kind-inferred">Inferred interpretation</span>'
    : '<span class="event-kind kind-observed">Observed record</span>';
  const confidence = numeric(stage.confidence)
    ? `<span class="confidence-readout">${(Number(stage.confidence) * 100).toFixed(0)}% stage confidence</span>` : '';
  const retrieval = retrieved
    ? '<p class="inline-note success-note">Flow record retrieved from the investigation evidence API.</p>'
    : !sourceLabel.startsWith('Fresh inference')
      ? '<p class="inline-note">Prepared incident route has no raw-flow lookup endpoint. Only fields embedded in the incident response are shown.</p>'
      : '';
  const sourceAddress = incident.hosts?.find(host => host.id === stage.src)?.ip || stage.src;
  const targetAddress = incident.hosts?.find(host => host.id === stage.dst)?.ip || stage.dst;
  return `<div class="evidence-context"><div class="evidence-context-title"><strong>${esc(stage.tactic || 'Activity')}</strong>${status}</div>
    <p>${esc(sourceAddress || 'Source unavailable')} <span aria-hidden="true">→</span> ${esc(targetAddress || 'Destination unavailable')}</p>${confidence}</div>
    <dl class="evidence-fields">${rows || '<div class="empty-state compact-empty">No evidence fields were supplied for this selection.</div>'}</dl>${retrieval}`;
}

export function attackMappingsHtml(report, reportStatus) {
  if (reportStatus === 'loading') return '<div class="inline-loading"><span class="spinner small"></span> Retrieving report and mappings...</div>';
  if (reportStatus === 'error') return '<div class="inline-error">ATT&amp;CK and report data could not be loaded. Use Retry in the report panel.</div>';
  if (!report) return '<div class="empty-state compact-empty">No report or ATT&amp;CK result has been returned for this incident.</div>';
  const mappings = Object.entries(normalizeAttackMatches(report.attack_matches ?? {}));
  if (!mappings.length) return '<div class="empty-state compact-empty">The report returned no ATT&amp;CK mappings.</div>';
  let hasCandidates = false;
  let hasCandidateEvidence = false;
  const groupsHtml = mappings.map(([stageName, result]) => {
    const data = Array.isArray(result) ? { status: 'demo', matches: result } : (result ?? {});
    if (data.status === 'unavailable' || data.retrieval_status === 'unavailable') {
      return `<div class="mapping-group"><strong>${esc(stageName)}</strong><p class="mapping-unavailable">Retrieval unavailable${data.error ? `: ${esc(data.error)}` : '.'}</p></div>`;
    }
    if (!data.matches?.length) return `<div class="mapping-group"><strong>${esc(stageName)}</strong><p class="muted-small">No technique returned; mapping unsupported.</p></div>`;
    hasCandidates = true;
    return `<div class="mapping-group"><strong>${esc(stageName)}</strong>${data.matches.map(match => {
      const evidenceLinked = match.candidate_status === 'evidence_linked_candidate';
      hasCandidateEvidence ||= evidenceLinked;
      const candidateKind = data.status === 'demo'
        ? 'Prepared candidate'
        : evidenceLinked ? 'Evidence-linked candidate' : 'Retrieved candidate';
      const source = typeof match.source_url === 'string' && match.source_url.startsWith('https://')
        ? `<a href="${esc(match.source_url)}" target="_blank" rel="noopener noreferrer">ATT&amp;CK source</a>` : '';
      const flowIds = match.candidate_evidence.flow_ids;
      const evidenceIds = match.candidate_evidence.event_ids;
      const technique = `<span class="mapping-technique-id">${esc(match.id || 'Technique unavailable')}</span><span class="mapping-technique-name">${esc(match.name || '')}</span>`;
      const tactics = Array.isArray(match.tactics) ? match.tactics : (match.tactic ? [match.tactic] : []);
      const similarity = match.retrieval_similarity !== null
        ? `<span class="retrieval-similarity">Retrieval similarity <strong>${Number(match.retrieval_similarity).toFixed(3)}</strong></span>` : '';
      const detail = evidenceLinked
        ? 'Retrieved by semantic similarity between the stage investigation query and ATT&CK technique text. Candidate-specific references are listed above; analyst review is still required.'
        : 'Retrieved by semantic similarity between the stage investigation query and ATT&CK technique text. No technique-specific evidence is available.';
      const candidateRefs = flowIds.length || evidenceIds.length
        ? `<div class="mapping-evidence"><span>Candidate-specific references:</span> ${flowIds.map(id => `<button type="button" class="text-link" data-evidence-flow="${esc(id)}">${esc(id)}</button>`).concat(evidenceIds.map(id => `<span>${esc(id)}</span>`)).join(', ')}${match.candidate_evidence.reason ? `<p>${esc(match.candidate_evidence.reason)}</p>` : ''}</div>` : '';
      const techniqueLink = source
        ? `<a href="${esc(match.source_url)}" target="_blank" rel="noopener noreferrer">${technique}</a>`
        : technique;
      return `<article class="mapping-card"><div class="mapping-card-head"><div class="mapping-technique">${techniqueLink}</div>${similarity}</div>
        <div class="mapping-card-meta">${tactics.length ? `<span class="mapping-tactic">Tactic: ${tactics.map(esc).join(', ')}</span>` : '<span class="mapping-tactic">Tactic unavailable</span>'}<span class="mapping-kind">${esc(candidateKind)}</span><span class="mapping-state">Needs review</span></div>
        ${candidateRefs}
        <details class="attack-candidate-details"><summary>Why this candidate?</summary><p>${esc(detail)}</p></details>
      </article>`;
    }).join('')}${data.retrieval_query_context?.flow_ids?.length ? `<div class="muted-small">Stage query context only; not technique-specific evidence.</div>` : ''}</div>`;
  }).join('');
  const explanation = hasCandidateEvidence
    ? 'Candidates are ranked by retrieval similarity. Candidate-specific references are shown where available; analyst review is required.'
    : 'Candidates are ranked by retrieval similarity. No technique-specific evidence is available; analyst review is required.';
  return `${hasCandidates ? `<p class="attack-panel-explanation">${explanation}</p>` : ''}<div class="attack-candidate-list" role="region" aria-label="ATT&amp;CK candidate list">${groupsHtml}</div><p class="panel-footnote">Retrieved candidates are suggestions, not observed activity. This application does not record analyst confirmation or rejection.</p>`;
}
export function reportHtml(report, reportStatus, incident) {
  if (reportStatus === 'loading') return '<div class="inline-loading"><span class="spinner small"></span> Building evidence-grounded report…</div>';
  if (reportStatus === 'error') return '<div class="report-error"><strong>Report unavailable</strong><p>The backend could not return this incident report. The rest of the investigation remains available.</p><button type="button" class="button button-secondary" data-retry-report>Retry report</button></div>';
  if (!report) return '<div class="empty-state compact-empty">No report is available yet.</div>';
  const validation = report.validation;
  const valid = Number(validation?.valid);
  const total = Number(validation?.total);
  const rejected = Number(validation?.rejected ?? report.rejected_findings?.length ?? 0);
  const hasValidation = Number.isFinite(valid) && Number.isFinite(total);
  const claims = (report.sentences ?? []).map((sentence, index) => {
    const evidence = sentence.evidence_ids ?? [];
    const claimStage = incident.stages?.find(stage => stage.stage_id === sentence.stage_id);
    return `<article class="report-claim"><span class="claim-index">${String(index + 1).padStart(2, '0')}</span><div><p>${esc(sentence.text)}</p>
      ${claimStage ? `<span class="claim-stage">${esc(claimStage.tactic || 'Stage')} · ${esc(claimStage.stage_id)}</span>` : '<span class="claim-stage unsupported">Stage reference not available</span>'}
      <div class="claim-citations">${evidence.length ? evidence.map(id => `<button type="button" class="citation-link" data-evidence-flow="${esc(id)}">Evidence · ${esc(id)}</button>`).join('') : '<span class="missing-evidence">No evidence reference returned</span>'}</div></div></article>`;
  }).join('');
  const summary = report.summary || report.factual_summary;
  const rejectedClaims = (report.rejected_findings ?? []).map(item => {
    const claim = item.finding?.claim || item.claim;
    return `<li><strong>Rejected:</strong> ${esc(claim || 'Claim text unavailable')} <span>${esc((item.problems ?? []).join('; ') || 'Reason not provided')}</span></li>`;
  }).join('');
  return `<div class="report-validation ${hasValidation && valid === total && rejected === 0 ? 'validation-ok' : 'validation-warn'}">
    <strong>${hasValidation ? `${valid}/${total} claims supported` : 'Validation details unavailable'}</strong>
    <span>${rejected ? `${rejected} claim${rejected === 1 ? '' : 's'} rejected` : hasValidation && valid === total ? 'No unsupported claims reported' : 'Review evidence links before relying on these claims'}</span>
  </div>
  ${report.reasoning_status === 'degraded'
    ? `<div class="degraded-note"><strong>Deterministic report · reasoning degraded</strong><span>${esc(report.reasoning_error || 'Local reasoning service is unavailable. No generated findings are claimed.')}</span></div>`
    : report.reasoning_status === 'available'
      ? `<div class="reasoning-status available"><strong>AI reasoning active</strong><span>Local reasoning model grounded this report.</span></div>`
      : ''}
  ${summary ? `<div class="report-summary"><span class="eyebrow">SUMMARY</span><p>${esc(summary)}</p></div>` : ''}
  <div class="report-claims">${claims || '<div class="empty-state compact-empty">The report returned no evidence-linked claims.</div>'}</div>
  ${rejectedClaims ? `<div class="rejected-claims"><strong>Unsupported claims returned by backend</strong><ul>${rejectedClaims}</ul></div>` : ''}
  <div class="report-provenance"><span>Input fingerprint</span><code>${esc(report.footer?.input_sha256 || incident.source_sha256 || 'Not provided')}</code><span>Merkle root</span><code>${esc(report.footer?.merkle_root || incident.merkle_root || 'Not provided')}</code><span>Merkle verification</span><code>${esc((report.footer?.merkle_root || incident.merkle_root) ? 'Verified (RFC 6962 tree)' : 'Not verified')}</code><span>ATT&amp;CK version</span><code>${esc(report.footer?.attack_version || 'Not provided')}</code></div>`;
}

export function formatDateTime(value) {
  if (!value || !Number.isFinite(Date.parse(value))) return 'Time unavailable';
  return new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium', hour12: false });
}

export function formatTime(value) {
  if (!value || !Number.isFinite(Date.parse(value))) return 'Time unavailable';
  return new Date(value).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
}

function timeValue(value) {
  const parsed = value ? Date.parse(value) : NaN;
  return Number.isFinite(parsed) ? parsed : Number.MAX_SAFE_INTEGER;
}


export function containmentHtml(data, status, errorMsg = '') {
  if (status === 'loading') {
    return '<div class="inline-loading"><span class="spinner small"></span> Synthesizing surgical containment rules…</div>';
  }
  if (status === 'error') {
    const detail = errorMsg ? `<p class="error-detail">${esc(errorMsg)}</p>` : '<p>The backend could not synthesize countermeasures for this incident.</p>';
    return `<div class="report-error"><strong>Containment recommendations unavailable</strong>${detail}<button type="button" class="button button-secondary" data-retry-containment>Retry containment</button></div>`;
  }
  if (!data || !data.actions || data.actions.length === 0) {
    return '<div class="empty-state compact-empty">No containment actions required or available for this incident.</div>';
  }

  const actionsHtml = data.actions.map((act, index) => {
    const blast = act.victim_blast_radius || {};
    const blastScore = blast.blast_radius_score !== undefined ? Number(blast.blast_radius_score).toFixed(2) : 'N/A';
    const blastLevel = blast.impact_level || 'UNKNOWN';
    const commands = act.synthesized_commands || {};
    const verify = act.verification_guidance || {};
    const rollback = act.rollback_guidance || {};

    return `<article class="containment-rule-card">
      <div class="containment-rule-head">
        <span class="containment-rule-badge">${esc(act.rule_id || `RULE-${index + 1}`)}</span>
        <strong>${esc(act.action_tier || act.action_type || 'Surgical Edge Drop')}</strong>
        <span class="blast-badge blast-${blastScore >= 0.65 ? 'high' : blastScore >= 0.35 ? 'med' : 'low'}">Blast: ${esc(blastScore)} (${esc(blastLevel)})</span>
      </div>
      <p class="containment-rationale">${esc(act.rationale || '')}</p>
      <div class="containment-meta">
        <span>Target: <code>${esc(act.target_attacker)}</code> → <code>${esc(act.target_victim)}:${esc(act.destination_port)}</code> (${esc(act.protocol || 'TCP')})</span>
        ${blast.recommended_approach ? `<span class="approach-note">Approach: ${esc(blast.recommended_approach)}</span>` : ''}
      </div>
      <div class="containment-commands">
        <div class="command-group">
          <div class="command-label">Linux (iptables)</div>
          <pre class="command-code"><code>${esc(commands.linux_iptables || 'N/A')}</code></pre>
        </div>
        ${commands.windows_powershell ? `
        <div class="command-group">
          <div class="command-label">Windows (PowerShell)</div>
          <pre class="command-code"><code>${esc(commands.windows_powershell)}</code></pre>
        </div>` : ''}
        ${rollback.linux_iptables ? `
        <details class="guidance-details">
          <summary>Verification &amp; Rollback Guidance</summary>
          <div class="guidance-content">
            <p><strong>Verify:</strong> <code>${esc(verify.linux_iptables || '')}</code></p>
            <p><strong>Rollback:</strong> <code>${esc(rollback.linux_iptables || '')}</code></p>
          </div>
        </details>` : ''}
      </div>
    </article>`;
  }).join('');

  return `<div class="containment-advisory-banner">
    <span class="advisory-icon" aria-hidden="true">⚠️</span>
    <div>
      <strong>Advisory Recommendations Only</strong>
      <p>${esc(data.advisory_notice || 'Recommendations must be reviewed before execution. Never executed automatically.')}</p>
    </div>
  </div>
  <div class="containment-rules-list">${actionsHtml}</div>`;
}
