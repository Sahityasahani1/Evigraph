import './styles.css';
import {
  getIncident,
  getInvestigation,
  getInvestigationEvidence,
  getInvestigationIncidents,
  getInvestigationReport,
  getReport,
  listIncidents,
  startInvestigation,
} from './api/client.js';
import { USE_MOCK } from './config.js';
import { downloadFile, esc } from './utils.js';
import { AttackGraph } from './scene/AttackGraph.js';
import { createReportExport } from './ui/reportExport.js';
import {
  attackMappingsHtml,
  evidenceHtml,
  eventButtonHtml,
  filteredEvents,
  incidentCardHtml,
  incidentMatches,
  overviewHtml,
  observedReplayEvents,
  reportHtml,
  timelineEvents,
} from './ui/dashboard.js';

const $ = id => document.getElementById(id);
const state = {
  incidents: [],
  incident: null,
  sourceKey: null,
  jobId: null,
  report: null,
  reportStatus: 'idle',
  events: [],
  selectedEventKey: null,
  selectedStage: null,
  selectedHost: null,
  selectedFlowId: null,
  embeddedEvidence: null,
  retrievedEvidence: null,
  evidenceError: '',
  graph: null,
  replayEvents: [],
  replayIndex: -1,
  replayTimer: null,
};
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

state.graph = new AttackGraph($('attackGraph'), selection => {
  pauseReplay();
  if (selection.stage) selectStage(selection.stage);
  else if (selection.host) selectHost(selection.host);
});

function sourceLabel(incident) {
  if (state.jobId || incident?.inference_source === 'fresh') {
    const detector = incident?.detector_label || incident?.detection_model;
    const name = detector === 'gnn_legacy_migrated'
      ? 'GraphSAGE migrated legacy · temporal isolation unverified'
      : detector === 'gnn' ? 'GraphSAGE GNN' : detector === 'xgb' ? 'XGBoost' : '';
    return name ? `Fresh inference · ${name}` : 'Fresh inference';
  }
  return USE_MOCK ? 'Prepared / demo' : 'Prepared incident';
}

function setConnection(text, isError = false) {
  $('connectionStatus').textContent = text;
  $('connectionStatus').parentElement.classList.toggle('connection-error', isError);
}

function showLoadError(message) {
  $('investigation').hidden = true;
  $('loadState').hidden = false;
  $('loadState').className = 'state-card state-error';
  $('loadState').innerHTML = `<span class="state-symbol" aria-hidden="true">!</span><div><strong>Unable to load investigations</strong><p>${esc(message)}</p><button type="button" id="retryLoad" class="button button-secondary">Retry connection</button></div>`;
}

function renderIncidentList() {
  const search = $('incidentSearch').value;
  const level = $('severityFilter').value;
  const visible = state.incidents.filter(incident => incidentMatches(incident, search, level));
  $('incidentCount').textContent = String(state.incidents.length);
  $('incidentList').innerHTML = visible.length
    ? visible.map(incident => incidentCardHtml(incident, state.sourceKey)).join('')
    : `<div class="empty-state list-empty"><strong>No matching incidents</strong><p>Adjust the search or severity filter.</p></div>`;
}

async function refreshIncidents() {
  $('incidentList').innerHTML = '<div class="inline-loading"><span class="spinner small"></span> Loading incidents…</div>';
  try {
    const incidents = await listIncidents();
    state.incidents = incidents.map(incident => ({
      ...incident,
      _sourceKey: incident.inference_source === 'fresh' && incident.investigation_job_id
        ? `fresh:${incident.investigation_job_id}:${incident.incident_id}`
        : incident.incident_id,
    }));
    setConnection('API connected');
    renderIncidentList();
    if (!state.incidents.length) {
      $('incidentList').innerHTML = '<div class="empty-state list-empty"><strong>No incidents returned</strong><p>Run an investigation or check the backend incident store.</p></div>';
      $('loadState').className = 'state-card';
      $('loadState').innerHTML = '<span class="state-symbol" aria-hidden="true">—</span><div><strong>No incidents available</strong><p>Choose a flow file and run an investigation to create a fresh case.</p></div>';
      return;
    }
    await selectIncident(state.incidents[0]._sourceKey);
  } catch (error) {
    setConnection('API unavailable', true);
    $('incidentList').innerHTML = `<div class="empty-state list-empty"><strong>Incident list unavailable</strong><p>${esc(error.message)}</p><button type="button" class="button button-secondary" id="retryList">Retry</button></div>`;
    showLoadError(error.message);
  }
}

async function selectIncident(sourceKey) {
  const listItem = state.incidents.find(item => item._sourceKey === sourceKey);
  if (!listItem) return;
  $('investigation').hidden = true;
  $('loadState').hidden = false;
  $('loadState').className = 'state-card';
  $('loadState').innerHTML = '<span class="spinner" aria-hidden="true"></span><div><strong>Loading incident</strong><p>Retrieving incident details from the configured backend.</p></div>';
  renderIncidentList();
  try {
    const incident = listItem.inference_source === 'fresh' && listItem.investigation_job_id
      ? (await getInvestigationIncidents(listItem.investigation_job_id)).find(item => item.incident_id === listItem.incident_id)
      : await getIncident(listItem.incident_id);
    if (!incident) throw new Error(`The API did not return incident ${listItem.incident_id}.`);
    state.incident = { ...incident, inference_source: listItem.inference_source || incident.inference_source };
    state.sourceKey = sourceKey;
    renderIncidentList();
    state.jobId = listItem.investigation_job_id || null;
    state.report = null;
    state.reportStatus = 'loading';
    state.events = timelineEvents(state.incident);
    stopReplay();
    state.replayEvents = observedReplayEvents(state.events);
    configureReplay();
    state.selectedEventKey = state.events[0]?.key ?? null;
    const first = state.events[0];
    state.selectedStage = first?.stage ?? null;
    state.selectedHost = null;
    state.selectedFlowId = first?.evidence?.flow_id ?? null;
    state.embeddedEvidence = first?.evidence ?? null;
    state.retrievedEvidence = null;
    state.evidenceError = '';
    state.graph.setIncident(state.incident);
    state.graph.setSelection(first ? { stage: first.stage.stage_id } : null);
    $('loadState').hidden = true;
    $('investigation').hidden = false;
    renderInvestigation();
    renderEvents();
    renderEvidence();
    loadReport();
    if (state.selectedFlowId) loadEvidence(state.selectedFlowId);
  } catch (error) {
    showLoadError(error.message);
  }
}

function renderInvestigation() {
  const incident = state.incident;
  if (!incident) return;
  $('incidentOverview').innerHTML = overviewHtml(incident, sourceLabel(incident));
  $('mode').textContent = sourceLabel(incident).toUpperCase();
  $('mode').className = `source-badge ${state.jobId ? 'source-fresh' : 'source-prepared'}`;
  state.graph.setSelection(
    {
      ...(state.selectedHost ? { host: state.selectedHost } : {}),
      ...(state.selectedStage ? { stage: state.selectedStage.stage_id } : {}),
    },
  );
  $('attackMappings').innerHTML = attackMappingsHtml(state.report, state.reportStatus);
  $('reportContent').innerHTML = reportHtml(state.report, state.reportStatus, incident);
}

function renderEvents() {
  const events = filteredEvents(state.events, $('eventSearch').value, $('eventTypeFilter').value);
  $('timeline').innerHTML = events.length
    ? events.map(event => eventButtonHtml(event, state.selectedEventKey)).join('')
    : '<div class="empty-state compact-empty"><strong>No matching activity</strong><p>Change the event filter or search query.</p></div>';
}

function configureReplay() {
  const progress = $('replayProgress');
  progress.max = String(state.replayEvents.length);
  progress.value = '0';
  progress.disabled = state.replayEvents.length === 0;
  $('replayToggle').disabled = state.replayEvents.length === 0;
  $('replayRestart').disabled = state.replayEvents.length === 0;
  $('replayToggle').textContent = 'Play';
  $('replayToggle').setAttribute('aria-label', 'Play observed evidence replay');
  $('replayStatus').textContent = state.replayEvents.length
    ? `Ready · ${state.replayEvents.length} observed evidence events`
    : 'No observed evidence to replay';
}

function stopReplay() {
  if (state.replayTimer) clearInterval(state.replayTimer);
  state.replayTimer = null;
}

function replayStep(index) {
  if (!state.replayEvents.length) return;
  const bounded = Math.max(0, Math.min(index, state.replayEvents.length - 1));
  state.replayIndex = bounded;
  const event = state.replayEvents[bounded];
  state.graph.setReplay(event.stage.stage_id);
  selectEvent(event.key);
  $('replayProgress').value = String(bounded + 1);
  $('replayStatus').textContent = `Observed event ${bounded + 1} of ${state.replayEvents.length} · ${event.stage.tactic || 'Activity'}`;
}

function playReplay() {
  if (!state.replayEvents.length || state.replayTimer) return;
  if (state.replayIndex >= state.replayEvents.length - 1) state.replayIndex = -1;
  replayStep(state.replayIndex + 1);
  if (state.replayIndex >= state.replayEvents.length - 1) return;
  $('replayToggle').textContent = 'Pause';
  $('replayToggle').setAttribute('aria-label', 'Pause observed evidence replay');
  state.replayTimer = setInterval(() => {
    if (state.replayIndex >= state.replayEvents.length - 1) {
      stopReplay();
      $('replayToggle').textContent = 'Play';
      $('replayToggle').setAttribute('aria-label', 'Play observed evidence replay');
      return;
    }
    replayStep(state.replayIndex + 1);
    if (state.replayIndex >= state.replayEvents.length - 1) {
      stopReplay();
      $('replayToggle').textContent = 'Play';
      $('replayToggle').setAttribute('aria-label', 'Play observed evidence replay');
    }
  }, 1200);
}

function pauseReplay() {
  stopReplay();
  $('replayToggle').textContent = 'Play';
  $('replayToggle').setAttribute('aria-label', 'Play observed evidence replay');
}

function restartReplay() {
  pauseReplay();
  state.replayIndex = -1;
  state.graph.setReplay(null);
  $('replayProgress').value = '0';
  $('replayStatus').textContent = state.replayEvents.length
    ? `Ready · ${state.replayEvents.length} observed evidence events`
    : 'No observed evidence to replay';
}

function renderEvidence() {
  $('evidenceInspector').innerHTML = evidenceHtml(
    state.incident,
    state.selectedStage,
    state.embeddedEvidence,
    state.retrievedEvidence,
    sourceLabel(state.incident),
  );
  if (state.evidenceError) $('evidenceInspector').insertAdjacentHTML('beforeend', `<p class="inline-error">${esc(state.evidenceError)}</p>`);
  if (state.selectedHost && !state.selectedStage) {
    const host = state.incident.hosts?.find(item => item.id === state.selectedHost);
    $('evidenceInspector').innerHTML = host
      ? `<div class="host-inspector"><span class="eyebrow">SELECTED HOST</span><h3>${esc(host.id || 'Host')}</h3><dl class="evidence-fields">${[['IP address', host.ip], ['Role', host.role], ['Network zone', host.zone]].filter(([, value]) => value).map(([label, value]) => `<div class="evidence-field"><dt>${label}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl><p class="inline-note">Select a connected path or timeline event to inspect flow evidence.</p></div>`
      : '<div class="empty-state compact-empty">Host details were not returned.</div>';
  }
}

function selectStage(stageId) {
  const stage = state.incident?.stages?.find(item => item.stage_id === stageId);
  if (!stage) return;
  const event = state.events.find(item => item.stage.stage_id === stageId);
  syncReplaySelection(event);
  state.selectedStage = stage;
  state.selectedHost = null;
  state.selectedEventKey = event?.key ?? null;
  state.selectedFlowId = event?.evidence?.flow_id ?? null;
  state.embeddedEvidence = event?.evidence ?? null;
  state.retrievedEvidence = null;
  state.evidenceError = '';
  state.graph.setSelection({ stage: stageId });
  renderEvents();
  renderEvidence();
  if (state.selectedFlowId) loadEvidence(state.selectedFlowId);
}

function selectHost(hostId) {
  const related = state.events.find(event => event.stage.src === hostId || event.stage.dst === hostId);
  syncReplaySelection(related);
  state.selectedHost = hostId;
  if (related) {
    state.selectedStage = related.stage;
    state.selectedEventKey = related.key;
    state.selectedFlowId = related.evidence?.flow_id ?? null;
    state.embeddedEvidence = related.evidence;
    state.retrievedEvidence = null;
    state.evidenceError = '';
    if (state.selectedFlowId) loadEvidence(state.selectedFlowId);
  } else {
    state.selectedStage = null;
    state.selectedEventKey = null;
    state.selectedFlowId = null;
    state.embeddedEvidence = null;
    state.retrievedEvidence = null;
  }
  state.graph.setSelection({ host: hostId, ...(related ? { stage: related.stage.stage_id } : {}) });
  renderEvents();
  renderEvidence();
}

function selectEvent(eventKey) {
  const event = state.events.find(item => item.key === eventKey);
  if (!event) return;
  syncReplaySelection(event);
  state.selectedEventKey = event.key;
  state.selectedStage = event.stage;
  state.selectedHost = null;
  state.selectedFlowId = event.evidence?.flow_id ?? null;
  state.embeddedEvidence = event.evidence;
  state.retrievedEvidence = null;
  state.evidenceError = '';
  state.graph.setSelection({ stage: event.stage.stage_id });
  renderEvents();
  renderEvidence();
  if (state.selectedFlowId) loadEvidence(state.selectedFlowId);
}

function syncReplaySelection(event) {
  const progress = $('replayProgress');
  const status = $('replayStatus');
  if (!event) {
    state.replayIndex = -1;
    progress.value = '0';
    state.graph.setReplay(null);
    status.textContent = state.replayEvents.length
      ? `Ready · ${state.replayEvents.length} observed evidence events`
      : 'No observed evidence to replay';
    return;
  }
  const replayPosition = state.replayEvents.findIndex(item => item.key === event.key);
  if (replayPosition >= 0) {
    state.replayIndex = replayPosition;
    progress.value = String(replayPosition + 1);
    state.graph.setReplay(event.stage.stage_id);
    status.textContent = `Selected observed event ${replayPosition + 1} of ${state.replayEvents.length}`;
  } else {
    state.replayIndex = -1;
    progress.value = '0';
    state.graph.setReplay(null);
    status.textContent = 'Inferred or unsupported activity is excluded from replay';
  }
}

async function selectEvidenceReference(flowId) {
  const event = state.events.find(item => item.evidence?.flow_id === flowId);
  if (event) {
    selectEvent(event.key);
    return;
  }
  state.selectedHost = null;
  state.selectedFlowId = flowId;
  state.retrievedEvidence = null;
  state.evidenceError = '';
  if (state.selectedStage) state.graph.setSelection({ stage: state.selectedStage.stage_id });
  await loadEvidence(flowId);
  if (!state.retrievedEvidence) {
    $('evidenceInspector').innerHTML = `<div class="empty-state"><strong>Referenced flow not in incident stages</strong><p>${esc(flowId)} was referenced by the report but could not be retrieved through the incident evidence API.</p></div>`;
  } else {
    const flow = state.retrievedEvidence.flow ?? {};
    $('evidenceInspector').innerHTML = `<div class="evidence-context"><div class="evidence-context-title"><strong>Report citation</strong><span class="event-kind kind-observed">Retrieved</span></div><p>${esc(flowId)}</p></div><dl class="evidence-fields">${Object.entries({
      'Flow ID': flow.flow_id,
      'Evidence ID': flow.evidence_id,
      Timestamp: flow.timestamp,
      Source: flow.src_ip,
      'Source port': flow.src_port,
      Destination: flow.dst_ip,
      'Destination port': flow.dst_port,
      Protocol: flow.protocol,
      'Input SHA-256': flow.source_sha256,
    }).filter(([, value]) => value !== undefined && value !== null && value !== '').map(([label, value]) => `<div class="evidence-field"><dt>${label}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl>`;
  }
}

async function loadEvidence(flowId) {
  if (!state.jobId || !flowId) return;
  const jobId = state.jobId;
  const incidentId = state.incident.incident_id;
  state.evidenceError = '';
  renderEvidence();
  try {
    const retrieved = await getInvestigationEvidence(jobId, incidentId, flowId);
    if (state.selectedFlowId !== flowId || state.jobId !== jobId || state.incident?.incident_id !== incidentId) return;
    state.retrievedEvidence = retrieved;
    renderEvidence();
  } catch (error) {
    if (state.selectedFlowId !== flowId || state.jobId !== jobId || state.incident?.incident_id !== incidentId) return;
    state.evidenceError = `Evidence API lookup failed: ${error.message}`;
    renderEvidence();
  }
}

async function loadReport() {
  const incidentId = state.incident?.incident_id;
  const sourceKey = state.sourceKey;
  if (!incidentId) return;
  state.reportStatus = 'loading';
  renderInvestigation();
  try {
    const report = state.jobId
      ? await getInvestigationReport(state.jobId, incidentId)
      : await getReport(incidentId);
    if (state.incident?.incident_id !== incidentId || state.sourceKey !== sourceKey) return;
    state.report = report;
    state.reportStatus = 'loaded';
    renderInvestigation();
  } catch (error) {
    if (state.incident?.incident_id !== incidentId || state.sourceKey !== sourceKey) return;
    state.reportStatus = 'error';
    renderInvestigation();
  }
}

async function exportReport(format) {
  if (!state.report && state.reportStatus !== 'loading') await loadReport();
  if (!state.report) return;
  const file = createReportExport(state.incident, state.report, format);
  downloadFile(file.filename, file.content, file.mimeType);
}

async function runFreshInvestigation() {
  const file = $('inputFile').files?.[0];
  const button = $('runInvestigation');
  const progress = $('jobProgress');
  if (!file) {
    progress.hidden = false;
    progress.textContent = 'Choose a supported flow or capture file first.';
    return;
  }
  button.disabled = true;
  progress.hidden = false;
  progress.textContent = 'Uploading input…';
  try {
    const job = await startInvestigation(file, $('detector').value);
    let status = job;
    while (status.status === 'queued' || status.status === 'running') {
      progress.textContent = `${status.stage || 'Investigation running'} · ${status.progress ?? 0}%`;
      await pause(800);
      status = await getInvestigation(job.job_id);
    }
    if (status.status !== 'completed') throw new Error(status.error || 'Investigation did not complete.');
    const incidents = await getInvestigationIncidents(job.job_id);
    const fresh = incidents.map(incident => ({
      ...incident,
      _sourceKey: `fresh:${job.job_id}:${incident.incident_id}`,
      investigation_job_id: job.job_id,
      inference_source: 'fresh',
    }));
    if (!fresh.length) {
      progress.textContent = `Fresh inference complete: ${status.result?.alerts ?? 0} alerts; no incidents were formed.`;
      return;
    }
    state.incidents = [...fresh, ...state.incidents.filter(item => !fresh.some(next => next._sourceKey === item._sourceKey))];
    renderIncidentList();
    progress.textContent = `${status.result?.flows_scored ?? '—'} flows · ${status.result?.alerts ?? '—'} alerts · ${fresh.length} incidents`;
    await selectIncident(fresh[0]._sourceKey);
  } catch (error) {
    progress.textContent = `Investigation failed: ${error.message}`;
  } finally {
    button.disabled = false;
  }
}

document.addEventListener('click', event => {
  const incident = event.target.closest('[data-incident]');
  if (incident) {
    selectIncident(incident.dataset.incident);
    return;
  }
  const eventButton = event.target.closest('[data-event-key]');
  if (eventButton) {
    pauseReplay();
    selectEvent(eventButton.dataset.eventKey);
    return;
  }
  if (event.target.closest('#replayToggle')) {
    if (state.replayTimer) pauseReplay(); else playReplay();
    return;
  }
  if (event.target.closest('#replayRestart')) {
    restartReplay();
    return;
  }
  const citation = event.target.closest('[data-evidence-flow]');
  if (citation) {
    selectEvidenceReference(citation.dataset.evidenceFlow);
    return;
  }
  const exportButton = event.target.closest('[data-export]');
  if (exportButton) {
    exportReport(exportButton.dataset.export).catch(error => {
      $('reportContent').insertAdjacentHTML('afterbegin', `<div class="inline-error">${esc(error.message)}</div>`);
    });
    return;
  }
  if (event.target.closest('[data-retry-report]')) loadReport();
  if (event.target.closest('#retryLoad, #retryList')) refreshIncidents();
});

$('incidentSearch').addEventListener('input', renderIncidentList);
$('severityFilter').addEventListener('change', renderIncidentList);
$('eventSearch').addEventListener('input', renderEvents);
$('eventTypeFilter').addEventListener('change', renderEvents);
$('replayProgress').addEventListener('input', event => {
  pauseReplay();
  const value = Number(event.target.value);
  if (value <= 0) restartReplay();
  else replayStep(value - 1);
});
$('retryIncidents').addEventListener('click', refreshIncidents);
$('runInvestigation').addEventListener('click', runFreshInvestigation);

document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && document.activeElement?.matches('input[type="search"]')) {
    document.activeElement.value = '';
    document.activeElement.dispatchEvent(new Event('input', { bubbles: true }));
  }
});

refreshIncidents();
