import './styles.css';
import {
  getIncident,
  getInvestigation,
  getInvestigationEvidence,
  getInvestigationIncidents,
  getInvestigationReport,
  getReport,
  getCountermeasures,
  listIncidents,
  startInvestigation,
} from './api/client.js';
import { USE_MOCK, colorOf, css } from './config.js';
import { clockAt, downloadFile, esc } from './utils.js';
import { AttackGraph } from './scene/AttackGraph.js';
import { NetworkScene } from './scene/NetworkScene.js';
import { createReportExport } from './ui/reportExport.js';
import {
  attackMappingsHtml,
  evidenceHtml,
  eventButtonHtml,
  filteredEvents,
  incidentCardHtml,
  incidentMatches,
  mergeIncidents,
  overviewHtml,
  observedReplayEvents,
  reportHtml,
  containmentHtml,
  timelineEvents,
  fullscreenStageCardHtml,
} from './ui/dashboard.js';
import { heroHtml, chainHtml, capHtml } from './ui/panels.js';
import { hostStatus, activeStage, prepareTimelineIncident, findInitialAttacker } from './ui/story.js';
export { findInitialAttacker };
export { prepareTimelineIncident };

const $ = id => document.getElementById(id);
const state = {
  incidents: [],
  incident: null,
  sourceKey: null,
  jobId: null,
  report: null,
  reportStatus: 'idle',
  recovery: null,
  recoveryStatus: 'idle',
  recoveryError: '',
  events: [],
  selectedEventKey: null,
  selectedStage: null,
  selectedHost: null,
  selectedFlowId: null,
  embeddedEvidence: null,
  retrievedEvidence: null,
  evidenceError: '',
  graph: null,
  graphMode: '3d',
  fsGraph: null,
  fsIncident: null,
  fsTime: 0,
  fsPlaying: false,
  fsRaf: null,
  fsLastTick: 0,
  fsActiveId: null,
  fsStKey: '',
  fsSel: null,
  fsSpeed: 1,
  fsAttackerHost: null,
  fsReplayIndex: -1,
  fsReplayTimer: null,
  replayEvents: [],
  replayIndex: -1,
  replayTimer: null,
};
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

function onGraphSelect(selection) {
  if (!selection) return;
  pauseReplay();
  if (selection.stage) selectStage(selection.stage);
  else if (selection.host) selectHost(selection.host);
}

function updateGraphModeToggle() {
  const btn = $('graphModeToggle');
  if (!btn) return;
  const is3D = state.graphMode === '3d';
  btn.textContent = is3D ? '2D' : '3D';
  btn.title = is3D ? 'Switch to 2D view' : 'Switch to 3D view';
  btn.setAttribute('aria-label', is3D ? 'Switch to 2D graph view' : 'Switch to 3D graph view');
  btn.setAttribute('aria-pressed', String(is3D));
  btn.dataset.currentMode = state.graphMode;
}

function initGraph(mode = '3d') {
  const container = $('attackGraph');
  if (!container) return;

  if (state.graph) {
    if (typeof state.graph.dispose === 'function') {
      state.graph.dispose();
    }
    state.graph = null;
    container.innerHTML = '';
  }

  let graph = null;
  if (mode === '3d') {
    try {
      if (typeof document !== 'undefined') {
        const testCanvas = document.createElement('canvas');
        const gl = testCanvas.getContext('webgl2') || testCanvas.getContext('webgl') || testCanvas.getContext('experimental-webgl');
        if (!gl) {
          throw new Error('WebGL not supported');
        }
      }
      graph = new NetworkScene(container, onGraphSelect);
      state.graphMode = '3d';
    } catch (err) {
      console.warn('WebGL initialization failed, falling back to 2D graph:', err);
      container.innerHTML = '';
      graph = new AttackGraph(container, onGraphSelect);
      state.graphMode = '2d';
    }
  } else {
    graph = new AttackGraph(container, onGraphSelect);
    state.graphMode = '2d';
  }

  state.graph = graph;
  updateGraphModeToggle();

  if (state.incident) {
    state.graph.setIncident(state.incident);
    const selection = {
      ...(state.selectedHost ? { host: state.selectedHost } : {}),
      ...(state.selectedStage ? { stage: state.selectedStage.stage_id } : {}),
    };
    if (selection.host || selection.stage) {
      state.graph.setSelection(selection);
    }
    if (state.replayIndex >= 0 && state.replayEvents[state.replayIndex]) {
      state.graph.setReplay(state.replayEvents[state.replayIndex].stage.stage_id);
    }
  }
}

initGraph('3d');

export function getFsReplayRate(inc) {
  if (!inc || !inc.durationMin || inc.durationMin <= 0) return 1.5;
  return Math.max(0.5, inc.durationMin / 20);
}

function getFsStages() {
  return [...(state.incident?.stages || [])].sort((a, b) => {
    const tA = a.start ? Date.parse(a.start) : 0;
    const tB = b.start ? Date.parse(b.start) : 0;
    return tA - tB;
  });
}

function fsSetTime(t) {
  const inc = state.fsIncident;
  if (!inc) return;
  state.fsTime = t;

  const progress = $('fsReplayProgress');
  if (progress) progress.value = String(t);

  const clk = $('fsClock');
  if (clk) {
    clk.textContent = `T+${t.toFixed(1)} min · ${clockAt(inc.start, t) || 'Ready'}`;
  }

  if (state.fsGraph) {
    if (typeof state.fsGraph.setTime === 'function') state.fsGraph.setTime(t);
  }

  const st = hostStatus(inc, t);
  const key = JSON.stringify(st);
  if (key !== state.fsStKey) {
    state.fsStKey = key;
    state.fsGraph?.setStatus?.(st);
  }

  const act = activeStage(inc, t);
  const kind = act ? act.stage_id : (t >= inc.durationMin - 0.05 ? 'END' : 'START');
  if (kind !== state.fsActiveId) {
    state.fsActiveId = kind;
    const cap = $('fsCap');
    if (cap) {
      cap.innerHTML = capHtml(inc, act, kind, state.fsAttackerHost);
      cap.style.setProperty('--c', act ? css(colorOf(act.tactic)) : 'var(--accent, #58cfde)');
    }
    if (act) {
      state.fsGraph?.focus?.(act.stage_id);
      selectStage(act.stage_id);
      const idx = inc.stages.findIndex(s => s.stage_id === act.stage_id);
      if (idx >= 0) state.fsReplayIndex = idx;
    } else if (kind === 'START') {
      const attackerHost = state.fsAttackerHost || findInitialAttacker(inc);
      if (attackerHost) {
        state.fsGraph?.setSelection?.({ host: attackerHost.id });
      }
      state.fsGraph?.focus?.(null);
    } else {
      state.fsGraph?.focus?.(null);
    }
  }

  const playhead = $('fsPlayhead');
  if (playhead && inc.durationMin > 0) {
    playhead.style.left = `${Math.min(100, Math.max(0, (t / inc.durationMin) * 100))}%`;
  }
  document.querySelectorAll('#fsTimeline .fs-tl-seg').forEach(seg => {
    const stageId = seg.dataset.stage;
    const s = inc.stages?.find(x => x.stage_id === stageId);
    if (!s) return;
    const isDone = t > s.t1;
    const isLive = act && act.stage_id === s.stage_id;
    const isTodo = t < s.t0;
    seg.classList.toggle('stage-completed', isDone);
    seg.classList.toggle('stage-active', isLive);
    seg.classList.toggle('stage-upcoming', isTodo);
  });

  document.querySelectorAll('#fullscreenLeft .card, #fullscreenLeft .fs-chain-card').forEach(c => {
    const s = inc.stages.find(x => x.stage_id === (c.dataset.stage || c.dataset.stageId));
    if (!s) return;
    const isDone = t > s.t1;
    const isLive = act && act.stage_id === s.stage_id;
    const isTodo = t < s.t0;
    c.classList.toggle('done', isDone);
    c.classList.toggle('live', isLive);
    c.classList.toggle('todo', isTodo);
    c.classList.toggle('stage-completed', isDone);
    c.classList.toggle('stage-active', isLive);
    c.classList.toggle('stage-upcoming', isTodo);
    if (isLive) {
      c.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' });
    }
  });

  document.querySelectorAll('#fullscreenChain .fs-chain-card').forEach((c, idx) => {
    const s = inc.stages[idx];
    if (!s) return;
    const isLive = act && act.stage_id === s.stage_id;
    const isDone = t > s.t1;
    const isTodo = t < s.t0;
    c.classList.toggle('active', isLive);
    c.classList.toggle('live', isLive);
    c.classList.toggle('done', isDone);
    c.classList.toggle('todo', isTodo);
    c.classList.toggle('stage-active', isLive);
    c.classList.toggle('stage-completed', isDone);
    c.classList.toggle('stage-upcoming', isTodo);
    if (isLive) {
      c.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' });
    }
  });

  renderFsRightSidebar();

  const status = $('fsReplayStatus');
  if (status) {
    status.textContent = act
      ? `${act.tactic || 'Activity'} · ${act.src} → ${act.dst}${act.port ? `:${act.port}` : ''}`
      : 'Ready';
  }
  const stageProgress = $('fsReplayStageProgress');
  if (stageProgress && inc.stages?.length) {
    const currentIdx = act ? inc.stages.findIndex(s => s.stage_id === act.stage_id) : (t >= inc.durationMin - 0.05 ? inc.stages.length - 1 : 0);
    stageProgress.textContent = `Stage ${Math.max(1, currentIdx + 1)} of ${inc.stages.length}`;
  }
}

function fsSetPlay(playing) {
  state.fsPlaying = playing;
  const btn = $('fsPlayPauseBtn');
  if (btn) btn.textContent = playing ? 'Pause' : 'Play';

  if (playing) {
    if (state.fsIncident && state.fsTime >= state.fsIncident.durationMin - 0.05) {
      fsSetTime(0);
    }
    state.fsLastTick = performance.now();
    if (!state.fsRaf) {
      const loop = n => {
        if (!state.fsPlaying) {
          state.fsRaf = null;
          return;
        }
        const dt = Math.min((n - state.fsLastTick) / 1000, 0.1);
        state.fsLastTick = n;
        if (state.fsIncident) {
          const speed = state.fsSpeed || 1;
          const rate = getFsReplayRate(state.fsIncident);
          const newT = Math.min(state.fsTime + dt * rate * speed, state.fsIncident.durationMin);
          fsSetTime(newT);
          if (newT >= state.fsIncident.durationMin) {
            fsSetPlay(false);
            state.fsRaf = null;
            return;
          }
        }
        state.fsRaf = requestAnimationFrame(loop);
      };
      state.fsRaf = requestAnimationFrame(loop);
    }
  } else {
    if (state.fsRaf) {
      cancelAnimationFrame(state.fsRaf);
      state.fsRaf = null;
    }
    if (state.fsReplayTimer) {
      clearInterval(state.fsReplayTimer);
      state.fsReplayTimer = null;
    }
  }
}

function fsPlayReplay() {
  fsSetPlay(true);
}

function fsStopReplay() {
  fsSetPlay(false);
}

function fsRestartReplay() {
  fsSetPlay(false);
  fsSetTime(0);
  state.fsGraph?.fit?.();
  const attackerHost = state.fsAttackerHost || findInitialAttacker(state.fsIncident);
  if (attackerHost) {
    state.fsGraph?.setSelection?.({ host: attackerHost.id });
    selectHost(attackerHost.id);
  }
}

function fsJump(dir) {
  const inc = state.fsIncident;
  if (!inc || !inc.stages?.length) return;
  fsSetPlay(false);
  const t = state.fsTime;
  const target = dir > 0
    ? inc.stages.find(s => s.t0 > t + 0.05)
    : [...inc.stages].reverse().find(s => s.t0 < t - 0.3);
  fsSetTime(target ? target.t0 + 0.01 : (dir > 0 ? inc.durationMin : 0));
}

function fsReplayStep(index) {
  const stages = state.fsIncident?.stages || getFsStages();
  if (!stages.length) return;
  const bounded = Math.max(0, Math.min(index, stages.length - 1));
  state.fsReplayIndex = bounded;
  const stage = stages[bounded];
  if (stage && stage.t0 != null) {
    fsSetTime(stage.t0 + 0.01);
  } else if (stage) {
    state.fsGraph?.setReplay?.(stage.stage_id);
    state.fsGraph?.setSelection?.({ stage: stage.stage_id });
    selectStage(stage.stage_id);
  }
}

function openFullscreen3D() {
  if (!state.incident) return;
  const overlay = $('fullscreenOverlay');
  if (!overlay) return;

  overlay.hidden = false;
  $('fullscreenTitle').textContent = `Incident ${state.incident.incident_id || ''} — 3D Forensic Console`;

  const inc = prepareTimelineIncident(state.incident);
  state.fsIncident = inc;
  state.fsActiveId = null;
  state.fsStKey = '';
  state.fsSel = null;

  const stages = inc.stages || [];
  if ($('fullscreenChainCount')) $('fullscreenChainCount').textContent = String(stages.length);

  const chainEl = $('fullscreenChain');
  if (chainEl) {
    chainEl.hidden = false;
    chainEl.innerHTML = stages.map((s, idx) => fullscreenStageCardHtml(s, idx, idx === 0)).join('');
  }

  const slider = $('fsReplayProgress');
  if (slider) {
    slider.min = '0';
    slider.max = String(inc.durationMin);
    slider.step = '0.01';
    slider.value = '0';
    slider.disabled = stages.length === 0;
  }

  if ($('fsPlayPauseBtn')) {
    $('fsPlayPauseBtn').textContent = 'Play';
    $('fsPlayPauseBtn').disabled = stages.length === 0;
  }
  if ($('fsRestartBtn')) $('fsRestartBtn').disabled = stages.length === 0;
  if ($('fsSpeedSelect')) $('fsSpeedSelect').value = String(state.fsSpeed || 1);

  const tl = $('fsTimeline');
  if (tl && stages.length) {
    tl.innerHTML = stages.map(s =>
      `<i class="fs-tl-seg stage-upcoming" data-stage="${esc(s.stage_id)}" title="${esc(s.tactic)} (${esc(s.src)} → ${esc(s.dst)}) · T+${Math.floor(s.t0)}m" style="left:${(s.t0 / inc.durationMin) * 100}%;width:${Math.max(1, ((s.t1 - s.t0) / inc.durationMin) * 100)}%;background:${css(colorOf(s.tactic))}"></i>`
    ).join('') + `<div id="fsPlayhead" class="fs-playhead" style="left:0%"></div>`;
  } else if (tl) {
    tl.innerHTML = '';
  }

  const container = $('fullscreenGraphCanvas');
  if (container) {
    container.innerHTML = '';
    if (state.fsGraph) {
      if (typeof state.fsGraph.dispose === 'function') state.fsGraph.dispose();
      state.fsGraph = null;
    }

    const onFsSelect = selection => {
      if (!selection) return;
      fsSetPlay(false);
      state.fsSel = selection;
      state.fsGraph?.setSelection?.(selection);
      if (selection.stage) {
        const s = inc.stages.find(x => x.stage_id === selection.stage);
        if (s && !(state.fsTime >= s.t0 && state.fsTime <= s.t1)) {
          fsSetTime(s.t0 + 0.01);
        }
        selectStage(selection.stage);
      } else if (selection.host) {
        selectHost(selection.host);
      }
      renderFsRightSidebar();
    };

    try {
      if (typeof document !== 'undefined') {
        const testCanvas = document.createElement('canvas');
        const gl = testCanvas.getContext('webgl2') || testCanvas.getContext('webgl');
        if (!gl) throw new Error('WebGL not supported');
      }
      state.fsGraph = new NetworkScene(container, onFsSelect);
    } catch (err) {
      console.warn('Fullscreen WebGL failed, falling back to 2D:', err);
      container.innerHTML = '';
      state.fsGraph = new AttackGraph(container, onFsSelect);
    }

    state.fsGraph.setIncident(inc);
    state.fsGraph.fit();
    const attackerHost = findInitialAttacker(inc);
    state.fsAttackerHost = attackerHost;
    if (attackerHost) {
      state.fsGraph.setSelection({ host: attackerHost.id });
      selectHost(attackerHost.id);
    }
    fsSetTime(0);
    renderFsRightSidebar();
  }
}

function renderFsRightSidebar() {
  const evInspector = $('fsEvidenceInspector');
  if (evInspector) {
    if (state.selectedHost && !state.selectedStage) {
      const host = state.incident?.hosts?.find(item => item.id === state.selectedHost);
      evInspector.innerHTML = host
        ? `<div class="host-inspector"><span class="eyebrow">SELECTED HOST</span><h3>${esc(host.id || 'Host')}</h3><dl class="evidence-fields">${[['IP address', host.ip], ['Role', host.role], ['Network zone', host.zone]].filter(([, value]) => value).map(([label, value]) => `<div class="evidence-field"><dt>${label}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl><p class="inline-note">Select an attack stage to inspect flow evidence.</p></div>`
        : '<div class="empty-state compact-empty">Select a host or stage to inspect evidence.</div>';
    } else {
      evInspector.innerHTML = evidenceHtml(
        state.incident,
        state.selectedStage,
        state.embeddedEvidence,
        state.retrievedEvidence,
        sourceLabel(state.incident),
      );
    }
  }
  const repContent = $('fsReportContent');
  if (repContent) {
    repContent.innerHTML = reportHtml(state.report, state.reportStatus, state.incident);
  }
  const mapContent = $('fsAttackMappings');
  if (mapContent) {
    mapContent.innerHTML = attackMappingsHtml(state.report, state.reportStatus);
  }
}

function closeFullscreen3D() {
  fsSetPlay(false);
  const overlay = $('fullscreenOverlay');
  if (overlay) overlay.hidden = true;

  if (state.fsGraph) {
    if (typeof state.fsGraph.dispose === 'function') state.fsGraph.dispose();
    state.fsGraph = null;
  }

  if (state.graph && state.incident) {
    state.graph.setIncident(state.incident);
    const sel = {
      ...(state.selectedHost ? { host: state.selectedHost } : {}),
      ...(state.selectedStage ? { stage: state.selectedStage.stage_id } : {}),
    };
    if (sel.host || sel.stage) state.graph.setSelection(sel);
    if (state.replayIndex >= 0 && state.replayEvents[state.replayIndex]) {
      state.graph.setReplay(state.replayEvents[state.replayIndex].stage.stage_id);
    }
  }
}

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
    const urlParams = typeof window !== 'undefined' ? new URLSearchParams(window.location.search) : null;
    const initialJobId = urlParams ? (urlParams.get('job_id') || urlParams.get('job')) : null;
    if (initialJobId) {
      try {
        const freshIncidents = await getInvestigationIncidents(initialJobId);
        if (freshIncidents?.length) {
          const fresh = freshIncidents.map(incident => ({
            ...incident,
            _sourceKey: `fresh:${initialJobId}:${incident.incident_id}`,
            investigation_job_id: initialJobId,
            inference_source: 'fresh',
          }));
          state.incidents = mergeIncidents(state.incidents, fresh, { isFresh: true });
        }
      } catch (err) {
        console.warn('Failed to load initial job from URL:', err);
      }
    }
    const incidents = await listIncidents();
    state.incidents = mergeIncidents(state.incidents, incidents, { isFresh: false });

    setConnection('API connected');
    renderIncidentList();
    if (!state.incidents.length) {
      $('incidentList').innerHTML = '<div class="empty-state list-empty"><strong>No incidents returned</strong><p>Run an investigation or check the backend incident store.</p></div>';
      $('loadState').className = 'state-card';
      $('loadState').innerHTML = '<span class="state-symbol" aria-hidden="true">—</span><div><strong>No incidents available</strong><p>Choose a flow file and run an investigation to create a fresh case.</p></div>';
      return;
    }
    const currentKey = state.sourceKey;
    const stillExists = currentKey && state.incidents.some(item => item._sourceKey === currentKey);
    await selectIncident(stillExists ? currentKey : state.incidents[0]._sourceKey);
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
    state.recovery = null;
    state.recoveryStatus = 'loading';
    state.recoveryError = '';
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
  loadContainment();
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
  renderContainment();
  renderFsRightSidebar();
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
  renderFsRightSidebar();
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


function renderContainment() {
  const el = $('containmentContent');
  if (!el) return;
  el.innerHTML = containmentHtml(state.recovery, state.recoveryStatus, state.recoveryError);
  const retryBtn = el.querySelector('[data-retry-containment]');
  if (retryBtn) {
    retryBtn.addEventListener('click', () => loadContainment());
  }
}

async function loadContainment() {
  const incidentId = state.incident?.incident_id;
  const sourceKey = state.sourceKey;
  if (!incidentId) return;
  state.recoveryStatus = 'loading';
  state.recoveryError = '';
  renderContainment();
  try {
    const data = await getCountermeasures(incidentId, state.jobId);
    if (state.incident?.incident_id !== incidentId || state.sourceKey !== sourceKey) return;
    state.recovery = data;
    state.recoveryStatus = 'loaded';
    state.recoveryError = '';
    renderContainment();
  } catch (error) {
    if (state.incident?.incident_id !== incidentId || state.sourceKey !== sourceKey) return;
    state.recoveryStatus = 'error';
    state.recoveryError = error.message || 'Countermeasure request failed';
    renderContainment();
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
    const selectedModel = status.result?.selected_detector || status.result?.model_type || 'xgb';
    const selectedName = selectedModel === 'gnn' ? 'GraphSAGE GNN' : 'XGBoost';
    const reason = status.result?.selection_reason;
    if (!fresh.length) {
      const autoNote = $('detector').value === 'auto' ? ` (Auto: ${selectedName})` : '';
      progress.textContent = `Fresh inference complete${autoNote}: ${status.result?.alerts ?? 0} alerts; no incidents were formed.`;
      return;
    }
    state.incidents = mergeIncidents(state.incidents, fresh, { isFresh: true });
    renderIncidentList();
    if ($('detector').value === 'auto') {
      progress.textContent = `${status.result?.flows_scored ?? '—'} flows · ${status.result?.alerts ?? '—'} alerts · ${fresh.length} incidents · Auto selected: ${selectedName}${reason ? ` (${reason})` : ''}`;
    } else {
      progress.textContent = `${status.result?.flows_scored ?? '—'} flows · ${status.result?.alerts ?? '—'} alerts · ${fresh.length} incidents`;
    }
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
  if (event.target.closest('[data-retry-containment]')) loadContainment();
  if (event.target.closest('#retryLoad, #retryList')) refreshIncidents();
  const fsTabBtn = event.target.closest('[data-fs-tab]');
  if (fsTabBtn) {
    const tab = fsTabBtn.dataset.fsTab;
    document.querySelectorAll('.fs-tab-btn').forEach(btn => {
      const isCur = btn.dataset.fsTab === tab;
      btn.classList.toggle('active', isCur);
      btn.setAttribute('aria-selected', String(isCur));
    });
    const evTab = $('fsEvidenceTab');
    const repTab = $('fsReportTab');
    if (evTab) evTab.hidden = tab !== 'evidence';
    if (repTab) repTab.hidden = tab !== 'report';
    return;
  }
});

const inputFile = $('inputFile');
const selectedFileInfo = $('selectedFileInfo');
const selectedFileName = $('selectedFileName');
const selectedFileSize = $('selectedFileSize');
const clearSelectedFile = $('clearSelectedFile');

function updateSelectedFile() {
  const file = inputFile?.files?.[0];

  if (selectedFileInfo) {
    selectedFileInfo.hidden = !file;
  }

  if (!file) {
    if (selectedFileName) selectedFileName.textContent = '';
    if (selectedFileSize) selectedFileSize.textContent = '';
    return;
  }

  if (selectedFileName) selectedFileName.textContent = file.name;

  const size = file.size < 1024 * 1024
    ? `${(file.size / 1024).toFixed(1)} KB`
    : `${(file.size / (1024 * 1024)).toFixed(2)} MB`;

  if (selectedFileSize) selectedFileSize.textContent = size;
}

inputFile?.addEventListener('change', updateSelectedFile);

clearSelectedFile?.addEventListener('click', () => {
  if (inputFile) inputFile.value = '';
  updateSelectedFile();
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
$('graphModeToggle')?.addEventListener('click', () => {
  initGraph(state.graphMode === '3d' ? '2d' : '3d');
});
$('fullscreen3dBtn')?.addEventListener('click', openFullscreen3D);
$('fullscreenExitBtn')?.addEventListener('click', closeFullscreen3D);
$('fsPrevBtn')?.addEventListener('click', () => fsJump(-1));
$('fsNextBtn')?.addEventListener('click', () => fsJump(1));
$('fsPlayPauseBtn')?.addEventListener('click', () => {
  fsSetPlay(!state.fsPlaying);
});
$('fsRestartBtn')?.addEventListener('click', fsRestartReplay);
$('fsSpeedSelect')?.addEventListener('change', event => {
  const val = parseFloat(event.target.value);
  state.fsSpeed = !isNaN(val) && val > 0 ? val : 1;
});
const handleFsScrubber = event => {
  fsSetPlay(false);
  const value = Number(event.target.value);
  fsSetTime(value);
};
$('fsReplayProgress')?.addEventListener('input', handleFsScrubber);
$('fsReplayProgress')?.addEventListener('change', handleFsScrubber);

function scrubFsTimeline(event) {
  const tl = $('fsTimeline');
  if (!tl || !state.fsIncident || state.fsIncident.durationMin <= 0) return;
  const rect = tl.getBoundingClientRect();
  if (rect.width <= 0) return;
  const clientX = event.clientX != null ? event.clientX : (event.touches?.[0]?.clientX ?? 0);
  const ratio = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
  const newT = ratio * state.fsIncident.durationMin;
  fsSetPlay(false);
  fsSetTime(newT);
  const act = activeStage(state.fsIncident, newT);
  if (act) {
    state.fsGraph?.setSelection?.({ stage: act.stage_id });
    selectStage(act.stage_id);
    renderFsRightSidebar();
  }
}

let isTlScrubbing = false;
const tlEl = $('fsTimeline');
if (tlEl) {
  tlEl.addEventListener('pointerdown', event => {
    isTlScrubbing = true;
    try { tlEl.setPointerCapture(event.pointerId); } catch {}
    const seg = event.target.closest('[data-stage]');
    if (seg) {
      const stageId = seg.dataset.stage;
      const s = state.fsIncident?.stages.find(x => x.stage_id === stageId);
      if (s) {
        fsSetPlay(false);
        fsSetTime(s.t0 + 0.01);
        state.fsGraph?.setSelection?.({ stage: stageId });
        selectStage(stageId);
        renderFsRightSidebar();
        return;
      }
    }
    scrubFsTimeline(event);
  });
  tlEl.addEventListener('pointermove', event => {
    if (isTlScrubbing) {
      scrubFsTimeline(event);
    }
  });
  const endScrub = event => {
    if (isTlScrubbing) {
      isTlScrubbing = false;
      try { tlEl.releasePointerCapture(event.pointerId); } catch {}
    }
  };
  tlEl.addEventListener('pointerup', endScrub);
  tlEl.addEventListener('pointercancel', endScrub);
  tlEl.addEventListener('keydown', event => {
    if (!state.fsIncident || state.fsIncident.durationMin <= 0) return;
    const step = state.fsIncident.durationMin / 50;
    if (event.key === 'ArrowRight' || event.key === 'ArrowUp') {
      event.preventDefault();
      fsSetPlay(false);
      fsSetTime(Math.min(state.fsIncident.durationMin, (state.fsTime || 0) + step));
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowDown') {
      event.preventDefault();
      fsSetPlay(false);
      fsSetTime(Math.max(0, (state.fsTime || 0) - step));
    }
  });
}

$('fullscreenLeft')?.addEventListener('click', event => {
  const card = event.target.closest('[data-stage]') || event.target.closest('[data-stage-id]');
  if (!card) return;
  const stageId = card.dataset.stage || card.dataset.stageId;
  const s = state.fsIncident?.stages.find(x => x.stage_id === stageId);
  if (s) {
    fsSetPlay(false);
    fsSetTime(s.t0 + 0.01);
    state.fsGraph?.setSelection?.({ stage: stageId });
    selectStage(stageId);
    renderFsRightSidebar();
  }
});
[['fsBenignBtn', 'benign'], ['fsRotateBtn', 'rotate'], ['fsPacketsBtn', 'packets'], ['fsFollowBtn', 'follow']].forEach(([id, opt]) => {
  $(id)?.addEventListener('click', e => {
    const on = e.currentTarget.classList.toggle('on');
    state.fsGraph?.setOption?.(opt, on);
  });
});
$('fullscreenChain')?.addEventListener('click', event => {
  const card = event.target.closest('[data-stage-id]');
  if (!card) return;
  const stageId = card.dataset.stageId;
  const stages = state.fsIncident?.stages || getFsStages();
  const idx = stages.findIndex(s => s.stage_id === stageId);
  if (idx >= 0) {
    fsStopReplay();
    fsReplayStep(idx);
    state.fsGraph?.setSelection?.({ stage: stageId });
    selectStage(stageId);
    renderFsRightSidebar();
  }
});

document.addEventListener('keydown', event => {
  if (event.key === 'Escape') {
    const overlay = $('fullscreenOverlay');
    if (overlay && !overlay.hidden) {
      closeFullscreen3D();
      return;
    }
    if (document.activeElement?.matches('input[type="search"]')) {
      document.activeElement.value = '';
      document.activeElement.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }
});

refreshIncidents();
