import './styles.css';
import { API_BASE } from './config.js';
const numeric = v => v !== undefined && v !== null && v !== '' && !isNaN(Number(v));
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
let scene3d = null;
function show3D(enabled) {
  const canvas = $('attackGraph3d');
  const graph = $('attackGraph');
  if (enabled) {
    graph.hidden = true;
    canvas.hidden = false;
    if (!scene3d) scene3d = new NetworkScene(canvas, { onSelect: (host) => selectHost(host), onHover: () => {} });
    if (state.incident) scene3d.setIncident(state.incident);
    requestAnimationFrame(() => scene3d._resize());
  } else {
    canvas.hidden = true;
    graph.hidden = false;
  }
}

let scene3dFs = null;
let fsPlay = false;
let fsT = 0;
let fsBeginner = false;

function setupGraphFullscreen3D() {
  const fsCanvas = document.getElementById('graphFsCanvas3d');
  if (!fsCanvas) return;
  if (!scene3dFs) {
    scene3dFs = new NetworkScene(fsCanvas, {
      onSelect: (sel) => {
        if (sel?.host) { selectHost(sel.host); updateGraphFullscreen(); }
        else if (sel?.stage) { selectStage(sel.stage); updateGraphFullscreen(); }
      },
      onHover: () => {}
    });
  }
  if (state.incident) {
    scene3dFs.setIncident(state.incident);
    if (state.selectedHost) scene3dFs.setSelection({ host: state.selectedHost });
    else if (state.selectedStage) scene3dFs.setSelection({ stage: state.selectedStage.stage_id });
    else scene3dFs.setSelection(null);
  }
  requestAnimationFrame(() => {
    if (scene3dFs) scene3dFs._resize();
  });
}

function fmtFsTime(t) {
  if (!Number.isFinite(t)) return 'T+0.0 min';
  const m = 842 + Math.floor(t);
  const s = Math.floor((t % 1) * 60);
  return `T+${t.toFixed(1)} min · ${Math.floor(m/60)}:${String(m%60).padStart(2,'0')}:${String(s).padStart(2,'0')} UTC`;
}

function explainSimple(s) {
  if (!s) return 'No details.';
  return `An attempt was made from ${s.src||'unknown'} to ${s.dst||'unknown'}${s.port?` on port ${s.port}`:''}. This looks like ${s.tactic||'activity'}. It's marked as ${s.observed?'confirmed (seen in traffic)':'likely (inferred)'}.`;
}

function explainTech(s) {
  if (!s) return 'No details.';
  const ev = (s.evidence||[]).map(e=>e.flow_id).filter(Boolean).join(', ')||'-';
  return `${s.tactic_id||''} ${s.tactic||''}: ${s.src||''}→${s.dst||''}${s.port?':'+s.port:''} (conf ${numeric(s.confidence)?Number(s.confidence).toFixed(2):'-'}). Evidence: ${ev}. ${s.summary||''}`;
}

function updateGraphFullscreen() {
  const fs = document.getElementById('graphFullscreen');
  const title = document.getElementById('graphFsTitle');
  if (!fs || fs.hidden) return;
  if (title) title.textContent = state.incident ? state.incident.incident_id : '';

  // Incident dropdown
  const sel = document.getElementById('fsIncSelect');
  if (sel && state.incidents?.length) {
    if (sel.options.length !== state.incidents.length) {
      sel.innerHTML = state.incidents.map(i => `<option value="${esc(i._sourceKey||i.incident_id)}">${esc(i.incident_id)}${i.inference_source==='prepared'?' (prep)':''}</option>`).join('');
    }
    const cur = state.incidents.find(i => (i._sourceKey===state.sourceKey) || i.incident_id===state.incident?.incident_id);
    if (cur) sel.value = cur._sourceKey || cur.incident_id;
    sel.onchange = async () => {
      const key = sel.value;
      const found = state.incidents.find(i => (i._sourceKey===key)||i.incident_id===key);
      if (found) await selectIncident(found._sourceKey||found.incident_id);
      setupGraphFullscreen3D();
      if (scene3dFs && state.incident) {
        scene3dFs.setIncident(state.incident);
        scene3dFs.setSelection(state.selectedHost?{host:state.selectedHost}:(state.selectedStage?{stage:state.selectedStage.stage_id}:null));
      }
      updateGraphFullscreen();
    };
  }

  // Auto rotate
  const ar = document.getElementById('fsAutoRotate');
  if (ar && scene3dFs) {
    if (scene3dFs.opt.rotate === undefined) scene3dFs.opt.rotate = true;
    ar.textContent = scene3dFs.opt.rotate ? 'Auto-rotate: On' : 'Auto-rotate: Off';
    ar.onclick = () => {
      scene3dFs.opt.rotate = !scene3dFs.opt.rotate;
      ar.textContent = scene3dFs.opt.rotate ? 'Auto-rotate: On' : 'Auto-rotate: Off';
    };
  }

  // Beginner toggle
  const beg = document.getElementById('fsBeginner');
  if (beg) {
    beg.textContent = fsBeginner ? 'Beginner: On' : 'Beginner: Off';
    beg.onclick = () => { fsBeginner = !fsBeginner; updateGraphFullscreen(); };
  }

  const incId = document.getElementById('fsIncId');
  const incSev = document.getElementById('fsIncSev');
  if (incId) incId.textContent = state.incident?.incident_id || '-';
  if (incSev) {
    const sev = numeric(state.incident?.score) ? Number(state.incident.score).toFixed(2) : (numeric(state.incident?.severity) ? state.incident.severity : '-');
    incSev.textContent = sev;
  }

  // Replay controls
  const rb = document.getElementById('fsReplayBtn');
  const sl = document.getElementById('fsSl');
  if (rb) {
    rb.onclick = () => {
      fsPlay = !fsPlay;
      rb.textContent = fsPlay ? '⏸ Pause' : '▶ Replay';
      if (fsPlay && state.incident?.stages?.length) {
        state.incident.stages.forEach((s,idx)=>{ s.t0 = idx * 4; s.t1 = idx * 4 + 3.5; });
        if (sl) { sl.max = String(state.incident.stages.length * 4); sl.value = String(fsT); }
        const step = () => {
          if (!fsPlay) return;
          fsT += 0.15;
          const maxT = (state.incident.stages.length) * 4;
          if (fsT >= maxT) { fsT = maxT; fsPlay = false; rb.textContent = '▶ Replay'; if (scene3dFs) { scene3dFs.setTime(fsT); scene3dFs.setSelection(state.selectedStage?{stage:state.selectedStage.stage_id}:null); } if (sl) sl.value = String(fsT); const tm = document.getElementById('fsTime'); if (tm) tm.textContent = fmtFsTime(fsT); updateGraphFullscreen(); return; }
          if (scene3dFs) { scene3dFs.setTime(fsT); scene3dFs.setSelection(state.selectedStage?{stage:state.selectedStage.stage_id}:null); }
          // Auto-select stage for current time window
          const cur = state.incident.stages.find(s => fsT >= s.t0 && fsT <= s.t1);
          if (cur && state.selectedStage?.stage_id !== cur.stage_id) {
            selectStage(cur.stage_id);
          }
          if (sl) sl.value = String(fsT);
          const tm = document.getElementById('fsTime');
          if (tm) tm.textContent = fmtFsTime(fsT);
          updateGraphFullscreen();
          setTimeout(step, 40);
        };
        step();
      } else if (fsPlay) {
        const maxT = 30;
        if (sl) sl.max = String(maxT);
        const step = () => {
          if (!fsPlay) return;
          fsT += 0.2;
          if (fsT >= maxT) { fsT = maxT; fsPlay = false; rb.textContent = '▶ Replay'; if (scene3dFs) scene3dFs.setTime(fsT); if (sl) sl.value = String(fsT); const tm = document.getElementById('fsTime'); if (tm) tm.textContent = fmtFsTime(fsT); updateGraphFullscreen(); return; }
          if (scene3dFs) scene3dFs.setTime(fsT);
          if (sl) sl.value = String(fsT);
          const tm = document.getElementById('fsTime');
          if (tm) tm.textContent = fmtFsTime(fsT);
          updateGraphFullscreen();
          setTimeout(step, 50);
        };
        step();
      }
    };
  }
  if (sl) {
    sl.oninput = () => {
      fsT = Number(sl.value);
      if (scene3dFs && state.incident?.stages) { state.incident.stages.forEach((s,idx)=>{if(s.t0===undefined)s.t0=idx*5;if(s.t1===undefined)s.t1=idx*5+4;}); scene3dFs.setTime(fsT); } else if (scene3dFs) scene3dFs.setTime(fsT);
      const tm = document.getElementById('fsTime');
      if (tm) tm.textContent = fmtFsTime(fsT);
      updateGraphFullscreen();
    };
  }
  if (scene3dFs && state.incident?.stages) { state.incident.stages.forEach((s,idx)=>{if(s.t0===undefined)s.t0=idx*5;if(s.t1===undefined)s.t1=idx*5+4;}); scene3dFs.setTime(fsT); } else if (scene3dFs) scene3dFs.setTime(fsT);

  const chain = document.getElementById('fsChain');
  if (chain) {
    if (!state.incident?.stages?.length) {
      chain.innerHTML = '<div class="fs-mu">No stages available</div>';
    } else {
      const scols = {Recon:0x4cc9f0,Cred:0xf9c74f,Lateral:0xf8961e,C2:0xb388ff,Exfil:0xff4d6d,Initial:0xf9c74f,'Command and Control':0xb388ff,Exfiltration:0xff4d6d,'Lateral Movement':0xf8961e,'Credential Access':0xf9c74f,'Reconnaissance':0x4cc9f0};
      chain.innerHTML = state.incident.stages.map((s, idx) => {
        const c = scols[s.tactic] || 0x4cc9f0;
        const col = '#' + c.toString(16).padStart(6,'0');
        const sel = state.selectedStage?.stage_id === s.stage_id ? 'on' : '';
        const obs = s.observed ? 'ob' : 'inf';
        const conf = numeric(s.confidence) ? Number(s.confidence).toFixed(2) : '-';
        const tid = s.tactic_id || '';
        return `<div class="fs-card ${sel}" style="--c:${col}" data-fs-c="${esc(s.stage_id)}"><b>${idx+1}. ${esc(s.tactic||'Unknown')}</b><span class="fs-pill ${obs==='ob'?'fs-ob':'fs-inf'}">${obs==='ob'?'observed':'inferred'}</span><div class="fs-mu">${esc(s.src||'')} → ${esc(s.dst||'')}${s.port?':'+esc(s.port):''}</div><div class="fs-bar"><i style="width:${conf==='-'?0:Number(conf)*100}%"></i></div><div class="fs-mu">confidence ${conf} · ${esc(tid)}</div></div>`;
      }).join('');
      chain.querySelectorAll('[data-fs-c]').forEach(el => {
        el.onclick = () => { selectStage(el.dataset.fsC); updateGraphFullscreen(); };
      });
    }
  }

  const det = document.getElementById('fsDet');
  const tabEv = document.getElementById('fsTabEv');
  const tabRep = document.getElementById('fsTabRep');
  const isRep = tabRep?.classList.contains('on');
  if (tabEv) tabEv.onclick = () => { tabEv.classList.add('on'); tabRep?.classList.remove('on'); updateGraphFullscreen(); };
  if (tabRep) tabRep.onclick = () => { tabRep.classList.add('on'); tabEv?.classList.remove('on'); updateGraphFullscreen(); };

  if (isRep) {
    if (!state.incident) {
      det.innerHTML = '<h4>Verified report</h4><div class="fs-mu">No incident loaded.</div>';
    } else if (state.reportStatus === 'loading') {
      det.innerHTML = '<h4>Incident report · ' + esc(state.incident.incident_id) + '</h4><div class="fs-mu">Loading...</div>';
    } else if (state.reportStatus === 'error' || !state.report) {
      det.innerHTML = '<h4>Incident report · ' + esc(state.incident.incident_id) + '</h4><div class="fs-mu">Report unavailable</div>';
    } else {
      const rep = state.report;
      const valid = Number(rep.validation?.valid);
      const total = Number(rep.validation?.total);
      det.innerHTML = '<h4>Incident report · ' + esc(state.incident.incident_id) + '</h4><div class="fs-pill fs-ob">validator: ' + (Number.isFinite(valid)&&Number.isFinite(total)?valid+'/'+total:'-/-') + ' claims cite valid evidence IDs</div>' + (rep.sentences||[]).map((s,i)=>'<p>'+(i+1)+'. ' + esc(s.text||'') + (s.evidence_ids&&s.evidence_ids.length? ' ' + s.evidence_ids.map(id=>'<span class="fs-tag">[E:'+esc(id)+']</span>').join(' '):'') + '</p>').join('') + '<div class="fs-mu" style="font-size:11px">Footer · input sha256 <code>' + esc(rep.footer?.input_sha256||state.incident.source_sha256||'-') + '</code> · manifest <code>' + esc(rep.footer?.manifest_id||'-') + '</code> · ATT&CK ' + esc(rep.footer?.attack_version||'-') + '</div>';
    }
  } else {
    if (!state.incident) {
      det.innerHTML = '<h4>Evidence panel</h4><div class="fs-mu">No incident loaded.</div>';
    } else if (state.selectedStage) {
      const s = state.selectedStage;
      const ev = s.evidence || [];
      const scols = {Recon:0x4cc9f0,Cred:0xf9c74f,Lateral:0xf8961e,C2:0xb388ff,Exfil:0xff4d6d,Initial:0xf9c74f,'Command and Control':0xb388ff,Exfiltration:0xff4d6d,'Lateral Movement':0xf8961e,'Credential Access':0xf9c74f,'Reconnaissance':0x4cc9f0};
      const c = scols[s.tactic] || 0x4cc9f0;
      const col = '#' + c.toString(16).padStart(6,'0');
      const text = fsBeginner ? explainSimple(s) : explainTech(s);
      det.innerHTML = '<h4>' + esc(s.tactic||'') + ' · ' + esc(s.tactic_id||'') + '</h4><b style="color:' + col + '">' + esc(s.src||'') + ' → ' + esc(s.dst||'') + (s.port?':'+esc(s.port):'') + '</b><span class="fs-pill ' + (s.observed?'fs-ob':'fs-inf') + '">' + (s.observed?'observed':'inferred') + '</span><div class="fs-bar"><i style="width:' + (numeric(s.confidence)?Number(s.confidence)*100:0) + '%;background:' + col + '"></i></div><div class="fs-mu">confidence ' + (numeric(s.confidence)?Number(s.confidence).toFixed(2):'-') + '</div><p>' + esc(text) + '</p><h4>Evidence trail</h4>' + (ev.length?'<table><tr><th>ID</th><th>Time</th><th>Details</th></tr>' + ev.map(e=>'<tr><td><span class="fs-tag">' + esc(e.flow_id||'') + '</span></td><td>' + esc(e.ts||s.start||'-') + '</td><td>' + esc(e.pcap_sha256?e.pcap_sha256.slice(0,8):'-') + '</td></tr>').join('') + '</table>':'<div class="fs-mu">No evidence references available.</div>');
    } else if (state.selectedHost) {
      const h = state.incident.hosts?.find(x=>x.id===state.selectedHost);
      const rel = (state.incident.stages||[]).filter(o=>o.src===state.selectedHost||o.dst===state.selectedHost);
      det.innerHTML = '<h4>Host</h4><b>' + esc(state.selectedHost) + '</b> · <code>' + esc(h?.ip||'-') + '</code><div class="fs-mu">' + esc(h?.role||'') + ' · zone ' + esc(h?.zone||'-') + '</div><h4>Involved in</h4>' + (rel.length?rel.map((o,i)=>'<div class="fs-card" style="--c:#4cc9f0" data-fs-c2="' + esc(o.stage_id) + '">' + (i+1) + '. ' + esc(o.tactic||'') + ' · ' + esc(o.src||'') + ' → ' + esc(o.dst||'') + '</div>').join('') : '<div class="fs-mu">Only benign traffic observed or no related stages.</div>');
      det.querySelectorAll('[data-fs-c2]').forEach(el => { el.onclick = () => { selectStage(el.dataset.fsC2); updateGraphFullscreen(); }; });
    } else {
      det.innerHTML = '<h4>Evidence panel</h4><div class="fs-mu">Select a host, an edge, or an attack step. Claims must cite flow IDs when available.</div><h4>Incident</h4><div class="fs-mu">' + esc(state.incident.incident_id) + (state.incident.inference_source==='prepared'?' · Prepared/demo':'') + '</div><div class="fs-mu">Alerts: ' + (numeric(state.incident.total_alerts)?Number(state.incident.total_alerts):'-') + ' · Hosts: ' + (state.incident.hosts?.length||0) + ' · Stages: ' + (state.incident.stages?.length||0) + '</div>';
    }
  }

  const tl = document.getElementById('fsTl');
  if (tl) {
    tl.innerHTML = '';
    if (state.incident?.stages?.length) {
      const scols = {Recon:0x4cc9f0,Cred:0xf9c74f,Lateral:0xf8961e,C2:0xb388ff,Exfil:0xff4d6d,Initial:0xf9c74f,'Command and Control':0xb388ff,Exfiltration:0xff4d6d,'Lateral Movement':0xf8961e,'Credential Access':0xf9c74f,'Reconnaissance':0x4cc9f0};
      const maxT = Math.max(30, state.incident.stages.length * 5);
      state.incident.stages.forEach((s,idx) => {
        const c = scols[s.tactic] || 0x4cc9f0;
        const col = '#' + c.toString(16).padStart(6,'0');
        const i = document.createElement('i');
        i.style.cssText = 'left:' + ((idx+1)/(state.incident.stages.length+1)*100) + '%;width:2%;background:' + col;
        tl.appendChild(i);
      });
      const tags = document.createElement('div');
      tags.style.cssText = 'position:absolute;top:16px;left:0;right:0;display:flex;gap:8px;font-size:11px';
      const uniq = [...new Set(state.incident.stages.map(s=>s.tactic).filter(Boolean))];
      uniq.slice(0,4).forEach(t => {
        const c = scols[t] || 0x4cc9f0;
        const col = '#' + c.toString(16).padStart(6,'0');
        tags.innerHTML += `<span style="color:${col}">■ ${esc(t)}</span>`;
      });
      tl.appendChild(tags);
    } else {
      tl.innerHTML = '<div class="fs-mu">No timeline data</div>';
    }
  }
  const slv = document.getElementById('fsSl');
  if (slv) slv.value = String(fsT);
  const tm = document.getElementById('fsTime');
  if (tm) tm.textContent = fmtFsTime(fsT);

  if (scene3dFs) {
    if (state.selectedHost) scene3dFs.setSelection({ host: state.selectedHost });
    else if (state.selectedStage) scene3dFs.setSelection({ stage: state.selectedStage.stage_id });
    else scene3dFs.setSelection(null);
    requestAnimationFrame(() => scene3dFs._resize());
  }
}
$('attackGraph').closest('.graph-panel')?.addEventListener('click', event => {
  const action = event.target.closest('[data-graph-action]')?.dataset.graphAction;
  if (action === 'view-2d') show3D(false);
  if (action === 'view-3d') show3D(true);
});

document.getElementById('graphFullscreenBtn')?.addEventListener('click', () => {
  const fs = document.getElementById('graphFullscreen');
  if (fs) {
    fs.hidden = false;
    setupGraphFullscreen3D();
    if (scene3dFs && state.incident) {
      scene3dFs.setIncident(state.incident);
      if (state.selectedHost) scene3dFs.setSelection({ host: state.selectedHost });
      else if (state.selectedStage) scene3dFs.setSelection({ stage: state.selectedStage.stage_id });
      else scene3dFs.setSelection(null);
    }
    updateGraphFullscreen();
    setTimeout(() => { if (scene3dFs) { scene3dFs._resize(); } }, 50);
    requestAnimationFrame(() => { if (scene3dFs) scene3dFs._resize(); });
  }
});
document.getElementById('graphFsExit')?.addEventListener('click', () => {
  const fs = document.getElementById('graphFullscreen');
  if (fs) fs.hidden = true;
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    const fs = document.getElementById('graphFullscreen');
    if (fs && !fs.hidden) {
      fs.hidden = true;
    }
  }
});

function sourceLabel(incident) {
  if (state.jobId || incident?.inference_source === 'fresh') {
    const detector = incident?.detector_label || incident?.detection_model;
    const name = detector === 'gnn_legacy_migrated'
      ? 'Graph analysis · temporal isolation unverified'
      : detector === 'gnn' ? 'Relationship analysis' : detector === 'xgb' ? 'Network activity detection' : '';
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

function renderPipeline(status) {
  const stages = [
    {name: 'Upload', desc: 'Upload and store input file'},
    {name: 'Data validation', desc: 'Check file format and required fields'},
    {name: 'Data processing', desc: 'Parse and normalize flows'},
    {name: 'Threat detection', desc: 'Run detector on flows'},
    {name: 'Incident correlation', desc: 'Group alerts into incidents'},
    {name: 'Attack reconstruction', desc: 'Build attack chains'},
    {name: 'Evidence verification', desc: 'Build Merkle evidence and verify'},
    {name: 'AI review', desc: 'AI analysis of findings'},
    {name: 'Report generation', desc: 'Generate evidence-grounded reports'}
  ];
  const container = document.getElementById('pipelineStages');
  if (!container) return;
  // Check if this is a prepared incident with no live job
  const incident = state.incident;
  const isPrepared = incident && (!state.jobId || incident.inference_source === 'prepared') && incident.inference_source !== 'fresh';
  if (isPrepared && !status) {
    container.innerHTML = `<div style="grid-column:1/-1;padding:12px;border:1px solid var(--border);border-radius:6px;background:var(--surface-muted)"><strong>Prepared incident — no live job</strong><p style="margin:4px 0 0;color:var(--muted)">This is a prepared/demo incident. Pipeline status is not applicable.</p></div>`;
    return;
  }
  if (isPrepared && status && !status.status) {
    container.innerHTML = `<div style="grid-column:1/-1;padding:12px;border:1px solid var(--border);border-radius:6px;background:var(--surface-muted)"><strong>Prepared incident — no live job</strong><p style="margin:4px 0 0;color:var(--muted)">This is a prepared/demo incident. Pipeline status is not applicable.</p></div>`;
    return;
  }
  const current = status?.stage || '';
  const elapsed = status?.elapsed_seconds ? `${status.elapsed_seconds}s` : (status?.finished_at && status?.started_at ? `${(status.finished_at - status.started_at).toFixed(1)}s` : null);
  container.innerHTML = stages.map(s => {
    const isCurrent = current.includes(s.name);
    const cls = status?.status === 'failed' && isCurrent ? 'failed' : (status?.status === 'completed' ? 'completed' : (isCurrent && status?.status === 'running' ? 'running' : ''));
    const stateTxt = status?.status === 'completed' ? 'Completed' : status?.status === 'failed' && isCurrent ? 'Failed' : isCurrent && status?.status === 'running' ? 'Running' : status?.status === 'completed' ? 'Completed' : isCurrent ? 'Waiting' : 'Pending';
    const timeTxt = elapsed && status?.status === 'completed' && isCurrent ? elapsed : (elapsed && status?.status === 'completed' ? 'Done' : 'Unavailable');
    return `<div class="pipeline-stage ${cls}"><strong>${s.name}</strong><div>Status: ${stateTxt}</div><div>Time: ${timeTxt}</div><div style="font-size:11px;color:var(--muted)">${s.desc}</div>${status?.error && isCurrent ? `<div style="color:var(--red);font-size:11px">${esc(status.error)}</div>` : ''}</div>`;
  }).join('');
  if (status?.status === 'completed' && elapsed) {
    const total = document.createElement('div');
    total.style.gridColumn = '1/-1';
    total.innerHTML = `<strong>Total time: ${elapsed}</strong>`;
    container.appendChild(total);
  }
}

function renderStats() {
  const grid = document.getElementById('statsGrid');
  if (!grid) return;
  const incidents = state.incidents || [];
  let alertsSum = 0;
  let hasAlertData = false;
  for (const i of incidents) {
    if (i.total_alerts !== undefined && i.total_alerts !== null && i.total_alerts !== '') {
      hasAlertData = true;
      const v = Number(i.total_alerts);
      if (Number.isFinite(v)) {
        alertsSum += v;
      }
    }
  }
  const alertsDisplay = hasAlertData ? alertsSum : (incidents.length === 0 ? '—' : '—');
  const hosts = new Set(incidents.flatMap(i => (i.hosts||[]).map(h => h.id||h.ip).filter(Boolean))).size;
  const reportsAvailable = incidents.filter(i => i.reportAvailable === true || i.report || (state.report && i.incident_id === state.incident?.incident_id)).length;
  const reportsChecked = incidents.some(i => i.reportAvailable !== undefined);
  let reportsDisplay;
  if (reportsChecked) {
    reportsDisplay = String(reportsAvailable);
  } else {
    reportsDisplay = incidents.length === 0 ? '—' : '—';
  }
  grid.innerHTML = `
    <div class="stat-card"><strong>${incidents.length}</strong>Investigations</div>
    <div class="stat-card"><strong>${alertsDisplay}</strong>Alerts</div>
    <div class="stat-card"><strong>${hosts === 0 && incidents.length > 0 ? 0 : (hosts || (incidents.length === 0 ? '—' : '—'))}</strong>Affected hosts</div>
    <div class="stat-card"><strong>${incidents.filter(i=>i.inference_source==='fresh').length}</strong>Fresh investigations</div>
    <div class="stat-card"><strong>${reportsDisplay}</strong>Reports</div>
  `;
}

function renderIncidentList() {
  const search = $('incidentSearch').value;
  const level = $('severityFilter').value;
  const visible = state.incidents.filter(incident => incidentMatches(incident, search, level));
  $('incidentCount').textContent = String(state.incidents.length);
  $('incidentList').innerHTML = visible.length
    ? visible.map(incident => incidentCardHtml(incident, state.sourceKey)).join('')
    : `<div class="empty-state list-empty"><strong>No matching incidents</strong><p>Adjust the search or severity filter.</p></div>`;
  renderStats();
}

async function checkReportsAvailability(incidents) {
  const { getReport } = await import('./api/client.js');
  for (const inc of incidents) {
    if (inc.reportAvailable !== undefined) continue;
    try {
      const report = await getReport(inc.incident_id);
      if (report && (report.sentences?.length || report.summary || report.report_id)) {
        inc.reportAvailable = true;
      } else {
        inc.reportAvailable = false;
      }
    } catch (e) {
      inc.reportAvailable = false;
    }
  }
  renderStats();
}

async function refreshIncidents() {
  $('incidentList').innerHTML = '<div class="inline-loading"><span class="spinner small"></span> Loading incidents…</div>';
  try {
    const incidents = await listIncidents();
    // For prepared/demo refresh, replace with latest API data but preserve fresh
    state.incidents = mergeIncidents(state.incidents, incidents, { isFresh: false });

    setConnection('API connected');
    renderIncidentList();
    checkReportsAvailability(state.incidents);
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
    if (scene3d) { scene3d.setIncident(state.incident); requestAnimationFrame(() => scene3d._resize()); }
    state.graph.setSelection(first ? { stage: first.stage.stage_id } : null);
    $('loadState').hidden = true;
    $('investigation').hidden = false;
    renderInvestigation();
    renderEvents();
    renderEvidence();
    // Render pipeline based on whether it's a prepared incident or has a job
    const isPrepared = state.incident.inference_source === 'prepared' || (!state.jobId && state.incident.inference_source !== 'fresh');
    if (isPrepared) {
      renderPipeline(null);
    } else if (state.jobId) {
      try {
        const jobStatus = await getInvestigation(state.jobId);
        renderPipeline(jobStatus);
      } catch (e) {
        renderPipeline(null);
      }
    } else {
      renderPipeline(null);
    }
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
  updateGraphFullscreen();
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
  updateGraphFullscreen();
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
  updateGraphFullscreen();
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
    const detector = $('detector')?.value || 'auto';
    const job = await startInvestigation(file, detector);
    let status = job;
    while (status.status === 'queued' || status.status === 'running') {
      progress.textContent = `${status.stage || 'Investigation running'} · ${status.progress ?? 0}%`;
      renderPipeline(status);
      await pause(800);
      status = await getInvestigation(job.job_id);
    }
    renderPipeline(status);
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
    state.incidents = mergeIncidents(state.incidents, fresh, { isFresh: true });
    renderIncidentList();
    checkReportsAvailability(state.incidents);
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

const inputFile = $('inputFile');
const selectedFileInfo = $('selectedFileInfo');
const selectedFileName = $('selectedFileName');
const selectedFileSize = $('selectedFileSize');
const clearSelectedFile = $('clearSelectedFile');

function updateSelectedFile() {
  const file = inputFile.files?.[0];

  selectedFileInfo.hidden = !file;

  if (!file) {
    selectedFileName.textContent = '';
    selectedFileSize.textContent = '';
    return;
  }

  selectedFileName.textContent = file.name;

  const size = file.size < 1024 * 1024
    ? `${(file.size / 1024).toFixed(1)} KB`
    : `${(file.size / (1024 * 1024)).toFixed(2)} MB`;

  selectedFileSize.textContent = size;
}

inputFile.addEventListener('change', updateSelectedFile);

clearSelectedFile.addEventListener('click', () => {
  inputFile.value = '';
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

document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && document.activeElement?.matches('input[type="search"]')) {
    document.activeElement.value = '';
    document.activeElement.dispatchEvent(new Event('input', { bubbles: true }));
  }
});

document.querySelectorAll('.nav-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    const nav = tab.dataset.nav;
    let el = null;
    if (nav === 'overview') el = document.getElementById('incidentOverview');
    else if (nav === 'reports') el = document.querySelector('.report-panel');
    else if (nav === 'graph3d') { document.querySelector('.graph-panel [data-graph-action="view-3d"]')?.click(); el = document.querySelector('.graph-panel'); }
    else if (nav === 'evidence') el = document.querySelector('.inspector-panel');
    else if (nav === 'attack') el = document.querySelector('.attack-panel');
    else if (nav === 'investigations') el = document.querySelector('.incident-sidebar');
    else if (nav === 'pipeline') el = document.getElementById('pipelinePanel');
    else if (nav === 'stats') el = document.getElementById('statsPanel');
    else if (nav === 'response') el = document.querySelector('.attack-panel');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      el.classList.add('nav-highlight');
      setTimeout(() => el.classList.remove('nav-highlight'), 1200);
    }
  });
});

const loginOverlay = document.getElementById('loginOverlay');
const loginBtn = document.getElementById('loginBtn');
const loginMsg = document.getElementById('loginMsg');
if (loginOverlay && loginBtn) {
  if (localStorage.getItem('evigraph_token')) loginOverlay.style.display = 'none';
  loginBtn.addEventListener('click', async () => {
    try {
      const base = API_BASE || 'http://localhost:8000';
      const res = await fetch(base + '/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: document.getElementById('loginUser')?.value || 'admin', password: document.getElementById('loginPass')?.value || '' })
      });
      if (res.ok) {
        const d = await res.json();
        localStorage.setItem('evigraph_token', d.token);
        loginOverlay.style.display = 'none';
      } else {
        loginMsg.textContent = 'Invalid credentials';
      }
    } catch (e) {
      loginMsg.textContent = e.message;
    }
  });
}

refreshIncidents();
