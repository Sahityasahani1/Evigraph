import './styles.css';
import { listIncidents, getIncident, getReport } from './api/client.js';
import { USE_MOCK, colorOf, css } from './config.js';
import { clockAt, esc, formatReportJson, formatReportMarkdown, downloadFile } from './utils.js';
import { NetworkScene } from './scene/NetworkScene.js';
import { icon } from './ui/icons.js';
import { hostStatus, activeStage } from './ui/story.js';
import { heroHtml, chainHtml, overviewHtml, detailHtml, reportHtml, soonHtml, isSoon, hoverHtml, capHtml } from './ui/panels.js';
import { initTips, showTip, hideTip } from './ui/tooltip.js';
import { startTour } from './ui/tour.js';

const $ = id => document.getElementById(id);
const root = document.documentElement;
const state = { inc: null, report: null, t: 0, play: false, sel: null, view: 'overview', stKey: '', activeId: null };

// Saved choices, else OS theme. Theme must be set before the scene is created.
root.dataset.theme = localStorage.getItem('evigraph_theme') || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
root.dataset.mode = localStorage.getItem('evigraph_mode') || 'beginner';
document.querySelectorAll('[data-ico]').forEach(b => { b.innerHTML = icon(b.dataset.ico, b.closest('#bottom') ? 16 : 20); });

const scene = new NetworkScene($('scene'), {
  onSelect: sel => select(sel),
  onHover: (h, x, y) => {
    if (!h || !state.inc) { hideTip(); $('scene').style.cursor = 'grab'; return; }
    $('scene').style.cursor = 'pointer'; showTip(hoverHtml(state.inc, h, state.t), x, y);
  },
});
initTips();
$('mode').textContent = USE_MOCK ? '● demo data' : '● live backend';

const paintTheme = () => { $('bTheme').innerHTML = icon(root.dataset.theme === 'dark' ? 'sun' : 'moon', 20); };
const paintMode = () => document.querySelectorAll('.seg button').forEach(b => b.classList.toggle('on', b.dataset.mode === root.dataset.mode));
const paintPlay = () => { $('play').innerHTML = icon(state.play ? 'pause' : 'play', 16) + (state.play ? ' Pause' : ' Replay'); };
paintTheme(); paintMode(); paintPlay();

function showError(e) {
  $('detail').innerHTML = `<h4>Backend error</h4><div class="mu">${esc(e.message)}</div><div class="mu">Check that the API is running, then run npm run check:api</div>`;
}
function select(sel) {
  state.sel = sel; state.view = 'overview'; scene.setSelection(sel);
  const s = sel?.stage && state.inc.stages.find(x => x.stage_id === sel.stage);
  if (s && !(state.t >= s.t0 && state.t <= s.t1)) setTime(s.t0 + 0.01);
  render();
}
function setTime(t) {
  const inc = state.inc; state.t = t; scene.setTime(t); $('slider').value = t;
  const st = hostStatus(inc, t), key = JSON.stringify(st);
  if (key !== state.stKey) { state.stKey = key; scene.setStatus(st); if (state.view === 'overview') render(); }
  const act = activeStage(inc, t), kind = act ? act.stage_id : t >= inc.durationMin - 0.05 ? 'END' : 'START';
  if (kind !== state.activeId) {
    state.activeId = kind; $('cap').innerHTML = capHtml(inc, act, kind);
    $('cap').style.setProperty('--c', act ? css(colorOf(act.tactic)) : 'var(--ac)');
    scene.focus(act?.stage_id ?? null);
  }
  document.querySelectorAll('#left .card').forEach(c => {
    const s = inc.stages.find(x => x.stage_id === c.dataset.stage); if (!s) return;
    c.classList.toggle('done', t > s.t1); c.classList.toggle('live', t >= s.t0 && t <= s.t1); c.classList.toggle('todo', t < s.t0);
  });
}
function render() {
  const { inc, sel, view } = state; if (!inc) return;
  document.querySelectorAll('#left .card').forEach(c => c.classList.toggle('on', c.dataset.stage === sel?.stage));
  document.querySelectorAll('#rail [data-view]').forEach(b => b.classList.toggle('on', b.dataset.view === view));
  $('detail').innerHTML = view === 'report' ? reportHtml(inc, state.report) : isSoon(view) ? soonHtml(view) : sel ? detailHtml(inc, sel, state.t) : overviewHtml(inc, state.t);
}
async function load(id) {
  const inc = await getIncident(id); state.inc = inc; state.report = null; state.sel = null; state.view = 'overview'; state.stKey = ''; state.activeId = null;
  scene.setIncident(inc);
  $('left').innerHTML = heroHtml(inc) + chainHtml(inc);
  $('slider').max = inc.durationMin;
  $('tl').innerHTML = inc.stages.map(s => `<i data-stage="${esc(s.stage_id)}" style="left:${(s.t0 / inc.durationMin) * 100}%;width:${((s.t1 - s.t0) / inc.durationMin) * 100}%;background:${css(colorOf(s.tactic))}"></i>`).join('');
  setTime(0); render();
}
async function setView(v) {
  state.view = v;
  if (v === 'overview') { state.sel = null; scene.setSelection(null); }
  render();
  if (v === 'report' && (!state.report || state.report.incident_id !== state.inc?.incident_id)) {
    try { state.report = await getReport(state.inc.incident_id); } catch (e) { $('detail').innerHTML = `<div class="mu">Report failed: ${esc(e.message)}</div>`; return; }
    if (state.view === 'report') render();
  }
}
async function handleReportDownload(format) {
  try {
    if (!state.inc) throw new Error('No incident selected');
    if (!state.report || state.report.incident_id !== state.inc.incident_id) {
      state.report = await getReport(state.inc.incident_id);
    }
    const inc = state.inc;
    const r = state.report;
    const iid = inc.incident_id || r.incident_id || 'incident';
    if (format === 'json') {
      const jsonStr = formatReportJson(r);
      downloadFile(`${iid}_report.json`, jsonStr, 'application/json');
    } else if (format === 'md') {
      const mdStr = formatReportMarkdown(inc, r);
      downloadFile(`${iid}_report.md`, mdStr, 'text/markdown;charset=utf-8');
    } else {
      throw new Error(`Unsupported export format: ${format}`);
    }
  } catch (err) {
    showError(new Error(`Download failed: ${err.message}`));
  }
}
const setPlay = p => { state.play = p; paintPlay(); };
const jump = dir => {
  const { inc, t } = state, ss = inc.stages;
  const target = dir > 0 ? ss.find(s => s.t0 > t + 0.02) : [...ss].reverse().find(s => s.t0 < t - 0.3);
  setTime(target ? target.t0 + 0.01 : dir > 0 ? inc.durationMin : 0);
};

document.addEventListener('click', e => {
  const dl = e.target.closest('[data-download]');
  if (dl) { handleReportDownload(dl.dataset.download); return; }
  const copy = e.target.closest('[data-copy]');
  if (copy) { navigator.clipboard?.writeText(copy.dataset.copy); copy.innerHTML = icon('check', 12) + ' Copied'; return; }
  const view = e.target.closest('#rail [data-view]'); if (view) { setView(view.dataset.view); return; }
  const el = e.target.closest('[data-stage],[data-host]'); if (!el) return;
  select(el.dataset.stage ? { stage: el.dataset.stage } : { host: el.dataset.host });
});
$('bTheme').onclick = () => {
  root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
  localStorage.setItem('evigraph_theme', root.dataset.theme); scene.setTheme(root.dataset.theme); paintTheme();
};
document.querySelectorAll('.seg button').forEach(b => b.onclick = () => { root.dataset.mode = b.dataset.mode; localStorage.setItem('evigraph_mode', b.dataset.mode); paintMode(); });
$('bTour').onclick = startTour;
$('incSel').onchange = e => load(e.target.value).catch(showError);
$('slider').oninput = e => { setPlay(false); setTime(+e.target.value); };
$('play').onclick = () => { setPlay(!state.play); if (state.play && state.t >= state.inc.durationMin) setTime(0); };
$('prev').onclick = () => jump(-1); $('next').onclick = () => jump(1);
[['bBenign', 'benign'], ['bRotate', 'rotate'], ['bPackets', 'packets'], ['bFollow', 'follow']].forEach(([id, k]) => $(id).onclick = e => { e.target.classList.toggle('on'); scene.setOption(k, e.target.classList.contains('on')); });

let last = performance.now();
(function tick(n) {
  const dt = Math.min((n - last) / 1000, 0.1); last = n;
  if (state.inc) {
    if (state.play) { setTime(Math.min(state.t + dt * 1.6, state.inc.durationMin)); if (state.t >= state.inc.durationMin) setPlay(false); }
    $('clk').textContent = `T+${state.t.toFixed(1)} min · ${clockAt(state.inc.start, state.t)}`;
  }
  requestAnimationFrame(tick);
})(last);

(async () => {
  try {
    const list = await listIncidents();
    $('incSel').innerHTML = list.map(i => `<option value="${esc(i.incident_id)}">${esc(i.incident_id)} · ${Number(i.score).toFixed(2)}</option>`).join('');
    if (list.length) await load(list[0].incident_id); else showError(new Error('Backend returned no incidents'));
    if (!localStorage.getItem('evigraph_toured')) setTimeout(startTour, 900);
  } catch (e) { showError(e); }
})();
