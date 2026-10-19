import './styles.css';
import { listIncidents, getIncident, getReport } from './api/client.js';
import { USE_MOCK, colorOf, css } from './config.js';
import { clockAt, esc } from './utils.js';
import { NetworkScene } from './scene/NetworkScene.js';
import { chainHtml, detailHtml, reportHtml } from './ui/panels.js';

const $ = id => document.getElementById(id);
const state = { inc: null, report: null, t: 0, play: false, sel: null, tab: 'E' };
const scene = new NetworkScene($('scene'), { onSelect: sel => select(sel, 'E') });
$('mode').textContent = USE_MOCK ? 'simulated demo data' : 'live backend';

function showError(e) {
  $('detail').innerHTML = `<h4>Backend error</h4><div class="mu">${esc(e.message)}</div><div class="mu">Check that the API is running, then run npm run check:api</div>`;
}
function select(sel, tab = state.tab) {
  state.sel = sel; state.tab = tab; scene.setSelection(sel);
  const s = sel?.stage && state.inc.stages.find(x => x.stage_id === sel.stage);
  if (s && !(state.t >= s.t0 && state.t <= s.t1)) setTime(s.t0 + 0.01);
  render();
}
function setTime(t) { state.t = t; scene.setTime(t); $('slider').value = t; }
function render() {
  const { inc, sel, tab } = state; if (!inc) return;
  $('left').innerHTML = chainHtml(inc);
  document.querySelectorAll('#left .card').forEach(c => c.classList.toggle('on', c.dataset.stage === sel?.stage));
  $('tabE').classList.toggle('on', tab === 'E'); $('tabP').classList.toggle('on', tab === 'P');
  $('detail').innerHTML = tab === 'P' ? reportHtml(inc, state.report) : detailHtml(inc, sel);
}
async function load(id) {
  const inc = await getIncident(id); state.inc = inc; state.report = null; state.sel = null;
  scene.setIncident(inc);
  $('slider').max = inc.durationMin;
  $('tl').innerHTML = inc.stages.map(s => `<i style="left:${(s.t0 / inc.durationMin) * 100}%;width:${((s.t1 - s.t0) / inc.durationMin) * 100}%;background:${css(colorOf(s.tactic))}"></i>`).join('');
  setTime(0); render();
}
async function showReport() {
  state.tab = 'P'; render();
  if (!state.report) { try { state.report = await getReport(state.inc.incident_id); } catch (e) { $('detail').innerHTML = `<div class="mu">Report failed: ${esc(e.message)}</div>`; return; } }
  render();
}

// events
document.addEventListener('click', e => {
  const el = e.target.closest('[data-stage],[data-host]'); if (!el) return;
  select(el.dataset.stage ? { stage: el.dataset.stage } : { host: el.dataset.host }, 'E');
});
$('tabE').onclick = () => { state.tab = 'E'; render(); };
$('tabP').onclick = showReport;
$('incSel').onchange = e => load(e.target.value).catch(showError);
$('slider').oninput = e => { state.play = false; $('play').textContent = '▶ Replay'; setTime(+e.target.value); };
$('play').onclick = () => { state.play = !state.play; if (state.play && state.t >= state.inc.durationMin) setTime(0); $('play').textContent = state.play ? '❚❚ Pause' : '▶ Replay'; };
[['bBenign', 'benign'], ['bRotate', 'rotate'], ['bPackets', 'packets']].forEach(([id, k]) => $(id).onclick = e => { e.target.classList.toggle('on'); scene.setOption(k, e.target.classList.contains('on')); });

// replay clock
let last = performance.now();
(function tick(n) {
  const dt = Math.min((n - last) / 1000, 0.1); last = n;
  if (state.inc) {
    if (state.play) { setTime(Math.min(state.t + dt * 1.6, state.inc.durationMin)); if (state.t >= state.inc.durationMin) { state.play = false; $('play').textContent = '▶ Replay'; } }
    $('clk').textContent = `T+${state.t.toFixed(1)} min · ${clockAt(state.inc.start, state.t)}`;
  }
  requestAnimationFrame(tick);
})(last);

(async () => {
  try {
  const list = await listIncidents();
  $('incSel').innerHTML = list.map(i => `<option value="${esc(i.incident_id)}">${esc(i.incident_id)} · ${Number(i.score).toFixed(2)}</option>`).join('');
  if (list.length) await load(list[0].incident_id);
  else showError(new Error('Backend returned no incidents'));
  } catch (e) { showError(e); }
})();
