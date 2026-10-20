// Pure HTML builders. Backend strings pass through esc(); static story text is trusted.
import { esc, clockAt } from '../utils.js';
import { colorOf, css } from '../config.js';
import { icon, roleIcon } from './icons.js';
import { GLOSSARY } from './tips.js';
import { plainOf, verdict, confWord, headline, affected, hostStatus, STATUS, ZONE_TXT } from './story.js';

const host = (inc, id) => inc.hosts.find(h => h.id === id);
const ip = (inc, id) => esc(host(inc, id)?.ip ?? id);
const seen = o => `<span class="chip2 ${o ? 'ok' : 'warn'}" data-tip="observed">${icon(o ? 'eye' : 'bulb', 12)}${o ? 'Seen' : 'Likely'}</span>`;
const conf = c => `<span class="chip2 c-${confWord(c).toLowerCase()}" data-tip="confidence"><span class="beg">${confWord(c)} confidence</span><span class="ana">${c.toFixed(2)} · ${confWord(c)}</span></span>`;
const stChip = (id, s) => `<span class="st st-${s}" data-tip="status" style="--s:${STATUS[s].col}">${STATUS[s].label}</span>`;
const route = (inc, s) => `${icon(roleIcon(host(inc, s.src)), 14)} ${ip(inc, s.src)} <span class="arrow">→</span> ${icon(roleIcon(host(inc, s.dst)), 14)} ${ip(inc, s.dst)}:${esc(s.port)}`;

export const heroHtml = inc => {
  const [vl, vc] = verdict(inc.score), obs = inc.stages.filter(s => s.observed).length;
  return `<div class="hero"><div class="hero-top"><span class="verdict ${vc}" data-tip="severity">${vl}</span><span class="mu">${esc(inc.incident_id)}<span class="ana"> · score ${Number(inc.score).toFixed(2)}</span></span></div>
  <h2>${esc(headline(inc))}</h2>
  <div class="hero-meta"><span data-tip="chain">${icon('scout', 14)} ${inc.stages.length} steps</span><span data-tip="observed">${icon('eye', 14)} ${obs} directly seen</span><span data-tip="status">${icon('laptop', 14)} ${affected(inc).length} machines hit</span><span>${Math.round(inc.durationMin)} min</span></div></div>`;
};

export const chainHtml = inc => `<h4 data-tip="chain">The story, step by step</h4><div class="chain">` + inc.stages.map((s, i) => {
  const p = plainOf(s.tactic);
  return `<div class="card" data-stage="${esc(s.stage_id)}" style="--c:${css(colorOf(s.tactic))}">
    <div class="ico-tile">${icon(p.icon, 20)}</div>
    <div class="cbody">
      <div class="ctitle"><span class="num">${String(i + 1).padStart(2, '0')}</span><b class="beg">${p.title}</b><b class="ana">${esc(s.tactic)}</b></div>
      <div class="mu cwhat"><span class="beg">${p.what}</span><span class="ana">${esc(s.tactic_id)} · ${p.title}</span></div>
      <div class="croute">${route(inc, s)}</div>
      <div class="cmeta">${seen(s.observed)}${conf(s.confidence)}</div>
    </div></div>`;
}).join('') + '</div>';

export function overviewHtml(inc, t) {
  const s0 = inc.stages[0], src = host(inc, s0.src), st = hostStatus(inc, t);
  const rows = inc.hosts.filter(h => h.zone !== 'EXTERNAL').map(h => `<div class="mrow" data-host="${esc(h.id)}">${icon(roleIcon(h), 18)}<div><b>${esc(h.id)}</b> <code>${esc(h.ip)}</code><div class="mu">${esc(h.role)} · ${esc(ZONE_TXT[h.zone]?.[0] ?? h.zone)}</div></div>${stChip(h.id, st[h.id])}</div>`).join('');
  return `<h4>Where it started</h4>
  <div class="mrow" data-tip="entry">${icon(roleIcon(src), 18)}<div><b>${esc(src?.ip ?? s0.src)}</b><div class="mu">${esc(src?.role ?? '')} · ${esc(ZONE_TXT[src?.zone]?.[0] ?? '')}</div></div></div>
  <h4 data-tip="status">Machines inside the network</h4>${rows}
  <h4>How to read the map</h4>
  <div class="legend">
    <div>${Object.entries(ZONE_TXT).map(([k, [n, d]]) => `<div class="lz"><b>${n}</b><span class="mu"> ${d}</span></div>`).join('')}</div>
    <div class="lrow"><span>${icon('skull', 16)} attacker</span><span>${icon('laptop', 16)} computer</span><span>${icon('db', 16)} database</span></div>
    <div class="lrow">${Object.entries(STATUS).map(([k, v]) => `<span><i style="background:${v.col}"></i>${v.label}</span>`).join('')}</div>
    <div class="mu fine">Glowing curved lines are attack connections. Grey lines are normal traffic.</div>
  </div>
  <h4>Terms you will see <span class="mu">(hover)</span></h4>
  <div class="chips">${GLOSSARY.map(k => `<span class="chip gl" data-tip="${k}">${k === 'c2' ? 'C2' : k === 'attck' ? 'ATT&amp;CK' : k === 'pcap' ? 'PCAP' : k === 'dmz' ? 'DMZ' : k[0].toUpperCase() + k.slice(1)}</span>`).join('')}</div>
  <p class="mu fine">Click a machine, a connection or a story card to open its proof. Click empty space to return here.</p>`;
}

const receipt = (s, e) => `<div class="receipt"><div class="rh"><span class="tag" data-stage="${esc(s.stage_id)}">${esc(e.flow_id)}</span><span class="mu">${esc(e.ts.slice(11, 19))} UTC</span></div>
  <div class="rf"><span data-tip="hash">Fingerprint</span> <code>${esc(e.pcap_sha256.slice(0, 16))}…</code>
  <button class="mini" data-copy="${esc(e.pcap_sha256)}">${icon('copy', 12)} Copy</button></div></div>`;

export function detailHtml(inc, sel, t) {
  if (sel?.stage) {
    const s = inc.stages.find(x => x.stage_id === sel.stage); if (!s) return '';
    const p = plainOf(s.tactic), col = css(colorOf(s.tactic));
    return `<div class="dhead" style="--c:${col}"><div class="ico-tile big">${icon(p.icon, 26)}</div><div>
      <div class="mu"><span class="beg">Step ${s.order}</span><span class="ana">${esc(s.tactic_id)}</span></div>
      <h3><span class="beg">${p.title}</span><span class="ana">${esc(s.tactic)}</span></h3></div></div>
    <div class="routebig">${route(inc, s)}</div>
    <div class="cmeta">${seen(s.observed)}${conf(s.confidence)}</div>
    <h4>What this means</h4><p>${p.what}</p>
    <h4>What we saw</h4><p>${esc(s.summary)}.</p>
    <p class="mu fine">${s.observed ? 'Seen: found directly in the captured traffic.' : 'Likely: deduced from patterns. A person should confirm it.'}</p>
    <h4 data-tip="explain">Why the system flagged it</h4>` +
      s.explanation.map(w => `<div class="why">${esc(w.feature)}<div class="bar"><i style="width:${w.weight * 100}%;background:${col}"></i></div></div>`).join('') +
      `<h4 data-tip="evidence">Proof · ${s.evidence.length} sample conversations</h4>
      <p class="mu fine">Each receipt is one network conversation. The fingerprint proves the capture was not altered: recompute it and it must match.</p>` +
      s.evidence.map(e => receipt(s, e)).join('');
  }
  if (sel?.host) {
    const h = host(inc, sel.host); if (!h) return '';
    const rel = inc.stages.filter(s => s.src === h.id || s.dst === h.id), z = ZONE_TXT[h.zone] ?? [h.zone, ''];
    return `<div class="dhead"><div class="ico-tile big">${icon(roleIcon(h), 26)}</div><div><h3>${esc(h.id)} <code>${esc(h.ip)}</code></h3><div class="mu">${esc(h.role)}</div></div></div>
    <div class="cmeta">${h.zone === 'EXTERNAL' ? '' : stChip(h.id, hostStatus(inc, t)[h.id])}</div>
    <h4>Where it sits</h4><p><b>${esc(z[0])}</b> <span class="mu">${esc(z[1])}</span></p><h4>Involved in</h4>` +
      (rel.map(s => { const p = plainOf(s.tactic); return `<div class="card" data-stage="${esc(s.stage_id)}" style="--c:${css(colorOf(s.tactic))}"><div class="ico-tile">${icon(p.icon, 18)}</div><div class="cbody"><b><span class="beg">${p.title}</span><span class="ana">${esc(s.tactic)}</span></b><div class="croute">${route(inc, s)}</div></div></div>`; }).join('') || '<div class="mu">Only normal traffic seen.</div>');
  }
  return '';
}

export function reportHtml(inc, r) {
  if (!r) return '<div class="mu">Generating report…</div>';
  const v = r.validation, stageOf = id => inc.stages.find(s => s.stage_id === id);
  return `<h4 data-tip="v_report">Incident report · ${esc(r.incident_id)}</h4>
  <span class="chip2 ${v.valid === v.total ? 'ok' : 'warn'}">${icon('check', 12)} ${v.valid}/${v.total} claims cite valid evidence · ${Math.round((v.valid / v.total) * 100)}% faithful</span>
  <p class="mu fine">Every sentence cites evidence. Click a tag to open its proof.</p>` +
    r.sentences.map((x, i) => { const s = stageOf(x.stage_id);
      return `<p class="rs"><span class="num">${String(i + 1).padStart(2, '0')}</span> ${s ? `<span class="mu">${esc(clockAt(inc.start, s.t0).slice(0, 8))}</span> ` : ''}${esc(x.text)} ${x.evidence_ids.map(id => `<span class="tag" data-stage="${esc(x.stage_id)}">[E:${esc(id)}]</span>`).join(' ')}</p>`; }).join('') +
    `<div class="mu fine">Input fingerprint <code>${esc(r.footer.input_sha256.slice(0, 16))}…</code> · run <code>${esc(r.footer.manifest_id)}</code> · ATT&amp;CK ${esc(r.footer.attack_version)}</div>`;
}

const SOON = {
  courtroom: ['Courtroom', 'scale', 'Will check whether the evidence would stand up in an audit: integrity, chain of custody and reproducibility.'],
  containment: ['Containment', 'shield', 'Will suggest which machines and ports to block first, ranked by impact.'],
  privacy: ['Privacy proof', 'lock', 'Will show that IP addresses were pseudonymized and that no raw traffic left the system.'],
};
export const isSoon = k => k in SOON;
export const soonHtml = k => `<div class="dhead"><div class="ico-tile big">${icon(SOON[k][1], 26)}</div><div><h3>${SOON[k][0]}</h3><div class="mu">Planned, not built yet</div></div></div><p>${SOON[k][2]}</p><p class="mu fine">This tab will connect to the backend once its endpoint is ready.</p>`;

export function hoverHtml(inc, h, t) {
  if (h.host) { const x = host(inc, h.host); if (!x) return '';
    return `<b>${esc(x.id)} · ${esc(x.ip)}</b><div>${esc(x.role)} · ${esc(ZONE_TXT[x.zone]?.[0] ?? x.zone)}</div>${x.zone === 'EXTERNAL' ? '' : `<div class="why">${STATUS[hostStatus(inc, t)[x.id]].label}</div>`}`; }
  const s = inc.stages.find(v => v.stage_id === h.stage); if (!s) return '';
  const p = plainOf(s.tactic);
  return `<b>${p.title}</b><div>${ip(inc, s.src)} → ${ip(inc, s.dst)}:${esc(s.port)}</div><div class="why">${s.observed ? 'Seen' : 'Likely'} · ${confWord(s.confidence)} confidence</div><div>${esc(s.summary)}</div>`;
}

export function capHtml(inc, s, kind) {
  if (!s) return kind === 'END'
    ? `<div class="ico-tile">${icon('check', 20)}</div><div><div class="cap-t"><b>End of incident</b></div><div class="cap-d">${esc(headline(inc))}</div></div>`
    : `<div class="ico-tile">${icon('play', 20)}</div><div><div class="cap-t"><b>Ready</b></div><div class="cap-d">Press Replay to watch the attack unfold. The camera follows each step.</div></div>`;
  const p = plainOf(s.tactic);
  return `<div class="ico-tile" style="--c:${css(colorOf(s.tactic))}">${icon(p.icon, 20)}</div><div>
    <div class="cap-t"><b><span class="beg">${p.title}</span><span class="ana">${esc(s.tactic)}</span></b><span class="mu">T+${Math.floor(s.t0)} min</span></div>
    <div class="cap-d"><span class="beg">${p.what} </span>${esc(s.summary)}.</div></div>`;
}
