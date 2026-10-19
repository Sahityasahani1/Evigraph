// Pure HTML builders. All backend strings pass through esc().
import { esc, clockAt } from '../utils.js';
import { colorOf, css } from '../config.js';

const pill = obs => `<span class="pill ${obs ? 'ob' : 'inf'}">${obs ? 'observed' : 'inferred'}</span>`;
const hostIp = (inc, id) => esc(inc.hosts.find(h => h.id === id)?.ip ?? id);

export function chainHtml(inc) {
  return `<h4>Incident ${esc(inc.incident_id)} · severity ${Number(inc.score).toFixed(2)}</h4>
  <div class="mu">Reconstructed attack chain (click a step)</div>` + inc.stages.map((s, i) => `
  <div class="card" data-stage="${esc(s.stage_id)}" style="--c:${css(colorOf(s.tactic))}">
    <b>${i + 1}. ${esc(s.tactic)}</b>${pill(s.observed)}
    <div class="mu">${hostIp(inc, s.src)} → ${hostIp(inc, s.dst)}:${esc(s.port)}</div>
    <div class="bar"><i style="width:${s.confidence * 100}%"></i></div>
    <div class="mu">confidence ${s.confidence.toFixed(2)} · ${esc(s.tactic_id)}</div>
  </div>`).join('');
}

function evidenceRows(s) {
  return s.evidence.map(e => `<tr><td><span class="tag" data-stage="${esc(s.stage_id)}">${esc(e.flow_id)}</span></td>
    <td>${esc(e.ts.slice(11, 19))}</td><td><code>${esc(e.pcap_sha256.slice(0, 16))}…</code></td></tr>`).join('');
}

export function detailHtml(inc, sel) {
  if (sel?.stage) {
    const s = inc.stages.find(x => x.stage_id === sel.stage); if (!s) return '';
    return `<h4>${esc(s.tactic)} · ${esc(s.tactic_id)}</h4>
    <b style="color:${css(colorOf(s.tactic))}">${hostIp(inc, s.src)} → ${hostIp(inc, s.dst)}:${esc(s.port)}</b>${pill(s.observed)}
    <div class="bar"><i style="width:${s.confidence * 100}%;background:${css(colorOf(s.tactic))}"></i></div>
    <div class="mu">confidence ${s.confidence.toFixed(2)} · behavior: ${esc(s.behavior)}</div>
    <p>${esc(s.summary)}.</p><h4>Why flagged (observable terms)</h4>` +
      s.explanation.map(w => `<div>${esc(w.feature)}<div class="bar"><i style="width:${w.weight * 100}%"></i></div></div>`).join('') +
      `<h4>Evidence trail</h4><table><tr><th>ID</th><th>Time</th><th>PCAP sha256</th></tr>${evidenceRows(s)}</table>`;
  }
  if (sel?.host) {
    const h = inc.hosts.find(x => x.id === sel.host); if (!h) return '';
    const rel = inc.stages.filter(s => s.src === h.id || s.dst === h.id);
    return `<h4>Host</h4><b>${esc(h.id)}</b> · <code>${esc(h.ip)}</code><div class="mu">${esc(h.role)} · zone ${esc(h.zone)}</div><h4>Involved in</h4>` +
      (rel.map(s => `<div class="card" data-stage="${esc(s.stage_id)}" style="--c:${css(colorOf(s.tactic))}">${esc(s.tactic)} · ${hostIp(inc, s.src)} → ${hostIp(inc, s.dst)}</div>`).join('') || '<div class="mu">Only benign traffic observed.</div>');
  }
  return '<h4>Evidence panel</h4><div class="mu">Select a host, an edge, or an attack step. Every claim drills down to flow IDs, timestamps and PCAP hashes (FR-8.4).</div>';
}

export function reportHtml(inc, r) {
  if (!r) return '<div class="mu">Generating report…</div>';
  const v = r.validation, stageOf = id => inc.stages.find(s => s.stage_id === id);
  return `<h4>Incident report · ${esc(r.incident_id)}</h4>
  <span class="pill ${v.valid === v.total ? 'ob' : 'inf'}">validator: ${v.valid}/${v.total} claims cite valid evidence · faithfulness ${Math.round((v.valid / v.total) * 100)}%</span>` +
    r.sentences.map((x, i) => { const s = stageOf(x.stage_id);
      return `<p>${i + 1}. ${s ? esc(clockAt(inc.start, s.t0).slice(0, 8)) + ': ' : ''}${esc(x.text)} ${x.evidence_ids.map(id => `<span class="tag" data-stage="${esc(x.stage_id)}">[E:${esc(id)}]</span>`).join(' ')}</p>`; }).join('') +
    `<div class="mu" style="font-size:11px">Footer · input sha256 <code>${esc(r.footer.input_sha256.slice(0, 16))}…</code> · manifest <code>${esc(r.footer.manifest_id)}</code> · ATT&amp;CK ${esc(r.footer.attack_version)}</div>`;
}
