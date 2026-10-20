// Plain-language layer. Static text only; nothing here claims more than the data shows (PRD FR-6.5).
const g = (k, t) => `<span class="gl" data-tip="${k}">${t}</span>`;
export const PLAIN = {
  'Reconnaissance': { title: 'Scouting the target', icon: 'scout', what: `The attacker checks which "doors" (${g('port', 'ports')}) are open on a machine.` },
  'Credential Access': { title: 'Guessing passwords', icon: 'key', what: 'Many quick login attempts, trying to find a way in.' },
  'Initial Access': { title: 'Getting in', icon: 'key', what: 'The attacker gets a first foothold on a machine.' },
  'Lateral Movement': { title: 'Spreading inside', icon: 'spread', what: 'Moving from one machine to others inside the network.' },
  'Command and Control': { title: 'Phoning home', icon: 'phone', what: `The infected machine keeps checking in with the attacker for orders (${g('c2', 'C2')}).` },
  'Exfiltration': { title: 'Stealing data', icon: 'steal', what: `Large amounts of data are sent out of the network (${g('exfil', 'exfiltration')}).` },
  'Exfil & Impact': { title: 'Reaching the goal', icon: 'steal', what: 'The final stage: stealing data or disrupting a service.' },
};
export const plainOf = t => PLAIN[t] ?? { title: t, icon: 'scout', what: 'This step was detected by the analysis engine.' };

export const ZONE_TXT = {
  EXTERNAL: ['Internet', 'Outside the organisation. Not trusted.'],
  DMZ: ['DMZ', 'Public-facing servers. A buffer between the internet and the inside.'],
  INTERNAL: ['Internal network', 'Private machines: staff PCs, databases, file servers.'],
};
export const STATUS = {
  safe: { label: 'Not affected', col: '#8b9bbd' },
  targeted: { label: 'Targeted', col: '#f9c74f' },
  compromised: { label: 'Compromised', col: '#ff8a3d' },
  stolen: { label: 'Data stolen', col: '#ff3b5c' },
};
const RANK = { safe: 0, targeted: 1, compromised: 2, stolen: 3 };

export const verdict = s => (s >= 0.85 ? ['Critical', 'v-crit'] : s >= 0.6 ? ['High', 'v-high'] : s >= 0.4 ? ['Medium', 'v-med'] : ['Low', 'v-low']);
export const confWord = c => (c >= 0.8 ? 'High' : c >= 0.6 ? 'Medium' : 'Low');
export const affected = inc => { const ids = new Set(inc.stages.flatMap(s => [s.src, s.dst])); return inc.hosts.filter(h => ids.has(h.id) && h.zone !== 'EXTERNAL'); };

export function headline(inc) {
  if (!inc.stages?.length) return `Incident ${inc.incident_id ?? ''} has no recorded attack stages.`;
  const byId = new Map((inc.hosts || []).map(h => [h.id, h])), s0 = inc.stages[0], src = byId.get(s0.src), dst = byId.get(s0.dst);
  const who = src?.zone === 'EXTERNAL' ? `An outside attacker (${src.ip})` : `A machine inside the network (${src?.ip ?? s0.src})`;
  const more = affected(inc).length - 1, ex = inc.stages.find(s => /exfil/i.test(s.tactic));
  return `${who} targeted the ${(dst?.role ?? 'first machine').toLowerCase()}` +
    (more > 0 ? ` and then reached ${more} more machine${more > 1 ? 's' : ''}` : '') +
    (ex ? (/impact/i.test(ex.tactic) ? (ex.observed ? ', and the attack reached its final stage (data theft or disruption).' : ', and the attack may have reached its final stage.') : (ex.observed ? ', and data was sent out of the network.' : ', and data may have been sent out.')) : '.');
}

// What the attacker has done to each machine by replay time t. Inferred steps never count as confirmed.
export function hostStatus(inc, t) {
  const out = {}, ext = new Set(inc.hosts.filter(h => h.zone === 'EXTERNAL').map(h => h.id));
  const up = (id, s) => { if (!ext.has(id) && RANK[s] > (RANK[out[id]] ?? 0)) out[id] = s; };
  for (const s of inc.stages) {
    if (t < s.t0) continue;
    if (/Reconnaissance|Credential|Initial/.test(s.tactic)) up(s.dst, 'targeted');
    else if (/Lateral/.test(s.tactic)) { up(s.src, 'compromised'); up(s.dst, s.observed ? 'compromised' : 'targeted'); }
    else if (/Command/.test(s.tactic)) up(s.src, 'compromised');
    else if (/Impact/.test(s.tactic)) { up(s.src, 'compromised'); up(s.dst, 'compromised'); }
    else if (/Exfil/.test(s.tactic)) up(s.src, s.observed ? 'stolen' : 'compromised');
  }
  inc.hosts.forEach(h => { out[h.id] ??= 'safe'; });
  return out;
}
export function activeStage(inc, t) {
  if (t < 0.01) return null;
  return inc.stages.filter(s => t >= s.t0 && t <= s.t1).sort((a, b) => b.t0 - a.t0)[0] ?? null;
}
