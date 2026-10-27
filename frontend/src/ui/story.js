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


export function prepareTimelineIncident(inc) {
  if (!inc) return inc;
  const clone = { ...inc };
  const rawStages = Array.isArray(inc.stages) ? inc.stages : [];

  const parseTs = val => {
    if (!val || typeof val !== 'string') return NaN;
    const ms = Date.parse(val);
    return isNaN(ms) ? NaN : ms;
  };

  const stageStarts = rawStages.map(s => {
    const t = parseTs(s.start);
    if (!isNaN(t)) return t;
    const flowTs = parseTs(s.evidence?.[0]?.ts);
    return !isNaN(flowTs) ? flowTs : NaN;
  }).filter(t => !isNaN(t));

  const stageEnds = rawStages.map(s => {
    const t = parseTs(s.end);
    if (!isNaN(t)) return t;
    const flowTs = parseTs(s.evidence?.at(-1)?.ts);
    return !isNaN(flowTs) ? flowTs : NaN;
  }).filter(t => !isNaN(t));

  const rawStartMs = parseTs(inc.start);
  const startMs = !isNaN(rawStartMs)
    ? rawStartMs
    : (stageStarts.length ? Math.min(...stageStarts) : 0);

  const rawEndMs = parseTs(inc.end);
  let endMs = !isNaN(rawEndMs)
    ? rawEndMs
    : (stageEnds.length ? Math.max(...stageEnds) : 0);

  if (startMs > 0 && endMs <= startMs) {
    if (stageEnds.length && Math.max(...stageEnds) > startMs) {
      endMs = Math.max(...stageEnds);
    } else {
      endMs = startMs + Math.max(1, rawStages.length * 5) * 60000;
    }
  }

  const hasRealTimestamps = startMs > 0 && endMs > startMs;
  let durationMin = hasRealTimestamps
    ? (endMs - startMs) / 60000
    : Math.max(1, rawStages.length * 5 || 30);

  if (!durationMin || durationMin < 1 || isNaN(durationMin)) {
    durationMin = Math.max(1, rawStages.length * 5 || 30);
  }

  const sortedStages = [...rawStages].sort((a, b) => {
    const aT = parseTs(a.start) || (a.evidence?.[0]?.ts ? parseTs(a.evidence[0].ts) : NaN);
    const bT = parseTs(b.start) || (b.evidence?.[0]?.ts ? parseTs(b.evidence[0].ts) : NaN);
    if (!isNaN(aT) && !isNaN(bT) && aT !== bT) return aT - bT;
    const aOrder = typeof a.order === 'number' ? a.order : 0;
    const bOrder = typeof b.order === 'number' ? b.order : 0;
    return aOrder - bOrder;
  });

  const count = Math.max(1, sortedStages.length);
  const slotDuration = durationMin / count;

  let maxT1 = 0;
  clone.stages = sortedStages.map((s, idx) => {
    const sStart = parseTs(s.start) || (s.evidence?.[0]?.ts ? parseTs(s.evidence[0].ts) : NaN);
    const sEnd = parseTs(s.end) || (s.evidence?.at(-1)?.ts ? parseTs(s.evidence.at(-1).ts) : NaN);

    let t0, t1;
    if (hasRealTimestamps && !isNaN(sStart)) {
      t0 = Math.max(0, (sStart - startMs) / 60000);
      if (!isNaN(sEnd) && sEnd > sStart) {
        t1 = Math.max(t0 + 0.2, (sEnd - startMs) / 60000);
      } else {
        t1 = t0 + Math.max(0.5, Math.min(2.0, slotDuration));
      }
    } else {
      t0 = idx * slotDuration;
      t1 = Math.min(durationMin, (idx + 1) * slotDuration);
      if (t1 <= t0) t1 = t0 + Math.max(0.2, slotDuration * 0.5);
    }

    if (t1 > maxT1) maxT1 = t1;
    return { ...s, t0, t1 };
  });

  if (maxT1 > durationMin) {
    durationMin = maxT1;
  }
  clone.durationMin = durationMin;
  return clone;
}

export function findInitialAttacker(inc) {
  if (!inc) return null;
  const hosts = Array.isArray(inc.hosts) ? inc.hosts : [];
  const stages = Array.isArray(inc.stages) ? inc.stages : [];

  // 1. Host with explicit attacker / adversary / threat role from incident evidence
  const roleHost = hosts.find(h => /attacker|adversary|threat/i.test(h.role || ''));
  if (roleHost) return roleHost;

  // 2. Direct match on host id 'ATK' or starting with 'ATK'
  const atkHost = hosts.find(h => h.id === 'ATK' || /^ATK\b/i.test(h.id));
  if (atkHost) return atkHost;

  // 3. Infrastructure role
  const infraHost = hosts.find(h => /infrastructure/i.test(h.role || ''));
  if (infraHost) return infraHost;

  // 4. Source of the initial chronological attack stage
  const s0 = stages[0];
  if (s0 && s0.src) {
    const srcHost = hosts.find(h => h.id === s0.src || h.ip === s0.src);
    if (srcHost) return srcHost;
    return { id: s0.src, ip: s0.src, role: 'Attacker origin', zone: 'EXTERNAL' };
  }

  // 5. Any external zone host
  const extHost = hosts.find(h => h.zone === 'EXTERNAL');
  if (extHost) return extHost;

  // 6. Safe fallback
  return null;
}
