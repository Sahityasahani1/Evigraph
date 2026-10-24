// Makes real pipeline data safe for the UI. Pure function, harmless on already-clean data.
// Fixes: naive timestamps (treated as UTC), null zones/roles, IP-only host IDs, null hashes,
// tactic names like "C2" / "Exfil & Impact", and runs of repeated identical stages.
const TACTICS = [[/impact/i, 'Exfil & Impact'], [/exfil/i, 'Exfiltration'], [/recon|scan|discover/i, 'Reconnaissance'], [/initial/i, 'Initial Access'], [/cred|brute/i, 'Credential Access'], [/lateral/i, 'Lateral Movement'], [/^c2$|command|control/i, 'Command and Control']];
export const canonTactic = t => TACTICS.find(([re]) => re.test(t ?? ''))?.[1] ?? t;
const utc = s => (typeof s === 'string' && s && !/(Z|[+-]\d{2}:?\d{2})$/.test(s) ? s.replace(' ', 'T') + 'Z' : s);
const isIp = s => /^[\d.]+$/.test(String(s)) || String(s).includes(':');
const ms = s => Date.parse(s);

export function adapt(raw) {
  const sIn = (raw.stages ?? []).map(s => ({ ...s, start: utc(s.start), end: utc(s.end ?? s.start), tactic: canonTactic(s.tactic) }))
    .sort((a, b) => ms(a.start) - ms(b.start));

  const hostIn = new Map((raw.hosts ?? []).map(h => [h.id ?? h.ip, h]));
  const touch = id => { if (id != null && !hostIn.has(id)) hostIn.set(id, { id, ip: id }); };
  sIn.forEach(s => { touch(s.src); touch(s.dst); });
  (raw.background ?? []).forEach(b => { touch(b.src); touch(b.dst); });

  if (!sIn.length) {
    let n = 0, attackerCount = 0;
    const alias = new Map();
    const hosts = [...hostIn.values()].map(h => {
      const old = h.id ?? h.ip;
      const isAttacker = /attacker|infrastructure/i.test(h.role ?? '');
      const id = isIp(old)
        ? (isAttacker ? (++attackerCount === 1 ? 'ATK' : `ATK${attackerCount}`) : `H${++n}`)
        : old;
      alias.set(old, id);
      return {
        ...h,
        id,
        ip: h.ip ?? old,
        zone: h.zone ?? (isAttacker ? 'EXTERNAL' : 'INTERNAL'),
        role: h.role ?? (isAttacker ? 'Attacker' : 'Host'),
      };
    });
    const m = id => alias.get(id) ?? id;
    const start = raw.start ? utc(raw.start) : null;
    const end = raw.end ? utc(raw.end) : start;
    return {
      ...raw,
      start,
      end,
      score: Number(raw.score ?? 0),
      hosts,
      stages: [],
      background: (raw.background ?? []).map(b => ({ src: m(b.src), dst: m(b.dst) })),
    };
  }

  const firstDst = sIn[0].dst, alias = new Map();
  let n = 0, attackerCount = 0;
  const hosts = [...hostIn.values()].map(h => {
    const old = h.id ?? h.ip;
    const isAttacker = /attacker|infrastructure/i.test(h.role ?? '');
    const id = isIp(old)
      ? (isAttacker ? (++attackerCount === 1 ? 'ATK' : `ATK${attackerCount}`) : `H${++n}`)
      : old;
    alias.set(old, id);
    return {
      ...h,
      id,
      ip: h.ip ?? old,
      zone: h.zone ?? (isAttacker ? 'EXTERNAL' : 'INTERNAL'),
      role: h.role ?? (isAttacker ? 'Attacker' : old === firstDst ? 'Target host' : 'Host'),
    };
  });
  const m = id => alias.get(id) ?? id;

  const merged = [];
  for (const s0 of sIn) {
    const s = {
      ...s0, src: m(s0.src), dst: m(s0.dst), port: String(s0.port ?? ''), confidence: Number(s0.confidence ?? 0.5),
      observed: s0.observed ?? true, behavior: s0.behavior ?? '', summary: s0.summary ?? `${s0.tactic} activity`, explanation: s0.explanation ?? [],
      evidence: (s0.evidence ?? []).map(e => ({ ...e, ts: utc(e.ts) ?? s0.start, pcap_sha256: e.pcap_sha256 ?? '' })),
    };
    const p = merged.at(-1);
    if (p && p.tactic === s.tactic && p.src === s.src && p.dst === s.dst) {
      if (ms(s.end) > ms(p.end)) p.end = s.end;
      p.confidence = Math.max(p.confidence, s.confidence); p.observed = p.observed && s.observed;
      p.evidence = [...p.evidence, ...s.evidence].slice(0, 8); p.merged = (p.merged ?? 1) + 1;
      if (s.port && !p.port.split(', ').includes(s.port) && p.port.split(', ').length < 3) p.port = p.port ? `${p.port}, ${s.port}` : s.port;
    } else merged.push(s);
  }
  merged.forEach((s, i) => { s.order = i + 1; if (s.merged) s.summary += ` (${s.merged} similar events grouped)`; });

  const first = merged[0].start, last = merged.reduce((a, s) => (ms(s.end) > ms(a) ? s.end : a), merged[0].end);
  const start = raw.start && ms(utc(raw.start)) < ms(first) ? utc(raw.start) : first;
  const end = raw.end && ms(utc(raw.end)) > ms(last) ? utc(raw.end) : last;
  return { ...raw, start, end, score: Number(raw.score ?? 0), hosts, stages: merged, background: (raw.background ?? []).map(b => ({ src: m(b.src), dst: m(b.dst) })) };
}
