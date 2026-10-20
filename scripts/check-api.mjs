// Contract check against a live backend. Usage: npm run check:api -- http://localhost:8000/api
// Set EVIGRAPH_TOKEN if the API needs auth. Exits 1 on any failure.
const base = (process.argv[2] || 'http://localhost:8000/api').replace(/\/$/, '');
const token = process.env.EVIGRAPH_TOKEN;
const ZONES = ['EXTERNAL', 'DMZ', 'INTERNAL'], errs = [], warns = [];
const bad = (w, m) => errs.push(`${w}: ${m}`);
const get = async p => {
  const r = await fetch(base + p, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  if (!r.ok) throw new Error(`${p} -> HTTP ${r.status}`);
  return r.json();
};
const iso = v => typeof v === 'string' && !Number.isNaN(Date.parse(v));

try {
  const list = await get('/incidents');
  if (!Array.isArray(list) || !list.length) bad('/incidents', 'must be a non-empty array');
  else {
    list.forEach((i, n) => { if (!i.incident_id) bad(`/incidents[${n}]`, 'missing incident_id'); if (typeof i.score !== 'number') bad(`/incidents[${n}]`, 'score must be a number'); });
    const inc = await get('/incidents/' + encodeURIComponent(list[0].incident_id));
    const w = `/incidents/${list[0].incident_id}`;
    if (!iso(inc.start) || !iso(inc.end)) bad(w, 'start/end must be ISO timestamps');
    const hosts = new Set();
    (inc.hosts ?? []).forEach((h, n) => {
      if (!h.id || !h.ip) bad(`${w} hosts[${n}]`, 'needs id and ip');
      if (!ZONES.includes(h.zone)) bad(`${w} hosts[${n}]`, `zone must be one of ${ZONES} (got ${h.zone})`);
      hosts.add(h.id);
    });
    if (!hosts.size) bad(w, 'hosts[] missing or empty');
    if (!Array.isArray(inc.stages) || !inc.stages.length) bad(w, 'stages[] missing or empty');
    (inc.stages ?? []).forEach((s, n) => {
      const sw = `${w} stages[${n}]`;
      for (const k of ['stage_id', 'order', 'tactic', 'src', 'dst']) if (s[k] == null) bad(sw, `missing ${k}`);
      if (!hosts.has(s.src) || !hosts.has(s.dst)) bad(sw, `src/dst (${s.src}, ${s.dst}) not in hosts[]`);
      if (!iso(s.start) || !iso(s.end) || Date.parse(s.end) < Date.parse(s.start)) bad(sw, 'start/end invalid or end < start');
      if (typeof s.confidence !== 'number' || s.confidence < 0 || s.confidence > 1) bad(sw, 'confidence must be 0..1');
      if (typeof s.observed !== 'boolean') bad(sw, 'observed must be boolean');
      if (!Array.isArray(s.evidence) || !s.evidence.length) bad(sw, 'evidence[] empty (every claim needs evidence)');
      (s.evidence ?? []).forEach(e => {
        if (!e.flow_id || !iso(e.ts) || !e.pcap_sha256) bad(sw, `evidence needs flow_id, ts, pcap_sha256 (${e.flow_id})`);
        if (e.flow_id && !/^flw_[0-9a-f]{16}$/.test(e.flow_id)) warns.push(`${e.flow_id} is not flw_<16 hex> (stand-in ID?)`);
      });
    });
  }
} catch (e) { bad('request', e.message); }

[...new Set(warns)].slice(0, 5).forEach(w => console.log('WARN', w));
if (errs.length) { errs.forEach(e => console.log('FAIL', e)); process.exit(1); }
console.log('OK: backend matches the frontend contract');
