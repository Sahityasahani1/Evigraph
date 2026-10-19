// Simulated data so the UI runs without a backend. DELETE or ignore once the real API is wired.
const START = '2026-10-13T14:02:00Z';
const at = m => new Date(Date.parse(START) + m * 60000).toISOString();
const hash = s => { let h = 2166136261; for (const c of s) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return (h >>> 0).toString(16).padStart(8, '0').repeat(8); };

const hosts = [
  { id: 'ATK', ip: '203.0.113.7', zone: 'EXTERNAL', role: 'Attacker' },
  { id: 'C2', ip: '198.51.100.23', zone: 'EXTERNAL', role: 'Rare external destination' },
  { id: 'WEB', ip: '10.0.1.10', zone: 'DMZ', role: 'Web server' },
  { id: 'WS1', ip: '10.0.2.11', zone: 'INTERNAL', role: 'Workstation' },
  { id: 'WS2', ip: '10.0.2.12', zone: 'INTERNAL', role: 'Workstation' },
  { id: 'WS3', ip: '10.0.2.13', zone: 'INTERNAL', role: 'Workstation' },
  { id: 'DB', ip: '10.0.2.50', zone: 'INTERNAL', role: 'Database' },
  { id: 'FS', ip: '10.0.2.60', zone: 'INTERNAL', role: 'File server' },
];
const S = (n, order, tactic, tactic_id, src, dst, port, a, b, confidence, observed, behavior, summary, ids, expl) => ({
  stage_id: `STG-${n}`, order, tactic, tactic_id, src, dst, port, start: at(a), end: at(b), confidence, observed, behavior, summary,
  evidence: ids.map((id, i) => ({ flow_id: `flow_${id}`, ts: at(a + (i * (b - a)) / 3), pcap_sha256: hash('pcap' + id) })),
  explanation: expl.map(([feature, weight]) => ({ feature, weight })),
});
const stages = [
  S(1, 1, 'Reconnaissance', 'TA0043', 'ATK', 'WEB', '1-1024', 0, 3.5, .91, true, 'scan', '412 short connections to 412 distinct ports within 3.5 minutes, 97% reset', [1001, 1002, 1003], [['distinct dst ports (412)', .95], ['RST ratio 0.97', .88], ['median flow < 40 ms', .61]]),
  S(2, 2, 'Credential Access', 'TA0006', 'ATK', 'WEB', '22', 4, 10, .87, true, 'brute-force-like', '182 short connections to port 22 from one source within 3 minutes, then one long session', [2041, 2042, 2043], [['conn count to :22 (182)', .92], ['similar byte sizes', .74], ['single source', .55]]),
  S(3, 3, 'Lateral Movement', 'TA0008', 'WEB', 'WS2', '445, 3389', 12, 16, .76, true, 'lateral', 'DMZ host opened connections to 9 new internal peers on admin ports after receiving suspicious traffic', [3310, 3311, 3312], [['new internal peers (9)', .84], ['admin ports', .7], ['prior inbound from ATK', .52]]),
  S(4, 4, 'Lateral Movement', 'TA0008', 'WS2', 'DB', '3306', 17, 20, .64, false, 'lateral', 'Workstation connected to the database on 3306, a first-seen peer', [3377, 3378, 3379], [['host continuity WS2', .66], ['rare client for :3306', .6], ['bytes in >> out', .4]]),
  S(5, 5, 'Command and Control', 'TA0011', 'WS2', 'C2', '443', 20, 28, .83, true, 'c2-beacon', 'Periodic outbound TLS connections every 60 s with under 3% jitter to a rare destination', [4410, 4411, 4412], [['beacon period 60s', .9], ['jitter < 3%', .81], ['rare destination', .65]]),
  S(6, 6, 'Exfiltration', 'TA0010', 'DB', 'C2', '443', 25, 30, .89, true, 'bulk-outbound', '1.8 GB sent outbound to a rare destination with out/in ratio of 49:1', [5502, 5503, 5504], [['bytes out 1.8 GB', .97], ['out/in ratio 49:1', .86], ['new destination', .5]]),
];
const incident = { incident_id: 'INC-0042', score: .93, status: 'open', start: START, end: at(30), hosts, stages,
  background: [['WS1', 'WEB'], ['WS3', 'FS'], ['WS1', 'DB'], ['WS3', 'WEB']].map(([src, dst]) => ({ src, dst })) };

export const mockList = () => [{ incident_id: incident.incident_id, score: incident.score, start: incident.start, end: incident.end, status: incident.status }];
export const mockIncident = () => structuredClone(incident);
export const mockReport = () => ({
  report_id: 'RPT-0042', incident_id: incident.incident_id,
  sentences: stages.map(s => ({ text: `${s.summary}.${s.observed ? '' : ' (inferred)'}`, stage_id: s.stage_id, evidence_ids: s.evidence.map(e => e.flow_id) })),
  validation: { valid: stages.length, total: stages.length },
  footer: { input_sha256: hash('cicids-lab.pcap'), manifest_id: 'run_' + hash('m1').slice(0, 8), attack_version: 'v15' },
});
