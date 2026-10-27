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

const inc0009Hosts = [
  { id: '172.20.10.10', ip: '172.20.10.10', zone: 'INTERNAL', role: 'compromised' },
  { id: '172.20.10.11', ip: '172.20.10.11', zone: 'INTERNAL', role: 'compromised' },
  { id: '203.0.113.88', ip: '203.0.113.88', zone: 'EXTERNAL', role: 'attacker infrastructure' },
  { id: '198.51.100.25', ip: '198.51.100.25', zone: 'EXTERNAL', role: 'attacker infrastructure' },
  { id: '172.20.10.14', ip: '172.20.10.14', zone: 'INTERNAL', role: 'target host' },
  { id: '172.20.10.17', ip: '172.20.10.17', zone: 'INTERNAL', role: 'target host' },
  { id: '172.20.10.29', ip: '172.20.10.29', zone: 'INTERNAL', role: 'target host' },
  { id: '172.20.10.36', ip: '172.20.10.36', zone: 'INTERNAL', role: 'target host' },
  { id: '172.20.10.15', ip: '172.20.10.15', zone: 'INTERNAL', role: 'target host' },
];
const inc0009Stages = [
  { stage_id: 'INC-0009-stage-1', order: 1, tactic: 'Lateral Movement', tactic_id: 'TA0008', src: '172.20.10.10', dst: '172.20.10.14', port: '445', start: '2026-11-02T15:04:49.778564Z', end: '2026-11-02T15:14:53.921692Z', confidence: 0.85, observed: true, behavior: 'Lateral-SMB-Relay', summary: 'Lateral SMB relay attack on port 445', evidence: [{ flow_id: 'flw_apt_smb_05474', ts: '2026-11-02T15:04:49.778564Z', pcap_sha256: hash('flw_apt_smb_05474') }], explanation: [{ feature: 'SMB relay activity', weight: 0.88 }] },
  { stage_id: 'INC-0009-stage-2', order: 2, tactic: 'Command and Control', tactic_id: 'TA0011', src: '172.20.10.10', dst: '203.0.113.88', port: '443', start: '2026-11-02T15:35:15.526534Z', end: '2026-11-02T15:56:39.972266Z', confidence: 0.92, observed: true, behavior: 'C2-Heartbeat', summary: 'Periodic C2 beaconing to external server', evidence: [{ flow_id: 'flw_apt_c2_08753', ts: '2026-11-02T15:35:15.526534Z', pcap_sha256: hash('flw_apt_c2_08753') }], explanation: [{ feature: 'C2 beacon regularity', weight: 0.94 }] },
  { stage_id: 'INC-0009-stage-3', order: 3, tactic: 'Exfiltration', tactic_id: 'TA0010', src: '172.20.10.11', dst: '198.51.100.25', port: '443', start: '2026-11-02T15:43:52.019064Z', end: '2026-11-02T15:53:19.829900Z', confidence: 0.89, observed: true, behavior: 'HTTPS-Exfiltration', summary: 'HTTPS exfiltration to remote destination', evidence: [{ flow_id: 'flw_apt_exfil_06163', ts: '2026-11-02T15:43:52.019064Z', pcap_sha256: hash('flw_apt_exfil_06163') }], explanation: [{ feature: 'Outbound exfiltration volume', weight: 0.91 }] },
];
const inc0009 = {
  incident_id: 'INC-0009', score: 0.92, status: 'Open',
  start: '2026-11-02T15:04:49.778564Z', end: '2026-11-02T15:56:39.972266Z',
  hosts: inc0009Hosts, stages: inc0009Stages, background: [],
};

export const mockList = () => [
  { incident_id: 'INC-0001', score: 0.8994, start: '2026-11-02T09:05:04.094161Z', end: '2026-11-02T10:23:38.562901Z', status: 'candidate' },
  { incident_id: inc0009.incident_id, score: inc0009.score, start: inc0009.start, end: inc0009.end, status: inc0009.status },
  { incident_id: 'INC-0002', score: 0.7726, start: '2026-10-15T09:11:04Z', end: '2026-10-15T09:21:38Z', status: 'candidate' },
  { incident_id: incident.incident_id, score: incident.score, start: incident.start, end: incident.end, status: incident.status },
];

export const mockIncident = (id) => {
  if (id === 'INC-0009') return structuredClone(inc0009);
  const base = structuredClone(incident);
  base.incident_id = id || incident.incident_id;
  return base;
};

export const mockReport = (id) => {
  if (id === 'INC-0009') {
    return {
      report_id: 'RPT-INC-0009',
      incident_id: 'INC-0009',
      summary: 'On 2026-11-02, a network security incident occurred, involving 4100 alerts across 9 hosts in 3 stages: Lateral-SMB-Relay (15:04:49 to 15:14:53), C2-Heartbeat (15:35:15 to 15:56:39), and HTTPS-Exfiltration (15:43:52 to 15:53:19). Internal hosts that sent attack traffic (possibly compromised): 172.20.10.10, 172.20.10.11. External servers that received traffic from internal hosts (possible attacker infrastructure): 203.0.113.88, 198.51.100.25. Internal hosts that received attack traffic (targets): 172.20.10.14, 172.20.10.17, 172.20.10.29, 172.20.10.36, 172.20.10.15.',
      factual_summary: 'On 2026-11-02, 4100 alerts in 3 stages, in time order: Lateral-SMB-Relay (15:04:49 to 15:14:53, 100 alerts); C2-Heartbeat (15:35:15 to 15:56:39, 2000 alerts); HTTPS-Exfiltration (15:43:52 to 15:53:19, 2000 alerts).',
      findings: [{ claim: 'The attackers used a lateral SMB relay attack, possibly using SMB/Windows Admin Shares and Forced Authentication to gain access to the network.', flow_ids: ['flw_apt_smb_05474', 'flw_apt_c2_08753'], technique_id: 'T1021.002' }],
      rejected_findings: [],
      sentences: inc0009Stages.map(s => ({ text: `${s.summary}.`, stage_id: s.stage_id, evidence_ids: s.evidence.map(e => e.flow_id) })),
      validation: { valid: 1, total: 1 },
      footer: { input_sha256: hash('inc0009'), manifest_id: 'run_inc0009', attack_version: 'v15' },
    };
  }
  if (id === 'INC-0001') {
    return {
      report_id: 'RPT-INC-0001',
      incident_id: 'INC-0001',
      summary: 'On 2026-11-02, 2200 alerts in 2 stages occurred: Reconnaissance (09:05:04 to 09:11:39) and Backdoor (10:10:22 to 10:23:38), involving internal hosts 10.0.1.12 and 10.0.1.28, and external hosts 198.51.100.3, 198.51.100.2, 198.51.100.4, and 198.51.100.12, with severity 0.8994 (HIGH).',
      factual_summary: 'On 2026-11-02, 2200 alerts in 2 stages: Reconnaissance (2100 alerts) and Backdoor (100 alerts).',
      findings: [{ claim: 'The incident started with reconnaissance, possibly involving network service discovery and active scanning.', flow_ids: ['flw_unsw_recon_04225', 'flw_unsw_recon_09901'], technique_id: 'T1595' }],
      rejected_findings: [],
      sentences: [
        { text: 'Reconnaissance port scan detected from 198.51.100.3 to 10.0.1.28.', stage_id: 'INC-0001-stage-1', evidence_ids: ['flw_unsw_recon_04225', 'flw_unsw_recon_09901'] },
        { text: 'Backdoor communication detected from 10.0.1.12 to 198.51.100.12.', stage_id: 'INC-0001-stage-2', evidence_ids: ['flw_unsw_back_02540', 'flw_unsw_back_08884'] }
      ],
      validation: { valid: 2, total: 2 },
      footer: { input_sha256: hash('inc0001'), manifest_id: 'run_inc0001', attack_version: 'v15' },
    };
  }
  if (id === 'INC-0002') {
    return {
      report_id: 'RPT-INC-0002',
      incident_id: 'INC-0002',
      summary: 'On 2026-10-15, a denial-of-service attack occurred, involving 10 alerts in 2 stages: PortScan reconnaissance on port 80 followed by DoS-Slowloris traffic exhausting the web server.',
      factual_summary: 'On 2026-10-15, 10 alerts in 2 stages: PortScan (port 80) and DoS-Slowloris (port 80).',
      findings: [{ claim: 'Denial-of-service slowloris flood targeting port 80.', flow_ids: ['flw_dos_0048', 'flw_dos_0049'], technique_id: 'T1499' }],
      rejected_findings: [],
      sentences: [
        { text: 'PortScan detected on port 80 from 172.16.0.105 to 192.168.10.50.', stage_id: 'INC-0002-stage-1', evidence_ids: ['flw_scan_0080', 'flw_scan_0081'] },
        { text: 'DoS-Slowloris activity on port 80 from 172.16.0.120 to 192.168.10.80.', stage_id: 'INC-0002-stage-2', evidence_ids: ['flw_dos_0048', 'flw_dos_0049'] }
      ],
      validation: { valid: 2, total: 2 },
      footer: { input_sha256: hash('inc0002'), manifest_id: 'run_inc0002', attack_version: 'v15' },
    };
  }
  const targetId = id || incident.incident_id;
  return {
    report_id: 'RPT-' + targetId,
    incident_id: targetId,
    sentences: stages.map(s => ({ text: `${s.summary}.${s.observed ? '' : ' (inferred)'}`, stage_id: s.stage_id, evidence_ids: s.evidence.map(e => e.flow_id) })),
    validation: { valid: stages.length, total: stages.length },
    footer: { input_sha256: hash('cicids-lab.pcap'), manifest_id: 'run_' + hash('m1').slice(0, 8), attack_version: 'v15' },
  };
};
