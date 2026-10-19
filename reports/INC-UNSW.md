# Incident report: INC-UNSW

## Executive summary (model-written, verified)
The network security incident began with reconnaissance from 198.51.100.3, 198.51.100.2, and 198.51.100.4 to 10.0.1.28, 10.0.1.17, and 10.0.1.16, generating 2100 alerts. The attackers then used fuzzers to scan for vulnerabilities, followed by exploits targeting 10.0.1.20, and finally established a backdoor through 10.0.1.10, 10.0.1.12, 10.0.1.13, 10.0.1.11, 10.0.1.14, 198.51.100.11, 198.51.100.10, 198.51.100.12, and 198.51.100.13, generating 2100 alerts. The most critical host is 198.51.100.11, which was initially a source of fuzzing alerts and later became a target of backdoor alerts, indicating a possible callback or reused infrastructure.

## Overview
- Severity: 0.972 (HIGH; bands: >=0.8 high, >=0.5 medium)
- Time span: 2026-11-02T09:05:04.094161 to 2026-11-02T10:26:39.545619
- Alerts: 8400 across 110 hosts

## Timeline (from detector alerts)
1. 2026-11-02T09:05:04.094161 to 2026-11-02T09:11:39.453799: Reconnaissance, 2100 alerts, from 198.51.100.3, 198.51.100.2, 198.51.100.4 to 10.0.1.28, 10.0.1.17, 10.0.1.16, 10.0.1.21, 10.0.1.73 and 65 more [flw_unsw_recon_04225, flw_unsw_recon_09901]
2. 2026-11-02T09:21:54.599564 to 2026-11-02T09:29:59.821140: Fuzzers, 2100 alerts, from 198.51.100.15, 198.51.100.30, 198.51.100.35, 198.51.100.10, 198.51.100.14 and 33 more to 10.0.1.5, 10.0.1.6, 10.0.1.20 [flw_unsw_fuzz_03138, flw_unsw_fuzz_02344]
3. 2026-11-02T09:59:51.633232 to 2026-11-02T10:09:59.669952: Exploits, 2100 alerts, from 198.51.100.9, 198.51.100.8, 198.51.100.5, 198.51.100.7, 198.51.100.6 to 10.0.1.20, 10.0.1.6, 10.0.1.5 [flw_unsw_exp_07777, flw_unsw_exp_09828]
4. 2026-11-02T10:10:22.296697 to 2026-11-02T10:26:39.545619: Backdoor, 2100 alerts, from 10.0.1.10, 10.0.1.12, 10.0.1.13, 10.0.1.11, 10.0.1.14 to 198.51.100.11, 198.51.100.10, 198.51.100.12, 198.51.100.13 [flw_unsw_back_02540, flw_unsw_back_09317]

## Possible pivot hosts
- None: no host appears as both a target and a source of alerts.

## Hosts whose role changed across stages (computed from the alerts)
- 10.0.1.10: target in Reconnaissance, then source in Backdoor (possible compromise)
- 10.0.1.12: target in Reconnaissance, then source in Backdoor (possible compromise)
- 10.0.1.13: target in Reconnaissance, then source in Backdoor (possible compromise)
- 10.0.1.11: target in Reconnaissance, then source in Backdoor (possible compromise)
- 10.0.1.14: target in Reconnaissance, then source in Backdoor (possible compromise)
- 198.51.100.11: source in Fuzzers, then target in Backdoor (possible callback or reused infrastructure)
- 198.51.100.10: source in Fuzzers, then target in Backdoor (possible callback or reused infrastructure)
- 198.51.100.12: source in Fuzzers, then target in Backdoor (possible callback or reused infrastructure)
- 198.51.100.13: source in Fuzzers, then target in Backdoor (possible callback or reused infrastructure)

## Key hosts
- 10.0.1.10: source of 457 flows (4 destination hosts, 4 destination ports), destination of 37 flows
- 10.0.1.12: source of 440 flows (4 destination hosts, 4 destination ports), destination of 25 flows
- 198.51.100.11: source of 61 flows (3 destination hosts, 4 destination ports), destination of 551 flows
- 10.0.1.20: source of 0 flows (0 destination hosts, 0 destination ports), destination of 1448 flows

## ATT&CK mapping (best search match per stage)
- Reconnaissance: T1046 Network Service Discovery (tactic: discovery); other candidates: T1049, T1018, T1016.001, T1595
- Fuzzers: T1595.002 Vulnerability Scanning (tactic: reconnaissance); other candidates: T1046, T1190, T1592.003, T1557.004
- Exploits: T1210 Exploitation of Remote Services (tactic: lateral-movement); other candidates: T1190, T1203, T1021, T1133
- Backdoor: T1668 Exclusive Control (tactic: persistence); other candidates: T1554, T1563, T1021, T1133

## Analyst findings (each verified against retrieved evidence)
- The incident started with reconnaissance, possibly involving network service discovery and active scanning. (T1595.002) [flw_unsw_recon_04225, flw_unsw_recon_09901]

## Verification summary
- Findings proposed: 1, accepted: 1, rejected: 0