import pytest
from frontend.api.server import resolve_finding_stage, get_report
from src.agent.mock import load_agent, investigate


def test_resolve_finding_stage_matches_timeline_and_technique():
    mock_agent = load_agent()
    agent_res = investigate(mock_agent, "INC-0009")

    # Finding 1: Stage 1 Lateral-SMB-Relay (technique T1021.002, flow flw_apt_smb_05474)
    f1 = {
        "claim": "The attackers used a lateral SMB relay attack.",
        "flow_ids": ["flw_apt_smb_05474", "flw_apt_c2_08753"],
        "technique_id": "T1021.002",
    }
    assert resolve_finding_stage(f1, "INC-0009", agent_res=agent_res) == "INC-0009-stage-1"

    # Finding 2: Stage 2 C2-Heartbeat (technique T1071, flow flw_apt_c2_08753)
    f2 = {
        "claim": "Periodic C2 beaconing to external server.",
        "flow_ids": ["flw_apt_c2_08753"],
        "technique_id": "T1071",
    }
    assert resolve_finding_stage(f2, "INC-0009", agent_res=agent_res) == "INC-0009-stage-2"

    # Finding 3: Stage 3 HTTPS-Exfiltration (flow flw_apt_exfil_06163)
    f3 = {
        "claim": "Outbound exfiltration volume observed.",
        "flow_ids": ["flw_apt_exfil_06163"],
    }
    assert resolve_finding_stage(f3, "INC-0009", agent_res=agent_res) == "INC-0009-stage-3"


def test_resolve_finding_stage_preserves_explicit_stage():
    mock_agent = load_agent()
    agent_res = investigate(mock_agent, "INC-0009")

    # Direct stage_id
    f_explicit = {"claim": "Explicit stage id", "stage_id": "INC-0009-stage-2"}
    assert resolve_finding_stage(f_explicit, "INC-0009", agent_res=agent_res) == "INC-0009-stage-2"

    # Direct stage integer
    f_num = {"claim": "Stage index 3", "stage": 3}
    assert resolve_finding_stage(f_num, "INC-0009", agent_res=agent_res) == "INC-0009-stage-3"


def test_resolve_finding_stage_returns_none_when_unmapped():
    mock_agent = load_agent()
    agent_res = investigate(mock_agent, "INC-0009")

    # Unknown flow, unknown technique: must NOT guess
    f_unknown = {
        "claim": "Uncorrelated observation",
        "flow_ids": ["flw_unknown_9999"],
        "technique_id": "T9999",
    }
    assert resolve_finding_stage(f_unknown, "INC-0009", agent_res=agent_res) is None

    # Empty finding
    assert resolve_finding_stage({}, "INC-0009", agent_res=agent_res) is None


def test_get_report_resolves_finding_stages():
    report = get_report("INC-0009")
    assert report["incident_id"] == "INC-0009"
    assert len(report["sentences"]) > 0

    # INC-0009 mock finding should resolve to stage 1
    s0 = report["sentences"][0]
    assert s0["stage_id"] == "INC-0009-stage-1"
    assert "flw_apt_smb_05474" in s0["evidence_ids"]


def test_resolve_finding_stage_with_case_incident():
    # Simulated pipeline case incident with primary attack chain
    case_inc = {
        "incident_id": "INC-0002",
        "primary_attack_chain": [
            {"step": 1, "flow_id": "flw_scan_0080", "attack_stage": "PortScan"},
            {"step": 2, "flow_id": "flw_dos_0048", "attack_stage": "DoS-Slowloris"},
        ],
    }

    f_step2 = {"claim": "Slowloris attack targeting port 80", "flow_ids": ["flw_dos_0048"]}
    assert resolve_finding_stage(f_step2, "INC-0002", case_incident=case_inc) == "INC-0002-stage-2"

    f_unmapped = {"claim": "Random flow", "flow_ids": ["flw_unknown"]}
    assert resolve_finding_stage(f_unmapped, "INC-0002", case_incident=case_inc) is None


def test_resolve_multi_finding_report_mapping(monkeypatch):
    from frontend.api import server

    mock_res = {
        "incident_id": "INC-0009",
        "timeline": [
            {"attack_class": "Lateral-SMB-Relay", "first_flow_id": "flw_apt_smb_05474"},
            {"attack_class": "C2-Heartbeat", "first_flow_id": "flw_apt_c2_08753"},
            {"attack_class": "HTTPS-Exfiltration", "first_flow_id": "flw_apt_exfil_06163"},
        ],
        "attack_matches": {
            "Lateral-SMB-Relay": [{"id": "T1021.002"}],
            "C2-Heartbeat": [{"id": "T1071"}],
            "HTTPS-Exfiltration": [{"id": "T1567"}],
        },
        "findings": [
            {"claim": "SMB relay attack", "technique_id": "T1021.002", "flow_ids": ["flw_apt_smb_05474"]},
            {"claim": "C2 heartbeat beaconing", "technique_id": "T1071", "flow_ids": ["flw_apt_c2_08753"]},
            {"claim": "HTTPS exfiltration", "technique_id": "T1567", "flow_ids": ["flw_apt_exfil_06163"]},
            {"claim": "Uncorrelated note", "technique_id": "T9999", "flow_ids": ["flw_random_0001"]},
        ],
        "rejected_findings": [],
    }

    monkeypatch.setattr(server, "mock_investigate", lambda agent, inc_id: mock_res)

    rpt = server.get_report("INC-0009")
    sentences = rpt["sentences"]
    assert len(sentences) == 4
    assert sentences[0]["stage_id"] == "INC-0009-stage-1"
    assert sentences[1]["stage_id"] == "INC-0009-stage-2"
    assert sentences[2]["stage_id"] == "INC-0009-stage-3"
    assert sentences[3]["stage_id"] is None


def test_real_report_api_preserves_evidence_grounded_attack_retrieval(monkeypatch):
    from frontend.api import server

    match = {
        "id": "T1110",
        "name": "Brute Force",
        "tactics": ["credential-access"],
        "score": 0.91,
        "source_url": "https://attack.mitre.org/techniques/T1110",
        "mapping_status": "inferred",
        "evidence_flow_ids": ["flw_000201"],
        "evidence_ids": ["sample_capture_001"],
        "assessment": "Inferred candidate; retrieval relevance is not confirmation.",
    }
    real_result = {
        "incident_id": "INC-001",
        "error": None,
        "timeline": [{
            "attack_class": "SSH-Patator",
            "first_flow_id": "flw_000201",
            "last_flow_id": "flw_000210",
            "flow_ids": ["flw_000201"],
        }],
        "attack_matches": {
            "SSH-Patator": {
                "status": "available",
                "mapping_status": "inferred",
                "attack_class": "SSH-Patator",
                "matches": [match],
            },
        },
        "retrieval_status": "available",
        "findings": [{
            "claim": "Possible SSH password guessing activity.",
            "flow_ids": ["flw_000201"],
            "technique_id": "T1110",
        }],
        "rejected_findings": [],
    }
    monkeypatch.setenv("EVIGRAPH_AGENT_MODE", "real")
    monkeypatch.setattr(server, "_load_real_agent", lambda: object())
    monkeypatch.setattr(server, "real_investigate", lambda agent, incident_id: real_result)

    report = server.get_report("INC-001")

    result = report["attack_matches"]["SSH-Patator"]
    assert report["retrieval_status"] == "available"
    assert result["matches"][0] == match
    assert report["sentences"][0]["stage_id"] == "INC-001-stage-1"




def test_group_fallback_stages_summarizes_portscan_and_ssh_patator():
    from frontend.api.server import _group_fallback_stages, _validate_fallback_citations

    # Construct 100 PortScan stages and 60 SSH-Patator stages
    stages = []
    flow_ids = []
    for i in range(1, 101):
        fid = f"flw_scan_{i:04d}"
        flow_ids.append(fid)
        stages.append({
            "stage_id": f"INC-0001-stage-{i}",
            "src": "172.16.0.105",
            "dst": "192.168.10.50",
            "behavior": "PortScan",
            "tactic": "Reconnaissance",
            "summary": "PortScan activity on port 80",
            "evidence": [{"flow_id": fid}],
        })
    for i in range(101, 161):
        fid = f"flw_ssh_{i:04d}"
        flow_ids.append(fid)
        stages.append({
            "stage_id": f"INC-0001-stage-{i}",
            "src": "172.16.0.105",
            "dst": "192.168.10.50",
            "behavior": "SSH-Patator",
            "tactic": "Credential Access",
            "summary": "SSH-Patator activity on port 22",
            "evidence": [{"flow_id": fid}],
        })

    sentences = _group_fallback_stages(stages)

    # 1. Summarized separately into 2 concise groups
    assert len(sentences) == 2
    assert "Observed 100 flows of PortScan activity" in sentences[0]["text"]
    assert "Observed 60 flows of SSH-Patator activity" in sentences[1]["text"]

    # 2. All 160 flow IDs remain traceable
    cited_ids = sentences[0]["evidence_ids"] + sentences[1]["evidence_ids"]
    assert len(cited_ids) == 160
    assert set(cited_ids) == set(flow_ids)

    # 3. Validation succeeds when all flows exist in store
    class MockStore:
        def get_flow(self, fid):
            return {"flow_id": fid} if fid in set(flow_ids) else None

    incident = {
        "incident_id": "INC-0001",
        "evidence_flow_ids": list(flow_ids),
        "alerts": [{"flow_id": fid} for fid in flow_ids],
    }
    normalized = {"stages": stages}
    res = _validate_fallback_citations(sentences, incident, normalized, MockStore())
    assert res == {"valid": 2, "total": 2, "rejected": 0}

    # 4. Invalid evidence ID is rejected
    tampered = [
        dict(sentences[0]),
        {
            "text": "Tampered statement",
            "stage_id": sentences[1]["stage_id"],
            "stage_ids": sentences[1]["stage_ids"],
            "evidence_ids": ["flw_nonexistent"],
        },
    ]
    res_tampered = _validate_fallback_citations(tampered, incident, normalized, MockStore())
    assert res_tampered == {"valid": 1, "total": 2, "rejected": 1}
