# EviGraph UI/UX Design Specification

## 1. Product Vision

EviGraph’s interface is an **evidence-first forensic operations console** for network security analysts.

It must not look like a generic alert dashboard. Its purpose is to help an analyst rapidly answer:

- **Who attacked whom?**
- **What sequence of attack stages occurred?**
- **Which raw network flows support each conclusion?**
- **Why did the detection models flag the traffic?**
- **Is the evidence cryptographically and logically verifiable?**
- **What containment action is recommended, and what is its blast radius?**

Every visual element must preserve the core EviGraph principle:

> **No finding without evidence. No evidence without traceability. No action without human approval.**

---

## 2. Design Principles

| Principle | UI Implication |
|---|---|
| **Evidence-first** | Every alert, graph node, timeline event, and report claim links to `flow_id`, `evidence_id`, hash, and Merkle proof status. |
| **Explainability** | Show detector contributions, risk score, causal stage, and ATT&CK mapping—not only a final label. |
| **Investigative flow** | Move naturally from incident → graph → timeline → evidence → response. |
| **Calm density** | High information density, but visually quiet; avoid alarm fatigue. |
| **Human control** | Containment and firewall actions require explicit review and approval. |
| **Honest uncertainty** | Missing, unverified, contradictory, or retrograde evidence must be visibly labeled. |
| **Forensic integrity** | Verification status is as important as threat severity. |

---

## 3. Primary User Personas

### 3.1 SOC Analyst
* **Needs:** Triage incidents, inspect suspicious hosts, understand attack progression, and decide whether escalation is required.

### 3.2 Forensic Investigator
* **Needs:** Immutable evidence, raw flow context, Merkle proofs, causal ordering, and a defensible report.

### 3.3 Incident Responder
* **Needs:** Clear containment recommendations, affected-service impact, firewall previews, and approval workflow.

### 3.4 Security Manager
* **Needs:** Incident severity, attack coverage, verification rate, resilience score, and response status.

---

## 4. Overall Layout

Persistent three-zone shell:

```text
┌────────────────────────────────────────────────────────────────────────┐
│  EviGraph Command Bar                                                  │
├───────────────┬───────────────────────────────────┬────────────────────┤
│ Incident Rail │        Investigation Canvas       │  Evidence / Agent  │
│               │                                   │  Panel             │
│ - Incidents   │ - Attack Graph                    │ - Evidence Chain   │
│ - Filters     │ - Causal Timeline                 │ - Merkle Proof     │
│ - Hosts       │ - ATT&CK Matrix                   │ - Citation Audit   │
│ - Stages      │ - Response & Resilience           │ - Copilot          │
└───────────────┴───────────────────────────────────┴────────────────────┘
```

### Layout Rules

* **Left rail:** 280–320 px; incident navigation and filters.
* **Center canvas:** flexible; graph, timeline, ATT&CK matrix, and response views.
* **Right panel:** 360–420 px; selected-object evidence, verification, and agent output.
* **Top bar:** global search, environment, dataset/run selector, Merkle root status, user role.
* **Bottom status bar:** selected incident, selected flow, evidence verification state, simulation mode.

---

## 5. Visual Design System

### 5.1 Theme
Dark-first SOC theme:
* **Background:** deep slate or near-black navy.
* **Surfaces:** subtly elevated dark panels.
* **Text:** high-contrast off-white.
* **Accent:** restrained cyan for selection and interactive states.
* **Status colors:** amber, red, and green used sparingly and consistently.

### 5.2 Color Semantics

| Token | Usage |
|---|---|
| `bg.canvas` | Main application background |
| `bg.panel` | Cards, side panels, graph containers |
| `bg.elevated` | Modals, popovers, evidence drawers |
| `text.primary` | Primary UI text |
| `text.secondary` | Metadata, timestamps, helper text |
| `accent.cyan` | Selection, focus, interactive controls |
| `status.benign` | Normal or low-risk telemetry |
| `status.suspicious` | Unverified, anomalous, or needs-review |
| `status.malicious` | Confirmed malicious path or critical incident |
| `status.verified` | Passed Merkle, citation, protocol, and temporal checks |
| `status.failed` | Failed verification or auditor objection |
| `status.simulation` | Counterfactual or hypothetical result |

### 5.3 Suggested Palette

```css
:root {
  --evi-bg-canvas: #0b1120;
  --evi-bg-panel: #111827;
  --evi-bg-elevated: #1f2937;
  --evi-border-subtle: #243044;
  --evi-text-primary: #e5edf8;
  --evi-text-secondary: #94a3b8;
  --evi-accent: #22d3ee;
  --evi-benign: #38bdf8;
  --evi-suspicious: #f59e0b;
  --evi-malicious: #ef4444;
  --evi-verified: #22c55e;
  --evi-failed: #f43f5e;
  --evi-simulation: #a78bfa;
}
```

### 5.4 Typography

| Use | Font | Style |
|---|---|---|
| UI text | Inter or IBM Plex Sans | 13–15 px |
| Section headings | Inter SemiBold | 16–20 px |
| Metrics | Inter SemiBold | 24–32 px |
| Flow IDs, hashes, IPs, ports | JetBrains Mono | 12–13 px |
| JSON evidence | JetBrains Mono | 12 px |

> [!IMPORTANT]
> Monospace is mandatory for forensic identifiers, cryptographic values, timestamps, IP addresses, ports, and raw telemetry.

---

## 6. Core Screens

### 6.1 Command Center

The landing screen provides situational awareness.

#### Components
* **KPI strip:**
  * Active incidents
  * Critical incidents
  * Highest-risk host
  * Detected ATT&CK stages
  * Evidence verification rate
  * Pending containment approvals
* **Incident queue:**
  * Incident ID
  * Severity
  * Primary attack chain
  * Suspected patient-zero host
  * Affected hosts
  * Ensemble confidence
  * Evidence verification badge
* **Threat activity chart:**
  * Alerts over time
  * Risk-score trend
  * Detector agreement
  * Attack-stage progression
* **MITRE ATT&CK matrix:**
  * Highlight observed tactics and techniques
  * Show alert density per stage
  * Filter the incident queue by stage
* **Live telemetry ticker:**
  * Recent high-risk flows only
  * Each row links to its incident and evidence record

#### Interaction
* Click incident → open Investigation Workspace.
* Click ATT&CK cell → filter incidents by stage.
* Click host → open host profile.
* Click flow → open Evidence Inspector.

---

### 6.2 Investigation Workspace

The primary workspace for deep analysis.

#### Left: Incident Summary
* Incident ID and title
* Severity and confidence
* Suspected patient-zero entry point
* Affected hosts
* Primary attack chain
* Detector consensus: XGBoost, HistGB, Autoencoder, GNN
* ATT&CK stages observed
* Evidence verification summary
* Related Merkle root

#### Center: Attack Graph
Utilizes **Cytoscape.js** for interactive host-communication topology.

##### Graph Model
* **Nodes:** hosts, IPs, or assets.
* **Edges:** network flows or aggregated communication relationships.
* **Node size:** risk, degree, or incident involvement.
* **Node color:** benign, suspicious, malicious, quarantined, or patient-zero.
* **Edge color:** ensemble risk and verification status.
* **Edge thickness:** bytes, packets, alert count, or risk score.
* **Edge label:** protocol or selected metric.

##### Graph Controls
* Search host or IP
* Zoom, pan, fit-to-view, reset layout
* Toggle force-directed / hierarchical layout
* Focus 1-hop suspicious subgraph
* Expand selected node / collapse unrelated nodes
* Show primary attack chain
* Show causal DAG edges
* Show Min-Cut bottleneck
* Show blast radius
* Show counterfactual simulated removal

##### Graph Layers

| Layer | Visual Treatment |
|---|---|
| **Benign traffic** | Low-opacity slate edges |
| **Suspicious traffic** | Amber edges |
| **Confirmed attack path** | Red directed edges with arrowheads |
| **Causal DAG** | Cyan dashed directed edges |
| **Min-Cut bottleneck** | Red highlighted edge set |
| **Blast radius** | Purple translucent affected region |
| **Counterfactual path** | Purple dashed edges with “Simulation” badge |

##### Node Click Behavior
Opens the right Evidence Panel with:
* Host identity
* In-degree / out-degree, Fan-in / fan-out
* Unique destination ports, Bytes sent / received
* Related incidents, Risk score, Detected stages
* Evidence citations & related raw flows

##### Edge Click Behavior
Opens the right Evidence Panel with:
* `flow_id` & `evidence_id`
* Source / destination, protocol, ports
* Bytes and packets, start / end timestamps
* Ensemble score & individual detector scores
* Risk explanation (SHAP / feature importances)
* Merkle leaf and inclusion proof
* Citation validation status
* Raw telemetry JSON

---

### 6.3 Causal Timeline

Reconstructs the attack sequence.

#### Layout
* Horizontal time axis.
* Swimlanes by host or attack stage.
* DAG-style event cards.
* Zoom, pan, and brush selection.
* Stage bands:
  * Reconnaissance
  * Initial Access
  * Lateral Movement
  * Privilege Escalation
  * Exfiltration
  * Impact

#### Event Card Fields
* Timestamp
* Host pair
* Flow ID
* Stage & ATT&CK technique
* Risk score
* Evidence status
* Short explanation

#### Temporal Objections
Events with retrograde or inconsistent timestamps must be explicitly labeled:

```text
⚠ Temporal Objection
Backwards-in-time sequence detected. Treated as an objection, not physical proof.
```

> [!WARNING]
> Do not visually present temporal objections as confirmed attack steps.

#### Graph Linkage
Selecting a time window filters the attack graph.
Button: `Show this window in Graph Explorer`

---

### 6.4 Evidence & Verdict Panel

EviGraph’s core verification differentiator.

#### Evidence Chain
For every selected claim, show:
* Raw flow preview
* `flow_id` and `evidence_id`
* Source and destination metadata, protocol, and ports
* Timestamps, SHA-256 digest
* Merkle leaf hash, inclusion proof, session Merkle root
* Certificate status & download raw evidence action

#### Citation Validator
Display every `[E:<flow_id>]` citation with:

| Field | Value |
|---|---|
| Citation | `[E:flow_10422]` |
| Raw flow exists | Yes / No |
| Claim supported | Faithful / Unfaithful / Uncertain |
| Evidence hash match | Verified / Failed |
| Validator message | Human-readable explanation |

#### Courtroom Auditor
Displays four independent audit gates:
1. **Cryptographic Merkle proof**
2. **Physical Layer-4 protocol consistency**
3. **Temporal causal monotonicity**
4. **Telemetry fact-checking**

Each gate displays:
* Passed / Failed / Needs review
* Auditor objection
* Evidence reference
* Recommended correction

#### Verdict Display
Explicit disclaimer language required:

```text
Technical Admissibility Audit
Engineering evidence assessment only.
Not legal advice and not a court ruling.
```

---

### 6.5 Response & Resilience Console

Converts forensic analysis into controlled response.

#### Containment Recommendations
* Recommended action
* Min-Cut bottleneck edges
* Affected hosts & blocked services
* Blast-radius score & operational impact
* Evidence supporting the recommendation

#### Firewall Rule Preview
Generated rules displayed in syntax tabs:
* Linux `nftables`
* Linux `iptables`
* Windows PowerShell
* Cisco ACL
* Cloud security group

> [!NOTE]
> All rules must remain strictly read-only until approved.

#### Approval Workflow
Explicit state machine:

```text
Draft → Reviewed → Approved → Deployed
```

**Rules:**
* **No automatic deployment.**
* Every state transition requires a named human actor.
* Show diff before approval.
* Log approver, timestamp, and evidence references.

#### Counterfactual Simulator
Allows testing hypothetical controls:
* Block port
* Quarantine host
* Microsegment subnet
* Drop perimeter path
* Remove suspected lateral-movement edge

**Metrics:**
* Before / after Defensive Resilience Index (DRI)
* Disrupted attack paths
* Residual single points of failure (SPOF)
* Estimated containment coverage & remaining exposure

> [!IMPORTANT]
> Every counterfactual result must carry a persistent badge:
> `Simulation — not deployed control`

---

## 7. Forensic Copilot

Right-side assistant for forensic reasoning.

### Allowed Actions
* Summarize an incident.
* Explain why an alert fired.
* Identify the primary attack chain.
* Compare detector outputs.
* Locate evidence for a claim.
* Explain a Merkle proof.
* Summarize auditor objections.
* Draft an incident report.

### Required Behavior
* Every answer must include inline clickable evidence chips (e.g. `[E:flow_10422]`).
* Clicking `[E:flow_10422]` opens the raw flow and Merkle proof.
* If evidence is absent or unverified, state that explicitly.
* **The agent must never invent IPs, hashes, MITRE mappings, verdicts, or containment outcomes.**

### Copilot Tabs
* **Investigation:** narrative explanation and next-step suggestions.
* **Evidence:** evidence-linked answers and citations.
* **Cross-Examination:** courtroom auditor objections and corrections.
* **Report:** draft forensic incident report.

---

## 8. Component Library

### Core Components
* `IncidentCard`
* `SeverityBadge`
* `EvidenceBadge`
* `MerkleProofCard`
* `CitationChip`
* `FlowEvidenceDrawer`
* `AttackGraph`
* `CausalTimeline`
* `AttackStageMatrix`
* `DetectorConsensusPanel`
* `AuditGateCard`
* `ContainmentRulePreview`
* `BlastRadiusPanel`
* `SimulationResultCard`
* `ForensicCopilot`
* `ApprovalWorkflow`

### Badge States

| Badge | Meaning |
|---|---|
| `Verified` | Evidence passed required checks |
| `Unverified` | Evidence exists but has not passed all checks |
| `Objection` | Auditor or temporal inconsistency detected |
| `Simulation` | Counterfactual result, not deployed |
| `Approved` | Human-approved response action |
| `Deployed` | Action executed after approval |
| `Needs Review` | Analyst decision required |

---

## 9. Interaction Rules

* **Single selection:** One selected incident at a time; one selected graph object at a time.
* **Bidirectional synchronization:** Selecting a timeline event highlights the corresponding graph edge; selecting a graph edge highlights its timeline event.
* **Contextual transparency:** Every evidence drawer must show both human-readable context and raw JSON.
* **Filter persistence:** Filters must persist while switching between graph, timeline, and response views.
* **Informative empty states:** Empty states must explain why data is absent; never show a blank panel.
* **Explicit loading states:** Distinguish between *“loading telemetry”*, *“verifying proof”*, and *“running simulation”*.

---

## 10. Accessibility

* Maintain **WCAG AA contrast** for text and critical status colors.
* Do not rely on color alone; pair color with icons, labels, and patterns.
* Provide keyboard navigation for:
  * Incident queue
  * Graph nodes and edges
  * Timeline events
  * Evidence drawer
  * Approval actions
* Screen-reader labels for graph nodes and evidence badges.
* Ensure graph controls have visible focus states.

---

## 11. Data Contracts

The UI consumes these EviGraph outputs:

| Output | UI Usage |
|---|---|
| `outputs/incident_cases.json` | Incident queue, graph, timeline, evidence links |
| `outputs/forensic_merkle_certificate.json` | Merkle root, proofs, verification status |
| `outputs/citation_validation_results.json` | Citation validator panel |
| `outputs/certified_forensic_verdict.json` | Courtroom auditor and verdict panel |
| `outputs/courtroom_cross_examination.md` | Cross-examination transcript view |
| `outputs/countermeasure_plan.json` | Containment recommendations and firewall previews |
| `outputs/incident_containment_advisory.md` | Human-readable response advisory |
| `outputs/counterfactual_simulation_results.json` | Resilience simulator |
| `outputs/resilience_simulation_report.md` | SPOF and resilience report |
| `outputs/run_manifest.json` | Dataset, model, git, and run provenance |

---

## 12. Recommended Stack

| Layer | Recommendation |
|---|---|
| **Framework** | Next.js App Router + React + TypeScript |
| **Styling** | Tailwind CSS |
| **Components** | shadcn/ui (dark mode token-driven) |
| **Graph** | Cytoscape.js |
| **Timeline** | D3.js or ECharts custom timeline |
| **Charts** | Recharts or Apache ECharts |
| **State** | Zustand |
| **Data Fetching** | TanStack Query |
| **API** | FastAPI |
| **Real-Time** | WebSocket or Server-Sent Events (SSE) |

---

## 13. Build Priority

1. **Incident queue and evidence inspector:** Establish traceability from alert to raw flow and Merkle proof.
2. **Attack graph:** Visualize host relationships, suspicious subgraphs, and attack paths.
3. **Causal timeline:** Reconstruct attack sequence and expose temporal objections.
4. **Courtroom auditor panel:** Surface cryptographic, protocol, temporal, and factual verification.
5. **Response and resilience console:** Present containment, blast radius, and counterfactual simulations.

---

## 14. Non-Goals

* Do not build a generic SIEM alert list.
* Do not auto-execute firewall or containment rules.
* Do not present simulations as deployed controls.
* Do not present temporal objections as confirmed attack steps.
* Do not allow the LLM copilot to produce claims without evidence citations.
* Do not treat the courtroom auditor output as legal advice or a court ruling.
