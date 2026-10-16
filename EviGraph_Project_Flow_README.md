# EviGraph --- Project Flow & System Structure

> **Purpose:** This README explains how EviGraph's components work
> together from network evidence intake to an evidence-grounded incident
> report. It describes the product flow and team boundaries;
> implementation details belong in the Technical Requirements Document
> (TRD) and API contract.

## 1. Product Goal

EviGraph turns raw network telemetry into a defensible, evidence-linked
forensic case:

-   Detect malicious and anomalous activity at flow, host, and subgraph
    levels.
-   Group related alerts into incidents and reconstruct an ordered
    attack chain with confidence scores.
-   Explain verdicts in terms an analyst can check.
-   Preserve evidence integrity and make results traceable and
    reproducible.
-   Generate incident reports in which every claim has a valid evidence
    reference.
-   Evaluate forensic quality, not detection accuracy alone.

EviGraph is an **investigation and reporting tool**, not an inline
prevention system.

## 2. High-Level Project Flow

``` mermaid
flowchart TD
    A[Network Evidence Input<br/>PCAP / flow files / supported logs]
    B[Ingestion and Integrity<br/>Preserve original evidence, hash, record provenance]
    C[Normalization and Flow Extraction<br/>Normalize records, extract features, assign flow IDs]
    D[Evidence Storage and Query Layer<br/>Flows, timestamps, hashes, metadata]
    E[Detection Engine<br/>Flow / host / subgraph anomaly detection]
    F[Host Communication Graph<br/>Build relationships and suspicious subgraphs]
    G[Incident Correlation and Chain Recovery<br/>Group alerts, order stages, attach confidence]
    H[Structured Incident Output<br/>Alerts, scores, stages, evidence IDs]
    I[LLM Forensic Analyst Agent<br/>Retrieve evidence, query flows, investigate]
    J[Evidence-Grounded Report<br/>Findings, ATT&CK mapping, citations]
    K[Analyst Dashboard<br/>Incident list, graph, timeline, evidence, report]
    L[Evaluation and Demonstration<br/>Metrics, scripted lab, validation, documentation]

    A --> B --> C --> D --> E
    D --> F
    E --> G
    F --> G
    G --> H --> I
    D -. evidence queries .-> I
    I --> J --> K
    H --> K
    K --> L
    E -. detection metrics .-> L
    G -. reconstruction metrics .-> L
    J -. report evidence checks .-> L
```

## 3. End-to-End Investigation

1.  **Evidence intake:** An analyst supplies a PCAP, flow file, or
    another supported input.
2.  **Integrity and provenance:** The system preserves the original
    evidence, computes and records its hash, and tracks provenance.
    Original evidence is not modified.
3.  **Normalization:** The pipeline converts supported input formats
    into a consistent representation, extracts flow features, and
    assigns a unique flow/evidence identifier.
4.  **Storage and query:** Normalized flows and their metadata are
    stored so downstream components can retrieve records by host, time,
    flow ID, or other supported query.
5.  **Detection:** The detector produces suspicious-flow or host-level
    findings, including scores and supporting feature information.
6.  **Graph construction:** The graph engine represents host
    communication and identifies suspicious subgraphs or relationships.
7.  **Incident correlation and chain recovery:** Related alerts are
    grouped into incidents. Candidate stages are ordered and assigned
    confidence. Stages that rely on indirect evidence are marked as
    inferred rather than presented as directly observed.
8.  **Agent investigation:** The LLM agent receives structured incident
    findings and uses evidence-query tools to inspect relevant flows and
    records. It may propose explanations and ATT&CK mappings only when
    the available evidence supports them.
9.  **Report generation:** The agent produces an incident report with
    claims linked to evidence IDs, timestamps, alerts, or other
    verifiable records.
10. **Analyst review:** The dashboard presents ranked incidents, an
    interactive attack graph, a timeline, evidence drill-down,
    explanations, and report export.
11. **Evaluation:** The team measures detection performance,
    incident/chain reconstruction, and report grounding. The lab demo
    should be repeatable.

## 4. Module Ownership and Handoffs

  -------------------------------------------------------------------------
  Owner             Module            Responsibility      Handoff
  ----------------- ----------------- ------------------- -----------------
  Member 1          Data and traffic  Ingest supported    Queryable
                    pipeline          data, preserve      normalized flows
                                      evidence, normalize with stable IDs,
                                      records, extract    timestamps,
                                      flow features,      hashes, and
                                      assign IDs, provide metadata
                                      storage/query       
                                      access              

  Member 2          Detection and     Detect suspicious   Structured
                    graph engine      behavior, build     incidents with
                                      host graph, extract alerts,
                                      suspicious          risk/confidence
                                      subgraphs,          scores, stage
                                      correlate alerts,   order, and
                                      reconstruct         evidence
                                      incident stages     references

  Member 3          LLM agent and RAG Retrieve approved   Report findings,
                                      forensic/ATT&CK     ATT&CK mappings,
                                      knowledge, query    explanations, and
                                      evidence through    citations to
                                      tools, generate     evidence
                                      evidence-grounded   
                                      hypotheses and      
                                      reports             

  Member 4          Dashboard,        Connect modules,    End-to-end
                    integration, and  present analyst     demonstrable
                    evaluation        workflow, build     system and
                                      controlled lab      evaluation
                                      demo, validate      write-up
                                      outputs, measure    
                                      performance,        
                                      document results    
  -------------------------------------------------------------------------

## 5. Information That Must Travel Through the Pipeline

The exact API schema is to be agreed in the API contract. At minimum,
downstream components need:

-   **Evidence identity:** flow/evidence ID and source-file hash or
    provenance reference.
-   **Time:** event timestamp or interval, with a consistent timezone
    convention.
-   **Network context:** source/destination host or IP representation,
    protocol, and available flow metadata.
-   **Detection output:** alert ID, score/confidence, behavior/features
    supporting the finding.
-   **Incident output:** incident ID, related alerts, ordered stages,
    stage confidence, and observed/inferred status.
-   **Agent output:** report claims and the evidence references
    supporting each claim.

Do not treat an LLM-generated explanation as a substitute for source
evidence. Evidence IDs must resolve to records that can be opened or
queried.

## 6. Analyst Dashboard Flow

The dashboard should support the PRD's investigation journey:

1.  **Ranked incident list:** incidents ordered by severity and
    confidence.
2.  **Incident investigation:** select an incident to open its attack
    graph and reconstructed timeline.
3.  **Graph exploration:** filter by time, protocol, and risk; select an
    edge or alert to inspect its supporting records.
4.  **Evidence drill-down:** show the exact flows, timestamps, and
    hashes behind a finding.
5.  **Explanation review:** display why a selected alert was flagged and
    any available explanation/stability information.
6.  **Report review and export:** show the evidence-linked incident
    report and provide report export.

## 7. Evaluation and Release Checks

The PRD's release criteria should guide the team's tests:

-   A PCAP or flow file can be ingested, hashed, and processed end to
    end without manual steps.
-   Detection results use a temporal split and report macro-F1,
    per-class recall, and false positives per hour.
-   At least one scripted multi-stage lab scenario is reconstructed and
    evaluated.
-   Every report statement links to evidence that can be opened from the
    dashboard.
-   The planned ablations and robustness test are completed and
    documented.
-   Dataset flaws, cleaning steps, and limitations are documented.

Evaluation should distinguish: - **Detection quality:** whether
suspicious activity is detected. - **Reconstruction quality:** whether
the incident and attack stages are grouped and ordered correctly. -
**Evidence/report quality:** whether claims are supported by valid,
relevant evidence. - **System behavior:** whether the workflow is
reproducible and failures are handled clearly.

## 8. Scope Boundaries

The first release does **not** include:

-   Real-time inline blocking or prevention.
-   TLS or other encrypted-payload decryption.
-   Endpoint-agent development; endpoint logs are an optional extension
    input.
-   Legal certification of evidence for court.
-   Production-scale enterprise deployment.

## 9. Decisions to Confirm Before Integration

The team should agree on these items before implementing
module-to-module calls:

-   Canonical flow and evidence ID formats.
-   Timestamp format and timezone convention.
-   Incident/stage JSON structure, including confidence and
    observed/inferred status.
-   How evidence queries are exposed to the agent.
-   How report claims reference evidence and how references are
    validated.
-   Which inputs and demo scenario are in the first release.
-   Which metrics and test split will be used for final evaluation.

## 10. Definition of the Complete Project Flow

The project is considered connected when a supported input can pass
through ingestion, detection, graph/incident reconstruction, and agent
investigation; the dashboard can display the resulting incident and
evidence; and the team can reproduce the run and report its evaluation
results.

This README describes the intended product flow. The PRD defines product
requirements; the TRD and API contract define implementation details and
exact interfaces.
