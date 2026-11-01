"use client";

import React from "react";
import { IncidentSummary } from "./IncidentSummary";
import { AttackGraph } from "./AttackGraph";
import { GraphControls } from "./GraphControls";
import { EvidenceInspector } from "./EvidenceInspector";

interface InvestigationWorkspaceProps {
  incident: any;
}

export function InvestigationWorkspace({ incident }: InvestigationWorkspaceProps) {
  if (!incident) {
    return (
      <div className="flex-1 flex items-center justify-center text-evi-muted font-mono text-xs">
        Loading forensic incident graph data...
      </div>
    );
  }

  return (
    <div className="flex-1 flex h-full overflow-hidden">
      {/* 1. Left Incident Summary Pane */}
      <IncidentSummary incident={incident} />

      {/* 2. Center Cytoscape.js Attack Graph */}
      <div className="flex-1 relative h-full">
        <GraphControls />
        <AttackGraph incident={incident} />
      </div>

      {/* 3. Right Evidence Inspector Pane */}
      <EvidenceInspector />
    </div>
  );
}
