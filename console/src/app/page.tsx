"use client";

import React, { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useConsoleStore } from "@/lib/store";
import {
  getIncidents,
  getIncident,
  getSystemOverview,
  getCourtroom,
  getCitations,
} from "@/lib/api";

import { TopCommandBar } from "@/components/layout/TopCommandBar";
import { IncidentRail } from "@/components/layout/IncidentRail";
import { BottomStatusBar } from "@/components/layout/BottomStatusBar";

import { CommandCenter } from "@/components/command-center/CommandCenter";
import { InvestigationWorkspace } from "@/components/investigation/InvestigationWorkspace";
import { CausalTimeline } from "@/components/timeline/CausalTimeline";
import { EvidenceVerdictPanel } from "@/components/evidence/EvidenceVerdictPanel";
import { ResponseResilienceConsole } from "@/components/resilience/ResponseResilienceConsole";
import { ForensicCopilot } from "@/components/copilot/ForensicCopilot";

export default function ForensicConsoleApp() {
  const { activeScreen, selectedIncidentId, setSelectedIncidentId } =
    useConsoleStore();

  // Queries
  const { data: incidents = [] } = useQuery({
    queryKey: ["incidents"],
    queryFn: getIncidents,
  });

  const { data: overview } = useQuery({
    queryKey: ["overview"],
    queryFn: getSystemOverview,
  });

  const { data: activeIncident } = useQuery({
    queryKey: ["incident", selectedIncidentId],
    queryFn: () => getIncident(selectedIncidentId),
    enabled: Boolean(selectedIncidentId),
  });

  const { data: courtroom } = useQuery({
    queryKey: ["courtroom", selectedIncidentId],
    queryFn: () => getCourtroom(selectedIncidentId),
    enabled: Boolean(selectedIncidentId),
  });

  const { data: citations } = useQuery({
    queryKey: ["citations", selectedIncidentId],
    queryFn: () => getCitations(selectedIncidentId),
    enabled: Boolean(selectedIncidentId),
  });

  // Ensure default incident is selected if none set
  useEffect(() => {
    if (incidents.length > 0 && !selectedIncidentId) {
      setSelectedIncidentId(incidents[0].incident_id);
    }
  }, [incidents, selectedIncidentId, setSelectedIncidentId]);

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-evi-canvas text-evi-text select-none">
      {/* 1. Persistent Top Command Bar */}
      <TopCommandBar incidents={incidents} />

      {/* 2. Middle Body: Incident Rail + Dynamic Canvas + Copilot */}
      <div className="flex-1 flex overflow-hidden relative">
        {/* Persistent Left Incident Rail (shown across investigation, timeline, evidence, resilience) */}
        {activeScreen !== "command-center" && (
          <IncidentRail incidents={incidents} />
        )}

        {/* Dynamic Center Canvas */}
        <main className="flex-1 flex flex-col overflow-hidden relative">
          {activeScreen === "command-center" && (
            <CommandCenter incidents={incidents} overview={overview} />
          )}

          {activeScreen === "investigation" && (
            <InvestigationWorkspace incident={activeIncident} />
          )}

          {activeScreen === "timeline" && (
            <CausalTimeline incident={activeIncident} />
          )}

          {activeScreen === "evidence" && (
            <EvidenceVerdictPanel
              courtroom={courtroom}
              citations={citations}
              incident={activeIncident}
            />
          )}

          {activeScreen === "resilience" && <ResponseResilienceConsole />}
        </main>

        {/* Persistent Forensic Copilot (Right Drawer) */}
        <ForensicCopilot />
      </div>

      {/* 3. Persistent Bottom Status Bar */}
      <BottomStatusBar overview={overview} />
    </div>
  );
}
