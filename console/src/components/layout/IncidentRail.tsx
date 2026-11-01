"use client";

import React, { useState } from "react";
import { useConsoleStore } from "@/lib/store";
import { Badge } from "@/components/ui/badge";
import { AlertCircle, Shield, Filter, Search, ChevronRight } from "lucide-react";

interface IncidentRailProps {
  incidents: any[];
}

export function IncidentRail({ incidents = [] }: IncidentRailProps) {
  const { selectedIncidentId, setSelectedIncidentId } = useConsoleStore();
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [search, setSearch] = useState<string>("");

  const filtered = incidents.filter((inc) => {
    if (filterSeverity === "critical" && inc.score < 0.85) return false;
    if (filterSeverity === "high" && (inc.score < 0.65 || inc.score >= 0.85)) return false;
    if (filterSeverity === "medium" && (inc.score < 0.4 || inc.score >= 0.65)) return false;
    if (search && !inc.incident_id.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <aside className="w-[300px] border-r border-evi-border bg-evi-panel flex flex-col h-full select-none">
      {/* Top filter bar */}
      <div className="p-3 border-b border-evi-border flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-xs font-bold text-white tracking-wide">
            <AlertCircle className="w-3.5 h-3.5 text-evi-accent" />
            <span>INCIDENT QUEUE ({filtered.length})</span>
          </div>
          <span className="text-[10px] text-evi-muted font-mono">PRIORITY ORDERED</span>
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="w-3 h-3 text-evi-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Filter incidents..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-evi-canvas border border-evi-border text-xs text-white pl-7 pr-2.5 py-1 rounded focus:outline-none focus:border-evi-accent font-mono placeholder:text-slate-500"
          />
        </div>

        {/* Severity Chips */}
        <div className="flex items-center gap-1 pt-1">
          {["all", "critical", "high", "medium"].map((lvl) => (
            <button
              key={lvl}
              onClick={() => setFilterSeverity(lvl)}
              className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase transition-all ${
                filterSeverity === lvl
                  ? "bg-evi-elevated border border-evi-accent text-evi-accent font-bold"
                  : "bg-evi-canvas border border-evi-border text-evi-muted hover:text-white"
              }`}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      {/* Incident List */}
      <div className="flex-1 overflow-y-auto divide-y divide-evi-border/40 p-2 space-y-1.5">
        {filtered.map((inc) => {
          const isSelected = inc.incident_id === selectedIncidentId;
          const score = inc.score || 0.75;
          const entryPoint = inc.hosts?.find((h: any) => h.zone === "EXTERNAL")?.ip || inc.stages?.[0]?.src || "172.16.0.105";

          return (
            <div
              key={inc.incident_id}
              onClick={() => setSelectedIncidentId(inc.incident_id)}
              className={`p-2.5 rounded-lg cursor-pointer transition-all border ${
                isSelected
                  ? "bg-evi-elevated/90 border-evi-accent shadow-sm"
                  : "bg-evi-canvas/60 border-evi-border hover:border-slate-600 hover:bg-evi-canvas"
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold text-xs text-white">
                    {inc.incident_id}
                  </span>
                  <Badge
                    variant={
                      score >= 0.85
                        ? "malicious"
                        : score >= 0.65
                        ? "suspicious"
                        : "benign"
                    }
                  >
                    {score.toFixed(2)}
                  </Badge>
                </div>
                <ChevronRight
                  className={`w-3.5 h-3.5 transition-transform ${
                    isSelected ? "text-evi-accent translate-x-0.5" : "text-slate-600"
                  }`}
                />
              </div>

              {/* Patient Zero and Stages */}
              <div className="mt-2 text-[11px] text-evi-muted flex flex-col gap-0.5">
                <div className="flex items-center justify-between">
                  <span>Patient Zero:</span>
                  <span className="font-mono text-white text-[10px]">{entryPoint}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Affected Hosts:</span>
                  <span className="font-mono text-white text-[10px]">
                    {inc.hosts?.length || 2} nodes
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Attack Steps:</span>
                  <span className="font-mono text-white text-[10px]">
                    {inc.stages?.length || 2} stages
                  </span>
                </div>
              </div>

              {/* Progress tactics pills */}
              <div className="mt-2 flex items-center gap-1 flex-wrap">
                {(inc.attack_classes || ["PortScan", "SSH-Patator"]).map((cls: string) => (
                  <span
                    key={cls}
                    className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-evi-panel border border-evi-border text-slate-300"
                  >
                    {cls}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </aside>
  );
}
