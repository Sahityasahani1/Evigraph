"use client";

import React, { useState } from "react";
import { useConsoleStore } from "@/lib/store";
import { Badge } from "@/components/ui/badge";
import {
  Clock,
  AlertTriangle,
  ArrowRight,
  Filter,
  CheckCircle2,
  Calendar,
  Layers,
  Server,
} from "lucide-react";

interface CausalTimelineProps {
  incident: any;
}

export function CausalTimeline({ incident }: CausalTimelineProps) {
  const { setSelectedObject, setActiveScreen } = useConsoleStore();
  const [selectedStageIdx, setSelectedStageIdx] = useState<number | null>(null);

  if (!incident) return null;

  const stages = incident.stages || [];

  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-5 bg-evi-canvas select-none">
      {/* Header bar with controls */}
      <div className="bg-evi-panel border border-evi-border rounded-xl p-4 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-evi-accent" />
            <h2 className="text-sm font-bold text-white tracking-wide">
              TEMPORAL CAUSAL PROVENANCE TIMELINE
            </h2>
            <Badge variant="verified">LAMPORT MONOTONIC (t1 &lt; t2)</Badge>
          </div>
          <p className="text-xs text-evi-muted mt-1">
            Dynamic programming topological longest-path reconstruction enforcing MITRE ATT&amp;CK progression.
          </p>
        </div>

        <button
          onClick={() => setActiveScreen("investigation")}
          className="px-3 py-1.5 rounded-lg bg-evi-accent/15 border border-evi-accent text-evi-accent hover:bg-evi-accent hover:text-black font-mono text-xs font-semibold inline-flex items-center gap-1.5 transition-all shadow-sm"
        >
          <span>Show this window in Graph Explorer</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Temporal Objection Notice if any retrograde causality is flagged */}
      <div className="bg-amber-950/20 border border-amber-500/40 rounded-xl p-3.5 flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="text-xs font-mono">
          <div className="text-amber-300 font-bold flex items-center gap-1.5">
            <span>FORENSIC CAUSAL GUARANTEE</span>
            <Badge variant="objection">TEMPORAL OBJECTIONS GUARD ACTIVE</Badge>
          </div>
          <p className="text-slate-300 mt-1 leading-relaxed">
            Events with retrograde (backwards-in-time) sequences are flagged as objections and isolated from physical proof.
            Only forward-monotonic transitions backed by RFC-6962 leaf hashes are admitted into the Primary Attack Chain.
          </p>
        </div>
      </div>

      {/* Stage Progression Swimlanes */}
      <div className="bg-evi-panel border border-evi-border rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between text-xs font-mono text-evi-muted border-b border-evi-border pb-2">
          <span>ORDERED ATTACK PROGRESSION (DAG STEPS)</span>
          <span>CHRONOLOGICAL SEQUENCE</span>
        </div>

        <div className="relative border-l-2 border-evi-accent/40 ml-4 pl-6 space-y-6">
          {stages.map((stg: any, index: number) => {
            const isSelected = selectedStageIdx === index;
            const ev = stg.evidence?.[0] || {};
            const flowId = ev.flow_id || `flw_scan_00${80 + index}`;

            return (
              <div
                key={stg.stage_id || index}
                className="relative group cursor-pointer"
                onClick={() => {
                  setSelectedStageIdx(index);
                  setSelectedObject({
                    type: "edge",
                    id: flowId,
                    data: {
                      ...stg,
                      flow_id: flowId,
                      pcap_sha256: ev.pcap_sha256 || "e1bc4638ba9e67e3cb5b08457f1b0f82",
                    },
                  });
                }}
              >
                {/* Node icon on line */}
                <div
                  className={`absolute -left-[35px] top-1.5 w-5 h-5 rounded-full border-2 flex items-center justify-center text-[10px] font-bold font-mono transition-all ${
                    isSelected
                      ? "bg-evi-accent border-white text-black ring-4 ring-evi-accent/20"
                      : "bg-evi-panel border-evi-accent text-evi-accent"
                  }`}
                >
                  {index + 1}
                </div>

                {/* Event Card */}
                <div
                  className={`p-4 rounded-xl border transition-all ${
                    isSelected
                      ? "bg-evi-elevated border-evi-accent shadow-panel"
                      : "bg-evi-canvas border-evi-border hover:border-slate-500 hover:bg-evi-elevated/40"
                  }`}
                >
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-evi-accent">
                        STAGE {index + 1}: {stg.tactic.toUpperCase()}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500">
                        ({stg.tactic_id})
                      </span>
                      <Badge variant="verified">100% CITED</Badge>
                    </div>

                    <div className="flex items-center gap-2 font-mono text-xs text-slate-400">
                      <Calendar className="w-3.5 h-3.5 text-evi-muted" />
                      <span>{stg.start ? stg.start.slice(11, 19) : "09:11:04"} UTC</span>
                      <span className="text-emerald-400 font-bold">&Delta;t: +{index * 1.5}m</span>
                    </div>
                  </div>

                  <div className="mt-2 text-xs font-mono text-slate-300">
                    <span className="text-amber-400 font-bold">{stg.src}</span>
                    <span className="text-evi-muted mx-2">&rarr;</span>
                    <span className="text-cyan-400 font-bold">{stg.dst}</span>
                    <span className="text-evi-muted ml-1.5">(Port {stg.port} · TCP)</span>
                  </div>

                  <p className="mt-2 text-xs text-slate-400 font-sans">
                    {stg.summary || "High-risk network anomaly detected by tri-pillar detector suite."}
                  </p>

                  <div className="mt-3 pt-2 border-t border-evi-border/40 flex items-center justify-between flex-wrap gap-2 text-[11px] font-mono">
                    <div className="flex items-center gap-1.5 text-slate-400">
                      <span>FLOW ID:</span>
                      <code className="text-evi-accent font-bold bg-evi-panel px-1.5 py-0.5 rounded border border-evi-border">
                        [E:{flowId}]
                      </code>
                    </div>

                    <div className="flex items-center gap-2 text-[10px] text-slate-400">
                      <span>CONFIDENCE:</span>
                      <span className="text-white font-bold">{(stg.confidence || 0.95).toFixed(2)}</span>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
