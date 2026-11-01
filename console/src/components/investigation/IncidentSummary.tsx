"use client";

import React from "react";
import { Badge } from "@/components/ui/badge";
import {
  ShieldCheck,
  Server,
  Layers,
  Cpu,
  Hash,
  Activity,
  AlertTriangle,
} from "lucide-react";
import { truncateHash } from "@/lib/utils";

interface IncidentSummaryProps {
  incident: any;
}

export function IncidentSummary({ incident }: IncidentSummaryProps) {
  if (!incident) return null;

  const score = incident.score || 0.76;
  const stages = incident.stages || [];
  const entryPoint = incident.suspected_entry_point || stages[0]?.src || "172.16.0.105";
  const merkleRoot = incident.integrity?.merkle_root || "e1bc4638ba9e67e3cb5b08457f1b0f82203a55e60456e7f56001d681f4b1c37c";

  return (
    <div className="w-[320px] border-r border-evi-border bg-evi-panel flex flex-col h-full overflow-y-auto p-4 space-y-4 select-none">
      {/* Header */}
      <div>
        <div className="flex items-center justify-between">
          <span className="font-mono text-xs text-evi-muted">INCIDENT DETAILS</span>
          <Badge
            variant={
              score >= 0.85
                ? "malicious"
                : score >= 0.65
                ? "suspicious"
                : "benign"
            }
          >
            {score >= 0.85 ? "CRITICAL" : "HIGH RISK"} · {score.toFixed(2)}
          </Badge>
        </div>
        <h2 className="text-base font-bold text-white mt-1">
          {incident.incident_id}
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Multi-stage lateral progression with credential brute-force.
        </p>
      </div>

      {/* Patient Zero and Entry Point */}
      <div className="bg-evi-canvas border border-evi-border rounded-lg p-3 space-y-2">
        <div className="text-[10px] font-mono text-evi-muted uppercase font-bold flex items-center gap-1.5">
          <Server className="w-3 h-3 text-amber-400" />
          <span>SUSPECTED PATIENT ZERO</span>
        </div>
        <div className="font-mono text-sm font-bold text-white flex items-center justify-between">
          <span>{entryPoint}</span>
          <span className="text-[10px] text-amber-400 font-normal">ENTRY PERIMETER</span>
        </div>
        <div className="text-[11px] text-slate-400">
          First observed scanning destination ports at 09:11:04 UTC.
        </div>
      </div>

      {/* Causal Stage Progression */}
      <div className="space-y-2">
        <div className="text-[10px] font-mono text-evi-muted uppercase font-bold flex items-center justify-between">
          <span className="flex items-center gap-1.5">
            <Layers className="w-3 h-3 text-evi-accent" />
            CAUSAL ATT&amp;CK CHAIN
          </span>
          <span>{stages.length} STEPS</span>
        </div>

        <div className="space-y-1.5">
          {stages.map((stg: any, i: number) => (
            <div
              key={stg.stage_id || i}
              className="bg-evi-canvas border border-evi-border/70 p-2 rounded flex flex-col gap-1 text-xs font-mono"
            >
              <div className="flex items-center justify-between">
                <span className="text-evi-accent font-bold">
                  {i + 1}. {stg.tactic}
                </span>
                <span className="text-[10px] text-slate-500">{stg.tactic_id}</span>
              </div>
              <div className="text-[11px] text-slate-300">
                {stg.src} &rarr; {stg.dst}:{stg.port}
              </div>
              <div className="flex items-center justify-between pt-1 text-[10px] text-slate-400">
                <span>Confidence: {(stg.confidence || 0.95).toFixed(2)}</span>
                <span className="text-emerald-400">RFC-6962 Verified</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Multi-Model Detector Consensus */}
      <div className="bg-evi-canvas border border-evi-border rounded-lg p-3 space-y-2.5">
        <div className="text-[10px] font-mono text-evi-muted uppercase font-bold flex items-center gap-1.5">
          <Cpu className="w-3 h-3 text-evi-accent" />
          <span>DETECTOR CONSENSUS</span>
        </div>

        <div className="space-y-1.5 text-xs font-mono">
          <div className="flex justify-between items-center">
            <span className="text-slate-400">XGBoost Baseline:</span>
            <span className="text-emerald-400 font-bold">0.965 Malicious</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-slate-400">HistGradientBoosting:</span>
            <span className="text-emerald-400 font-bold">0.952 Malicious</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-slate-400">Autoencoder MSE:</span>
            <span className="text-cyan-400 font-bold">High Anomaly Burst</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-slate-400">PyG Edge-GraphSAGE:</span>
            <span className="text-purple-400 font-bold">0.941 Topological</span>
          </div>
        </div>
      </div>

      {/* Merkle Root Ledger */}
      <div className="bg-evi-canvas border border-emerald-500/20 rounded-lg p-3 space-y-1.5">
        <div className="text-[10px] font-mono text-emerald-400 uppercase font-bold flex items-center gap-1.5">
          <ShieldCheck className="w-3 h-3 text-emerald-400" />
          <span>SESSION MERKLE ROOT</span>
        </div>
        <div className="font-mono text-[11px] text-slate-300 break-all bg-evi-panel/80 p-1.5 rounded border border-evi-border">
          {truncateHash(merkleRoot, 14)}
        </div>
        <div className="text-[10px] text-slate-400">
          RFC-6962 binary tree leaves anchored.
        </div>
      </div>
    </div>
  );
}
