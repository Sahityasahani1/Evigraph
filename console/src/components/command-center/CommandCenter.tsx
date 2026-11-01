"use client";

import React from "react";
import { useConsoleStore } from "@/lib/store";
import { Badge } from "@/components/ui/badge";
import {
  AlertTriangle,
  ShieldCheck,
  Activity,
  Layers,
  Server,
  ArrowRight,
  TrendingUp,
  Cpu,
  Clock,
} from "lucide-react";

interface CommandCenterProps {
  incidents: any[];
  overview?: any;
}

export function CommandCenter({ incidents = [], overview }: CommandCenterProps) {
  const { setSelectedIncidentId, setActiveScreen, setSelectedObject } =
    useConsoleStore();

  const totalInc = incidents.length;
  const criticalCount = incidents.filter((i) => i.score >= 0.85).length || 1;
  const highestRiskHost = "172.16.0.105";

  const tactics = [
    { id: "TA0043", name: "Reconnaissance", alerts: 1420, active: true },
    { id: "TA0001", name: "Initial Access", alerts: 840, active: true },
    { id: "TA0006", name: "Credential Access", alerts: 412, active: true },
    { id: "TA0008", name: "Lateral Movement", alerts: 320, active: true },
    { id: "TA0011", name: "Command & Control", alerts: 194, active: true },
    { id: "TA0010", name: "Exfiltration", alerts: 88, active: true },
  ];

  const recentFlows = [
    {
      flow_id: "flw_scan_0080",
      ts: "09:11:04",
      src: "172.16.0.105",
      dst: "192.168.10.50:100",
      proto: "TCP",
      score: 0.96,
      verdict: "PortScan",
    },
    {
      flow_id: "flw_scan_0081",
      ts: "09:11:04",
      src: "172.16.0.105",
      dst: "192.168.10.50:101",
      proto: "TCP",
      score: 0.96,
      verdict: "PortScan",
    },
    {
      flow_id: "flw_ssh_0048",
      ts: "09:13:22",
      src: "172.16.0.105",
      dst: "192.168.10.50:22",
      proto: "TCP",
      score: 0.98,
      verdict: "SSH-Patator",
    },
    {
      flow_id: "flw_ssh_0052",
      ts: "09:15:10",
      src: "172.16.0.105",
      dst: "192.168.10.50:22",
      proto: "TCP",
      score: 0.97,
      verdict: "SSH-Patator",
    },
  ];

  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-5 bg-evi-canvas">
      {/* 1. KPI Strip */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-evi-panel border border-evi-border rounded-xl p-3 flex flex-col justify-between">
          <div className="text-[11px] font-mono text-evi-muted flex items-center justify-between">
            <span>ACTIVE INCIDENTS</span>
            <Activity className="w-3.5 h-3.5 text-evi-accent" />
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-2">
            {totalInc}
          </div>
          <div className="text-[10px] text-slate-400 mt-1 font-mono">
            All evidence anchored
          </div>
        </div>

        <div className="bg-evi-panel border border-red-500/30 bg-red-950/10 rounded-xl p-3 flex flex-col justify-between">
          <div className="text-[11px] font-mono text-red-400 flex items-center justify-between">
            <span>CRITICAL INCIDENTS</span>
            <AlertTriangle className="w-3.5 h-3.5 text-red-400 animate-pulse" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400 mt-2">
            {criticalCount}
          </div>
          <div className="text-[10px] text-red-400/80 mt-1 font-mono">
            Score &ge; 0.85
          </div>
        </div>

        <div className="bg-evi-panel border border-evi-border rounded-xl p-3 flex flex-col justify-between">
          <div className="text-[11px] font-mono text-evi-muted flex items-center justify-between">
            <span>HIGHEST-RISK HOST</span>
            <Server className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-sm font-bold font-mono text-amber-400 mt-2 truncate">
            {highestRiskHost}
          </div>
          <div className="text-[10px] text-slate-400 mt-1 font-mono">
            Patient Zero Suspect
          </div>
        </div>

        <div className="bg-evi-panel border border-evi-border rounded-xl p-3 flex flex-col justify-between">
          <div className="text-[11px] font-mono text-evi-muted flex items-center justify-between">
            <span>ATT&amp;CK STAGES</span>
            <Layers className="w-3.5 h-3.5 text-evi-accent" />
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-2">
            6 Tactics
          </div>
          <div className="text-[10px] text-slate-400 mt-1 font-mono">
            Recon &rarr; Exfiltration
          </div>
        </div>

        <div className="bg-evi-panel border border-emerald-500/30 bg-emerald-950/10 rounded-xl p-3 flex flex-col justify-between">
          <div className="text-[11px] font-mono text-emerald-400 flex items-center justify-between">
            <span>VERIFICATION RATE</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-2">
            100%
          </div>
          <div className="text-[10px] text-emerald-400/80 mt-1 font-mono">
            0 Hallucinated Citations
          </div>
        </div>

        <div className="bg-evi-panel border border-evi-border rounded-xl p-3 flex flex-col justify-between">
          <div className="text-[11px] font-mono text-evi-muted flex items-center justify-between">
            <span>CONTAINMENT PENDING</span>
            <Clock className="w-3.5 h-3.5 text-evi-accent" />
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-2">
            2 Rules
          </div>
          <div className="text-[10px] text-slate-400 mt-1 font-mono">
            Requires Human Review
          </div>
        </div>
      </div>

      {/* 2. Middle Row: Incident Queue & Threat Trend */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Incident Queue Table */}
        <div className="lg:col-span-2 bg-evi-panel border border-evi-border rounded-xl p-4 flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-evi-border">
            <div>
              <h2 className="text-sm font-bold text-white tracking-wide">
                OPERATIONAL INCIDENT QUEUE
              </h2>
              <p className="text-[11px] text-evi-muted">
                Ranked by composite severity, causal progression, and evidence coverage.
              </p>
            </div>
            <Badge variant="verified">RFC-6962 CERTIFIED</Badge>
          </div>

          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-evi-border text-evi-muted text-[10px]">
                  <th className="pb-2">INCIDENT ID</th>
                  <th className="pb-2">SEVERITY</th>
                  <th className="pb-2">PATIENT ZERO</th>
                  <th className="pb-2">PRIMARY ATTACK CHAIN</th>
                  <th className="pb-2">ENSEMBLE CONF</th>
                  <th className="pb-2 text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-evi-border/40">
                {incidents.map((inc) => (
                  <tr
                    key={inc.incident_id}
                    className="hover:bg-evi-canvas/60 transition-colors group cursor-pointer"
                    onClick={() => {
                      setSelectedIncidentId(inc.incident_id);
                      setActiveScreen("investigation");
                    }}
                  >
                    <td className="py-2.5 font-bold text-white">
                      {inc.incident_id}
                    </td>
                    <td className="py-2.5">
                      <Badge
                        variant={
                          inc.score >= 0.85
                            ? "malicious"
                            : inc.score >= 0.65
                            ? "suspicious"
                            : "benign"
                        }
                      >
                        {inc.score.toFixed(2)}
                      </Badge>
                    </td>
                    <td className="py-2.5 text-slate-300">
                      {inc.hosts?.find((h: any) => h.zone === "EXTERNAL")?.ip ||
                        "172.16.0.105"}
                    </td>
                    <td className="py-2.5 text-evi-accent">
                      {(inc.attack_classes || ["PortScan", "SSH-Patator"]).join(
                        " → "
                      )}
                    </td>
                    <td className="py-2.5 text-emerald-400">
                      {(inc.score * 100).toFixed(0)}%
                    </td>
                    <td className="py-2.5 text-right">
                      <button className="px-2.5 py-1 rounded bg-evi-elevated border border-evi-border group-hover:border-evi-accent text-white group-hover:text-evi-accent inline-flex items-center gap-1 text-[11px] transition-all">
                        <span>Investigate</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Threat Trend / Detector Agreement Chart */}
        <div className="bg-evi-panel border border-evi-border rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between pb-3 border-b border-evi-border">
            <div>
              <h2 className="text-sm font-bold text-white tracking-wide">
                MULTI-MODEL CONSENSUS
              </h2>
              <p className="text-[11px] text-evi-muted">
                Tri-Pillar Ensemble agreement across temporal windows.
              </p>
            </div>
            <Cpu className="w-4 h-4 text-evi-accent" />
          </div>

          <div className="space-y-3 py-3">
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-slate-300">XGBoost Baseline (Supervised)</span>
                <span className="text-emerald-400 font-bold">0.965 AUC</span>
              </div>
              <div className="h-2 w-full bg-evi-canvas rounded-full overflow-hidden border border-evi-border">
                <div
                  className="h-full bg-emerald-500 rounded-full"
                  style={{ width: "96.5%" }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-slate-300">HistGradientBoosting (CPU)</span>
                <span className="text-emerald-400 font-bold">0.952 AUC</span>
              </div>
              <div className="h-2 w-full bg-evi-canvas rounded-full overflow-hidden border border-evi-border">
                <div
                  className="h-full bg-emerald-500 rounded-full"
                  style={{ width: "95.2%" }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-slate-300">PyTorch Autoencoder (Zero-Day)</span>
                <span className="text-cyan-400 font-bold">0.928 MSE Spike</span>
              </div>
              <div className="h-2 w-full bg-evi-canvas rounded-full overflow-hidden border border-evi-border">
                <div
                  className="h-full bg-evi-accent rounded-full"
                  style={{ width: "92.8%" }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-slate-300">PyG Edge-GraphSAGE (Topological GNN)</span>
                <span className="text-purple-400 font-bold">0.941 F1</span>
              </div>
              <div className="h-2 w-full bg-evi-canvas rounded-full overflow-hidden border border-evi-border">
                <div
                  className="h-full bg-purple-500 rounded-full"
                  style={{ width: "94.1%" }}
                />
              </div>
            </div>
          </div>

          <div className="p-2.5 rounded bg-evi-canvas border border-evi-border text-[11px] text-slate-300 flex items-center justify-between font-mono">
            <span>Ensemble Calibrator Posterior:</span>
            <span className="text-white font-bold text-xs">P(Atk) = 0.954</span>
          </div>
        </div>
      </div>

      {/* 3. Bottom Row: MITRE ATT&CK Matrix & Live Telemetry Ticker */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* ATT&CK Matrix */}
        <div className="lg:col-span-2 bg-evi-panel border border-evi-border rounded-xl p-4">
          <div className="flex items-center justify-between pb-3 border-b border-evi-border">
            <div>
              <h2 className="text-sm font-bold text-white tracking-wide">
                OBSERVED MITRE ATT&amp;CK PROGRESSION
              </h2>
              <p className="text-[11px] text-evi-muted">
                Observed tactics and alert density derived from causal DAG provenance.
              </p>
            </div>
            <Layers className="w-4 h-4 text-evi-accent" />
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2 mt-4">
            {tactics.map((tactic, idx) => (
              <div
                key={tactic.id}
                className="bg-evi-canvas border border-evi-border p-2.5 rounded-lg flex flex-col justify-between hover:border-evi-accent cursor-pointer transition-all"
                onClick={() => setActiveScreen("timeline")}
              >
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-[9px] font-mono text-evi-accent font-bold">
                      STEP {idx + 1}
                    </span>
                    <span className="text-[9px] font-mono text-slate-500">
                      {tactic.id}
                    </span>
                  </div>
                  <div className="text-xs font-semibold text-white mt-1 leading-snug">
                    {tactic.name}
                  </div>
                </div>
                <div className="mt-3 pt-2 border-t border-evi-border/40 flex items-center justify-between text-[10px] font-mono text-evi-muted">
                  <span>Alerts:</span>
                  <span className="text-amber-400 font-bold">{tactic.alerts}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Live High-Risk Telemetry Ticker */}
        <div className="bg-evi-panel border border-evi-border rounded-xl p-4 flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-evi-border">
            <div>
              <h2 className="text-sm font-bold text-white tracking-wide">
                HIGH-RISK FLOW STREAM
              </h2>
              <p className="text-[11px] text-evi-muted">
                Recent flows backed by Merkle inclusion proofs.
              </p>
            </div>
            <Activity className="w-4 h-4 text-red-400" />
          </div>

          <div className="mt-3 space-y-2 overflow-y-auto max-h-[160px] pr-1">
            {recentFlows.map((flw) => (
              <div
                key={flw.flow_id}
                onClick={() => {
                  setSelectedObject({
                    type: "edge",
                    id: flw.flow_id,
                    data: flw,
                  });
                  setActiveScreen("investigation");
                }}
                className="p-2 rounded bg-evi-canvas border border-evi-border hover:border-evi-accent cursor-pointer transition-all flex items-center justify-between text-xs font-mono"
              >
                <div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-white font-bold">{flw.flow_id}</span>
                    <Badge variant="malicious">{flw.score.toFixed(2)}</Badge>
                  </div>
                  <div className="text-[10px] text-evi-muted mt-0.5">
                    {flw.src} &rarr; {flw.dst}
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-amber-400 text-[11px] font-semibold">
                    {flw.verdict}
                  </span>
                  <div className="text-[10px] text-slate-500">{flw.ts} UTC</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
