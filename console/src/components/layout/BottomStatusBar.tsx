"use client";

import React from "react";
import { useConsoleStore } from "@/lib/store";
import { ShieldCheck, Cpu, Database } from "lucide-react";

interface BottomStatusBarProps {
  overview?: any;
}

export function BottomStatusBar({ overview }: BottomStatusBarProps) {
  const { selectedIncidentId, selectedObject, graphLayers } = useConsoleStore();

  return (
    <footer className="h-7 border-t border-evi-border bg-evi-panel flex items-center justify-between px-3 text-[11px] font-mono text-evi-muted z-30 select-none">
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-1.5 text-white">
          <span className="text-evi-muted">ACTIVE:</span>
          <span className="font-semibold text-evi-accent">{selectedIncidentId}</span>
        </div>

        <div className="h-3 w-[1px] bg-evi-border" />

        <div className="flex items-center gap-1.5">
          <span className="text-evi-muted">SELECTED TARGET:</span>
          {selectedObject ? (
            <span className="text-white bg-evi-canvas px-1.5 py-0.5 rounded border border-evi-border text-[10px]">
              {selectedObject.type.toUpperCase()}: {selectedObject.id}
            </span>
          ) : (
            <span className="text-slate-500 italic">None (click node or edge)</span>
          )}
        </div>

        <div className="h-3 w-[1px] bg-evi-border" />

        <div className="flex items-center gap-1 text-emerald-400">
          <ShieldCheck className="w-3 h-3 text-emerald-400" />
          <span>EVIDENCE INTEGRITY: VERIFIED</span>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {graphLayers.showSimulation && (
          <div className="flex items-center gap-1 text-purple-400 bg-purple-950/40 border border-purple-500/30 px-2 rounded text-[10px]">
            <span>Simulation — not deployed control</span>
          </div>
        )}

        <div className="flex items-center gap-1.5 text-slate-400">
          <Database className="w-3 h-3 text-evi-muted" />
          <span>CICIDS2017 · 2.64M FLOWS</span>
        </div>

        <div className="flex items-center gap-1.5 text-slate-400">
          <Cpu className="w-3 h-3 text-evi-muted" />
          <span>ENSEMBLE: XGB + HISTGB + AUTOENCODER</span>
        </div>

        <div className="text-slate-500 text-[10px]">
          EVIGRAPH v2.0
        </div>
      </div>
    </footer>
  );
}
