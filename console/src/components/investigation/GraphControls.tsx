"use client";

import React from "react";
import { useConsoleStore } from "@/lib/store";
import {
  Maximize2,
  RotateCcw,
  GitBranch,
  Layers,
  ShieldAlert,
  Flame,
  Radio,
  Eye,
  EyeOff,
} from "lucide-react";

export function GraphControls() {
  const {
    graphLayers,
    toggleLayer,
    graphLayout,
    setGraphLayout,
    focusedSubgraphNodeId,
    setFocusedSubgraphNodeId,
    selectedObject,
  } = useConsoleStore();

  return (
    <div className="absolute top-3 left-3 z-10 flex flex-col gap-2 select-none">
      {/* Layout & Reset toolbar */}
      <div className="bg-evi-panel/90 backdrop-blur-md border border-evi-border rounded-lg p-1 flex items-center gap-1 shadow-panel">
        <button
          onClick={() =>
            setGraphLayout(graphLayout === "hierarchical" ? "force" : "hierarchical")
          }
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono transition-all ${
            graphLayout === "hierarchical"
              ? "bg-evi-elevated border border-evi-accent text-evi-accent"
              : "text-evi-muted hover:text-white"
          }`}
          title="Toggle Hierarchical (Dagre) / Force-Directed (Cose) Layout"
        >
          <GitBranch className="w-3 h-3" />
          <span>{graphLayout === "hierarchical" ? "HIERARCHICAL" : "FORCE"}</span>
        </button>

        <div className="h-4 w-[1px] bg-evi-border" />

        {selectedObject?.type === "node" && (
          <button
            onClick={() =>
              setFocusedSubgraphNodeId(
                focusedSubgraphNodeId === selectedObject.id ? null : selectedObject.id
              )
            }
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono transition-all ${
              focusedSubgraphNodeId
                ? "bg-amber-950/60 border border-amber-500 text-amber-300 font-bold"
                : "text-evi-muted hover:text-white"
            }`}
            title="Focus 1-hop suspicious subgraph around selected node"
          >
            <Radio className="w-3 h-3" />
            <span>1-HOP FOCUS</span>
          </button>
        )}
      </div>

      {/* Forensic Layer Toggles */}
      <div className="bg-evi-panel/90 backdrop-blur-md border border-evi-border rounded-lg p-2 flex flex-col gap-1.5 shadow-panel text-[11px] font-mono">
        <div className="text-[10px] text-evi-muted uppercase font-bold flex items-center gap-1 mb-1">
          <Layers className="w-3 h-3 text-evi-accent" />
          <span>FORENSIC LAYERS</span>
        </div>

        <button
          onClick={() => toggleLayer("showAttackChain")}
          className={`flex items-center justify-between px-2 py-1 rounded text-left transition-all ${
            graphLayers.showAttackChain
              ? "bg-red-950/40 border border-red-500/40 text-red-300"
              : "text-slate-500 hover:text-slate-300"
          }`}
        >
          <span>Primary Attack Chain</span>
          {graphLayers.showAttackChain ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
        </button>

        <button
          onClick={() => toggleLayer("showBenign")}
          className={`flex items-center justify-between px-2 py-1 rounded text-left transition-all ${
            graphLayers.showBenign
              ? "bg-sky-950/40 border border-sky-500/40 text-sky-300"
              : "text-slate-500 hover:text-slate-300"
          }`}
        >
          <span>Normal Telemetry</span>
          {graphLayers.showBenign ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
        </button>

        <button
          onClick={() => toggleLayer("showMinCut")}
          className={`flex items-center justify-between px-2 py-1 rounded text-left transition-all ${
            graphLayers.showMinCut
              ? "bg-amber-950/60 border border-amber-500 text-amber-300 font-bold"
              : "text-slate-500 hover:text-slate-300"
          }`}
        >
          <span className="flex items-center gap-1">
            <ShieldAlert className="w-3 h-3 text-amber-400" />
            Min-Cut Bottleneck
          </span>
          {graphLayers.showMinCut ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
        </button>

        <button
          onClick={() => toggleLayer("showBlastRadius")}
          className={`flex items-center justify-between px-2 py-1 rounded text-left transition-all ${
            graphLayers.showBlastRadius
              ? "bg-purple-950/50 border border-purple-500 text-purple-300 font-bold"
              : "text-slate-500 hover:text-slate-300"
          }`}
        >
          <span className="flex items-center gap-1">
            <Flame className="w-3 h-3 text-purple-400" />
            Blast Radius
          </span>
          {graphLayers.showBlastRadius ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
        </button>

        <button
          onClick={() => toggleLayer("showSimulation")}
          className={`flex items-center justify-between px-2 py-1 rounded text-left transition-all ${
            graphLayers.showSimulation
              ? "bg-purple-950/40 border border-purple-400 text-purple-300"
              : "text-slate-500 hover:text-slate-300"
          }`}
        >
          <span>Counterfactual Cut</span>
          {graphLayers.showSimulation ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
        </button>
      </div>
    </div>
  );
}
