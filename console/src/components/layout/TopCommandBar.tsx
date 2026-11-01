"use client";

import React from "react";
import { useConsoleStore, ScreenType } from "@/lib/store";
import { Badge } from "@/components/ui/badge";
import {
  LayoutDashboard,
  Network,
  Clock,
  Scale,
  ShieldAlert,
  Search,
  ShieldCheck,
  Bot,
  Terminal,
} from "lucide-react";

interface TopCommandBarProps {
  incidents?: any[];
}

export function TopCommandBar({ incidents = [] }: TopCommandBarProps) {
  const {
    activeScreen,
    setActiveScreen,
    selectedIncidentId,
    setSelectedIncidentId,
    copilotOpen,
    setCopilotOpen,
  } = useConsoleStore();

  const screens: { id: ScreenType; label: string; icon: React.ElementType }[] = [
    { id: "command-center", label: "Command Center", icon: LayoutDashboard },
    { id: "investigation", label: "Investigation Workspace", icon: Network },
    { id: "timeline", label: "Causal Timeline", icon: Clock },
    { id: "evidence", label: "Evidence & Verdict", icon: Scale },
    { id: "resilience", label: "Response & Resilience", icon: ShieldAlert },
  ];

  const currentInc = incidents.find((i) => i.incident_id === selectedIncidentId);

  return (
    <header className="h-14 border-b border-evi-border bg-evi-panel flex items-center justify-between px-4 z-40 select-none">
      {/* Brand & Incident Selector */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-evi-accent/20 to-purple-500/20 border border-evi-accent/40 flex items-center justify-center text-evi-accent shadow-sm">
            <Terminal className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-1.5 font-bold text-sm tracking-wide text-white">
              <span>EviGraph</span>
              <span className="text-xs px-1.5 py-0.2 rounded bg-evi-accent/15 text-evi-accent border border-evi-accent/30 font-mono">
                OPS CONSOLE
              </span>
            </div>
            <div className="text-[10px] text-evi-muted font-mono tracking-tight">
              EVIDENCE-GROUNDED DFIR
            </div>
          </div>
        </div>

        {/* Incident Switcher */}
        <div className="h-6 w-[1px] bg-evi-border" />

        <div className="flex items-center gap-2">
          <label htmlFor="incident-select" className="text-xs text-evi-muted font-mono">
            INCIDENT:
          </label>
          <select
            id="incident-select"
            value={selectedIncidentId}
            onChange={(e) => setSelectedIncidentId(e.target.value)}
            className="bg-evi-canvas border border-evi-border text-white text-xs rounded-md px-2.5 py-1 focus:outline-none focus:border-evi-accent font-mono cursor-pointer"
          >
            {incidents.map((inc) => (
              <option key={inc.incident_id} value={inc.incident_id}>
                {inc.incident_id} (Risk: {(inc.score || 0.76).toFixed(2)})
              </option>
            ))}
          </select>
          {currentInc && (
            <Badge
              variant={
                currentInc.score >= 0.85
                  ? "malicious"
                  : currentInc.score >= 0.65
                  ? "suspicious"
                  : "benign"
              }
            >
              {currentInc.score >= 0.85
                ? "CRITICAL"
                : currentInc.score >= 0.65
                ? "HIGH RISK"
                : "MED RISK"}
            </Badge>
          )}
        </div>
      </div>

      {/* Center Nav Screens */}
      <nav className="flex items-center gap-1 bg-evi-canvas/80 p-1 rounded-lg border border-evi-border">
        {screens.map((screen) => {
          const Icon = screen.icon;
          const isActive = activeScreen === screen.id;
          return (
            <button
              key={screen.id}
              onClick={() => setActiveScreen(screen.id)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                isActive
                  ? "bg-evi-elevated text-evi-accent border border-evi-accent/40 shadow-sm"
                  : "text-evi-muted hover:text-white hover:bg-evi-panel/60"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{screen.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Right Controls & Merkle Integrity Anchor */}
      <div className="flex items-center gap-3">
        {/* Merkle Status */}
        <div className="flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-950/40 border border-emerald-500/30 px-2.5 py-1 rounded-md font-mono">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span className="hidden xl:inline">RFC-6962 SHA-256</span>
          <span className="text-[10px] text-emerald-500 font-bold">ANCHORED</span>
        </div>

        {/* Global Search Bar */}
        <div className="relative hidden md:block">
          <Search className="w-3.5 h-3.5 text-evi-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search host, flow_id, port..."
            className="w-48 bg-evi-canvas border border-evi-border text-xs text-white pl-8 pr-3 py-1 rounded-md focus:outline-none focus:border-evi-accent font-mono placeholder:text-slate-500"
          />
        </div>

        {/* Copilot Toggle */}
        <button
          onClick={() => setCopilotOpen(!copilotOpen)}
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold border transition-all ${
            copilotOpen
              ? "bg-evi-accent/15 border-evi-accent text-evi-accent shadow-sm"
              : "border-evi-border text-evi-muted hover:text-white bg-evi-panel"
          }`}
          title="Toggle Forensic Analyst Copilot"
        >
          <Bot className="w-3.5 h-3.5" />
          <span className="hidden lg:inline">Copilot</span>
        </button>
      </div>
    </header>
  );
}
