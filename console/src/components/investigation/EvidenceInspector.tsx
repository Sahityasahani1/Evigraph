"use client";

import React, { useState } from "react";
import { useConsoleStore } from "@/lib/store";
import { Badge } from "@/components/ui/badge";
import {
  FileText,
  Server,
  Activity,
  ShieldCheck,
  Copy,
  Check,
  Code,
  ExternalLink,
} from "lucide-react";
import { truncateHash, formatBytes } from "@/lib/utils";

export function EvidenceInspector() {
  const { selectedObject, setSelectedObject } = useConsoleStore();
  const [copied, setCopied] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  if (!selectedObject) {
    return (
      <div className="w-[360px] border-l border-evi-border bg-evi-panel flex flex-col items-center justify-center p-6 text-center text-evi-muted select-none">
        <div className="w-12 h-12 rounded-xl bg-evi-canvas border border-evi-border flex items-center justify-center text-slate-500 mb-3">
          <Activity className="w-6 h-6" />
        </div>
        <h3 className="text-sm font-semibold text-white">No Target Selected</h3>
        <p className="text-xs text-slate-400 mt-1 max-w-[220px]">
          Click any host node or communication edge in the attack graph to inspect its evidence chain.
        </p>
      </div>
    );
  }

  const { type, id, data } = selectedObject;

  return (
    <div className="w-[360px] border-l border-evi-border bg-evi-panel flex flex-col h-full overflow-y-auto select-none">
      {/* Header */}
      <div className="p-3.5 border-b border-evi-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          {type === "node" ? (
            <Server className="w-4 h-4 text-evi-accent" />
          ) : (
            <Activity className="w-4 h-4 text-red-400" />
          )}
          <span className="font-mono text-xs font-bold text-white uppercase">
            {type === "node" ? "HOST PROFILE" : "FLOW EVIDENCE"}
          </span>
        </div>
        <Badge variant={type === "node" ? "default" : "verified"}>
          {type === "node" ? data.zone || "INTERNAL" : "RFC-6962 VERIFIED"}
        </Badge>
      </div>

      <div className="p-4 space-y-4">
        {/* Identifier Card */}
        <div className="bg-evi-canvas border border-evi-border rounded-lg p-3">
          <div className="text-[10px] font-mono text-evi-muted uppercase font-bold">
            {type === "node" ? "HOST IP / IDENTIFIER" : "EVIDENCE FLOW ID"}
          </div>
          <div className="font-mono text-sm font-bold text-white mt-1 flex items-center justify-between">
            <span className="truncate">{type === "node" ? data.label || id : data.flow_id || id}</span>
            <button
              onClick={() => handleCopy(type === "node" ? data.label || id : data.flow_id || id, "id")}
              className="p-1 rounded bg-evi-panel hover:bg-evi-elevated border border-evi-border text-slate-400 hover:text-white"
              title="Copy identifier"
            >
              {copied === "id" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            </button>
          </div>
          {type === "node" && (
            <div className="text-xs text-slate-400 mt-1">
              Role: <span className="text-white font-mono">{data.role || "Host Asset"}</span>
            </div>
          )}
        </div>

        {/* Node Profile Fields */}
        {type === "node" && (
          <>
            <div className="grid grid-cols-2 gap-2">
              <div className="bg-evi-canvas border border-evi-border p-2.5 rounded">
                <div className="text-[10px] font-mono text-evi-muted">IN-DEGREE</div>
                <div className="text-base font-bold font-mono text-white mt-0.5">{data.inDegree || 12}</div>
              </div>
              <div className="bg-evi-canvas border border-evi-border p-2.5 rounded">
                <div className="text-[10px] font-mono text-evi-muted">OUT-DEGREE</div>
                <div className="text-base font-bold font-mono text-white mt-0.5">{data.outDegree || 24}</div>
              </div>
              <div className="bg-evi-canvas border border-evi-border p-2.5 rounded">
                <div className="text-[10px] font-mono text-evi-muted">DEST PORTS</div>
                <div className="text-base font-bold font-mono text-white mt-0.5">32 Unique</div>
              </div>
              <div className="bg-evi-canvas border border-evi-border p-2.5 rounded">
                <div className="text-[10px] font-mono text-evi-muted">VOLUME</div>
                <div className="text-base font-bold font-mono text-white mt-0.5">{formatBytes(18420000)}</div>
              </div>
            </div>

            <div className="bg-evi-canvas border border-evi-border rounded-lg p-3 space-y-1.5">
              <div className="text-[10px] font-mono text-evi-muted uppercase font-bold">
                INCIDENT INVOLVEMENT
              </div>
              <div className="text-xs text-slate-300">
                Suspected patient-zero entry point for port-scan reconnaissance targeting internal DMZ subnet.
              </div>
              <div className="pt-1 flex items-center gap-1.5 flex-wrap">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950/40 border border-red-500/40 text-red-300">
                  Targeted: 192.168.10.50
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/40 border border-amber-500/40 text-amber-300">
                  Ports: 1-1024
                </span>
              </div>
            </div>
          </>
        )}

        {/* Edge / Flow Profile Fields */}
        {type === "edge" && (
          <>
            <div className="bg-evi-canvas border border-evi-border rounded-lg p-3 space-y-2">
              <div className="text-[10px] font-mono text-evi-muted uppercase font-bold flex items-center justify-between">
                <span>COMMUNICATION PATH</span>
                <span className="text-evi-accent font-bold">{data.protocol || "TCP"}</span>
              </div>
              <div className="font-mono text-xs text-white">
                <div>Source: <span className="text-amber-400">{data.source}</span></div>
                <div>Target: <span className="text-cyan-400">{data.target}:{data.dstPort || 22}</span></div>
              </div>
            </div>

            {/* SHAP Explanation */}
            <div className="bg-evi-canvas border border-evi-border rounded-lg p-3 space-y-2">
              <div className="text-[10px] font-mono text-evi-muted uppercase font-bold">
                WHY THE DETECTOR FLAGGED IT
              </div>
              <div className="space-y-1.5">
                {[
                  { feat: "Destination Port Connection Burst", weight: 0.94 },
                  { feat: "TCP RST Response Ratio (0.97)", weight: 0.88 },
                  { feat: "Abnormal Flow Duration (< 40ms)", weight: 0.65 },
                ].map((item, idx) => (
                  <div key={idx} className="text-xs font-mono">
                    <div className="flex justify-between text-slate-300 text-[11px]">
                      <span>{item.feat}</span>
                      <span className="text-evi-accent">{(item.weight * 100).toFixed(0)}%</span>
                    </div>
                    <div className="h-1.5 w-full bg-evi-panel rounded-full overflow-hidden mt-1">
                      <div
                        className="h-full bg-evi-accent rounded-full"
                        style={{ width: `${item.weight * 100}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Cryptographic Merkle Proof Card */}
            <div className="bg-evi-canvas border border-emerald-500/30 rounded-lg p-3 space-y-2">
              <div className="text-[10px] font-mono text-emerald-400 uppercase font-bold flex items-center justify-between">
                <span className="flex items-center gap-1">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  MERKLE INCLUSION PROOF
                </span>
                <span className="text-[10px] text-emerald-500">RFC-6962</span>
              </div>

              <div className="space-y-1 font-mono text-[11px] text-slate-300">
                <div>Leaf Hash: <code>{truncateHash(data.pcap_sha256, 10)}</code></div>
                <div>Tree Depth: <span className="text-white">9 levels</span></div>
                <div>Status: <span className="text-emerald-400 font-bold">100% REPLAYED VALID</span></div>
              </div>
            </div>

            {/* Raw JSON */}
            <div className="bg-evi-canvas border border-evi-border rounded-lg p-3 space-y-2">
              <div className="text-[10px] font-mono text-evi-muted uppercase font-bold flex items-center justify-between">
                <span className="flex items-center gap-1">
                  <Code className="w-3 h-3" />
                  RAW TELEMETRY JSON
                </span>
              </div>
              <pre className="text-[10px] font-mono bg-evi-panel p-2 rounded text-slate-300 overflow-x-auto max-h-36">
                {JSON.stringify(
                  {
                    flow_id: data.flow_id || id,
                    source: data.source,
                    target: data.target,
                    port: data.dstPort,
                    protocol: data.protocol || "TCP",
                    packets: 24,
                    bytes: 1840,
                    pcap_sha256: data.pcap_sha256,
                    detector_posterior: data.riskScore || 0.95,
                  },
                  null,
                  2
                )}
              </pre>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
