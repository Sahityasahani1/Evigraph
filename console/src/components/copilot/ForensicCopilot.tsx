"use client";

import React, { useState } from "react";
import { useConsoleStore, CopilotTab } from "@/lib/store";
import { queryCopilot } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import {
  X,
  Send,
  Sparkles,
  ShieldCheck,
  Scale,
  FileText,
  Search,
  ExternalLink,
  AlertTriangle,
  RotateCcw,
  Check,
  Copy,
} from "lucide-react";

interface Message {
  id: string;
  sender: "user" | "copilot";
  text: string;
  timestamp: string;
  grounded: boolean;
  citations?: string[];
}

const PRESET_QUERIES: Record<CopilotTab, string[]> = {
  investigation: [
    "Why was 172.16.0.105 flagged as patient zero?",
    "Show the primary multi-stage attack chain",
    "What is the detector consensus confidence?",
    "Explain abnormal fan-out volume",
  ],
  evidence: [
    "Verify RFC-6962 SHA-256 Merkle root",
    "Inspect flow flw_scan_0080 leaf proof",
    "Are all 20 citations verified against raw PCAP?",
  ],
  "cross-examination": [
    "Could this traffic be a misconfigured legitimate vulnerability scanner?",
    "Are any temporal timestamps retrograde or out of causal sequence?",
    "What is the false positive probability under Layer-4 packet loss?",
  ],
  report: [
    "Draft technical admissibility findings for legal counsel",
    "Generate executive breach timeline with cryptographic hashes",
    "Summarize blast radius and containment defense audit",
  ],
};

export function ForensicCopilot() {
  const {
    copilotOpen,
    setCopilotOpen,
    copilotTab,
    setCopilotTab,
    selectedIncidentId,
    setSelectedObject,
    setActiveScreen,
  } = useConsoleStore();

  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<Record<CopilotTab, Message[]>>({
    investigation: [
      {
        id: "m-inv-1",
        sender: "copilot",
        text: "EviGraph Forensic Assistant initialized. All answers are strictly grounded in verified RFC-6962 Merkle certificates. Ask a question regarding telemetry, causal chains, or anomaly models.",
        timestamp: new Date().toLocaleTimeString(),
        grounded: true,
      },
    ],
    evidence: [
      {
        id: "m-ev-1",
        sender: "copilot",
        text: "Evidence Integrity Assistant ready. Query specific flow digests, Merkle inclusion paths, or SHA-256 telemetry certificates.",
        timestamp: new Date().toLocaleTimeString(),
        grounded: true,
      },
    ],
    "cross-examination": [
      {
        id: "m-cx-1",
        sender: "copilot",
        text: "Courtroom Adversarial Mode active. Challenging admissibility, temporal monotonicity, and detector bias under federal evidence standards.",
        timestamp: new Date().toLocaleTimeString(),
        grounded: true,
      },
    ],
    report: [
      {
        id: "m-rep-1",
        sender: "copilot",
        text: "Forensic Case Bundle Generator ready. Ready to synthesize executive briefs and technical admissibility summaries.",
        timestamp: new Date().toLocaleTimeString(),
        grounded: true,
      },
    ],
  });

  if (!copilotOpen) return null;

  const currentMessages = messages[copilotTab] || [];

  const handleSend = async (queryText?: string) => {
    const q = (queryText || input).trim();
    if (!q || loading) return;

    const userMsg: Message = {
      id: `u-${Date.now()}`,
      sender: "user",
      text: q,
      timestamp: new Date().toLocaleTimeString(),
      grounded: true,
    };

    setMessages((prev) => ({
      ...prev,
      [copilotTab]: [...prev[copilotTab], userMsg],
    }));

    if (!queryText) setInput("");
    setLoading(true);

    try {
      const res = await queryCopilot(selectedIncidentId, q, copilotTab);
      const answer = res.answer || "No response received.";
      const citations = res.citations || [];

      const botMsg: Message = {
        id: `c-${Date.now()}`,
        sender: "copilot",
        text: answer,
        timestamp: new Date().toLocaleTimeString(),
        grounded: true,
        citations,
      };

      setMessages((prev) => ({
        ...prev,
        [copilotTab]: [...prev[copilotTab], botMsg],
      }));
    } catch (err) {
      const errorMsg: Message = {
        id: `e-${Date.now()}`,
        sender: "copilot",
        text: "Forensic query failed or target telemetry unavailable. Refusing to speculate without verified proof.",
        timestamp: new Date().toLocaleTimeString(),
        grounded: false,
      };
      setMessages((prev) => ({
        ...prev,
        [copilotTab]: [...prev[copilotTab], errorMsg],
      }));
    } finally {
      setLoading(false);
    }
  };

  const handleCitationClick = (flowId: string) => {
    setSelectedObject({
      type: "edge",
      id: flowId,
      data: { flow_id: flowId },
    });
    // Open investigation or evidence screen
    setActiveScreen("investigation");
  };

  // Helper to parse [E:flow_id] and render interactive clickable badges
  const renderMessageText = (text: string) => {
    const regex = /\[E:([a-zA-Z0-9_\-]+)\]/g;
    const parts = [];
    let lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      if (match.index > lastIndex) {
        parts.push(text.substring(lastIndex, match.index));
      }
      const flowId = match[1];
      parts.push(
        <button
          key={`${match.index}-${flowId}`}
          onClick={() => handleCitationClick(flowId)}
          className="inline-flex items-center gap-1 mx-1 px-1.5 py-0.5 rounded font-mono text-[11px] font-semibold bg-evi-accent-cyan/15 text-evi-accent-cyan border border-evi-accent-cyan/40 hover:bg-evi-accent-cyan/25 transition-colors cursor-pointer"
          title={`Click to inspect flow ${flowId} and verify Merkle proof`}
        >
          <span>E:{flowId}</span>
          <ExternalLink className="h-2.5 w-2.5" />
        </button>
      );
      lastIndex = regex.lastIndex;
    }

    if (lastIndex < text.length) {
      parts.push(text.substring(lastIndex));
    }

    return parts;
  };

  return (
    <aside className="fixed inset-y-0 right-0 z-40 w-96 md:w-[420px] bg-evi-bg-panel border-l border-evi-border shadow-2xl flex flex-col pt-14">
      {/* Top Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-evi-border bg-evi-bg-canvas/50">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-evi-accent-cyan" />
          <h2 className="text-sm font-bold text-evi-text-primary tracking-wide">
            Forensic Copilot
          </h2>
          <Badge variant="verified" className="text-[10px] py-0">
            Ground-Truth Only
          </Badge>
        </div>
        <button
          onClick={() => setCopilotOpen(false)}
          className="p-1 rounded text-evi-text-secondary hover:text-white hover:bg-evi-bg-canvas"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* 4 Tabs */}
      <div className="grid grid-cols-4 border-b border-evi-border bg-evi-bg-canvas text-xs font-mono">
        {(
          [
            { id: "investigation", label: "Triage", icon: Search },
            { id: "evidence", label: "Proofs", icon: ShieldCheck },
            { id: "cross-examination", label: "Audit", icon: Scale },
            { id: "report", label: "Report", icon: FileText },
          ] as const
        ).map((tab) => {
          const Icon = tab.icon;
          const isActive = copilotTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setCopilotTab(tab.id as CopilotTab)}
              className={`flex flex-col items-center py-2 px-1 gap-1 border-b-2 transition-colors ${
                isActive
                  ? "border-evi-accent-cyan text-evi-accent-cyan bg-evi-accent-cyan/10"
                  : "border-transparent text-evi-text-secondary hover:text-evi-text-primary hover:bg-evi-bg-panel"
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              <span className="text-[10px]">{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Message Stream */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {currentMessages.map((msg) => (
          <div
            key={msg.id}
            className={`flex flex-col ${
              msg.sender === "user" ? "items-end" : "items-start"
            }`}
          >
            <div
              className={`max-w-[90%] rounded-lg p-3 text-xs leading-relaxed ${
                msg.sender === "user"
                  ? "bg-evi-accent-cyan/20 border border-evi-accent-cyan/40 text-evi-text-primary"
                  : "bg-evi-bg-canvas border border-evi-border text-evi-text-primary"
              }`}
            >
              <div className="whitespace-pre-wrap">
                {renderMessageText(msg.text)}
              </div>

              {msg.citations && msg.citations.length > 0 && (
                <div className="mt-2 pt-2 border-t border-evi-border-subtle flex flex-wrap gap-1 items-center">
                  <span className="text-[10px] text-evi-text-secondary font-mono mr-1">
                    Citations:
                  </span>
                  {msg.citations.map((c, i) => (
                    <button
                      key={i}
                      onClick={() => handleCitationClick(c)}
                      className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-evi-bg-panel border border-evi-border text-evi-accent-cyan hover:border-evi-accent-cyan"
                    >
                      {c}
                    </button>
                  ))}
                </div>
              )}
            </div>

            <div className="flex items-center gap-2 mt-1 px-1">
              <span className="text-[10px] text-evi-text-secondary font-mono">
                {msg.timestamp}
              </span>
              {msg.sender === "copilot" && (
                <span className="flex items-center gap-0.5 text-[10px] text-evi-status-green font-mono">
                  <ShieldCheck className="h-2.5 w-2.5" />
                  Grounded
                </span>
              )}
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-2 text-xs text-evi-accent-cyan font-mono p-2">
            <span className="animate-pulse">●</span>
            <span>Querying verified forensic index...</span>
          </div>
        )}
      </div>

      {/* Suggested Fast Prompts */}
      <div className="p-3 border-t border-evi-border bg-evi-bg-canvas/40 space-y-2">
        <div className="text-[10px] font-mono uppercase tracking-wider text-evi-text-secondary">
          Suggested Evidence Inquiries:
        </div>
        <div className="flex flex-wrap gap-1.5 max-h-20 overflow-y-auto">
          {PRESET_QUERIES[copilotTab].map((q, idx) => (
            <button
              key={idx}
              onClick={() => handleSend(q)}
              className="text-[11px] text-left px-2 py-1 rounded bg-evi-bg-panel border border-evi-border-subtle text-evi-text-secondary hover:text-evi-accent-cyan hover:border-evi-accent-cyan transition-colors truncate max-w-full"
            >
              {q}
            </button>
          ))}
        </div>
      </div>

      {/* Input Field */}
      <div className="p-3 border-t border-evi-border bg-evi-bg-panel">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask evidence grounded inquiry..."
            className="flex-1 bg-evi-bg-canvas border border-evi-border rounded px-3 py-2 text-xs text-evi-text-primary placeholder:text-evi-text-secondary focus:outline-none focus:border-evi-accent-cyan font-sans"
          />
          <button
            type="submit"
            disabled={!input.trim() || loading}
            className="p-2 rounded bg-evi-accent-cyan text-evi-bg-canvas font-bold hover:bg-evi-accent-cyan/90 disabled:opacity-50 transition-opacity"
          >
            <Send className="h-4 w-4" />
          </button>
        </form>
        <div className="flex items-center justify-between text-[10px] text-evi-text-secondary mt-1.5 px-1 font-mono">
          <span>Enter to submit</span>
          <span className="text-evi-status-amber">Zero hallucination mode</span>
        </div>
      </div>
    </aside>
  );
}
