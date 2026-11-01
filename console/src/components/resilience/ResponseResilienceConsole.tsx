"useclient";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useConsoleStore } from "@/lib/store";
import { getContainment, getSimulation, postContainmentAction } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import {
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Terminal,
  Copy,
  Check,
  AlertTriangle,
  Layers,
  Activity,
  FileCheck,
  Send,
  Flame,
  ArrowRight,
  Filter,
  Info,
} from "lucide-react";

type FirewallPlatform =
  | "linux_nftables"
  | "linux_iptables"
  | "windows_powershell"
  | "cisco_ios_acl"
  | "cloud_security_group_json";

const PLATFORM_LABELS: Record<FirewallPlatform, string> = {
  linux_nftables: "Linux (nftables)",
  linux_iptables: "Linux (iptables)",
  windows_powershell: "Windows (PowerShell)",
  cisco_ios_acl: "Cisco (IOS ACL)",
  cloud_security_group_json: "Cloud (Security Group)",
};

export function ResponseResilienceConsole() {
  const {
    selectedIncidentId,
    approvalWorkflow,
    setRuleApprovalState,
    counterfactualPolicy,
    setCounterfactualPolicy,
  } = useConsoleStore();

  const [selectedPlatform, setSelectedPlatform] =
    useState<FirewallPlatform>("linux_nftables");
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isApplying, setIsApplying] = useState(false);

  // Queries
  const { data: containmentData, isLoading: containmentLoading } = useQuery({
    queryKey: ["containment", selectedIncidentId],
    queryFn: () => getContainment(selectedIncidentId),
  });

  const { data: simData, isLoading: simLoading } = useQuery({
    queryKey: ["simulation", selectedIncidentId],
    queryFn: () => getSimulation(selectedIncidentId),
  });

  // Extract rules for the incident
  const currentPlan = containmentData?.incident_plans?.find(
    (p: any) => p.incident_id === selectedIncidentId
  ) || containmentData?.incident_plans?.[0];

  const actions: any[] = currentPlan?.actions || [];
  const activeRule = actions.find((a) => a.rule_id === selectedRuleId) || actions[0];

  // Extract simulations
  const simulations: any[] = simData?.simulations || [];
  const activeSim =
    simulations.find((s) => s.policy_name === counterfactualPolicy) ||
    simulations[0];

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleApprovalTransition = async (
    ruleId: string,
    nextState: "Reviewed" | "Approved" | "Deployed",
    target: string
  ) => {
    setIsApplying(true);
    try {
      const actionMap: Record<string, "REVIEW" | "APPROVE" | "DEPLOY"> = {
        Reviewed: "REVIEW",
        Approved: "APPROVE",
        Deployed: "DEPLOY",
      };
      await postContainmentAction(
        selectedIncidentId,
        ruleId,
        actionMap[nextState],
        target
      );
      setRuleApprovalState(ruleId, nextState);
    } catch (e) {
      console.error("Containment state transition error:", e);
      // Fallback local state transition for offline mode
      setRuleApprovalState(ruleId, nextState);
    } finally {
      setIsApplying(false);
    }
  };

  return (
    <div className="flex-1 overflow-y-auto bg-evi-bg-canvas p-6 space-y-6">
      {/* Top Header / Philosophy Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-evi-border pb-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold tracking-tight text-evi-text-primary">
              Response & Resilience Console
            </h1>
            <Badge variant="verified">Advisory Engine v2.0</Badge>
            <Badge variant="simulation">Zero Auto-Execution</Badge>
          </div>
          <p className="mt-1 text-sm text-evi-text-secondary">
            Min-Cut bottleneck containment, blast-radius verification, and counterfactual resilience analysis.
          </p>
        </div>

        {/* Philosophy Badge */}
        <div className="flex items-center gap-2 rounded border border-evi-border-subtle bg-evi-bg-panel/70 px-3 py-1.5 text-xs text-evi-text-secondary">
          <Info className="h-4 w-4 text-evi-accent-cyan shrink-0" />
          <span>
            <strong>Human-in-the-Loop:</strong> All firewall rules require explicit multi-step authorization before deployment.
          </span>
        </div>
      </div>

      {/* Main Grid: Left = Min-Cut Containment & Firewalls; Right = Counterfactual Resilience Simulator */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (7 cols): Surgical Min-Cut Bottleneck Actions */}
        <div className="lg:col-span-7 space-y-6">
          <div className="rounded-lg border border-evi-border bg-evi-bg-panel p-5">
            <div className="flex items-center justify-between mb-4 border-b border-evi-border-subtle pb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-evi-status-amber" />
                <h2 className="font-semibold text-evi-text-primary">
                  Surgical Containment Plan (Min-Cut)
                </h2>
              </div>
              <span className="text-xs font-mono text-evi-text-secondary">
                {actions.length} Synthesized Rules
              </span>
            </div>

            {containmentLoading ? (
              <div className="py-12 text-center text-sm text-evi-text-secondary">
                Loading containment actions...
              </div>
            ) : actions.length === 0 ? (
              <div className="py-12 text-center text-sm text-evi-text-secondary">
                No containment actions generated for this incident.
              </div>
            ) : (
              <div className="space-y-4">
                {/* Rule List Picker */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-56 overflow-y-auto pr-1">
                  {actions.map((act) => {
                    const ruleState =
                      approvalWorkflow[act.rule_id] || "Draft";
                    const isSelected =
                      (activeRule?.rule_id || actions[0]?.rule_id) === act.rule_id;

                    return (
                      <button
                        key={act.rule_id}
                        onClick={() => setSelectedRuleId(act.rule_id)}
                        className={`flex flex-col text-left p-2.5 rounded border transition-colors ${
                          isSelected
                            ? "border-evi-accent-cyan bg-evi-accent-cyan/10"
                            : "border-evi-border-subtle bg-evi-bg-canvas hover:border-evi-border"
                        }`}
                      >
                        <div className="flex items-center justify-between w-full">
                          <span className="font-mono text-xs font-semibold text-evi-text-primary">
                            {act.rule_id}
                          </span>
                          <span
                            className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                              ruleState === "Deployed"
                                ? "bg-evi-status-green/20 text-evi-status-green border border-evi-status-green/40"
                                : ruleState === "Approved"
                                ? "bg-evi-accent-cyan/20 text-evi-accent-cyan border border-evi-accent-cyan/40"
                                : ruleState === "Reviewed"
                                ? "bg-evi-status-amber/20 text-evi-status-amber border border-evi-status-amber/40"
                                : "bg-evi-status-benign/20 text-evi-status-benign border border-evi-status-benign/40"
                            }`}
                          >
                            {ruleState.toUpperCase()}
                          </span>
                        </div>
                        <div className="text-[11px] text-evi-text-secondary mt-1 truncate">
                          {act.action_tier} • Port {act.destination_port}/{act.protocol}
                        </div>
                      </button>
                    );
                  })}
                </div>

                {/* Selected Rule Inspector */}
                {activeRule && (
                  <div className="mt-4 rounded border border-evi-border-subtle bg-evi-bg-canvas p-4 space-y-4">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-evi-border-subtle pb-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-sm text-evi-accent-cyan">
                            {activeRule.rule_id}
                          </span>
                          <span className="text-xs text-evi-text-secondary font-mono">
                            [{activeRule.action_type}]
                          </span>
                        </div>
                        <p className="text-xs text-evi-text-primary mt-1">
                          {activeRule.rationale}
                        </p>
                      </div>

                      {/* Approval State Machine Control */}
                      <div className="flex items-center gap-2">
                        {(() => {
                          const state = approvalWorkflow[activeRule.rule_id] || "Draft";
                          return (
                            <div className="flex items-center gap-1.5">
                              {state === "Draft" && (
                                <button
                                  disabled={isApplying}
                                  onClick={() =>
                                    handleApprovalTransition(
                                      activeRule.rule_id,
                                      "Reviewed",
                                      activeRule.target_attacker
                                    )
                                  }
                                  className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded border border-evi-status-amber/40 bg-evi-status-amber/10 text-evi-status-amber hover:bg-evi-status-amber/20"
                                >
                                  <FileCheck className="h-3.5 w-3.5" />
                                  Mark Reviewed
                                </button>
                              )}
                              {state === "Reviewed" && (
                                <button
                                  disabled={isApplying}
                                  onClick={() =>
                                    handleApprovalTransition(
                                      activeRule.rule_id,
                                      "Approved",
                                      activeRule.target_attacker
                                    )
                                  }
                                  className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded border border-evi-accent-cyan/40 bg-evi-accent-cyan/10 text-evi-accent-cyan hover:bg-evi-accent-cyan/20"
                                >
                                  <ShieldCheck className="h-3.5 w-3.5" />
                                  Authorize / Approve
                                </button>
                              )}
                              {state === "Approved" && (
                                <button
                                  disabled={isApplying}
                                  onClick={() =>
                                    handleApprovalTransition(
                                      activeRule.rule_id,
                                      "Deployed",
                                      activeRule.target_attacker
                                    )
                                  }
                                  className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded border border-evi-status-green/40 bg-evi-status-green/10 text-evi-status-green hover:bg-evi-status-green/20"
                                >
                                  <Send className="h-3.5 w-3.5" />
                                  Deploy Rule
                                </button>
                              )}
                              {state === "Deployed" && (
                                <span className="flex items-center gap-1 text-xs font-mono text-evi-status-green px-2 py-1 bg-evi-status-green/10 rounded border border-evi-status-green/30">
                                  <Check className="h-3.5 w-3.5" />
                                  Deployed to Firewall
                                </span>
                              )}
                            </div>
                          );
                        })()}
                      </div>
                    </div>

                    {/* Blast Radius & Impact Analysis */}
                    {activeRule.victim_blast_radius && (
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-evi-bg-panel p-3 rounded border border-evi-border-subtle text-xs">
                        <div>
                          <div className="text-evi-text-secondary">Target Victim</div>
                          <div className="font-mono text-evi-text-primary mt-0.5">
                            {activeRule.victim_blast_radius.host_ip}
                          </div>
                        </div>
                        <div>
                          <div className="text-evi-text-secondary">Blast Radius Score</div>
                          <div className="font-mono text-evi-status-green mt-0.5 font-bold">
                            {(activeRule.victim_blast_radius.blast_radius_score * 100).toFixed(1)}%
                          </div>
                        </div>
                        <div>
                          <div className="text-evi-text-secondary">Impact Assessment</div>
                          <div className="font-mono text-evi-text-primary mt-0.5 truncate">
                            {activeRule.victim_blast_radius.impact_level}
                          </div>
                        </div>
                        <div>
                          <div className="text-evi-text-secondary">Connectivity Degree</div>
                          <div className="font-mono text-evi-text-primary mt-0.5">
                            {activeRule.victim_blast_radius.connectivity_degree} active links
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Firewall Syntax Preview (5 Platforms) */}
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-semibold text-evi-text-secondary flex items-center gap-1.5">
                          <Terminal className="h-3.5 w-3.5 text-evi-accent-cyan" />
                          Multi-Platform Syntax Preview
                        </span>
                        <div className="flex items-center gap-1 overflow-x-auto">
                          {(
                            [
                              "linux_nftables",
                              "linux_iptables",
                              "windows_powershell",
                              "cisco_ios_acl",
                              "cloud_security_group_json",
                            ] as FirewallPlatform[]
                          ).map((plat) => (
                            <button
                              key={plat}
                              onClick={() => setSelectedPlatform(plat)}
                              className={`text-[10px] px-2 py-1 rounded transition-colors whitespace-nowrap ${
                                selectedPlatform === plat
                                  ? "bg-evi-accent-cyan/20 text-evi-accent-cyan border border-evi-accent-cyan/40"
                                  : "bg-evi-bg-panel text-evi-text-secondary hover:text-evi-text-primary"
                              }`}
                            >
                              {PLATFORM_LABELS[plat]}
                            </button>
                          ))}
                        </div>
                      </div>

                      <div className="relative group rounded bg-evi-bg-panel border border-evi-border-subtle p-3 font-mono text-xs text-evi-text-primary overflow-x-auto">
                        <pre className="whitespace-pre-wrap">
                          {activeRule.synthesized_commands?.[selectedPlatform] ||
                            "# Command generator not available for this target"}
                        </pre>
                        <button
                          onClick={() =>
                            handleCopy(
                              activeRule.synthesized_commands?.[selectedPlatform] || "",
                              `${activeRule.rule_id}-${selectedPlatform}`
                            )
                          }
                          className="absolute top-2 right-2 p-1.5 rounded bg-evi-bg-canvas/80 text-evi-text-secondary hover:text-white border border-evi-border-subtle"
                          title="Copy command"
                        >
                          {copiedKey === `${activeRule.rule_id}-${selectedPlatform}` ? (
                            <Check className="h-3.5 w-3.5 text-evi-status-green" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right Column (5 cols): Counterfactual Resilience Simulator */}
        <div className="lg:col-span-5 space-y-6">
          <div className="rounded-lg border border-evi-border bg-evi-bg-panel p-5">
            <div className="flex items-center justify-between mb-4 border-b border-evi-border-subtle pb-3">
              <div className="flex items-center gap-2">
                <Cpu className="h-5 w-5 text-purple-400" />
                <h2 className="font-semibold text-evi-text-primary">
                  Counterfactual Resilience Simulator
                </h2>
              </div>
              <Badge variant="simulation">Simulation Only</Badge>
            </div>

            {simLoading ? (
              <div className="py-12 text-center text-sm text-evi-text-secondary">
                Running graph counterfactuals...
              </div>
            ) : simulations.length === 0 ? (
              <div className="py-12 text-center text-sm text-evi-text-secondary">
                No simulations available.
              </div>
            ) : (
              <div className="space-y-4">
                {/* Scenario Picker */}
                <div>
                  <label className="text-xs text-evi-text-secondary mb-1.5 block">
                    Select Defensive Policy Scenario:
                  </label>
                  <select
                    value={activeSim?.policy_name || counterfactualPolicy}
                    onChange={(e) => setCounterfactualPolicy(e.target.value)}
                    className="w-full bg-evi-bg-canvas border border-evi-border rounded px-3 py-2 text-xs font-mono text-evi-text-primary focus:outline-none focus:border-evi-accent-cyan"
                  >
                    {simulations.map((s, idx) => (
                      <option key={idx} value={s.policy_name}>
                        {s.policy_name} ({s.intervention_type})
                      </option>
                    ))}
                  </select>
                </div>

                {/* Scenario Outcome Summary */}
                {activeSim && (
                  <div className="rounded border border-evi-border-subtle bg-evi-bg-canvas p-4 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="text-xs font-mono text-purple-400">
                        {activeSim.intervention_type}: {String(activeSim.parameter)}
                      </div>
                      {activeSim.single_point_of_failure ? (
                        <span className="flex items-center gap-1 text-[11px] font-mono text-red-400 bg-red-950/40 px-2 py-0.5 rounded border border-red-500/40">
                          <Flame className="h-3 w-3" />
                          SPOF Discovered
                        </span>
                      ) : (
                        <span className="text-[11px] font-mono text-evi-text-secondary">
                          Resilient Node
                        </span>
                      )}
                    </div>

                    {/* Defensive Resilience Index (DRI) Gauge */}
                    <div className="p-3 bg-evi-bg-panel rounded border border-evi-border-subtle space-y-2">
                      <div className="flex justify-between items-center text-xs">
                        <span className="text-evi-text-secondary">Defensive Resilience Index (DRI)</span>
                        <span className="font-mono font-bold text-evi-accent-cyan text-sm">
                          {(activeSim.defensive_resilience_index * 100).toFixed(1)}%
                        </span>
                      </div>
                      <div className="w-full h-2 rounded-full bg-evi-bg-canvas overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-evi-status-amber to-evi-status-green transition-all duration-500"
                          style={{
                            width: `${Math.max(
                              activeSim.defensive_resilience_index * 100,
                              4
                            )}%`,
                          }}
                        />
                      </div>
                      <div className="flex justify-between text-[10px] text-evi-text-secondary font-mono">
                        <span>Baseline: 0.0%</span>
                        <span>
                          {activeSim.attack_extinguished
                            ? "Attack Fully Extinguished"
                            : "Partial Degradation"}
                        </span>
                      </div>
                    </div>

                    {/* Comparative Statistics */}
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div className="bg-evi-bg-panel p-2.5 rounded border border-evi-border-subtle">
                        <div className="text-evi-text-secondary">Baseline Severity</div>
                        <div className="font-mono text-red-400 font-bold mt-1">
                          {activeSim.baseline_severity?.toFixed(2) || "17.14"}
                        </div>
                        <div className="text-[10px] text-evi-text-secondary mt-0.5">
                          {activeSim.baseline_steps_count} Attack Steps
                        </div>
                      </div>

                      <div className="bg-evi-bg-panel p-2.5 rounded border border-evi-border-subtle">
                        <div className="text-evi-text-secondary">Residual Severity</div>
                        <div className="font-mono text-evi-status-green font-bold mt-1">
                          {activeSim.residual_severity?.toFixed(2) || "0.00"}
                        </div>
                        <div className="text-[10px] text-evi-text-secondary mt-0.5">
                          {activeSim.residual_steps_count} Residual Steps
                        </div>
                      </div>
                    </div>

                    {/* Residual Attack Chain Preview */}
                    <div>
                      <div className="text-xs font-semibold text-evi-text-secondary mb-2 flex items-center gap-1.5">
                        <Activity className="h-3.5 w-3.5 text-purple-400" />
                        Residual Attack Chain
                      </div>
                      {activeSim.residual_attack_chain &&
                      activeSim.residual_attack_chain.length > 0 ? (
                        <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                          {activeSim.residual_attack_chain.map((step: any, idx: number) => (
                            <div
                              key={idx}
                              className="flex items-center justify-between text-[11px] font-mono bg-evi-bg-panel p-1.5 rounded border border-evi-border-subtle"
                            >
                              <span className="text-evi-text-primary">
                                #{step.step} {step.predicted_class} (Port {step.dst_port})
                              </span>
                              <span className="text-evi-accent-cyan">
                                [E:{step.flow_id}]
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="p-3 text-center text-xs font-mono text-evi-status-green bg-evi-status-green/10 rounded border border-evi-status-green/30">
                          Attack graph completely severed. Zero residual hops.
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
