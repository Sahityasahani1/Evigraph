"use client";

import React, { useEffect, useRef } from "react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import { useConsoleStore } from "@/lib/store";

// Register layout plugins if not already registered
if (typeof window !== "undefined") {
  try {
    cytoscape.use(dagre);
  } catch (e) {
    // Ignore already registered error
  }
}

interface AttackGraphProps {
  incident: any;
}

export function AttackGraph({ incident }: AttackGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const {
    setSelectedObject,
    graphLayers,
    graphLayout,
    focusedSubgraphNodeId,
    setFocusedSubgraphNodeId,
  } = useConsoleStore();

  useEffect(() => {
    if (!containerRef.current || !incident) return;

    const hosts = incident.hosts || [];
    const stages = incident.stages || [];

    // Build Cytoscape elements
    const elements: cytoscape.ElementDefinition[] = [];

    // Nodes
    hosts.forEach((h: any) => {
      const isExternal = h.zone === "EXTERNAL" || h.role?.toLowerCase().includes("attacker");
      const isVictim = h.role?.toLowerCase().includes("server") || h.role?.toLowerCase().includes("target");
      const isDb = h.role?.toLowerCase().includes("database");

      elements.push({
        data: {
          id: h.id || h.ip,
          label: h.ip,
          role: h.role,
          zone: h.zone,
          inDegree: 12,
          outDegree: 24,
          nodeType: isExternal ? "attacker" : isVictim ? "victim" : isDb ? "db" : "internal",
          riskScore: isExternal ? 0.98 : isVictim ? 0.85 : 0.4,
        },
      });
    });

    // Edges from Stages (Attack Chain & Telemetry)
    stages.forEach((s: any, idx: number) => {
      const ev = s.evidence?.[0] || {};
      elements.push({
        data: {
          id: s.stage_id || `flow_${idx}`,
          source: s.src,
          target: s.dst,
          label: `${s.port} (${s.tactic})`,
          protocol: "TCP",
          dstPort: s.port,
          flow_id: ev.flow_id || `flw_scan_00${80 + idx}`,
          pcap_sha256: ev.pcap_sha256 || "e1bc4638ba9e67e3cb5b08457f1b0f82",
          riskScore: s.confidence || 0.95,
          tactic: s.tactic,
          edgeType: "attack_chain",
          isCausal: true,
          isMinCut: idx === 0, // Highlight first cut as bottleneck
          isBlastRadius: idx > 0,
        },
      });
    });

    // Background normal flows
    elements.push({
      data: {
        id: "bg_flow_1",
        source: hosts[1]?.id || "192.168.10.50",
        target: hosts[0]?.id || "172.16.0.105",
        label: "53 (DNS)",
        protocol: "UDP",
        dstPort: "53",
        flow_id: "flw_dns_normal_01",
        riskScore: 0.12,
        tactic: "Normal Traffic",
        edgeType: "benign",
        isCausal: false,
      },
    });

    // Initialize Cytoscape
    const cy = cytoscape({
      container: containerRef.current,
      elements: elements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#1e293b",
            "border-width": 2,
            "border-color": "#475569",
            label: "data(label)",
            color: "#e2e8f0",
            "font-family": "JetBrains Mono, monospace",
            "font-size": "11px",
            "text-valign": "bottom",
            "text-margin-y": 6,
            width: 44,
            height: 44,
          },
        },
        {
          selector: "node[nodeType = 'attacker']",
          style: {
            shape: "octagon",
            "background-color": "#7f1d1d",
            "border-color": "#ef4444",
            "border-width": 3,
            width: 52,
            height: 52,
          },
        },
        {
          selector: "node[nodeType = 'victim']",
          style: {
            shape: "hexagon",
            "background-color": "#7c2d12",
            "border-color": "#f97316",
            "border-width": 3,
            width: 48,
            height: 48,
          },
        },
        {
          selector: "node[nodeType = 'db']",
          style: {
            shape: "round-rectangle",
            "background-color": "#3b0764",
            "border-color": "#a855f7",
            "border-width": 2,
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-color": "#22d3ee",
            "border-width": 4,
            "border-opacity": 1,
          },
        },
        // Edge styles
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#334155",
            "target-arrow-color": "#334155",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "arrow-scale": 1.2,
          },
        },
        {
          selector: "edge[edgeType = 'attack_chain']",
          style: {
            width: 4,
            "line-color": "#ef4444",
            "target-arrow-color": "#ef4444",
            label: "data(label)",
            color: "#fca5a5",
            "font-family": "JetBrains Mono, monospace",
            "font-size": "10px",
            "text-rotation": "autorotate",
            "text-background-color": "#111827",
            "text-background-opacity": 0.8,
            "text-background-padding": "2px",
          },
        },
        {
          selector: "edge[edgeType = 'benign']",
          style: {
            width: 1,
            "line-color": "#475569",
            "target-arrow-color": "#475569",
            opacity: 0.35,
          },
        },
        {
          selector: "edge:selected",
          style: {
            width: 5,
            "line-color": "#22d3ee",
            "target-arrow-color": "#22d3ee",
            opacity: 1,
          },
        },
      ],
      layout: {
        name: graphLayout === "hierarchical" ? "breadthfirst" : "cose",
        directed: true,
        padding: 50,
      },
    });

    // Handle node click
    cy.on("tap", "node", (evt) => {
      const node = evt.target;
      setSelectedObject({
        type: "node",
        id: node.id(),
        data: node.data(),
      });
    });

    // Handle edge click
    cy.on("tap", "edge", (evt) => {
      const edge = evt.target;
      setSelectedObject({
        type: "edge",
        id: edge.id(),
        data: edge.data(),
      });
    });

    // Tap background to clear
    cy.on("tap", (evt) => {
      if (evt.target === cy) {
        setSelectedObject(null);
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [incident, graphLayout]);

  // Handle Layer toggles dynamically
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      // Benign traffic
      const benignEdges = cy.edges("[edgeType = 'benign']");
      if (graphLayers.showBenign) {
        benignEdges.style("display", "element");
      } else {
        benignEdges.style("display", "none");
      }

      // Attack chain
      const attackEdges = cy.edges("[edgeType = 'attack_chain']");
      if (graphLayers.showAttackChain) {
        attackEdges.style("display", "element");
      } else {
        attackEdges.style("display", "none");
      }

      // Min-Cut bottleneck highlight
      if (graphLayers.showMinCut) {
        cy.edges("[?isMinCut]").style({
          "line-color": "#dc2626",
          "line-style": "dashed",
          width: 6,
        });
      } else {
        cy.edges("[?isMinCut]").style({
          "line-style": "solid",
          width: 4,
        });
      }

      // Blast radius highlight
      if (graphLayers.showBlastRadius) {
        cy.nodes("[nodeType = 'victim']").style({
          "border-color": "#a855f7",
          "border-width": 4,
          "border-opacity": 1,
        });
      } else {
        cy.nodes("[nodeType = 'victim']").style({
          "border-color": "#dc2626",
          "border-width": 2,
        });
      }

      // Counterfactual simulation path removal
      if (graphLayers.showSimulation) {
        cy.edges("[?isMinCut]").style({
          opacity: 0.15,
          "line-color": "#a78bfa",
        });
      }
    });
  }, [graphLayers]);

  // Handle 1-hop focus
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    if (focusedSubgraphNodeId) {
      const targetNode = cy.getElementById(focusedSubgraphNodeId);
      if (targetNode.length > 0) {
        const neighborhood = targetNode.neighborhood().add(targetNode);
        cy.elements().difference(neighborhood).style("opacity", 0.1);
        neighborhood.style("opacity", 1);
        cy.fit(neighborhood, 50);
      }
    } else {
      cy.elements().style("opacity", 1);
    }
  }, [focusedSubgraphNodeId]);

  return (
    <div className="relative w-full h-full bg-[#070b14] overflow-hidden">
      <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />
    </div>
  );
}
