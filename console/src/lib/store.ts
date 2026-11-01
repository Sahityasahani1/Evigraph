import { create } from "zustand";

export type ScreenType =
  | "command-center"
  | "investigation"
  | "timeline"
  | "evidence"
  | "resilience";

export type CopilotTab =
  | "investigation"
  | "evidence"
  | "cross-examination"
  | "report";

export interface GraphLayers {
  showBenign: boolean;
  showSuspicious: boolean;
  showAttackChain: boolean;
  showCausalDag: boolean;
  showMinCut: boolean;
  showBlastRadius: boolean;
  showSimulation: boolean;
}

export interface SelectedObject {
  type: "node" | "edge";
  id: string;
  data: any;
}

interface ConsoleState {
  activeScreen: ScreenType;
  setActiveScreen: (screen: ScreenType) => void;

  selectedIncidentId: string;
  setSelectedIncidentId: (id: string) => void;

  selectedObject: SelectedObject | null;
  setSelectedObject: (obj: SelectedObject | null) => void;

  selectedTimeWindow: [string, string] | null;
  setSelectedTimeWindow: (window: [string, string] | null) => void;

  graphLayers: GraphLayers;
  toggleLayer: (layer: keyof GraphLayers) => void;

  graphLayout: "force" | "hierarchical";
  setGraphLayout: (layout: "force" | "hierarchical") => void;

  focusedSubgraphNodeId: string | null;
  setFocusedSubgraphNodeId: (id: string | null) => void;

  copilotOpen: boolean;
  setCopilotOpen: (open: boolean) => void;

  copilotTab: CopilotTab;
  setCopilotTab: (tab: CopilotTab) => void;

  approvalWorkflow: Record<string, "Draft" | "Reviewed" | "Approved" | "Deployed">;
  setRuleApprovalState: (
    ruleId: string,
    state: "Draft" | "Reviewed" | "Approved" | "Deployed"
  ) => void;

  counterfactualPolicy: string;
  setCounterfactualPolicy: (policy: string) => void;
}

export const useConsoleStore = create<ConsoleState>((set) => ({
  activeScreen: "command-center",
  setActiveScreen: (screen) => set({ activeScreen: screen }),

  selectedIncidentId: "INC-0001",
  setSelectedIncidentId: (id) =>
    set({
      selectedIncidentId: id,
      selectedObject: null,
      focusedSubgraphNodeId: null,
    }),

  selectedObject: null,
  setSelectedObject: (obj) => set({ selectedObject: obj }),

  selectedTimeWindow: null,
  setSelectedTimeWindow: (window) => set({ selectedTimeWindow: window }),

  graphLayers: {
    showBenign: true,
    showSuspicious: true,
    showAttackChain: true,
    showCausalDag: true,
    showMinCut: false,
    showBlastRadius: false,
    showSimulation: false,
  },
  toggleLayer: (layer) =>
    set((state) => ({
      graphLayers: {
        ...state.graphLayers,
        [layer]: !state.graphLayers[layer],
      },
    })),

  graphLayout: "hierarchical",
  setGraphLayout: (layout) => set({ graphLayout: layout }),

  focusedSubgraphNodeId: null,
  setFocusedSubgraphNodeId: (id) => set({ focusedSubgraphNodeId: id }),

  copilotOpen: true,
  setCopilotOpen: (open) => set({ copilotOpen: open }),

  copilotTab: "investigation",
  setCopilotTab: (tab) => set({ copilotTab: tab }),

  approvalWorkflow: {
    "RULE-INC-0001-01": "Approved",
    "RULE-INC-0001-02": "Reviewed",
  },
  setRuleApprovalState: (ruleId, approvalState) =>
    set((state) => ({
      approvalWorkflow: {
        ...state.approvalWorkflow,
        [ruleId]: approvalState,
      },
    })),

  counterfactualPolicy: "Firewall Policy: Block Port 22",
  setCounterfactualPolicy: (policy) => set({ counterfactualPolicy: policy }),
}));
