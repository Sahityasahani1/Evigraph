"""The investigation loop: the LLM asks for tools, our code runs them, the LLM reads the results."""
import json
import sys
import time

import ollama

from src.agent.attack_rag import AttackKnowledge
from src.agent.contract import load_incidents
from src.agent.flow_store import FlowStore
from src.agent.tools import ForensicTools

MODEL = "llama3.2:3b"

SYSTEM_PROMPT = """You are a network forensic analyst assistant for a security team.
Investigate the incident the user names, using ONLY the tools provided.

Rules:
1. Never invent IP addresses, ports, timestamps, flow IDs, counts or MITRE ATT&CK IDs. Use only values returned by tools.
2. Start with get_incident. Then call host_summary for the most important hosts (attackers, targets, and any host that appears as both).
3. For each attack stage, call search_attack_knowledge with a plain description of the behaviour you observed, and only cite technique IDs it returns.
4. Use get_flows if you need exact flow records as evidence.
5. When you have enough evidence, reply with a short investigation summary: what happened in time order, which hosts are involved, the ATT&CK technique for each stage, and for each claim the flow_id(s) that support it, written like [flw_000123].
6. If the data does not show something, say it is not shown. Do not guess."""

TOOL_NAMES = ["list_incidents", "get_incident", "host_summary", "get_flows", "search_attack_knowledge"]


class ForensicAgent:
    def __init__(self, tools: ForensicTools, model: str = MODEL, max_steps: int = 8, chat_fn=None):
        self.tools = tools
        self.model = model
        self.max_steps = max_steps
        self.chat = chat_fn or ollama.chat
        self.registry = {name: getattr(tools, name) for name in TOOL_NAMES}

    def _run_tool(self, name: str, args: dict) -> dict:
        fn = self.registry.get(name)
        if fn is None:
            return {"error": f"Unknown tool {name!r}. Available: {TOOL_NAMES}"}
        try:
            return fn(**args)
        except Exception as e:  # bad arguments from the model must not crash the loop
            return {"error": f"Tool call failed: {e}"}

    def investigate(self, incident_id: str) -> dict:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Investigate incident {incident_id}."},
        ]
        calls = []
        for step in range(1, self.max_steps + 1):
            resp = self.chat(
                model=self.model,
                messages=messages,
                tools=list(self.registry.values()),
                options={"temperature": 0},
            )
            msg = resp.message
            messages.append(msg)
            if not msg.tool_calls:
                return {"final": msg.content, "tool_calls": calls, "steps": step, "error": None}
            for call in msg.tool_calls:
                name, args = call.function.name, dict(call.function.arguments)
                result = self._run_tool(name, args)
                calls.append({"tool": name, "args": args})
                messages.append(
                    {"role": "tool", "tool_name": name, "content": json.dumps(result, default=str)}
                )
        return {"final": None, "tool_calls": calls, "steps": self.max_steps,
                "error": "max steps reached without a final answer"}


def build_agent() -> ForensicAgent:
    store = FlowStore("data/sample/sample_flows.csv")
    cases = load_incidents("data/sample/sample_incident_cases.json")
    return ForensicAgent(ForensicTools(store, cases, AttackKnowledge()))


if __name__ == "__main__":
    incident = sys.argv[1] if len(sys.argv) > 1 else "INC-001"
    t0 = time.time()
    result = build_agent().investigate(incident)
    for c in result["tool_calls"]:
        print("TOOL:", c)
    print(f"\n--- FINAL ({result['steps']} steps, {time.time() - t0:.0f}s) ---")
    print(result["final"] or result["error"])