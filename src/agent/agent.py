"""The investigation loop: the LLM asks for tools, our code runs them, the LLM reads the results.

playbook=True  (default): our code first runs the mandatory lookups, then the model writes.
playbook=False (free)    : the model alone decides which tools to call.
"""
import json
import re
import sys
import time

import ollama

from src.agent.attack_rag import AttackKnowledge
from src.agent.contract import load_incidents
from src.agent.flow_store import FlowStore
from src.agent.tools import ForensicTools

MODEL = "llama3.2:3b"

SYSTEM_PROMPT = """You are a network forensic analyst assistant for a security team.
Investigate the incident the user names, using ONLY tool results.

Rules:
1. Never invent IP addresses, ports, timestamps, flow IDs, counts or MITRE ATT&CK IDs. Use only values that appear in tool results.
2. Tool results may already be included in the user message. Use them. If you need more, call a tool: get_flows for exact flow records, host_summary for a host.
3. Choose an ATT&CK technique for each stage ONLY from the search results for that stage. If none fits well, say so.
4. A host that is first a target and later a source of attacks may have been compromised. Say "possibly" unless the evidence shows it.
5. Write a short summary with: overview, timeline in order, hosts and their roles, ATT&CK technique per stage, and limits of the evidence.
6. Support every claim with the flow_id(s) it rests on, written like [flw_000123], using only flow IDs present in the tool results.
7. If the data does not show something, say it is not shown. Do not guess."""

TOOL_NAMES = ["list_incidents", "get_incident", "host_summary", "get_flows", "search_attack_knowledge"]


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


# How analysts describe the CICIDS2017 attack classes (the detector's class names).
CLASS_DESCRIPTIONS = {
    _norm(k): v
    for k, v in {
        "SSH-Patator": "repeated failed SSH login attempts guessing passwords (brute force)",
        "FTP-Patator": "repeated failed FTP login attempts guessing passwords (brute force)",
        "PortScan": "port scan probing many ports and hosts for open services",
        "DoS Hulk": "denial of service flood of HTTP requests overwhelming a web server",
        "DoS GoldenEye": "denial of service flood of HTTP requests overwhelming a web server",
        "DoS slowloris": "slow HTTP connections exhausting a web server (denial of service)",
        "DoS Slowhttptest": "slow HTTP connections exhausting a web server (denial of service)",
        "DDoS": "distributed denial of service flood of traffic from many sources",
        "Bot": "infected host beaconing to a command and control server (botnet)",
        "Infiltration": "large outbound data transfer to an external server (data exfiltration)",
        "Web Attack Brute Force": "repeated login attempts guessing passwords on a web application",
        "Web Attack XSS": "cross-site scripting attack against a web application",
        "Web Attack Sql Injection": "SQL injection attack against a public-facing web application",
        "Heartbleed": "exploiting a vulnerability in a public-facing service to leak memory",
    }.items()
}


def _stage_query(attack_class: str) -> str:
    return CLASS_DESCRIPTIONS.get(_norm(attack_class), f"{attack_class} network attack")


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

    def _gather(self, incident_id: str, calls: list):
        def run(name, **args):
            result = self._run_tool(name, args)
            calls.append({"tool": name, "args": args, "forced": True})
            return result

        inc = run("get_incident", incident_id=incident_id)
        if "error" in inc:
            return None, inc["error"]
        hosts: list[str] = []
        for h in inc["top_alert_sources"] + inc["top_alert_targets"]:
            if h["host_ip"] not in hosts:
                hosts.append(h["host_ip"])
        summaries = {h: run("host_summary", host_ip=h) for h in hosts[:4]}
        attack = {}
        for stage in inc["stages_in_time_order"]:
            cls = stage["attack_class"]
            attack[cls] = run("search_attack_knowledge", query=_stage_query(cls))
        return {"incident": inc, "host_summaries": summaries, "attack_matches": attack}, None

    def investigate(self, incident_id: str, playbook: bool = True) -> dict:
        calls: list[dict] = []
        user = f"Investigate incident {incident_id}."
        if playbook:
            briefing, err = self._gather(incident_id, calls)
            if err:
                return {"final": None, "tool_calls": calls, "steps": 0, "error": err}
            user += "\n\nThese tool results were already gathered for you:\n" + json.dumps(
                briefing, default=str
            )
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
        ]
        for step in range(1, self.max_steps + 1):
            resp = self.chat(
                model=self.model,
                messages=messages,
                tools=list(self.registry.values()),
                options={"temperature": 0, "num_ctx": 8192},
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
    use_playbook = not (len(sys.argv) > 2 and sys.argv[2] == "free")
    t0 = time.time()
    result = build_agent().investigate(incident, playbook=use_playbook)
    for c in result["tool_calls"]:
        print("TOOL:", c)
    mode = "playbook" if use_playbook else "free"
    print(f"\n--- FINAL ({mode} mode, {result['steps']} model steps, {time.time() - t0:.0f}s) ---")
    print(result["final"] or result["error"])