"""
Ollama Connection and Tool-Calling Check
Origin: feature/llm-agent-rag branch (Member 3 / LLM Agent)

Verifies:
1. Connectivity to local Ollama runtime (default: llama3.2:3b)
2. Tool-calling / Function-calling capabilities for forensic agents
"""

import sys

MODEL = "llama3.2:3b"

def run_check():
    try:
        import ollama
    except ImportError:
        print("[!] The 'ollama' Python library is not installed in this environment.")
        print("    Install it via: pip install ollama")
        print("    Ensure Ollama is running locally: https://ollama.ai")
        return False

    print(f"[*] Testing connection to local Ollama daemon (model: {MODEL})...")
    try:
        # Test 1: plain chat
        r = ollama.chat(
            model=MODEL,
            messages=[{"role": "user", "content": "Reply with only the word: ready"}],
        )
        print("Chat test:", r.message.content)

        # Test 2: tool calling
        def get_flow_count(host_ip: str) -> int:
            """Return the number of network flows seen for a host.

            Args:
                host_ip: The IP address of the host, for example 10.0.0.14
            """
            return 42

        r = ollama.chat(
            model=MODEL,
            messages=[{"role": "user", "content": "How many flows were seen for host 10.0.0.14?"}],
            tools=[get_flow_count],
        )
        calls = r.message.tool_calls or []
        print("Tool calls requested:", calls)
        assert calls, "FAIL: model did not ask to use a tool"
        assert calls[0].function.name == "get_flow_count"
        print("PASS: model asked for get_flow_count with", calls[0].function.arguments)
        return True
    except Exception as e:
        print(f"[!] Ollama connection/inference error: {e}")
        print("    Tip: Check if Ollama service is active with: ollama serve")
        print("    Tip: Pull the model with: ollama pull llama3.2:3b")
        return False

if __name__ == "__main__":
    success = run_check()
    sys.exit(0 if success else 1)
