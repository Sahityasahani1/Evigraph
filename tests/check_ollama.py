import ollama

MODEL = "llama3.2:3b"

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