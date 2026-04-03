# AgentCop Scanner — Roadmap

AI agents are being deployed into production with almost no security tooling built for them.
AgentCop is changing that: a security scanner purpose-built for agentic AI code — not generic
SAST dressed up with LLM buzzwords.

---

## What's Built (v0.1 — April 2026)

The foundation is real. No smoke, no fake demos.

### Static Analysis Engine
- **AST taint tracking** — follows data from external sources (HTTP requests, env vars, user input,
  agent memory reads) through f-strings, binary ops, and function calls, down to dangerous sinks
- **OWASP LLM Top 10 coverage** — LLM01 (prompt injection), LLM02 (insecure output handling),
  LLM08 (excessive agency / unreviewed external actions), and more
- **CWE mapping** — every finding is tagged with a CWE ID (CWE-20, CWE-78, CWE-94, CWE-284, ...)
- **Framework detection** — identifies LangChain, LangGraph, CrewAI, AutoGen, LlamaIndex, and
  generic agent patterns; adjusts rules accordingly
- **Call graph analysis** — detects recursive agent calls without depth limits and unbounded loops
- **Pattern rules** — 20+ AST-level rules for hardcoded secrets, disabled SSL verification,
  pickle deserialization, open redirect, SSRF vectors, world-readable file permissions, and more

### Multi-Input Scan Surface
- Paste raw Python code in the browser
- Upload a `.zip` of an entire agent project (up to 50 MB)
- Scan a public GitHub repo by URL (clones, walks all `.py` files)
- REST API (`POST /api/scan`, `POST /api/scan/zip`) for CI pipeline integration

### Results & UX
- Security score (0–100) derived from finding severity weights
- Import graph visualization per scanned project
- AI-generated verdict (Claude Sonnet 4.6 "Sentinel" persona) — cop voice, specific, no filler
- AI-generated targeted code fixes with before/after diffs for critical and warning findings
- SQLite result caching with content hashing — identical code returns instantly
- Shareable scan URLs (`/scan/{id}`) — send a link, no account needed

---

## What's Coming

### Near-term (v0.2)

**Multi-file deep analysis**
The current taint engine is per-file. The next step: cross-file taint propagation. If `agent.py`
passes a tainted value into a function defined in `tools.py`, the engine needs to follow it.
This requires building an interprocedural call graph across the import graph we already construct.

**Semgrep custom rule pack**
A published Semgrep ruleset (`agentcop`) that ships alongside the web scanner — installable via
`semgrep --config agentcop`. Rules target AI-specific patterns that generic Semgrep packs miss:
delegation without guardrails, tool calls with unvalidated LLM output, agent memory poisoning
vectors, and autonomous action gates. Open source, community-extensible.

**Better GitHub support**
- Private repo scanning via GitHub token
- Scan on push via webhook (not just on-demand)
- Per-file findings linked back to exact GitHub line numbers

---

### Medium-term (v0.3)

**GitHub App**
Install AgentCop on a repo and get automatic PR comments:

```
AgentCop found 2 new issues in this PR:
  [CRITICAL] Prompt Injection via agent.run — tools/search.py:47
  [WARNING]  Unreviewed External POST — actions/email.py:23
```

No CI config needed — install the app, done. Results posted directly on the diff. Block merges
on critical findings if you want to. This is the path to making AI agent security a default,
not an afterthought.

**VS Code Extension**
Inline security feedback as you write agent code. Highlights tainted data flows, flags sink calls
with hover explanations, and suggests fixes without leaving the editor. Powered by the same AST
engine — no round-trip to the cloud required for basic checks.

---

### Longer-term (v1.0)

**Runtime monitoring via `agentcop` Python package**
Static analysis catches structure; runtime monitoring catches behavior.

```python
from agentcop import monitor

@monitor()
def my_agent(user_input: str):
    ...
```

The decorator instruments tool calls, LLM invocations, and external actions at runtime:
- Detects prompt injection attempts in live inputs
- Logs and optionally blocks autonomous actions that exceed a declared scope
- Emits structured security events to your existing observability stack (OpenTelemetry, Datadog, etc.)
- Enforces human-in-the-loop gates before irreversible actions (email sends, API writes, file deletes)

This is the bridge between "found a vulnerability in code review" and "prevented an attack in production."

**Policy-as-code**
Define what your agent is allowed to do, and AgentCop enforces it:

```yaml
# agentcop.yml
agent: email-assistant
allow:
  - read_email
  - draft_reply
deny:
  - send_email          # require human approval
  - access: filesystem  # not in scope
  - external_requests:
      except: [api.company.com]
```

Violations fail the scan. Runtime violations trigger alerts or hard stops.

---

## The Vision

Every AI agent deployed in production should have a security posture as clear as its test coverage.
AgentCop aims to be the `pytest` of AI agent security — a tool developers run without being told to,
because it catches real bugs before they become incidents.

The OWASP LLM Top 10 exists. The vulnerabilities are well-understood. What's been missing is
tooling that actually speaks the language of agent frameworks — LangChain tools, CrewAI crews,
LangGraph state machines, AutoGen conversations. That's the gap AgentCop fills.

Static analysis → CI integration → GitHub App → runtime monitoring.
Each layer catches what the previous one can't.

---

## Contributing

The Semgrep rule pack and VS Code extension will be developed in the open. If you're building
agent security tooling, working on a framework integration, or have found a vulnerability class
that AgentCop misses — open an issue or reach out.
