"""
AgentCop Security Scanner — Production-grade static analysis for AI agent security.

Architecture:
  1. FileIngestion    — parse .py files recursively, build import graph, detect framework
  2. TaintAnalyzer   — AST-based data flow analysis (marks sources, tracks to sinks)
  3. CallGraphAnalyzer — detect recursive calls without depth limits, unbounded loops
  4. RuleEngine       — OWASP LLM Top 10 + framework-specific AST pattern rules
  5. Scanner          — orchestrator: scan_code / scan_directory / scan_zip / scan_github
"""

import ast
import re
import hashlib
import zipfile
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

# ─── Scoring ─────────────────────────────────────────────────────────────────

SEVERITY_DELTA = {
    "critical": -25,
    "warning": -10,
    "info": -3,
    "protected": +5,
}

# ─── Taint Sources ───────────────────────────────────────────────────────────
# Any call/attr whose result is considered user-/externally-controlled.

TAINT_SOURCE_ATTRS = {
    # HTTP request inputs
    "json", "form", "args", "data", "get_json",
    # OS env
    "environ", "getenv",
    # User prompt
    "input",
    # Agent memory reads
    "get", "load", "read", "search", "recall",
}

TAINT_SOURCE_CALLS = {
    "input", "os.getenv", "os.environ.get",
    "request.json", "request.form", "request.args", "request.get_json",
    "requests.get", "requests.post", "httpx.get", "httpx.post",
    "response.json", "response.text",
    "open",
}

# ─── Taint Sinks ─────────────────────────────────────────────────────────────
# (sink_pattern, owasp, cwe, severity, title, explanation)

TAINT_SINKS: List[Tuple] = [
    # ── LLM01 prompt injection sinks ──
    ("llm.invoke",     "LLM01","CWE-20","critical","Prompt Injection via llm.invoke",      "Tainted data flows into LLM without sanitization."),
    ("llm.run",        "LLM01","CWE-20","critical","Prompt Injection via llm.run",         "Tainted data flows into LLM without sanitization."),
    ("llm.predict",    "LLM01","CWE-20","critical","Prompt Injection via llm.predict",     "Tainted data flows into LLM without sanitization."),
    ("llm.call",       "LLM01","CWE-20","critical","Prompt Injection via llm.call",        "Tainted data flows into LLM without sanitization."),
    ("llm.generate",   "LLM01","CWE-20","critical","Prompt Injection via llm.generate",    "Tainted data flows into LLM without sanitization."),
    ("chain.run",      "LLM01","CWE-20","critical","Prompt Injection via chain.run",       "Tainted data flows into chain execution without sanitization."),
    ("chain.invoke",   "LLM01","CWE-20","critical","Prompt Injection via chain.invoke",    "Tainted data flows into chain invocation without sanitization."),
    ("agent.run",      "LLM01","CWE-20","critical","Prompt Injection via agent.run",       "Tainted data flows into agent execution without sanitization."),
    ("agent.execute",  "LLM01","CWE-20","critical","Prompt Injection via agent.execute",   "Tainted data flows into agent execution without sanitization."),
    # ── LLM02 code/command execution sinks ──
    ("eval",           "LLM02","CWE-94","critical", "LLM Output Executed via eval()",       "eval() executes arbitrary Python. Never pass LLM output to eval()."),
    ("exec",           "LLM02","CWE-94","critical", "LLM Output Executed via exec()",       "exec() executes arbitrary Python. Never pass LLM output to exec()."),
    ("compile",        "LLM02","CWE-94","warning",  "Code Compiled from External Data",     "compile() with external input enables code injection."),
    ("subprocess.run", "LLM02","CWE-78","critical", "Command Injection via subprocess.run","Tainted data in subprocess.run enables OS command injection."),
    ("subprocess.call","LLM02","CWE-78","critical", "Command Injection via subprocess.call","Tainted data in subprocess.call enables OS command injection."),
    ("subprocess.Popen","LLM02","CWE-78","critical","Command Injection via Popen",          "Tainted data in Popen enables OS command injection."),
    ("os.system",      "LLM02","CWE-78","critical", "OS Command Injection via os.system",   "os.system with tainted data enables full shell injection."),
    ("os.popen",       "LLM02","CWE-78","critical", "OS Command Injection via os.popen",    "os.popen with tainted data enables shell injection."),
    # ── LLM08 network/email sinks ──
    ("requests.post",  "LLM08","CWE-284","warning", "Unreviewed External POST Request",     "Tainted data triggers external action without human review gate."),
    ("httpx.post",     "LLM08","CWE-284","warning",  "Unreviewed External POST Request",    "Tainted data triggers external action without human review gate."),
    ("send_email",     "LLM08","CWE-284","warning",  "Email Sent with Unvalidated Content", "Tainted data used in email without recipient validation."),
    ("smtp.sendmail",  "LLM08","CWE-284","warning",  "SMTP Send with Unvalidated Content",  "Tainted data in SMTP sendmail."),
]

# ─── Framework Detection ─────────────────────────────────────────────────────

FRAMEWORK_MARKERS: Dict[str, Set[str]] = {
    "langgraph":  {"langgraph", "StateGraph", "END", "START", "add_node", "add_edge", "interrupt_before"},
    "crewai":     {"crewai", "Crew", "CrewAI", "allow_delegation"},
    "autogen":    {"autogen", "pyautogen", "ConversableAgent", "UserProxyAgent", "AssistantAgent", "is_termination_msg"},
    "llamaindex": {"llama_index", "llama-index", "VectorStoreIndex", "SimpleDirectoryReader", "QueryEngine"},
    "langchain":  {"langchain", "LangChain", "ChatOpenAI", "LLMChain", "AgentExecutor", "Tool"},
}


def detect_framework(files: Dict[str, str]) -> str:
    combined = "\n".join(files.values())
    best, best_score = "generic", 0
    for fw, markers in FRAMEWORK_MARKERS.items():
        score = sum(1 for m in markers if m in combined)
        if score > best_score:
            best, best_score = fw, score
    return best


def build_import_graph(files: Dict[str, str]) -> Dict[str, List[str]]:
    graph: Dict[str, List[str]] = {}
    for filename, source in files.items():
        try:
            tree = ast.parse(source)
        except SyntaxError:
            graph[filename] = []
            continue
        imports: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        graph[filename] = sorted(imports)
    return graph


# ─── AST helpers ─────────────────────────────────────────────────────────────

def node_name(node) -> str:
    """Resolve dotted name from ast.Name or ast.Attribute chain."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = node_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def get_line(lines: List[str], n: int) -> str:
    return lines[n - 1].strip() if 0 < n <= len(lines) else ""


# ─── Taint Analyzer ──────────────────────────────────────────────────────────

class TaintAnalyzer(ast.NodeVisitor):
    """
    Single-file taint analysis via AST traversal.
    Marks variables as tainted when they receive values from user-controlled sources,
    then reports when tainted values reach dangerous sinks.
    """

    def __init__(self, source: str, filename: str):
        self.lines = source.splitlines()
        self.filename = filename
        self.tainted: Set[str] = set()
        self.findings: List[dict] = []
        self._scope_stack: List[Set[str]] = []  # saved outer scopes

    def _ln(self, n: int) -> str:
        return get_line(self.lines, n)

    def _is_source_call(self, node) -> bool:
        if not isinstance(node, ast.Call):
            return False
        fn = node_name(node.func)
        return fn in TAINT_SOURCE_CALLS or any(fn.endswith(f".{s}") for s in TAINT_SOURCE_ATTRS)

    def _is_tainted_expr(self, node) -> bool:
        """Recursively check if node carries tainted data."""
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Attribute):
            nm = node_name(node)
            base = node_name(node.value)
            return nm in self.tainted or base in self.tainted
        if isinstance(node, ast.JoinedStr):          # f-string
            return any(self._is_tainted_expr(v) for v in ast.walk(node) if isinstance(v, ast.FormattedValue))
        if isinstance(node, ast.BinOp):
            return self._is_tainted_expr(node.left) or self._is_tainted_expr(node.right)
        if isinstance(node, ast.Call):
            if self._is_source_call(node):
                return True
            return any(self._is_tainted_expr(a) for a in node.args)
        if isinstance(node, ast.IfExp):
            return self._is_tainted_expr(node.body) or self._is_tainted_expr(node.orelse)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_tainted_expr(e) for e in node.elts)
        if isinstance(node, ast.Dict):
            return any(self._is_tainted_expr(v) for v in node.values if v)
        if isinstance(node, ast.Subscript):
            return self._is_tainted_expr(node.value)
        return False

    def _mark_target(self, target, tainted: bool):
        nm = node_name(target)
        if nm and tainted:
            self.tainted.add(nm)

    def visit_Assign(self, node):
        t = self._is_source_call(node.value) or self._is_tainted_expr(node.value)
        for target in node.targets:
            self._mark_target(target, t)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        if self._is_tainted_expr(node.value):
            self._mark_target(node.target, True)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value:
            t = self._is_source_call(node.value) or self._is_tainted_expr(node.value)
            self._mark_target(node.target, t)
        self.generic_visit(node)

    def visit_Call(self, node):
        fn = node_name(node.func)
        fn_tail = fn.split(".")[-1]
        fn_prefix = ".".join(fn.split(".")[:-1])  # e.g. "subprocess" from "subprocess.run"
        all_args = list(node.args) + [kw.value for kw in node.keywords]

        matched = None
        for sink in TAINT_SINKS:
            sink_pat = sink[0]
            sink_parts = sink_pat.split(".")
            # Exact match
            if fn == sink_pat:
                matched = sink; break
            # Single-word sink (eval, exec, open, etc.) — match by tail only
            if len(sink_parts) == 1 and fn_tail == sink_pat:
                matched = sink; break
            # Multi-word sink: match if last two parts align
            # e.g. sink="subprocess.run", fn="subprocess.run" or "a.subprocess.run"
            if len(sink_parts) >= 2:
                sink_tail2 = ".".join(sink_parts[-2:])
                fn_tail2 = ".".join(fn.split(".")[-2:]) if "." in fn else fn
                if fn_tail2 == sink_tail2:
                    matched = sink; break
            # LLM method tail match (invoke/run/predict/call on any object)
            # Only for sinks that start with "llm." / "chain." / "agent."
            if sink_parts[0] in ("llm","chain","agent") and fn_tail == sink_parts[-1]:
                # Make sure it's NOT a known non-LLM prefix
                KNOWN_NON_LLM = {"subprocess","requests","httpx","os","smtp","re","json","sys","io"}
                if fn_prefix.split(".")[-1] not in KNOWN_NON_LLM:
                    matched = sink; break

        if matched:
            for arg in all_args:
                if self._is_tainted_expr(arg):
                    _, owasp, cwe, sev, title, expl = matched
                    self.findings.append({
                        "owasp": owasp, "cwe": cwe, "severity": sev,
                        "title": title, "file": self.filename,
                        "line": node.lineno, "code_snippet": self._ln(node.lineno),
                        "explanation": expl,
                    })
                    break

        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        # Save and create new scope; merge on exit (conservative: taint persists)
        self._scope_stack.append(set(self.tainted))
        self.tainted = set()
        self.generic_visit(node)
        outer = self._scope_stack.pop()
        self.tainted = outer | self.tainted

    visit_AsyncFunctionDef = visit_FunctionDef


# ─── Rule Engine ─────────────────────────────────────────────────────────────

class RuleEngine:
    """
    OWASP LLM Top 10 + framework-specific rules via AST pattern matching.
    Each _rule_* method receives (tree, lines, filename) and returns List[dict].
    """

    def __init__(self, framework: str = "generic"):
        self.framework = framework

    def run(self, source: str, filename: str) -> List[dict]:
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            return [{
                "owasp": "N/A", "cwe": "N/A", "severity": "info",
                "title": "Syntax Error — File Not Fully Analyzed",
                "file": filename, "line": getattr(e, "lineno", 1) or 1,
                "code_snippet": str(e), "explanation": f"File has a syntax error: {e}",
            }]

        lines = source.splitlines()
        findings: List[dict] = []
        for method in sorted(dir(self)):
            if method.startswith("_rule_"):
                findings.extend(getattr(self, method)(tree, lines, filename))
        return findings

    @staticmethod
    def _f(owasp, cwe, severity, title, file, line, lines, explanation) -> dict:
        return {
            "owasp": owasp, "cwe": cwe, "severity": severity,
            "title": title, "file": file, "line": line,
            "code_snippet": get_line(lines, line),
            "explanation": explanation,
        }

    # ── LLM01: Prompt Injection ──────────────────────────────────────────────

    def _rule_llm01_fstring_prompt(self, tree, lines, filename):
        """f-string with variable interpolation assigned to a prompt variable."""
        findings = []
        PROMPT_NAMES = {"system_prompt", "prompt", "user_prompt", "human_prompt", "messages"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for tgt in node.targets:
                nm = node_name(tgt)
                if nm in PROMPT_NAMES and isinstance(node.value, ast.JoinedStr):
                    if any(isinstance(v, ast.FormattedValue) for v in node.value.values):
                        findings.append(self._f(
                            "LLM01","CWE-20","critical",
                            f"Unsanitized Variable Interpolation in `{nm}`",
                            filename, node.lineno, lines,
                            f"`{nm}` is an f-string containing variable references. "
                            "If any variable is user-controlled this enables prompt injection. "
                            "Sanitize all dynamic values before prompt construction."
                        ))
        return findings

    def _rule_llm01_format_prompt(self, tree, lines, filename):
        """.format() used to build prompt strings."""
        findings = []
        PROMPT_NAMES = {"system_prompt", "prompt", "user_prompt", "human_prompt"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for tgt in node.targets:
                nm = node_name(tgt)
                if nm in PROMPT_NAMES:
                    v = node.value
                    if isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and v.func.attr == "format":
                        findings.append(self._f(
                            "LLM01","CWE-20","warning",
                            f"Prompt Built with .format() — Injection Risk in `{nm}`",
                            filename, node.lineno, lines,
                            f"`{nm}` uses .format() for construction. "
                            "Validate and allowlist all arguments before formatting into prompts."
                        ))
        return findings

    def _rule_llm01_concat_prompt(self, tree, lines, filename):
        """String concatenation used to build prompt."""
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for tgt in node.targets:
                nm = node_name(tgt)
                if "prompt" in nm.lower() and isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                    findings.append(self._f(
                        "LLM01","CWE-20","warning",
                        "Prompt Constructed via String Concatenation",
                        filename, node.lineno, lines,
                        f"`{nm}` is built via `+` concatenation. "
                        "Ensure both operands are sanitized; prefer structured message APIs."
                    ))
        return findings

    # ── LLM02: Insecure Output ───────────────────────────────────────────────

    def _rule_llm02_eval_exec(self, tree, lines, filename):
        """eval()/exec() calls — especially when near LLM variable names."""
        findings = []
        # Collect variables that come from LLM calls
        llm_vars: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                attr = ""
                if isinstance(node.value.func, ast.Attribute):
                    attr = node.value.func.attr
                if attr in ("invoke","run","predict","generate","chat","complete","call","stream"):
                    for t in node.targets:
                        nm = node_name(t)
                        if nm:
                            llm_vars.add(nm)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node_name(node.func)
            if fn not in ("eval","exec","compile"):
                continue
            # Always flag eval/exec as at least warning
            sev = "critical"
            expl = (f"`{fn}()` executes dynamic code. "
                    "LLM output passed to eval/exec enables arbitrary code execution. "
                    "Never execute LLM-generated content directly.")
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in llm_vars:
                    expl = f"Variable `{arg.id}` (from LLM call) passed to `{fn}()`. " + expl
                    break
            findings.append(self._f(
                "LLM02","CWE-94",sev,
                f"Dynamic Code Execution via {fn}()",
                filename, node.lineno, lines, expl
            ))
        return findings

    def _rule_llm02_html_render(self, tree, lines, filename):
        """LLM output rendered as raw HTML without escaping."""
        findings = []
        UNSAFE = {"render_template_string", "Markup", "innerHTML", "unescape"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node_name(node.func)
            fn_part = fn.split(".")[-1]
            if fn_part in UNSAFE:
                findings.append(self._f(
                    "LLM02","CWE-79","critical",
                    f"LLM Output Rendered as Raw HTML via {fn_part}() — XSS Risk",
                    filename, node.lineno, lines,
                    f"`{fn}` renders content as raw HTML without escaping. "
                    "Always escape LLM output before HTML rendering to prevent XSS."
                ))
        return findings

    # ── LLM03: Training Data Poisoning ──────────────────────────────────────

    def _rule_llm03_unvalidated_memory(self, tree, lines, filename):
        """Unvalidated data written to vector stores / agent memory."""
        findings = []
        WRITE_METHODS = {"add","save","insert","upsert","add_texts","add_documents","store","push"}
        MEM_OBJECTS = {"memory","vector_store","vectorstore","db","store","retriever","index","collection"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            method = node.func.attr
            obj_nm = node_name(node.func.value).lower()
            if method in WRITE_METHODS and any(m in obj_nm for m in MEM_OBJECTS):
                findings.append(self._f(
                    "LLM03","CWE-20","warning",
                    f"Unvalidated Data Written to Agent Memory: {obj_nm}.{method}()",
                    filename, node.lineno, lines,
                    f"`{obj_nm}.{method}()` writes to memory/vector store without evident validation. "
                    "Poisoned memory corrupts all future agent responses. "
                    "Validate and sanitize data before persisting."
                ))
        return findings

    # ── LLM04: Model DoS ────────────────────────────────────────────────────

    def _rule_llm04_while_true(self, tree, lines, filename):
        """while True without break/return."""
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.While):
                continue
            if isinstance(node.test, ast.Constant) and node.test.value is True:
                has_exit = any(isinstance(n, (ast.Break, ast.Return)) for n in ast.walk(node))
                if not has_exit:
                    findings.append(self._f(
                        "LLM04","CWE-400","critical",
                        "Infinite Loop Without Termination Condition",
                        filename, node.lineno, lines,
                        "`while True` loop with no break or return. "
                        "Agent execution loops must have explicit termination conditions "
                        "to prevent infinite loops and resource exhaustion."
                    ))
        return findings

    def _rule_llm04_recursive_no_limit(self, tree, lines, filename):
        """Self-calling function without depth/limit parameter."""
        findings = []
        for func_node in ast.walk(tree):
            if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = {a.arg for a in func_node.args.args}
            has_limit = any(kw in p for p in params for kw in ("depth","limit","max","count","iter"))
            for call in ast.walk(func_node):
                if not isinstance(call, ast.Call):
                    continue
                called = node_name(call.func)
                if called == func_node.name and not has_limit:
                    findings.append(self._f(
                        "LLM04","CWE-674","critical",
                        f"Recursive Agent Call Without Depth Limit: {func_node.name}()",
                        filename, call.lineno, lines,
                        f"`{func_node.name}` calls itself without a depth/limit guard. "
                        "Add a `max_depth` parameter and check it before recursing."
                    ))
                    break
        return findings

    def _rule_llm04_no_timeout(self, tree, lines, filename):
        """LLM constructors without timeout."""
        findings = []
        LLM_CTORS = {
            "ChatOpenAI","OpenAI","AzureChatOpenAI","ChatAnthropic","Anthropic",
            "Ollama","ChatOllama","HuggingFacePipeline","Bedrock","LLM","ChatLLM",
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node_name(node.func).split(".")[-1]
            if fn in LLM_CTORS:
                kwarg_names = {kw.arg for kw in node.keywords}
                if "timeout" not in kwarg_names and "request_timeout" not in kwarg_names:
                    findings.append(self._f(
                        "LLM04","CWE-400","warning",
                        f"LLM `{fn}` Instantiated Without Timeout",
                        filename, node.lineno, lines,
                        f"`{fn}()` has no `timeout` parameter. "
                        "Requests can hang indefinitely, exhausting resources. "
                        "Set `timeout=30` or similar."
                    ))
        return findings

    # ── LLM05: Supply Chain ──────────────────────────────────────────────────

    def _rule_llm05_remote_tool_load(self, tree, lines, filename):
        """Code/tools fetched from remote URLs without integrity check."""
        findings = []
        FETCH_FUNS = {"requests.get","urllib.request.urlopen","httpx.get","urlopen"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node_name(node.func)
            if fn not in FETCH_FUNS:
                continue
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.startswith(("http://","https://")):
                        findings.append(self._f(
                            "LLM05","CWE-494","warning",
                            "Remote Content Fetched Without Integrity Check",
                            filename, node.lineno, lines,
                            f"Fetching from `{arg.value[:60]}` without hash/signature verification. "
                            "Remote tool loading without integrity checks enables supply chain attacks."
                        ))
        return findings

    # ── LLM06: Sensitive Info Disclosure ────────────────────────────────────

    def _rule_llm06_hardcoded_secrets(self, tree, lines, filename):
        """Hardcoded API keys, tokens, passwords in string literals."""
        findings = []
        SENSITIVE_VAR_PARTS = {"api_key","secret","password","token","private_key",
                                "auth_token","bearer","passwd","credentials","access_key"}
        KEY_PATTERNS = [
            (re.compile(r'^sk-[a-zA-Z0-9]{32,}$'),       "OpenAI API Key"),
            (re.compile(r'^sk-ant-[a-zA-Z0-9_\-]{40,}$'),"Anthropic API Key"),
            (re.compile(r'^ghp_[a-zA-Z0-9]{36,}$'),       "GitHub Personal Access Token"),
            (re.compile(r'^AKIA[0-9A-Z]{16}$'),            "AWS Access Key ID"),
        ]

        for node in ast.walk(tree):
            # Variable assignment with sensitive name
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    nm = node_name(tgt).lower()
                    if any(s in nm for s in SENSITIVE_VAR_PARTS):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            val = node.value.value
                            if len(val) > 8 and val.lower() not in ("","your_key_here","replace_me","...","<your_key>"):
                                findings.append(self._f(
                                    "LLM06","CWE-312","critical",
                                    f"Hardcoded Secret: `{node_name(node.targets[0])}`",
                                    filename, node.lineno, lines,
                                    f"Sensitive variable `{node_name(node.targets[0])}` contains a hardcoded string. "
                                    "Use environment variables or a secrets manager. Never commit secrets."
                                ))

            # Known secret patterns in any string constant
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for pattern, name in KEY_PATTERNS:
                    if pattern.match(str(node.value)):
                        ln = getattr(node, "lineno", 1) or 1
                        findings.append(self._f(
                            "LLM06","CWE-312","critical",
                            f"{name} Found in Source Code",
                            filename, ln, lines,
                            f"A {name} pattern was detected as a string literal. "
                            "Rotate this key immediately and store secrets in env vars."
                        ))
        return findings

    def _rule_llm06_pii_in_log(self, tree, lines, filename):
        """PII-named variables passed to logging functions."""
        findings = []
        LOG_FUNS = {"print","info","debug","warning","error","exception","critical","log"}
        PII_NAMES = {"email","phone","ssn","dob","address","credit_card","password","passwd",
                     "user_id","username","full_name","name","ip_address"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node_name(node.func).split(".")[-1]
            if fn not in LOG_FUNS:
                continue
            for arg in node.args:
                if isinstance(arg, ast.Name) and any(p in arg.id.lower() for p in PII_NAMES):
                    findings.append(self._f(
                        "LLM06","CWE-532","warning",
                        f"PII Variable `{arg.id}` Passed to Log",
                        filename, node.lineno, lines,
                        f"`{arg.id}` may contain PII and is passed to `{fn}()`. "
                        "Redact sensitive fields before logging to prevent information disclosure."
                    ))
        return findings

    def _rule_llm06_prompt_in_response(self, tree, lines, filename):
        """system_prompt returned in API response dict."""
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Return):
                continue
            if not isinstance(node.value, ast.Dict):
                continue
            for key in node.value.keys:
                if isinstance(key, ast.Constant) and "system_prompt" in str(key.value).lower():
                    findings.append(self._f(
                        "LLM10","CWE-200","critical",
                        "System Prompt Exposed in API Response",
                        filename, node.lineno, lines,
                        "`system_prompt` is returned in an API response dict. "
                        "This exposes proprietary instructions and enables targeted injection attacks. "
                        "Remove system_prompt from all API responses."
                    ))
        return findings

    # ── LLM07: Insecure Plugin/Tool Design ───────────────────────────────────

    def _rule_llm07_unrestricted_file_write(self, tree, lines, filename):
        """Tool functions with file write but no path validation."""
        findings = []
        for func_node in ast.walk(tree):
            if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            is_tool = any(
                ("tool" in (d.id if isinstance(d, ast.Name) else
                            (d.attr if isinstance(d, ast.Attribute) else
                             (node_name(d.func) if isinstance(d, ast.Call) else ""))).lower())
                for d in func_node.decorator_list
            )
            if not (is_tool or "write" in func_node.name.lower() or "file" in func_node.name.lower()):
                continue

            func_lines_txt = "\n".join(lines[func_node.lineno - 1:getattr(func_node, "end_lineno", func_node.lineno)])
            has_guard = any(g in func_lines_txt for g in
                            ("allowlist","whitelist","allowed_path","startswith","abspath","realpath","is_relative_to","resolve"))

            for child in ast.walk(func_node):
                if not isinstance(child, ast.Call):
                    continue
                fn = node_name(child.func)
                if fn != "open":
                    continue
                # Check for write mode
                write_mode = False
                for i, arg in enumerate(child.args):
                    if i == 1 and isinstance(arg, ast.Constant) and any(m in str(arg.value) for m in ("w","a","x","+")):
                        write_mode = True
                for kw in child.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and any(m in str(kw.value.value) for m in ("w","a","x","+")):
                        write_mode = True
                if write_mode and not has_guard:
                    findings.append(self._f(
                        "LLM07","CWE-22","critical",
                        f"Tool `{func_node.name}` Writes Files Without Path Validation",
                        filename, child.lineno, lines,
                        f"`{func_node.name}` opens files for writing without path allowlist or traversal protection. "
                        "An agent could be directed to overwrite arbitrary files. "
                        "Use realpath() and validate against an allowed directory."
                    ))
        return findings

    def _rule_llm07_web_browse_no_allowlist(self, tree, lines, filename):
        """Web-browsing tools without URL allowlist."""
        findings = []
        for func_node in ast.walk(tree):
            if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not ("browse" in func_node.name.lower() or "fetch" in func_node.name.lower() or "scrape" in func_node.name.lower()):
                continue
            func_txt = "\n".join(lines[func_node.lineno - 1:getattr(func_node, "end_lineno", func_node.lineno)])
            has_allowlist = any(g in func_txt for g in ("allowlist","whitelist","allowed_url","allowed_domain","ALLOWED"))
            if not has_allowlist:
                findings.append(self._f(
                    "LLM07","CWE-918","warning",
                    f"Web-Browsing Tool `{func_node.name}` Without URL Allowlist",
                    filename, func_node.lineno, lines,
                    f"`{func_node.name}` fetches arbitrary URLs without an allowlist. "
                    "Agents can be directed to SSRF internal services or exfiltrate data. "
                    "Validate URLs against an explicit allowlist of permitted domains."
                ))
        return findings

    # ── LLM08: Excessive Agency ──────────────────────────────────────────────

    def _rule_llm08_dangerous_action_no_gate(self, tree, lines, filename):
        """Irreversible actions without human review gate."""
        findings = []
        DANGER_ATTRS = {"delete","remove","drop","destroy","truncate","send","deploy","publish"}
        for func_node in ast.walk(tree):
            if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            func_txt = "\n".join(lines[func_node.lineno - 1:getattr(func_node, "end_lineno", func_node.lineno)])
            has_gate = any(g in func_txt for g in
                           ("human_review","require_approval","interrupt_before","human_input",
                            "confirm","approval","checkpoint","ask_user","hitl"))
            if has_gate:
                continue
            for child in ast.walk(func_node):
                if not isinstance(child, ast.Call):
                    continue
                fn_part = node_name(child.func).split(".")[-1].lower()
                if fn_part in DANGER_ATTRS:
                    findings.append(self._f(
                        "LLM08","CWE-284","warning",
                        f"Irreversible Action `{fn_part}()` Without Human Review Gate",
                        filename, child.lineno, lines,
                        f"`{fn_part}()` performs a potentially irreversible action with no human approval gate. "
                        "Add `interrupt_before`, `require_approval()`, or a human-in-the-loop check."
                    ))
                    break  # one finding per function
        return findings

    def _rule_llm08_agent_self_modifies(self, tree, lines, filename):
        """Agent modifying its own instructions/system_prompt at runtime."""
        findings = []
        INSTRUCTION_ATTRS = {"system_prompt","instructions","role","persona","task"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for tgt in node.targets:
                if isinstance(tgt, ast.Attribute) and tgt.attr in INSTRUCTION_ATTRS:
                    findings.append(self._f(
                        "LLM08","CWE-284","warning",
                        f"Agent Modifies Own `{tgt.attr}` at Runtime",
                        filename, node.lineno, lines,
                        f"Attribute `{tgt.attr}` is reassigned at runtime. "
                        "Agents that rewrite their own instructions are vulnerable to manipulation attacks. "
                        "Treat instructions as immutable after initialization."
                    ))
        return findings

    # ── LLM09: Overreliance ──────────────────────────────────────────────────

    def _rule_llm09_direct_control_flow(self, tree, lines, filename):
        """LLM invocation used directly as if/while condition."""
        findings = []
        LLM_CALL_ATTRS = {"invoke","run","predict","generate","chat","complete","call"}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.If, ast.While)):
                continue
            if isinstance(node.test, ast.Call):
                fn = node_name(node.test.func)
                fn_part = fn.split(".")[-1]
                if fn_part in LLM_CALL_ATTRS:
                    findings.append(self._f(
                        "LLM09","CWE-693","warning",
                        "LLM Output Used Directly as Control Flow Condition",
                        filename, node.lineno, lines,
                        f"LLM call `{fn}()` used directly as an if/while condition without validation. "
                        "LLM outputs are non-deterministic. Validate and parse output before branching."
                    ))
        return findings

    # ── LLM10: Model Theft ───────────────────────────────────────────────────

    def _rule_llm10_prompt_in_logs(self, tree, lines, filename):
        """Prompt variables logged without redaction."""
        findings = []
        LOG_FUNS = {"print","info","debug","warning","error","log"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node_name(node.func).split(".")[-1]
            if fn not in LOG_FUNS:
                continue
            for arg in node.args:
                if isinstance(arg, ast.Name) and "prompt" in arg.id.lower():
                    findings.append(self._f(
                        "LLM10","CWE-200","warning",
                        f"System Prompt Variable `{arg.id}` Logged — Model Theft Risk",
                        filename, node.lineno, lines,
                        f"Variable `{arg.id}` (likely containing prompt instructions) is passed to `{fn}()`. "
                        "Logging system prompts exposes proprietary instructions. "
                        "Redact prompt contents from logs."
                    ))
        return findings

    # ── Framework-Specific Rules ─────────────────────────────────────────────

    def _rule_fw_langgraph_no_interrupt(self, tree, lines, filename):
        if self.framework != "langgraph":
            return []
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node_name(node.func).split(".")[-1]
            if fn == "compile":
                kwargs = {kw.arg for kw in node.keywords}
                if "interrupt_before" not in kwargs and "interrupt_after" not in kwargs:
                    findings.append(self._f(
                        "LLM08","CWE-284","warning",
                        "LangGraph Graph Compiled Without interrupt_before",
                        filename, node.lineno, lines,
                        "LangGraph `.compile()` called without `interrupt_before` on high-risk nodes. "
                        "Add `interrupt_before=['tool_call_node']` to require human approval before tool use."
                    ))
                if "checkpointer" not in kwargs:
                    findings.append(self._f(
                        "LLM04","CWE-400","info",
                        "LangGraph Graph Compiled Without Checkpointer",
                        filename, node.lineno, lines,
                        "No `checkpointer` provided to `.compile()`. "
                        "Without checkpointing, agent state cannot be recovered after failure."
                    ))
        return findings

    def _rule_fw_crewai_delegation(self, tree, lines, filename):
        if self.framework != "crewai":
            return []
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node_name(node.func)
            if fn.split(".")[-1] != "Agent":
                continue
            kw_map = {kw.arg: kw.value for kw in node.keywords}
            if "allow_delegation" in kw_map:
                val = kw_map["allow_delegation"]
                if isinstance(val, ast.Constant) and val.value is True:
                    if "max_iter" not in kw_map:
                        findings.append(self._f(
                            "LLM08","CWE-284","warning",
                            "CrewAI Agent: allow_delegation=True Without max_iter",
                            filename, node.lineno, lines,
                            "CrewAI agent has delegation enabled without `max_iter`. "
                            "Unscoped delegation can result in uncontrolled sub-agent chains. "
                            "Add `max_iter=5` or scope delegation to specific roles."
                        ))
        return findings

    def _rule_fw_autogen_no_termination(self, tree, lines, filename):
        if self.framework != "autogen":
            return []
        findings = []
        AGENT_CTORS = {"ConversableAgent","UserProxyAgent","AssistantAgent","GroupChatManager"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node_name(node.func).split(".")[-1]
            if fn not in AGENT_CTORS:
                continue
            kw_map = {kw.arg: kw.value for kw in node.keywords}

            if "human_input_mode" in kw_map:
                val = kw_map["human_input_mode"]
                if isinstance(val, ast.Constant) and val.value == "NEVER":
                    findings.append(self._f(
                        "LLM08","CWE-284","warning",
                        f"AutoGen `{fn}` with human_input_mode=NEVER",
                        filename, node.lineno, lines,
                        f"`{fn}` configured with `human_input_mode='NEVER'` disables all human oversight. "
                        "Use 'TERMINATE' or 'ALWAYS' for agents executing high-risk operations."
                    ))

            has_term = "is_termination_msg" in kw_map or "max_consecutive_auto_reply" in kw_map
            if not has_term:
                findings.append(self._f(
                    "LLM04","CWE-400","warning",
                    f"AutoGen `{fn}` Missing Termination Condition",
                    filename, node.lineno, lines,
                    f"`{fn}` has no `is_termination_msg` or `max_consecutive_auto_reply`. "
                    "Agent may run indefinitely without a stopping condition."
                ))
        return findings

    def _rule_fw_llamaindex_no_access_control(self, tree, lines, filename):
        if self.framework != "llamaindex":
            return []
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node_name(node.func)
            fn_part = fn.split(".")[-1]
            if fn_part not in ("from_documents", "VectorStoreIndex") and "Index" not in fn_part:
                continue
            # Check for access control options
            kw_names = {kw.arg for kw in node.keywords}
            if not any(k in kw_names for k in ("access_control","node_postprocessors","filters","auth")):
                findings.append(self._f(
                    "LLM07","CWE-284","info",
                    f"LlamaIndex `{fn_part}` Without Access Control",
                    filename, node.lineno, lines,
                    f"`{fn_part}` created without explicit access control configuration. "
                    "Consider adding document-level permissions via node_postprocessors or filters."
                ))
        return findings

    # ── Good Practice Rewards ────────────────────────────────────────────────

    def _rule_zzz_protected_patterns(self, tree, lines, filename):
        """Reward security best practices (code only, ignores comments)."""
        findings = []
        # Strip comment-only lines and inline comments for pattern matching
        code_only_lines = []
        for ln in lines:
            stripped = ln.strip()
            if stripped.startswith("#"):
                continue
            # Remove inline comment
            in_str = False
            i = 0
            while i < len(ln):
                c = ln[i]
                if c in ('"', "'"):
                    in_str = not in_str
                if c == '#' and not in_str:
                    ln = ln[:i]
                    break
                i += 1
            code_only_lines.append(ln)
        source = "\n".join(code_only_lines)

        REWARDS = [
            (r'\bsanitize\b',         "LLM01", "Input Sanitization Present"),
            (r'\bvalidate\b',          "LLM01", "Input Validation Present"),
            (r'\bescape\b',            "LLM02", "Output Escaping Detected"),
            (r'\bhuman_review\b',      "LLM08", "Human Review Gate Present"),
            (r'\brequire_approval\b',  "LLM08", "Approval Gate Detected"),
            (r'\binterrupt_before\s*=', "LLM08", "LangGraph Interrupt Gate Present"),
            (r'\bmax_depth\b',         "LLM04", "Recursion Depth Limit Found"),
            (r'\btimeout\s*=',         "LLM04", "Timeout Configured on LLM Call"),
            (r'\bos\.environ\b',       "LLM06", "Secrets Loaded from Environment"),
        ]
        awarded = set()
        for pattern, owasp, title in REWARDS:
            if owasp not in awarded and re.search(pattern, source, re.IGNORECASE):
                findings.append({
                    "owasp": owasp, "cwe": "N/A", "severity": "protected",
                    "title": title, "file": filename, "line": 1,
                    "code_snippet": f"# {title}",
                    "explanation": f"Good practice detected: {title}.",
                })
                awarded.add(owasp)
        return findings


# ─── Requirements Checker ────────────────────────────────────────────────────

def check_requirements(content: str, filename: str) -> List[dict]:
    findings = []
    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(("#","--","-r","git+")):
            continue
        pkg = re.split(r'[><=!;\[]', line, maxsplit=1)[0].strip()
        if pkg and "==" not in line and "~=" not in line:
            findings.append({
                "owasp":"LLM05","cwe":"CWE-1104","severity":"warning",
                "title":f"Unpinned Dependency: `{pkg}`",
                "file":filename,"line":i,"code_snippet":line,
                "explanation":(
                    f"`{pkg}` has no version pin (==). Unpinned dependencies can "
                    "silently upgrade to compromised or breaking versions. Use `{pkg}==X.Y.Z`."
                ),
            })
    return findings


# ─── Main Scanner ─────────────────────────────────────────────────────────────

class Scanner:
    """
    Orchestrates all analysis passes.
    Entry points: scan_code, scan_directory, scan_zip, scan_github.
    """

    def scan_files(self, files: Dict[str, str]) -> dict:
        """
        Core: files = {relative_path: source_text}
        Returns raw analysis result dict (without AI-generated diffs/verdict).
        """
        py_files = {k: v for k, v in files.items() if k.endswith(".py") and v.strip()}
        other_files = {k: v for k, v in files.items() if not k.endswith(".py")}

        framework = detect_framework(files)
        import_graph = build_import_graph(py_files)
        rule_engine = RuleEngine(framework)

        raw_findings: List[dict] = []

        for filename, source in py_files.items():
            # Skip venv/cache paths
            parts = Path(filename).parts
            if any(p in parts for p in (".venv","venv","env","__pycache__","site-packages","node_modules")):
                continue

            # Taint analysis
            try:
                tree = ast.parse(source)
                ta = TaintAnalyzer(source, filename)
                ta.visit(tree)
                raw_findings.extend(ta.findings)
            except SyntaxError:
                pass

            # Rule engine
            raw_findings.extend(rule_engine.run(source, filename))

        # Requirements files
        for filename, content in other_files.items():
            if re.search(r'requirements.*\.txt$', filename, re.IGNORECASE):
                raw_findings.extend(check_requirements(content, filename))

        # Deduplicate: same file + line + owasp = keep most severe / first seen
        seen: Set[tuple] = set()
        findings: List[dict] = []
        for f in raw_findings:
            key = (f["file"], f["line"], f["owasp"])
            if key not in seen:
                seen.add(key)
                findings.append(f)

        # Sort: critical first, then warning, info, protected
        sev_order = {"critical": 0, "warning": 1, "info": 2, "protected": 3}
        findings.sort(key=lambda x: sev_order.get(x["severity"], 9))

        # Assign IDs
        for i, f in enumerate(findings, 1):
            f["id"] = f"AGC-{i:03d}"
            f.setdefault("diff", {"before": f.get("code_snippet",""), "after": ""})

        score = self._score(findings)

        return {
            "score": score,
            "framework": framework,
            "files_analyzed": len(py_files),
            "import_graph": import_graph,
            "findings": findings,
        }

    @staticmethod
    def _score(findings: List[dict]) -> int:
        s = 100
        for f in findings:
            s += SEVERITY_DELTA.get(f["severity"], 0)
        return max(0, min(100, s))

    def scan_code(self, code: str, filename: str = "snippet.py") -> dict:
        return self.scan_files({filename: code})

    def scan_directory(self, path: Path) -> dict:
        files: Dict[str, str] = {}
        SKIP = {".venv","venv","env","__pycache__","node_modules",".git","site-packages","dist","build"}
        for f in path.rglob("*"):
            if not f.is_file():
                continue
            rel = f.relative_to(path)
            if any(p in SKIP for p in rel.parts):
                continue
            if f.suffix in (".py",) or re.search(r'requirements.*\.txt$', f.name, re.IGNORECASE):
                try:
                    files[str(rel)] = f.read_text(errors="replace")
                except (IOError, PermissionError):
                    pass
        return self.scan_files(files)

    def scan_zip(self, zip_path: Path) -> dict:
        files: Dict[str, str] = {}
        SKIP = {".venv","venv","__pycache__","site-packages"}
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                parts = Path(name).parts
                if any(p in SKIP for p in parts):
                    continue
                if name.endswith(".py") or re.search(r'requirements.*\.txt$', name, re.IGNORECASE):
                    try:
                        files[name] = zf.read(name).decode("utf-8", errors="replace")
                    except Exception:
                        pass
        return self.scan_files(files)

    def scan_github(self, url: str, timeout: int = 25) -> dict:
        """Clone a public GitHub repo (depth=1) and scan it."""
        if not re.match(r'^https://github\.com/[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+(\.git)?(/.*)?$', url):
            raise ValueError("Only public GitHub URLs are supported (https://github.com/owner/repo)")

        # Strip any path components beyond the repo
        m = re.match(r'^(https://github\.com/[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+)', url)
        clean_url = m.group(1) if m else url

        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                ["git", "clone", "--depth=1", "--quiet", clean_url, tmpdir],
                capture_output=True, text=True, timeout=timeout
            )
            if result.returncode != 0:
                err = result.stderr.strip()[:300]
                raise RuntimeError(f"Git clone failed: {err}")
            return self.scan_directory(Path(tmpdir))
