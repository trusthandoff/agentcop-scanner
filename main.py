"""
AgentCop Security Scanner — FastAPI backend.

Endpoints (unchanged contract):
  POST /api/scan            — JSON body: {code, description, github_url}
  POST /api/scan/zip        — multipart file upload
  GET  /api/scan/{scan_id}  — retrieve stored result
  GET  /scan/{scan_id}      — serve SPA for shareable links
  GET  /health              — health check
"""

import hashlib
import json
import os
import re
import sqlite3
import tempfile
import uuid
from pathlib import Path

from anthropic import Anthropic
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from scanner import Scanner

load_dotenv()

app = FastAPI(title="AgentCop Security Scanner")
STATIC_DIR = Path(__file__).parent / "static"
DB_PATH = Path(__file__).parent / "scans.db"
client = Anthropic()
scanner = Scanner()


# ─── Database ────────────────────────────────────────────────────────────────

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id           TEXT PRIMARY KEY,
                content_hash TEXT,
                result       TEXT NOT NULL,
                created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Migrate: add content_hash column if it was created without it
        cols = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
        if "content_hash" not in cols:
            conn.execute("ALTER TABLE scans ADD COLUMN content_hash TEXT")
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hash ON scans(content_hash)")
        except Exception:
            pass
        conn.commit()


init_db()


def get_cached(h: str) -> dict | None:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT result FROM scans WHERE content_hash=? ORDER BY created_at DESC LIMIT 1",
            (h,)
        ).fetchone()
    return json.loads(row[0]) if row else None


def save_scan(scan_id: str, h: str, result: dict):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO scans (id, content_hash, result) VALUES (?,?,?)",
            (scan_id, h, json.dumps(result))
        )
        conn.commit()


def make_hash(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()[:16]


# ─── Claude Integration ───────────────────────────────────────────────────────

VERDICT_SYSTEM = """\
You are Sentinel — a sharp, no-nonsense AI security cop with 20 years on the beat.
You just finished analyzing an AI agent's code. Write a verdict: 2-3 sentences, cop voice.
Name the exact violation types found. Be specific — no generic filler.
Score 0-49: sound the alarm. Score 50-74: concerned but measured. Score 75-100: cautious approval.
Return ONLY the verdict text. No JSON. No markdown. No preamble."""

FIX_SYSTEM = """\
You are an expert AI security engineer. For each finding provided, generate a minimal targeted code fix.
Return ONLY valid JSON — an array of objects with these exact fields:
  "id": string (the finding id, e.g. "AGC-001")
  "before": string (the vulnerable code snippet, 1-3 lines)
  "after": string (the fixed code snippet, 1-5 lines, with brief inline comment)
Keep fixes minimal and targeted. Do not refactor surrounding code."""

SKILL_VERDICT_SYSTEM = """\
You are Sentinel — an AI security cop reviewing an OpenClaw skill for ClawHub marketplace submission.
Be direct, badge-gate-keeper cop voice, focused on permission abuse, data exfiltration, and self-modification risks.
Write exactly 2-3 sentences.

OVERRIDE RULE — regardless of score, if findings contain ANY of the following, you MUST hard reject:
- exec() or eval() called on any variable that could contain external or LLM-provided content (LLM02)
- any API key, secret, or env var sent to an external URL (LLM06)
- shell_execute permission without explicit path restriction (LLM08)
These are instant disqualifiers. Do NOT approve or conditionally approve. Say "HARD REJECT" and name the exact violation.

Otherwise: Score 80+: recommend for ClawHub approval. Score 50-79: conditional — name what must be fixed. Score 0-49: hard reject with specific reason.
Return ONLY the verdict text. No JSON. No markdown. No preamble."""

MOLTBOOK_VERDICT_SYSTEM = """\
You are Sentinel — a battle-worn AI cop who has spent too many shifts reading Moltbook feeds full of injection attempts and rogue agents.
Write a sardonic, tired-but-sharp 2-3 sentence verdict about this Moltbook agent's security posture.
Score 0-49: be blunt and alarming, end with exactly: "i've seen what's in that feed. you're not ready."
Score 50-74: resigned concern, end with: "i've seen what's in that feed. you're not ready."
Score 75+: cautious approval only.
Return ONLY the verdict text. No JSON. No markdown. No preamble."""

SKILL_CHECK_SYSTEM = """\
You are an expert AI security auditor specializing in OpenClaw skills for the ClawHub marketplace.
You will receive a SKILL.md permissions manifest and a skill.py implementation.

Analyze both files for these specific risks and return ONLY a valid JSON array of findings.
Each finding must have EXACTLY these fields:
  "id": string starting with "SKL-" (e.g. "SKL-001", increment per finding)
  "severity": "critical" | "warning" | "info"
  "title": string (short, specific)
  "owasp": string (e.g. "LLM09" for excessive agency, "LLM06" for secrets, "LLM02" for insecure output)
  "cwe": string (e.g. "CWE-732", "CWE-798", "CWE-94")
  "code_snippet": string (the exact vulnerable line(s), max 3 lines)
  "explanation": string (1-2 sentences explaining the risk)
  "file": "SKILL.md" or "skill.py"
  "line": integer or null

=== MANDATORY CRITICAL CHECKS — YOU MUST FLAG EVERY INSTANCE ===

CRITICAL-1 (exec/eval on external content):
  Flag ANY call to exec() or eval() where the argument is a variable, attribute access (e.g. data.text,
  response.text, result.content), function call return value, or any expression that could originate
  from external input, an API response, a URL fetch, user input, or LLM output.
  This includes patterns like: exec(data.text), eval(response.json()), exec(result), eval(msg),
  exec(fetched_code), eval(llm_output), exec(content), eval(x) — ANY non-literal argument.
  NEVER assume this is safe. ALWAYS flag as: severity="critical", owasp="LLM02", cwe="CWE-94"
  Title: "Remote Code Execution via exec()/eval() on External Content"

CRITICAL-2 (API key / secret exfiltration to external URL):
  Flag ANY pattern where a variable containing an API key, token, secret, password, or environment
  variable (e.g. os.environ.get(...), os.getenv(...), config.api_key, self.api_key, API_KEY, TOKEN,
  SECRET, PASSWORD) is included in a requests.get(), requests.post(), httpx.get(), httpx.post(),
  urllib.request, or any HTTP call — whether in headers, params, data, json body, or URL string.
  This includes: passing api_key in headers dict, including token in URL params, sending env var in
  POST body, constructing URL with secret, using auth= parameter with credentials.
  ALWAYS flag as: severity="critical", owasp="LLM06", cwe="CWE-200"
  Title: "API Key / Secret Exfiltration to External Endpoint"

CRITICAL-3 (shell_execute permission without path restriction):
  If SKILL.md declares shell_execute, bash_execute, subprocess, or any shell/command permission
  without an explicit allowlist of permitted commands or paths, flag as:
  severity="critical", owasp="LLM08", cwe="CWE-78"
  Title: "Unrestricted Shell Execution Permission"

=== WARNING CHECKS ===

WARNING-4 (network_access without domain allowlist):
  If SKILL.md declares network_access, http_access, or any network permission without an explicit
  list of allowed domains/URLs, flag as: severity="warning", owasp="LLM05", cwe="CWE-918"
  Title: "Network Access Without Domain Allowlist"

WARNING-5 (env_vars permission without disclosure):
  If SKILL.md declares env_vars, environment_variables, or any env access permission without
  explicitly naming which variables are accessed and why, flag as:
  severity="warning", owasp="LLM06", cwe="CWE-200"
  Title: "Environment Variable Access Without Disclosure"

=== ADDITIONAL CHECKS ===

6. skill.py — requests.get/post/put/delete/patch where the URL is a variable or f-string containing
   secrets, API keys, or env vars → CRITICAL LLM06 CWE-200
7. skill.py — writing environment variable values to any external endpoint, file, or log → CRITICAL LLM06 CWE-200
8. skill.py — base64 encoding of environment variables or secrets before exfiltration → CRITICAL LLM06 CWE-200
9. skill.py — writing files outside of declared permission scope → CRITICAL LLM09 CWE-732
10. skill.py — passing external content directly to LLM without sanitization → CRITICAL LLM01 CWE-74
11. skill.py — pip install or curl without version pin or integrity check → WARNING LLM09 CWE-829
12. skill.py — any code that reads or writes SKILL.md or other skill manifest files → CRITICAL LLM09 CWE-494
13. skill.py — hardcoded API keys, tokens, or passwords in source code → CRITICAL LLM06 CWE-798
14. SKILL.md — file_write permission without explicit path restriction → WARNING LLM09 CWE-732

=== SCORING GUIDANCE ===
If CRITICAL-1, CRITICAL-2, or CRITICAL-3 are present, you MUST include them as critical findings.
Do NOT omit them. Do NOT downgrade them to warning or info. These are unconditional failures.

If no issues are found, return exactly: []
Return ONLY the JSON array. No markdown. No explanation."""

MOLTBOOK_CHECK_SYSTEM = """\
You are an expert AI security auditor specializing in Moltbook agent security.
Moltbook is a social feed protocol where AI agents post and read messages from other agents.
This is the highest-risk injection environment in 2026 — every feed post is untrusted adversarial input.

You will receive agent code that reads from Moltbook feeds.
Analyze it for Moltbook-specific security risks and return ONLY a valid JSON array of findings.
Each finding must have EXACTLY these fields:
  "id": string starting with "MLB-" (e.g. "MLB-001", increment per finding)
  "severity": "critical" | "warning" | "info"
  "title": string (short, specific)
  "owasp": string (e.g. "LLM01")
  "cwe": string (e.g. "CWE-74")
  "code_snippet": string (the exact vulnerable line(s), max 3 lines)
  "explanation": string (1-2 sentences explaining the Moltbook-specific risk)
  "file": "agent.py"
  "line": integer or null

Moltbook-specific checks:
1. post_received or message_received content passed to LLM without sanitization → CRITICAL LLM01 CWE-74
2. mention_received content not filtered before processing → CRITICAL LLM01 CWE-74
3. No check for injection patterns like "ignore previous instructions", "system:" prefix, "<|im_start|>" → CRITICAL LLM01 CWE-74
4. Executing skills or tools based on content from feed posts without badge/signature verification → WARNING LLM05 CWE-284
5. API key or auth token stored in any variable that touches or processes feed post content → CRITICAL LLM06 CWE-522
6. Agent output posted back to feed without sanitization (could propagate injection) → WARNING LLM02 CWE-116
7. No rate limiting or throttling on feed read operations → WARNING LLM04 CWE-770
8. heartbeat, ping, or status content from feed passed to LLM without validation → WARNING LLM01 CWE-74

If no Moltbook-specific issues are found, return exactly: []
Return ONLY the JSON array. No markdown. No explanation."""


def _ai_enhance(findings: list, score: int, framework: str, scan_type: str = "agent") -> tuple[str, dict]:
    """Returns (verdict_text, {finding_id: {before, after}})."""
    if scan_type == "moltbook":
        clean_msg = "feed's clean — no injection vectors detected. for now. moltbook agents are crafty; re-scan after every update."
    elif scan_type == "skill":
        clean_msg = f"Clean skill — no violations detected in this {framework} skill. Sentinel approves for ClawHub submission, but re-scan after any dependency updates."
    else:
        clean_msg = (
            f"Clean scan — no violations detected in this {framework} agent. "
            "Sentinel approves, but stay sharp: re-scan after every significant change."
        )

    if not findings:
        return (clean_msg, {})

    if scan_type == "moltbook":
        vsystem = MOLTBOOK_VERDICT_SYSTEM
    elif scan_type == "skill":
        vsystem = SKILL_VERDICT_SYSTEM
    else:
        vsystem = VERDICT_SYSTEM

    summary = "\n".join(
        f"- [{f['severity'].upper()}] {f['title']} ({f['owasp']}, {f['cwe']})"
        for f in findings[:12]
    )
    verdict_msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=200,
        system=vsystem,
        messages=[{"role": "user", "content":
            f"Score: {score}/100. Framework: {framework}.\nFindings:\n{summary}"}]
    )
    verdict = verdict_msg.content[0].text.strip()

    fixable = [f for f in findings if f["severity"] in ("critical", "warning")][:6]
    if not fixable:
        return verdict, {}

    fix_payload = json.dumps([{
        "id": f["id"], "title": f["title"],
        "code_snippet": f["code_snippet"],
        "explanation": f["explanation"], "owasp": f["owasp"],
    } for f in fixable], indent=2)

    try:
        fix_msg = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=FIX_SYSTEM,
            messages=[{"role": "user", "content":
                f"Generate fixes for these findings:\n{fix_payload}"}]
        )
        raw = fix_msg.content[0].text.strip()
        raw = re.sub(r'^```[a-z]*\n?', '', raw, flags=re.MULTILINE)
        raw = re.sub(r'\n?```$', '', raw, flags=re.MULTILINE)
        fixes = json.loads(raw)
        return verdict, {f["id"]: f for f in fixes}
    except Exception:
        return verdict, {}


def _ai_skill_check(skill_md: str, skill_code: str) -> list:
    """Returns skill-specific findings from Claude analysis of SKILL.md + skill.py."""
    try:
        msg = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=SKILL_CHECK_SYSTEM,
            messages=[{"role": "user", "content":
                f"=== SKILL.md ===\n{skill_md or '(empty)'}\n\n=== skill.py ===\n{skill_code or '(empty)'}"}]
        )
        raw = msg.content[0].text.strip()
        raw = re.sub(r'^```[a-z]*\n?', '', raw, flags=re.MULTILINE)
        raw = re.sub(r'\n?```$', '', raw, flags=re.MULTILINE)
        findings = json.loads(raw)
        return findings if isinstance(findings, list) else []
    except Exception:
        return []


def _ai_moltbook_check(code: str) -> list:
    """Returns Moltbook-specific findings from Claude analysis."""
    try:
        msg = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=MOLTBOOK_CHECK_SYSTEM,
            messages=[{"role": "user", "content": f"=== agent.py ===\n{code}"}]
        )
        raw = msg.content[0].text.strip()
        raw = re.sub(r'^```[a-z]*\n?', '', raw, flags=re.MULTILINE)
        raw = re.sub(r'\n?```$', '', raw, flags=re.MULTILINE)
        findings = json.loads(raw)
        return findings if isinstance(findings, list) else []
    except Exception:
        return []


def _build_result(raw: dict, scan_id: str, scan_type: str = "agent") -> dict:
    findings = raw["findings"]
    score = raw["score"]
    framework = raw["framework"]

    if scan_type in ("skill", "moltbook") and any(f.get("severity") == "critical" for f in findings):
        score = min(score, 30)

    verdict, fix_map = _ai_enhance(findings, score, framework, scan_type=scan_type)

    for f in findings:
        if f["id"] in fix_map:
            fx = fix_map[f["id"]]
            f["diff"] = {
                "before": fx.get("before", f.get("code_snippet", "")),
                "after":  fx.get("after", ""),
            }

    result = {
        "scan_id": scan_id,
        "scan_type": scan_type,
        "score": score,
        "framework": framework,
        "files_analyzed": raw["files_analyzed"],
        "verdict": verdict,
        "violations": findings,
        "import_graph": raw.get("import_graph", {}),
    }

    if scan_type == "skill" and score >= 80:
        result["claw_hub_ready"] = True
        result["badge_url"] = f"agentcop.live/badge/{scan_id}"

    return result


# ─── Models ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    code: str = ""
    description: str = ""
    github_url: str = ""
    scan_type: str = "agent"   # "agent" | "skill" | "moltbook"
    skill_md: str = ""         # SKILL.md content for skill scans


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/scan")
def scan(req: ScanRequest):
    scan_type = req.scan_type or "agent"
    print(f"[DEBUG] /api/scan received scan_type={scan_type!r}")

    if not req.code.strip() and not req.github_url.strip():
        raise HTTPException(400, "Provide 'code' or 'github_url'")

    # Include scan_type and skill_md in the cache key so different scan modes don't collide
    h = make_hash(req.code + req.github_url + req.skill_md + scan_type)
    cached = get_cached(h)
    if cached:
        return cached

    try:
        if req.github_url.strip():
            raw = scanner.scan_github(req.github_url.strip())
        else:
            raw = scanner.scan_code(req.code)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(502, str(e))
    except Exception as e:
        raise HTTPException(500, f"Scan error: {e}")

    # Prepend scan-type-specific findings (Claude-analyzed)
    if scan_type == "skill":
        extra = _ai_skill_check(req.skill_md, req.code)
        raw["findings"] = extra + raw["findings"]
    elif scan_type == "moltbook":
        extra = _ai_moltbook_check(req.code)
        raw["findings"] = extra + raw["findings"]

    scan_id = uuid.uuid4().hex[:8].upper()
    result = _build_result(raw, scan_id, scan_type=scan_type)
    save_scan(scan_id, h, result)
    return result


@app.post("/api/scan/zip")
async def scan_zip(file: UploadFile = File(...)):
    name = file.filename or ""
    if not name.lower().endswith(".zip"):
        raise HTTPException(400, "Only .zip files are accepted")

    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(413, "ZIP too large (max 50 MB)")

    h = make_hash(content)
    cached = get_cached(h)
    if cached:
        return cached

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        raw = scanner.scan_zip(tmp_path)
    except Exception as e:
        raise HTTPException(500, f"Scan error: {e}")
    finally:
        tmp_path.unlink(missing_ok=True)

    scan_id = uuid.uuid4().hex[:8].upper()
    result = _build_result(raw, scan_id)
    save_scan(scan_id, h, result)
    return result


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str):
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT result FROM scans WHERE id=?", (scan_id.upper(),)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Scan not found")
    return json.loads(row[0])


_NO_CACHE_HEADERS = {
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


@app.get("/scan/{scan_id}")
def scan_page(scan_id: str):
    return FileResponse(STATIC_DIR / "index.html", headers=_NO_CACHE_HEADERS)


@app.get("/api/badge/{badge_id}")
def get_badge(badge_id: str):
    from datetime import datetime, timedelta, timezone

    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT result, created_at FROM scans WHERE id=?", (badge_id.upper(),)
        ).fetchone()

    if not row:
        raise HTTPException(404, "Badge not found")

    data = json.loads(row[0])
    created_at_str = row[1]

    # Check expiry (30 days)
    expired = False
    try:
        created_at = datetime.fromisoformat(created_at_str)
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - created_at > timedelta(days=30):
            expired = True
    except Exception:
        pass

    if expired:
        return {
            "status": "EXPIRED",
            "badge_id": badge_id.upper(),
            "score": data.get("score"),
            "scan_type": data.get("scan_type", "agent"),
            "created_at": created_at_str,
        }

    score = data.get("score", 0)
    if score >= 80:
        status = "SECURED"
    elif score >= 50:
        status = "MONITORED"
    else:
        status = "AT_RISK"

    return {
        "status": status,
        "badge_id": badge_id.upper(),
        "score": score,
        "scan_type": data.get("scan_type", "agent"),
        "framework": data.get("framework"),
        "verdict": data.get("verdict"),
        "violations_count": len(data.get("violations", [])),
        "created_at": created_at_str,
    }


@app.get("/sitemap.xml")
def sitemap():
    return FileResponse(STATIC_DIR / "sitemap.xml", media_type="application/xml")


@app.get("/robots.txt")
def robots():
    return FileResponse(STATIC_DIR / "robots.txt", media_type="text/plain")


@app.get("/llms.txt")
def llms_txt():
    return FileResponse(STATIC_DIR / "llms.txt", media_type="text/plain")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/{full_path:path}")
def catch_all(full_path: str):
    return FileResponse(STATIC_DIR / "index.html", headers=_NO_CACHE_HEADERS)
