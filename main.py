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


def _ai_enhance(findings: list, score: int, framework: str) -> tuple[str, dict]:
    """Returns (verdict_text, {finding_id: {before, after}})."""
    if not findings:
        return (
            f"Clean scan — no violations detected in this {framework} agent. "
            "Sentinel approves, but stay sharp: re-scan after every significant change.",
            {}
        )

    summary = "\n".join(
        f"- [{f['severity'].upper()}] {f['title']} ({f['owasp']}, {f['cwe']})"
        for f in findings[:12]
    )
    verdict_msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=200,
        system=VERDICT_SYSTEM,
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


def _build_result(raw: dict, scan_id: str) -> dict:
    findings = raw["findings"]
    score = raw["score"]
    framework = raw["framework"]

    verdict, fix_map = _ai_enhance(findings, score, framework)

    for f in findings:
        if f["id"] in fix_map:
            fx = fix_map[f["id"]]
            f["diff"] = {
                "before": fx.get("before", f.get("code_snippet", "")),
                "after":  fx.get("after", ""),
            }

    return {
        "scan_id": scan_id,
        "score": score,
        "framework": framework,
        "files_analyzed": raw["files_analyzed"],
        "verdict": verdict,
        "violations": findings,
        "import_graph": raw.get("import_graph", {}),
    }


# ─── Models ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    code: str = ""
    description: str = ""
    github_url: str = ""


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/scan")
def scan(req: ScanRequest):
    if not req.code.strip() and not req.github_url.strip():
        raise HTTPException(400, "Provide 'code' or 'github_url'")

    h = make_hash(req.code + req.github_url)
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

    scan_id = uuid.uuid4().hex[:8].upper()
    result = _build_result(raw, scan_id)
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


@app.get("/scan/{scan_id}")
def scan_page(scan_id: str):
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/{full_path:path}")
def catch_all(full_path: str):
    return FileResponse(STATIC_DIR / "index.html")
