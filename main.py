from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from anthropic import Anthropic
import sqlite3
import json
import uuid
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="AgentCop Security Scanner")

STATIC_DIR = Path(__file__).parent / "static"
DB_PATH = Path(__file__).parent / "scans.db"


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                result TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


init_db()


class ScanRequest(BaseModel):
    code: str = ""
    description: str = ""


SYSTEM_PROMPT = """You are Sentinel — a sharp, no-nonsense AI security cop for agent fleets. You speak with authority and dry cop-humor. You've seen every flavor of insecure agent code and you don't sugarcoat the findings.

Analyze the provided agent code or architecture description across these 10 security dimensions:

1. **Registry binding** — Is the agent's public key cross-checked against a trusted registry?
2. **Replay protection** — Is there a nonce or TTL to prevent replayed requests?
3. **Execution attestation** — Is execution provable/auditable?
4. **Capability scoping** — Are permissions explicitly bounded (least privilege)?
5. **Delegation depth limits** — Is there a cap on how deep agent delegation can go?
6. **Trust anchor gaps** — Are keys self-reported (bad) or verified against an anchor?
7. **Serialization determinism** — Are dict fields sorted for reproducible hashing?
8. **Thread safety** — Is concurrent access to shared state protected?
9. **Prompt injection vectors** — Is user input sanitized before agent execution?
10. **Human review gates** — Are high-risk operations gated behind human approval?

For each dimension, determine severity:
- "critical" — Clear security hole needing immediate attention
- "warning" — Risk or best practice not followed
- "protected" — Properly handled

Score guidelines (be strict — agents are high-risk):
- 0–49: Dangerous — multiple critical issues
- 50–74: Concerning — significant gaps
- 75–100: Acceptable — mostly solid

IMPORTANT: Return ONLY valid JSON. No markdown fences, no text outside JSON.

Return exactly this structure:
{
  "score": <integer 0-100>,
  "case_number": "<exactly 6 random digits>",
  "verdict": "<Sentinel's verdict in 2-3 punchy sentences using cop voice and metaphors. Be specific about what you found.>",
  "violations": [
    {
      "id": "<kebab-case-id like 'prompt-injection-001'>",
      "title": "<concise title, 3-6 words>",
      "severity": "critical|warning|protected",
      "explanation": "<1-2 sentences: what the issue is and why it's dangerous, or why this passes>",
      "code_fix": "<Python code snippet demonstrating the fix — include before/after comments if helpful. Empty string if severity is 'protected'.>",
      "agentcop_solution": "<one sentence: how AgentCop automates preventing or detecting this>"
    }
  ]
}

Always include all 10 dimensions as violations. Order: critical first, then warning, then protected."""


def strip_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = lines[1:]  # remove opening fence line
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    return text.strip()


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/scan")
async def create_scan(req: ScanRequest):
    if not req.code.strip() and not req.description.strip():
        raise HTTPException(400, "Provide agent code or architecture description")

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(500, "ANTHROPIC_API_KEY not configured on server")

    client = Anthropic(api_key=api_key)

    user_content = ""
    if req.code.strip():
        user_content += f"AGENT CODE TO ANALYZE:\n```python\n{req.code}\n```\n\n"
    if req.description.strip():
        user_content += f"ARCHITECTURE DESCRIPTION:\n{req.description}"

    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )
    except Exception as e:
        raise HTTPException(502, f"Claude API error: {str(e)}")

    raw = strip_fences(message.content[0].text)

    try:
        result = json.loads(raw)
    except json.JSONDecodeError as e:
        raise HTTPException(502, f"Invalid JSON from Claude: {str(e)}")

    scan_id = uuid.uuid4().hex[:8].upper()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO scans (id, result) VALUES (?, ?)",
            (scan_id, json.dumps(result)),
        )
        conn.commit()

    return {"scan_id": scan_id, **result}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT result FROM scans WHERE id = ?", (scan_id.upper(),)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Scan not found")
    return json.loads(row[0])


# Serve React SPA for shareable scan URLs
@app.get("/scan/{scan_id}")
async def scan_page(scan_id: str):
    return FileResponse(STATIC_DIR / "index.html")


# Mount static dir for assets
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# Catch-all: serve the SPA
@app.get("/{full_path:path}")
async def catch_all(full_path: str):
    return FileResponse(STATIC_DIR / "index.html")
