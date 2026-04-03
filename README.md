# AgentCop Security Scanner

AI-powered security scanner for agent fleets, powered by Sentinel (Claude) and FastAPI.

## Setup

### 1. Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env .env.local  # or edit .env directly
# Set your Anthropic API key:
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
```

### 3. Run the server

```bash
# Quick start (handles venv + deps automatically):
chmod +x start.sh
sudo ./start.sh

# Or manually:
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 80
```

Open http://localhost (or http://agentcop.live if deployed).

## Deploy to Production (agentcop.live → 204.168.157.86)

### DNS Configuration

Add an A record in your DNS provider:

| Type | Host | Value | TTL |
|------|------|-------|-----|
| A | agentcop.live | 204.168.157.86 | 300 |
| A | www.agentcop.live | 204.168.157.86 | 300 |

### systemd Service

```bash
# Copy service file
sudo cp agentcop-scanner.service /etc/systemd/system/

# Install venv and deps first
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable agentcop-scanner
sudo systemctl start agentcop-scanner

# Check status
sudo systemctl status agentcop-scanner
sudo journalctl -u agentcop-scanner -f
```

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scan` | Submit code/description for scanning |
| GET | `/api/scan/{scan_id}` | Retrieve scan results |
| GET | `/scan/{scan_id}` | Shareable results page |
| GET | `/health` | Health check |

### POST /api/scan

```json
{
  "code": "def agent(user_input): ...",
  "description": "optional plain-text architecture description"
}
```

Response:
```json
{
  "scan_id": "A1B2C3D4",
  "score": 42,
  "case_number": "847291",
  "verdict": "Your agent is wide open...",
  "violations": [...]
}
```

## Architecture

```
agentcop-scanner/
  main.py           FastAPI app + Claude API integration
  static/
    index.html      React SPA (landing + results pages)
  scans.db          SQLite scan history (auto-created)
  requirements.txt
  start.sh
  agentcop-scanner.service
```
