# Quick Start Guide

This guide walks you through getting LLM Security Workbench running on your local machine from scratch.

---

## Prerequisites

| Requirement | Version | Notes |
|:------------|:--------|:------|
| Python | 3.10+ | 3.11 recommended |
| [Ollama](https://ollama.com/download) | Latest | Must be running before starting the app |
| pip | Latest | `pip install --upgrade pip` |
| *(Optional)* Docker Desktop | Latest | Only required for containerized deployment |

> **GPU is not required.** All classifiers are configured to run on CPU/ONNX. GPU VRAM is reserved exclusively for Ollama inference.

---

## Step 1 — Install Ollama

Download and install Ollama from [https://ollama.com/download](https://ollama.com/download).

Verify it is running:

```bash
ollama list
```

If the command returns without error, Ollama is ready.

---

## Step 2 — Pull Required Models

The application needs the following models available in Ollama before first launch. Pull them now so the startup screen has nothing to download (or let the First Run screen handle it automatically):

```bash
# Primary target LLM
ollama pull llama3

# Safety moderation (Gate 3)
ollama pull llama-guard3

# Attacker/Defender LLM for Red Teaming (lightweight)
ollama pull phi3
```

> The First Run loading screen in the app will detect missing models and display live download progress so you know the app is not frozen.

---

## Step 3 — Clone the Repository

```bash
git clone https://github.com/your-org/llm-sec-workbench.git
cd llm-sec-workbench
```

---

## Step 4 — Configure Environment Variables

```bash
cp .env.example .env
```

Open `.env` and fill in your values:

| Variable | Description | Required |
|:---------|:------------|:---------|
| `OLLAMA_HOST` | URL of your Ollama instance | Yes |
| `PANW_API_KEY` | Palo Alto Networks AIRS key | Only for cloud gates |

For a native (non-Docker) run, change the `OLLAMA_HOST` to:

```env
OLLAMA_HOST="http://localhost:11434"
```

---

## Step 5 — Create a Virtual Environment and Install Dependencies

Always install into a virtual environment — never into the global Python installation.
**Python 3.11 is strongly recommended** (pre-built wheels for all dependencies are available).
Python 3.12+ may require compilation of some packages (`sentencepiece`, `thinc`, `llm-guard`).

### Create and activate the venv

**Windows (Git Bash / MINGW):**
```bash
py -3.11 -m venv venv
source venv/Scripts/activate
```

**Windows (PowerShell):**
```powershell
py -3.11 -m venv venv
venv\Scripts\activate
```

**Mac / Linux:**
```bash
python3.11 -m venv venv
source venv/bin/activate
```

Your prompt will show `(venv)` when the environment is active.

> If `py -3.11` is not found, see [Installing Python 3.11](#installing-python-311) below.

### Install dependencies

```bash
pip install -r requirements.txt
```

> PyTorch is installed in **CPU-only** mode to prevent CUDA/ONNX conflicts and preserve GPU VRAM for Ollama.

> **Always activate the venv before working on this project.** Run `deactivate` to exit it.

---

## Step 6 — Launch the Application

### Option A: 1-Click Scripts

**Windows:**
```bat
start.bat
```

**Mac / Linux:**
```bash
chmod +x start.sh
./start.sh
```

The script will:
1. Copy `.env.example` to `.env` if no `.env` exists.
2. Start the Streamlit app (or `docker-compose up` for the Docker path).
3. Open your browser to `http://localhost:8501`.

### Option B: Manual

```bash
streamlit run app.py
```

Then open [http://localhost:8501](http://localhost:8501) in your browser.

---

## Step 7 — Docker Deployment (Optional)

```bash
# Build and start the app container
docker-compose up --build

# Tear down
docker-compose down
```

The Compose file expects Ollama to be running on the **host machine** (not inside Docker). The `OLLAMA_HOST` in `.env` should remain set to `http://host.docker.internal:11434`.

---

## First-Run Experience

On the very first launch (or when required Ollama models are missing), the app will show a **First Run loading screen** instead of the main UI. It will:

- Display which models need to be pulled.
- Stream live download progress from `ollama pull` so you can see exactly what is happening.
- Redirect to the main application automatically once all models are ready.

---

## Gate Configuration

By default, all gates start in `AUDIT` mode. You can change each gate independently via the sidebar:

| Mode | Behavior |
|:-----|:---------|
| `OFF` | Gate is skipped entirely (zero latency cost) |
| `AUDIT` | Gate scans and logs results, but never blocks the pipeline |
| `ENFORCE` | Gate blocks the pipeline and returns a refusal on any violation |

---

## Agentic Security Setup

The Agentic Security Monitor intercepts Claude Code tool calls (Bash, Edit, Write, WebFetch) using Claude Code hook events, classifies them with a local Ollama guard model, and writes structured audit records to `audit/`. The dedicated **Agentic Security** view in the app lets you review and query the full audit history.

> This setup is **independent of the main chatbot pipeline**. You do not need the chatbot models pulled or Ollama running for the Agentic Security UI — it reads from local JSONL files only.

### Step A — Pull the Guard Model

The hook uses a small, fast model to stay below the synchronous latency budget (sub-200ms target):

```bash
ollama pull qwen2.5:1.5b
```

Fallback if VRAM is constrained:

```bash
ollama pull tinyllama
```

Update `config.yaml` to match whichever model you pulled:

```yaml
agentic:
  guard_model: "qwen2.5:1.5b"   # or "tinyllama"
```

### Step B — Register the Hooks

Claude Code hooks are configured in `.claude/settings.json`. This file is gitignored (kept local). Copy the committed template:

**Windows (Git Bash):**
```bash
cp hooks/settings.template.json .claude/settings.json
```

**Windows (PowerShell):**
```powershell
Copy-Item hooks\settings.template.json .claude\settings.json
```

This registers `PreToolUse` hooks for `Bash`, `Edit`, `Write`, and `WebFetch`, plus a `PostToolUse` hook for `Bash` (output exfiltration audit).

> **Note:** `.claude/settings.json` may already exist with your permission rules in `settings.local.json`. The hooks file is separate — both files are read by Claude Code independently.

### Step C — Understand `audit_only` Mode

By default the hook runs in **audit-only mode** (`audit_only: true` in `config.yaml`). In this mode:

| Verdict | What happens |
|:--------|:-------------|
| `ALLOW` | Tool call proceeds. Logged. |
| `ALLOWLISTED` | Tool call proceeds. Logged. No Ollama call made. |
| `BLOCK` | Tool call **proceeds** (not blocked). Logged as "would have blocked". Stderr shows `[agentic-guard] AUDIT: would have blocked — <reason>`. |
| `ERROR` | Ollama unreachable or timed out. Tool call proceeds. Logged. |

Switch to enforcement mode when you want BLOCK verdicts to actually prevent tool calls:

```yaml
agentic:
  audit_only: false   # exit 2 on BLOCK — Claude Code cancels the tool call
```

**Recommendation:** Keep `audit_only: true` during active development. Switch to `false` for security review sessions.

### Step D — Verify the Hook Fires

Start a Claude Code session in this project:

```bash
claude
```

Ask Claude anything that triggers a tool call — for example:
> "What's the current git branch?"

Then check the audit directory:

```bash
ls audit/
```

A file named `audit/{session_id}.jsonl` should appear (UUID-style name from Claude Code's session). Inspect it:

```bash
python -c "
import json, sys
fname = sys.argv[1]
with open(fname) as f:
    for line in f:
        r = json.loads(line)
        print(r['event_type'], '|', r.get('tool_name',''), '|', r.get('verdict',''), '|', r.get('latency_ms',''), 'ms')
" audit/<your-session-id>.jsonl
```

The first line should be `SESSION_START` followed by `TOOL_CALL` records with verdicts of `ALLOWLISTED`, `ALLOW`, `BLOCK`, or `ERROR`.

### Step E — Open the Agentic Security View

```bash
streamlit run app.py
```

Navigate to **Agentic Security** in the sidebar. Three tabs:

| Tab | Purpose |
|:----|:--------|
| **Live Feed** | Auto-refreshing table of the 50 most recent hook events |
| **Audit Explorer** | Filter by session, tool, verdict, date, keyword — click rows for detail |
| **Dashboard** | Aggregate KPIs, block rate trend, latency histogram, session timeline |

### Agentic Security Troubleshooting

**`audit/` directory is empty after a Claude Code session**
- Confirm `.claude/settings.json` exists and contains the hook matchers.
- Confirm `qwen2.5:1.5b` (or your configured `guard_model`) is pulled: `ollama list`.
- Run a command that triggers a tool call (e.g. ask Claude to read a file) — `git status` is allowlisted and still creates a record.

**Hook creates a file but with a UUID name, not my test `$SID`**
- Expected. Claude Code assigns its own session ID. The UUID is the real session ID for that Claude Code invocation. Use `ls audit/` to find the file and inspect it directly.

**Everything is `verdict: ERROR` with `"timeout after 5000ms"`**
- Ollama is not running or the guard model is not pulled.
- Start Ollama: `ollama serve` (or open the Ollama desktop app).
- Pull the model: `ollama pull qwen2.5:1.5b`.
- The hook fails open on error — tool calls are never blocked, but no classification is logged.

**Hook is blocking my Edit/Write tool calls**
- You are in enforcement mode (`audit_only: false`) and the guard model is flagging file edits.
- Switch to `audit_only: true` in `config.yaml` during development.
- Alternatively, remove the `Edit` and `Write` matchers from `.claude/settings.json` to limit hook coverage to `Bash` and `WebFetch` only.

**`ZoneInfoNotFoundError` in the Streamlit UI**
- Windows does not ship timezone data. The app uses `datetime.now().astimezone()` to avoid this — ensure you are running the latest code (`git pull`).

---

## Troubleshooting

**App shows "Connection refused" when calling Ollama**
- Confirm Ollama is running: `ollama list`
- Check that `OLLAMA_HOST` in `.env` matches where Ollama is listening.
- If using Docker, ensure it is set to `http://host.docker.internal:11434`, not `localhost`.

**Out-of-memory / VRAM crash during inference**
- Only one Ollama model should be loaded at a time. The app is designed to use a single Ollama instance with internal queuing.
- Check the VRAM telemetry panel to see which models are resident.

**`llm-guard` or `transformers` install errors**
- Ensure you are using Python 3.10+.
- Run `pip install --upgrade pip setuptools wheel` before re-running `pip install -r requirements.txt`.
- If you are on Python 3.12+ and packages fail to build (e.g. `sentencepiece`, `llm-guard`), use Python 3.11 — pre-built wheels are available for that version. See [Installing Python 3.11](#installing-python-311) below.

---

## Installing Python 3.11

Check if it is already available:

```bash
py --list
```

If `-V:3.11` appears, you are ready — go back to [Step 5](#step-5--create-a-virtual-environment-and-install-dependencies).

If not, download the **Windows installer (64-bit)** from:

```
https://www.python.org/downloads/release/python-3119/
```

Run the installer and check **"Add python.exe to PATH"** on the first screen. Then verify:

```bash
py -3.11 --version
```

**Prisma AIRS gates return errors**
- Verify `PANW_API_KEY` is set correctly in `.env`.
- Cloud gates are designed to **fail open** (they log an error but never block the pipeline on a timeout).
