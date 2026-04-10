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

## Step 5 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

> PyTorch is installed in **CPU-only** mode to prevent CUDA/ONNX conflicts and preserve GPU VRAM for Ollama.

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
- If you are on Python 3.13+ and packages fail to build (e.g. `sentencepiece`, `llm-guard`), use a Python 3.11 or 3.12 virtual environment — pre-built wheels are available for those versions. See [Using Python 3.11/3.12 via a virtual environment](#using-python-3113-12-via-a-virtual-environment) below.

---

## Using Python 3.11 via a virtual environment

Python 3.12+ may fail to build some packages (e.g. `thinc`, `sentencepiece`, `llm-guard`) because pre-built wheels are not yet available for those versions on Windows. **Python 3.11 is the recommended version** — all wheels are available and no compilation is required.

### 1. Install Python 3.11

Check if it is already available:

```bash
py --list
```

If `-V:3.11` appears, skip to step 2. If not, download the **Windows installer (64-bit)** from:

```
https://www.python.org/downloads/release/python-3119/
```

Run the installer and check **"Add python.exe to PATH"** on the first screen.

### 2. Verify the version is available

```bash
py -3.11 --version
```

### 3. Delete any existing venv and recreate with 3.11

```bash
rm -rf venv
py -3.11 -m venv venv
```

### 4. Activate the virtual environment

**Windows (Git Bash / MINGW):**
```bash
source venv/Scripts/activate
```

**Windows (PowerShell):**
```powershell
venv\Scripts\activate
```

**Mac / Linux:**
```bash
source venv/bin/activate
```

Your prompt will change to show `(venv)` when the environment is active.

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the app

```bash
python -m streamlit run app.py
```

> Always activate the virtual environment before working on this project. Run `deactivate` to exit it.

**Prisma AIRS gates return errors**
- Verify `PANW_API_KEY` is set correctly in `.env`.
- Cloud gates are designed to **fail open** (they log an error but never block the pipeline on a timeout).
