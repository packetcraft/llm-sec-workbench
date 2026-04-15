#!/usr/bin/env bash
# start.sh — Native launcher for LLM Security Workbench (Python 3.11 venv)
#
# Usage:
#   ./start.sh            # native venv (default)
#   ./start.sh --docker   # docker compose path
#
set -euo pipefail

DOCKER_MODE=false
for arg in "$@"; do
    [[ "$arg" == "--docker" ]] && DOCKER_MODE=true
done

echo ""
echo " =========================================="
echo "  LLM Security Workbench — Starting Up"
echo " =========================================="
echo ""

# ── .env bootstrap ────────────────────────────────────────────────────────────
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo "[Setup] No .env found — copying .env.example to .env ..."
        cp .env.example .env
        echo "[Setup] .env created. Edit it to set PANW_API_KEY if needed."
    else
        echo "[Warning] Neither .env nor .env.example found. Continuing anyway."
    fi
else
    echo "[Setup] .env already exists. Skipping copy."
fi
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# DOCKER PATH
# ══════════════════════════════════════════════════════════════════════════════
if $DOCKER_MODE; then
    if ! docker info > /dev/null 2>&1; then
        echo "[Error] Docker is not running. Start Docker Desktop and retry."
        exit 1
    fi
    OLLAMA_URL="${OLLAMA_HOST:-http://localhost:11434}"
    if ! curl -s -o /dev/null -w "%{http_code}" "$OLLAMA_URL" 2>/dev/null | grep -q "200"; then
        echo "[Warning] Ollama not reachable at $OLLAMA_URL. LLM features will be unavailable."
        echo ""
    fi
    echo "[Docker] Running docker compose up --build -d ..."
    docker compose up --build -d
    echo ""
    echo "[Ready] Waiting for Streamlit to become healthy..."
    ATTEMPTS=0
    until curl -s -f http://localhost:8501/_stcore/health > /dev/null 2>&1; do
        ATTEMPTS=$((ATTEMPTS + 1))
        [ "$ATTEMPTS" -ge 20 ] && echo "[Timeout] Run: docker compose logs workbench" && exit 1
        sleep 3
    done
    if command -v open > /dev/null 2>&1; then open "http://localhost:8501"
    elif command -v xdg-open > /dev/null 2>&1; then xdg-open "http://localhost:8501"
    elif command -v wslview > /dev/null 2>&1; then wslview "http://localhost:8501"
    fi
    echo ""
    echo " Workbench running at http://localhost:8501  (stop: docker compose down)"
    echo ""
    exit 0
fi

# ══════════════════════════════════════════════════════════════════════════════
# NATIVE PATH (default)
# ══════════════════════════════════════════════════════════════════════════════

# ── 1. Locate Python 3.11 ─────────────────────────────────────────────────────
# py launcher (Windows/Git-Bash), then fall back to python3.11 (Linux/Mac)
if command -v py > /dev/null 2>&1 && py -3.11 --version > /dev/null 2>&1; then
    PYTHON="py -3.11"
elif command -v python3.11 > /dev/null 2>&1; then
    PYTHON="python3.11"
else
    echo "[Error] Python 3.11 not found."
    echo "        Install it from https://www.python.org/downloads/release/python-3119/"
    echo "        or run:  py --list  to see available versions."
    exit 1
fi
echo "[Python] Using: $($PYTHON --version)"

# ── 2. Create venv if it doesn't exist ───────────────────────────────────────
if [ ! -d "venv" ]; then
    echo "[Venv] Creating Python 3.11 virtual environment in ./venv ..."
    $PYTHON -m venv venv
    echo "[Venv] Created."
fi

# ── 3. Activate venv ─────────────────────────────────────────────────────────
# Works in Git Bash (Scripts/activate) and Mac/Linux (bin/activate)
if [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
elif [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    echo "[Error] Cannot find venv/Scripts/activate or venv/bin/activate."
    exit 1
fi
echo "[Venv] Activated: $(python --version)"

# ── 4. Install / sync dependencies ───────────────────────────────────────────
echo ""
echo "[Deps] Checking requirements.txt ..."
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo "[Deps] Dependencies OK."

# ── 5. Bootstrap spaCy model for presidio-analyzer ───────────────────────────
# en_core_web_lg is needed by the PII/secrets gates. Download once; skip if
# already present to avoid re-downloading (~750 MB) on every launch.
if ! python -c "import spacy; spacy.load('en_core_web_lg')" > /dev/null 2>&1; then
    echo ""
    echo "[spaCy] Downloading en_core_web_lg (~750 MB) — one-time setup ..."
    python -m spacy download en_core_web_lg
    echo "[spaCy] Model ready."
else
    echo "[spaCy] en_core_web_lg already installed. Skipping download."
fi

# ── 6. Check Ollama & pull required models ───────────────────────────────────
echo ""
OLLAMA_URL="${OLLAMA_HOST:-http://localhost:11434}"
if curl -s -o /dev/null -w "%{http_code}" "$OLLAMA_URL" 2>/dev/null | grep -q "200"; then
    # Pull qwen2.5:1.5b (Little Canary canary model) if not already present
    if ! ollama list 2>/dev/null | grep -q "qwen2.5:1.5b"; then
        echo "[Ollama] Pulling qwen2.5:1.5b (Little Canary canary model, ~934 MB) ..."
        ollama pull qwen2.5:1.5b
        echo "[Ollama] qwen2.5:1.5b ready."
    else
        echo "[Ollama] qwen2.5:1.5b already present."
    fi
else
    echo "[Warning] Ollama not reachable at $OLLAMA_URL."
    echo "          LLM features will be unavailable until Ollama is running."
    echo "          Download: https://ollama.com/download"
    echo ""
fi

# ── 7. Launch Streamlit ───────────────────────────────────────────────────────
echo "[Start] Launching Streamlit ..."
echo ""
echo " =========================================="
echo "  Workbench starting at http://localhost:8501"
echo "  Stop with: Ctrl+C"
echo " =========================================="
echo ""
streamlit run app.py
