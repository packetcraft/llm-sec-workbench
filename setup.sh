#!/usr/bin/env bash
# setup.sh — one-shot native environment setup for LLM Security Workbench
# Run once on a fresh clone:  bash setup.sh
set -euo pipefail

echo ""
echo " =========================================="
echo "  LLM Security Workbench — Native Setup"
echo " =========================================="
echo ""

# ── 1. Require Python 3.11 ────────────────────────────────────────────────────
if command -v py &> /dev/null && py -3.11 --version &> /dev/null; then
    PYTHON="py -3.11"
elif command -v python3.11 &> /dev/null; then
    PYTHON="python3.11"
else
    echo "[Error] Python 3.11 not found."
    echo "        Install it from https://www.python.org/downloads/release/python-3119/"
    echo "        Then re-run this script."
    exit 1
fi

echo "[Python] Using: $($PYTHON --version)"

# ── 2. Create virtual environment ─────────────────────────────────────────────
if [ -d "venv" ]; then
    echo "[venv]   Already exists — skipping creation."
else
    echo "[venv]   Creating virtual environment with Python 3.11..."
    $PYTHON -m venv venv
    echo "[venv]   Created."
fi

# ── 3. Activate venv ──────────────────────────────────────────────────────────
if [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate   # Windows (Git Bash / MINGW)
else
    source venv/bin/activate       # macOS / Linux
fi

echo "[venv]   Active: $(python --version)"

# ── 4. Upgrade pip ────────────────────────────────────────────────────────────
echo "[pip]    Upgrading pip..."
python -m pip install --upgrade pip --quiet

# ── 5. Install dependencies ───────────────────────────────────────────────────
echo "[pip]    Installing requirements (this may take a few minutes)..."
pip install -r requirements.txt \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    --quiet

echo "[pip]    All dependencies installed."

# ── 6. Copy .env if missing ───────────────────────────────────────────────────
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "[env]    .env created from .env.example."
        echo "         Edit it and set OLLAMA_HOST=http://localhost:11434 for native runs."
    fi
else
    echo "[env]    .env already exists — skipping."
fi

# ── 7. Done ───────────────────────────────────────────────────────────────────
echo ""
echo " =========================================="
echo "  Setup complete."
echo ""
echo "  To start the app:"
echo "    source venv/Scripts/activate   # Windows"
echo "    source venv/bin/activate       # macOS / Linux"
echo "    python -m streamlit run app.py"
echo " =========================================="
echo ""
