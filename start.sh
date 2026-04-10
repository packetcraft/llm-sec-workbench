#!/usr/bin/env bash
set -euo pipefail

echo ""
echo " =========================================="
echo "  LLM Security Workbench — Starting Up"
echo " =========================================="
echo ""

# ── 1. Copy .env.example to .env if no .env exists ───────────────────────────
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo "[Setup] No .env file found. Copying .env.example to .env ..."
        cp .env.example .env
        echo "[Setup] .env created. Edit it to set your PANW_API_KEY if needed."
    else
        echo "[Warning] Neither .env nor .env.example found. Continuing without env file."
    fi
else
    echo "[Setup] .env already exists. Skipping copy."
fi

echo ""

# ── 2. Check that Docker is available ────────────────────────────────────────
if ! docker info > /dev/null 2>&1; then
    echo "[Error] Docker does not appear to be running."
    echo "        Please start Docker Desktop (or the Docker daemon) and re-run this script."
    exit 1
fi

# ── 3. Check that Ollama is reachable ─────────────────────────────────────────
echo "[Check] Verifying Ollama is reachable..."
OLLAMA_URL="${OLLAMA_HOST:-http://localhost:11434}"
if ! curl -s -o /dev/null -w "%{http_code}" "$OLLAMA_URL" 2>/dev/null | grep -q "200"; then
    echo "[Warning] Ollama does not appear to be running at $OLLAMA_URL."
    echo "          The app will start but LLM features will not work until Ollama is running."
    echo "          Download Ollama from: https://ollama.com/download"
    echo ""
fi

# ── 4. Start the stack with Docker Compose ───────────────────────────────────
echo "[Docker] Starting containers with docker compose up --build -d ..."
docker compose up --build -d

echo ""
echo "[Ready] Containers started. Waiting for Streamlit to become healthy..."
echo ""

# ── 5. Wait for Streamlit healthcheck ────────────────────────────────────────
ATTEMPTS=0
MAX_ATTEMPTS=20
until curl -s -f http://localhost:8501/_stcore/health > /dev/null 2>&1; do
    ATTEMPTS=$((ATTEMPTS + 1))
    if [ "$ATTEMPTS" -ge "$MAX_ATTEMPTS" ]; then
        echo "[Timeout] App did not become healthy after $((MAX_ATTEMPTS * 3)) seconds."
        echo "          Run: docker compose logs workbench"
        exit 1
    fi
    sleep 3
done

# ── 6. Open the browser ───────────────────────────────────────────────────────
URL="http://localhost:8501"
echo "[Open] Opening $URL ..."

# Cross-platform browser open
if command -v open > /dev/null 2>&1; then
    open "$URL"                          # macOS
elif command -v xdg-open > /dev/null 2>&1; then
    xdg-open "$URL"                      # Linux (X11)
elif command -v wslview > /dev/null 2>&1; then
    wslview "$URL"                       # WSL
else
    echo "[Info] Could not detect a browser opener. Navigate to $URL manually."
fi

echo ""
echo " =========================================="
echo "  Workbench is running at localhost:8501"
echo "  To stop:  docker compose down"
echo " =========================================="
echo ""
