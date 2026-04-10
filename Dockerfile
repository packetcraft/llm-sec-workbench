# ── Stage: runtime ────────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="LLM Security Workbench"
LABEL org.opencontainers.image.description="Locally-hosted LLM security pipeline and red-team workbench"

# Prevents Python from writing .pyc files and buffers stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install OS-level deps (curl for healthcheck, ca-certs for cloud API TLS)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Dependencies ──────────────────────────────────────────────────────────────
# Copy requirements first so Docker layer cache is reused when only app code changes.
COPY requirements.txt .

# Install CPU-only PyTorch explicitly before the rest of requirements.txt
# to avoid the full CUDA wheel being pulled in by a transitive dependency.
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements.txt

# ── Application code ──────────────────────────────────────────────────────────
COPY . .

# ── Runtime config ────────────────────────────────────────────────────────────
# The .env file is bind-mounted at runtime (see docker-compose.yml).
# Never bake secrets into the image.
EXPOSE 8501

# Streamlit healthcheck — container is ready once the HTTP server responds.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Run the Streamlit app.
# --server.address=0.0.0.0 is required so the port is reachable from the host.
ENTRYPOINT ["streamlit", "run", "app.py", \
    "--server.port=8501", \
    "--server.address=0.0.0.0", \
    "--server.headless=true"]
