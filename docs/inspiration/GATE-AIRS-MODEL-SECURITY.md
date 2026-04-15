# AIRS Model Security — Technical Reference

> **Scope:** Complete technical reference for the 🔍 Model Security scanner in this workbench. Covers the SDK-based sidecar architecture, private PyPI bootstrap, credentials, request/response schema, and UI integration.
> For runtime prompt/response security, see **[`docs/GATE-AIRS.md`](GATE-AIRS.md)**.
> For setup instructions, see **[`docs/SETUP-GUIDE-FULL.md`](SETUP-GUIDE-FULL.md)**.

---

## What Model Security Is

**AIRS Model Security** scans AI model artifacts — weights, tokenizer files, config files — for supply-chain threats *before or after deployment*. This is a different threat surface from runtime security:

| | Runtime Security (AIRS-Inlet / AIRS-Dual) | Model Security |
| :--- | :--- | :--- |
| **What is scanned** | Prompts and responses at inference time | Model files and artifacts |
| **When it runs** | Every chat turn (automatic) | On-demand |
| **Threat category** | Prompt injection, DLP, jailbreak | Malicious code, backdoors, supply-chain tampering |
| **Credentials** | `AIRS_API_KEY` | OAuth2 client credentials (separate) |
| **Sidecar port** | None | `:5004` |

### What it detects

- **Malicious code injection** — pickle exploits, `__reduce__` overrides, deserialization bombs embedded in model files
- **Backdoors and trojans** — hidden behaviours triggered by specific inputs at inference time
- **Supply-chain tampering** — weights or configs modified after original publication
- **Policy violations** — violations of security rules configured in the AIRS console
- **Unsafe serialisation formats** — formats known to allow arbitrary code execution on model load

---

## Architecture

```
Browser (8b UI — Model Security pane)
    │  POST /api/model-scan  { model_id: "google/flan-t5-small" }
    ▼
src/server.js  :3080
    │  forwards to http://localhost:5004/scan/hf
    ▼
services/airs-model-scan/model_scan_server.py  :5004
    │  normalises model_id → https://huggingface.co/google/flan-t5-small
    │  calls ModelSecurityAPIClient.scan(security_group_uuid, model_uri)
    ▼
model-security-client SDK  (private PyPI package)
    │  OAuth2 client_credentials → access token
    │  POST https://api.sase.paloaltonetworks.com/aims  (model scan API)
    ▼
Result: { eval_outcome, ... } — Pydantic v2 model, serialised as JSON
    ▼
server.js returns result to browser
    ▼
8b UI: status pill + metrics + violations list + raw JSON
```

**This gate uses its own Python sidecar** — like LLM-Guard and Little-Canary, it must be running before scans will work. The sidecar wraps the private `model-security-client` SDK which handles OAuth2 token acquisition internally.

---

## Setup

> **Run all commands from the project root** (`llm-security-workbench/`) unless stated otherwise.
> **Windows users:** use Git Bash for all shell commands below.

---

### Step 1 — Get credentials from the AIRS console

Model Security uses **OAuth2 client credentials** — these are separate from the `AIRS_API_KEY` used for runtime security. Get them from the Palo Alto AI Model Security console:

| Credential | Where to find it |
| :--- | :--- |
| `MODEL_SECURITY_CLIENT_ID` | Prisma Cloud → AI Model Security → API Credentials |
| `MODEL_SECURITY_CLIENT_SECRET` | Same page — shown once at creation time |
| `TSG_ID` | Tenant Service Group ID — visible in the console URL or tenant settings |
| `SECURITY_GROUP_UUID_HF` | AI Model Security → Security Groups → select your HuggingFace group → copy UUID |
| `SECURITY_GROUP_UUID_LOCAL` | Same — select your local model scanning group → copy UUID (optional) |

---

### Step 2 — Add credentials to `.env`

Open `.env` in the project root (copy from `.env.example` if it doesn't exist yet) and add:

```env
MODEL_SECURITY_CLIENT_ID=your-client-id
MODEL_SECURITY_CLIENT_SECRET=your-client-secret
TSG_ID=your-tsg-id
SECURITY_GROUP_UUID_HF=your-hf-security-group-uuid
SECURITY_GROUP_UUID_LOCAL=your-local-security-group-uuid
MODEL_SECURITY_API_ENDPOINT=https://api.sase.paloaltonetworks.com/aims
```

---

### Step 3 — Create the Python virtual environment

```bash
# py: This is a utility specific to WINDOWS installations of Python.
py -3.12 -m venv services/airs-model-scan/.venv

# python3: This is the standard command for **macOS and Linux.**
python3.12 -m venv services/airs-model-scan/.venv
```

> **Python 3.12 is required** — the same version as LLM-Guard. Do not use 3.13 or 3.14.

Verify:
```bash
# Windows
services/airs-model-scan/.venv/Scripts/python --version
# Python 3.12.x


# macOS
services/airs-model-scan/.venv/bin/python --version
```

---

### Step 4 — Install base dependencies

```bash
# Windows
services/airs-model-scan/.venv/Scripts/pip install flask python-dotenv

# MacOS
services/airs-model-scan/.venv/bin/pip install flask python-dotenv
```

---

### Step 5 — Get the private PyPI URL

The `model-security-client` SDK is **not on public PyPI** — it lives on an authenticated private index. The included script handles the OAuth2 flow to retrieve the URL.

First load your credentials into the shell:
```bash
set -a && source .env && set +a
```

Then run the script:
```bash
PYPI_URL=$(bash services/airs-model-scan/getPYPIurl.sh)
echo "PyPI URL: $PYPI_URL"
```

You should see a URL printed. If it prints empty or an error, check that `MODEL_SECURITY_CLIENT_ID`, `MODEL_SECURITY_CLIENT_SECRET`, and `TSG_ID` are all exported (re-run the `set -a && source .env && set +a` line).

---

### Step 6 — Install the SDK from the private index

```bash
# Windows
services/airs-model-scan/.venv/Scripts/pip install model-security-client --extra-index-url "$PYPI_URL"
# MacOS
services/airs-model-scan/.venv/bin/pip install model-security-client --extra-index-url "$PYPI_URL"
```

The real package is larger than the public stub (1.5 kB). Confirm the correct version installed:
```bash
services/airs-model-scan/.venv/Scripts/pip show model-security-client
```

---

### Step 7 — Verify with the CLI scan tool

Before starting the full sidecar, confirm the SDK and credentials work end-to-end:

```bash
# Windows
services/airs-model-scan/.venv/Scripts/python services/airs-model-scan/hf-scan.py google/flan-t5-small
# MacOS
services/airs-model-scan/.venv/bin/python services/airs-model-scan/hf-scan.py google/flan-t5-small
```

Expected output:
```
🚀 Initiating scan for: https://huggingface.co/google/flan-t5-small
Scan completed: SAFE

{
  "eval_outcome": "SAFE",
  ...
}
```

Try the known-malicious model too:
```bash
# Windows
services/airs-model-scan/.venv/Scripts/python services/airs-model-scan/hf-scan.py opendiffusion/sentimentcheck
# MacOS
services/airs-model-scan/.venv/bin/python services/airs-model-scan/hf-scan.py opendiffusion/sentimentcheck
```

Expected: `eval_outcome` is something other than `SAFE` with violations present.

---

### Step 8 — Start the sidecar

```bash
npm run model-scan
```

Expected output:
```
🔍 AIRS Model Security sidecar running on http://localhost:5004
   Base URL   : https://api.sase.paloaltonetworks.com/aims
   HF UUID    : <your-uuid>
   Local UUID : <your-uuid>
```

Verify health:
```bash
curl http://localhost:5004/health
# → { "status": "ok", "service": "airs-model-scan", "sdk_available": true, "sdk_error": null }
```

The 🔍 icon in the 8b nav panel shows a **green dot** when the sidecar is online with the SDK loaded, and a **grey dot** when offline or the SDK is not installed.

---

### Step 9 — Use the UI

1. Ensure `npm start` is running (Node proxy on `:3080`)
2. Open `http://localhost:3080/dev/8b`
3. Click the **🔍** icon in the left rail
4. Click `google/flan-t5-small` → **Scan**

Results appear in the status pill, metrics row, and raw JSON panel.

---

### Docker Compose Setup

If you are running the workbench using `docker compose`, you can install the private SDK into the running container using the following steps:

1. **Get the private PyPI URL** (from your host shell):
   ```bash
   set -a && source .env && set +a
   PYPI_URL=$(bash services/airs-model-scan/getPYPIurl.sh)
   ```

2. **Install the SDK into the running container**:
   ```bash
   docker compose exec model-scan pip install model-security-client --extra-index-url "$PYPI_URL"
   ```

3. **Restart the service to reload the SDK**:
   ```bash
   docker compose restart model-scan
   ```

4. **Verify**:
   ```bash
   curl http://localhost:5004/health
   ```
   `sdk_available` should be `true`.

> [!NOTE]
> This installation is **ephemeral**. If you rebuild the image (e.g., using `--build`), it will be lost and you will need to repeat these steps.

---

### Troubleshooting

| Symptom | Likely cause | Fix |
| :--- | :--- | :--- |
| `PYPI_URL` is empty | Credentials not exported | Re-run `set -a && source .env && set +a` then retry |
| `ModuleNotFoundError: No module named 'model_security_client.api'` | Stub from public PyPI installed | `pip uninstall model-security-client -y` then redo Steps 5–6 |
| `sdk_available: false` in health response | SDK not installed in the venv | Redo Steps 5–6 and restart `npm run model-scan` |
| `502` from `/api/model-scan` | Sidecar not running | Run `npm run model-scan` in a separate terminal |
| `SECURITY_GROUP_UUID_HF not set` | Missing env var | Add to `.env` and restart sidecar |
| `⚠️ An error occurred` in CLI scan | Wrong UUID or no entitlement | Verify UUID in AIRS console; confirm Model Security is enabled on your account |

---

## CLI Scripts

Three standalone scripts in `services/airs-model-scan/` can be run directly inside the venv. Use them to verify credentials and the SDK work before starting the full sidecar.

| Script | What it does |
| :--- | :--- |
| `getPYPIurl.sh` | Gets the private PyPI URL from the AIRS auth API — pipe output to `pip install --extra-index-url` |
| `hf-scan.py` | Scans a HuggingFace model from the command line |
| `local-scan.py` | Scans a local model directory from the command line |

```bash
# Verify HuggingFace scanning works
.venv/Scripts/python services/airs-model-scan/hf-scan.py google/flan-t5-small

# Verify local scanning works
.venv/Scripts/python services/airs-model-scan/local-scan.py /path/to/model
```

Both scripts accept bare `author/model-name` or a full `https://huggingface.co/...` URL. They print `eval_outcome` and the full JSON result to stdout.

---

## SDK Reference

### Package

```
model-security-client   (private PyPI — see bootstrap above)
```

### Client construction

```python
from model_security_client.api import ModelSecurityAPIClient

client = ModelSecurityAPIClient(
    base_url="https://api.sase.paloaltonetworks.com/aims"
)
```

The client reads `MODEL_SECURITY_CLIENT_ID`, `MODEL_SECURITY_CLIENT_SECRET`, and `TSG_ID` from the environment automatically after `load_dotenv()`. No credentials are passed to the constructor.

### Scan a HuggingFace model

```python
result = client.scan(
    security_group_uuid="<SECURITY_GROUP_UUID_HF>",
    model_uri="https://huggingface.co/google/flan-t5-small"
)
```

### Response

The result is a **Pydantic v2 model**. Key fields:

| Field | Type | Description |
| :--- | :--- | :--- |
| `eval_outcome` | str | Top-level verdict — e.g. `"SAFE"`, `"UNSAFE"` |
| *(full schema)* | — | Use `result.model_dump_json(indent=2)` to see all fields — the full schema is defined inside the private package |

The sidecar returns `json.loads(result.model_dump_json())` — the complete Pydantic model as a plain JSON dict.

---

## Sidecar API

**File:** `services/airs-model-scan/model_scan_server.py`
**Port:** `5004`

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/health` | GET | Returns `{ status, service, sdk_available, sdk_error }` |
| `/scan/hf` | POST | Scans a HuggingFace model |

**`POST /scan/hf` — request:**
```json
{ "model_id": "google/flan-t5-small" }
```
or equivalently:
```json
{ "model_uri": "https://huggingface.co/google/flan-t5-small" }
```

Both forms are accepted. `model_id` (bare `author/model-name`) is normalised to a full URL internally.

**`POST /scan/hf` — response:**
```json
{
  "eval_outcome": "SAFE",
  ...
}
```

---

## Node Proxy Routes

| Route | Description |
| :--- | :--- |
| `GET /api/model-scan/health` | Proxies to `:5004/health` — used by the UI status dot |
| `POST /api/model-scan` | Proxies to `:5004/scan/hf` — used by the Scan button |

Both routes are in `src/server.js`. If the sidecar is not running, the proxy returns `502` with a message telling you to run `npm run model-scan`.

---

## Pre-configured Model Cards

Two models are hardcoded in the UI as quick-select shortcuts:

| Model | Expected verdict | Purpose |
| :--- | :--- | :--- |
| `google/flan-t5-small` | ✅ SAFE | Baseline test — confirms scanner is working on a known-clean model |
| `opendiffusion/sentimentcheck` | ⚠ Malicious | Positive test — confirms scanner correctly flags a known-malicious model |

---

## Model Security vs Runtime Security

| Dimension | Runtime Security | Model Security |
| :--- | :--- | :--- |
| Pipeline position | Gates 1 and 6 | Standalone panel — not in the chat pipeline |
| Credentials | `AIRS_API_KEY` (x-pan-token) | OAuth2 client credentials |
| Sidecar | None | `:5004` (Python SDK wrapper) |
| Scans | Prompts + responses | Model artifacts |
| Frequency | Every message automatically | On-demand |
| Blocking | Blocks individual chat turns | Reports only — does not block chat |

---

## Limitations

- **HuggingFace only.** The workbench UI supports HuggingFace Hub scanning only. Local file path scanning is implemented in the sidecar (`/scan/local` not yet wired to the UI).
- **Private PyPI.** The `model-security-client` package requires the three-step bootstrap above. The sidecar will start without it but every scan will return a `503` with the install instructions.
- **Separate entitlement.** Model Security is a separate AIRS product. If your account does not have it, the OAuth2 token request or the scan call will return an auth or entitlement error.
- **Scan latency.** Model scanning is not real-time — large models (>1 GB) may take minutes. The UI shows a spinner but does not stream progress.
- **No pipeline integration.** Model Security results do not appear in the API Inspector, Live Telemetry, or Red Teaming panels.
