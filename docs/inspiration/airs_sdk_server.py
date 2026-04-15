"""
AIRS Python SDK sidecar — port 5003

Wraps pan-aisecurity (aisecurity package) to expose:
  GET  /health       — SDK availability check
  POST /scan/sync    — single prompt/response scan via sync_scan()
  POST /scan/batch   — parallel scan of up to N prompts via ThreadPoolExecutor (5 workers)

The Node proxy (/api/airs-sdk/*) injects the API key from .env before forwarding here.
"""

import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify

# ── SDK import (graceful fallback if not installed) ──────────────────────────
SDK_AVAILABLE = False
SDK_ERROR = None

try:
    import aisecurity
    from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
    from aisecurity.scan.inline.scanner import Scanner
    from aisecurity.scan.models.content import Content
    SDK_AVAILABLE = True
except Exception as e:
    SDK_ERROR = str(e)

app = Flask(__name__)

# Protects aisecurity.init() which sets a global config
_init_lock = threading.Lock()


def init_and_get_scanner(api_key: str) -> "Scanner":
    """Init global SDK config then return a fresh Scanner instance."""
    with _init_lock:
        aisecurity.init(api_key=api_key)
    return Scanner()


def response_to_dict(resp) -> dict:
    """Convert SDK response object to a plain dict for JSON serialisation."""
    if hasattr(resp, "to_dict"):
        return resp.to_dict()
    if hasattr(resp, "model_dump"):
        return resp.model_dump()
    return vars(resp)


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"sdk_available": SDK_AVAILABLE, "sdk_error": SDK_ERROR})


@app.route("/scan/sync", methods=["POST"])
def scan_sync():
    if not SDK_AVAILABLE:
        return jsonify({"error": f"aisecurity SDK not installed — {SDK_ERROR}"}), 503

    data = request.get_json(force=True)
    api_key = data.get("api_key") or os.environ.get("AIRS_API_KEY", "")
    profile = data.get("profile", "")
    prompt = data.get("prompt", "")
    response_text = data.get("response") or None

    try:
        scanner = init_and_get_scanner(api_key)
        ai_profile = AiProfile(profile_name=profile)
        content = Content(prompt=prompt, response=response_text)
        result = scanner.sync_scan(ai_profile=ai_profile, content=content)
        return jsonify(response_to_dict(result))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/scan/batch", methods=["POST"])
def scan_batch():
    if not SDK_AVAILABLE:
        return jsonify({"error": f"aisecurity SDK not installed — {SDK_ERROR}"}), 503

    data = request.get_json(force=True)
    api_key = data.get("api_key") or os.environ.get("AIRS_API_KEY", "")
    profile = data.get("profile", "")
    prompts = data.get("prompts", [])

    if not prompts:
        return jsonify([])

    # Init SDK config once before spawning threads (sets global config)
    with _init_lock:
        aisecurity.init(api_key=api_key)

    results = [None] * len(prompts)

    def scan_one(idx: int, prompt_text: str):
        scanner = Scanner()  # Each thread gets its own Scanner instance
        ai_profile = AiProfile(profile_name=profile)
        content = Content(prompt=prompt_text)
        last_exc = None
        for attempt in range(3):
            try:
                result = scanner.sync_scan(ai_profile=ai_profile, content=content)
                return idx, response_to_dict(result)
            except Exception as e:
                last_exc = e
                if attempt < 2:
                    time.sleep(0.5 * (2 ** attempt))  # 0.5s, then 1.0s
        raise last_exc

    BATCH_WORKERS = 5
    with ThreadPoolExecutor(max_workers=BATCH_WORKERS) as executor:
        futures = {executor.submit(scan_one, i, p): i for i, p in enumerate(prompts)}
        for future in as_completed(futures):
            try:
                idx, result = future.result()
                results[idx] = result
            except Exception as e:
                idx = futures[future]
                results[idx] = {"error": str(e)}

    return jsonify(results)


if __name__ == "__main__":
    print("🐍 AIRS SDK sidecar starting on :5003")
    print(f"   SDK available: {SDK_AVAILABLE}")
    if SDK_ERROR:
        print(f"   SDK error: {SDK_ERROR}")
    app.run(port=5003, debug=False)
