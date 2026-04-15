"""
Little Canary microservice — wraps SecurityPipeline as a REST endpoint.
Called by server.js /api/canary proxy.

Install:  pip install flask little-canary
Run:      python python/canary_server.py
Port:     5001
"""

from flask import Flask, request, jsonify
from little_canary import SecurityPipeline

app = Flask(__name__)


def build_pipeline(model: str, mode: str, threshold: float) -> SecurityPipeline:
    return SecurityPipeline(
        canary_model=model,
        mode=mode,
        block_threshold=threshold,
        skip_canary_if_structural_blocks=True,
    )


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "little-canary"})


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(force=True)
    user_input = data.get("input", "")
    model     = data.get("model",     "qwen2.5:1.5b")
    mode      = data.get("mode",      "full")
    threshold = float(data.get("threshold", 0.6))

    if not user_input:
        return jsonify({"error": "Missing 'input' field"}), 400

    try:
        pipeline = build_pipeline(model, mode, threshold)
        verdict  = pipeline.check(user_input)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    advisory_payload = None
    if verdict.advisory and verdict.advisory.flagged:
        advisory_payload = {
            "flagged":       True,
            "severity":      verdict.advisory.severity,
            "system_prefix": verdict.advisory.to_system_prefix(),
        }

    return jsonify({
        "safe":     verdict.safe,
        "summary":  verdict.summary,
        "advisory": advisory_payload,
    })


if __name__ == "__main__":
    print("🐦 Little Canary service starting on http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
