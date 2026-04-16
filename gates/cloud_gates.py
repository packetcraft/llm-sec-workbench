"""
gates/cloud_gates.py
─────────────────────
Cloud-tier security gates backed by Palo Alto Networks AIRS
(AI Runtime Security).

Both gates share the same API endpoint:
  POST https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request

Authentication: x-pan-token header.
  Priority: ``api_key`` config key → ``AIRS_API_KEY`` env var → ``PANW_API_KEY`` env var.
  When no key is found, both gates degrade gracefully to SKIP — all local
  gates run unaffected.

Gates
-----
AIRSInletGate  (``airs_inlet``)
    Scans the user PROMPT before LLM inference.
    Fail-CLOSED: on API errors the gate sets ``is_blocked=True`` and records
    an ERROR metric.  In ENFORCE mode this halts the pipeline so a
    configuration/credential problem surfaces immediately rather than being
    silently bypassed.  In AUDIT mode the PipelineManager's standard AUDIT
    semantics clear ``is_blocked`` and the pipeline continues.

AIRSDualGate  (``airs_dual``)
    Scans the LLM RESPONSE (with original prompt as context) after generation.
    Fail-OPEN: on API errors the gate records an ERROR metric but the response
    is never withheld — inference already happened.
    DLP masking: when AIRS returns ``response_masked_data``, the gate replaces
    ``payload.output_text`` with the redacted version and records a
    ``DLP_MASK`` verdict (even when ``action`` is ``"allow"``).

Reference: docs/inspiration/GATE-AIRS.md
"""

from __future__ import annotations

import os
import time

import httpx

from core.payload import PipelinePayload
from gates.base_gate import SecurityGate

# ── AIRS endpoint ─────────────────────────────────────────────────────────────

_AIRS_ENDPOINT = (
    "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"
)

# ── Threat flag → human-readable label maps ────────────────────────────────────

_PROMPT_FLAG_LABELS: dict[str, str] = {
    "injection":      "Prompt Injection",
    "agent":          "Agent System Abuse",
    "dlp":            "Sensitive Data (DLP)",
    "toxic_content":  "Toxic Content",
    "malicious_code": "Malicious Code",
    "url_cats":       "Unsafe URL",
    "ip_reputation":  "IP Reputation",
    "malware":        "Malware",
}

_RESPONSE_FLAG_LABELS: dict[str, str] = {
    "dlp":            "Sensitive Data (DLP)",
    "toxic_content":  "Toxic Content",
    "malicious_code": "Malicious Code",
    "url_cats":       "Unsafe URL",
    "db_security":    "Database Security Risk",
    "ungrounded":     "Hallucination / Ungrounded",
    "ip_reputation":  "IP Reputation",
    "malware":        "Malware",
}


# ── Internal helpers ──────────────────────────────────────────────────────────

_PLACEHOLDER_PREFIXES = (
    "your_",
    "your-",
    "<",
    "xxx",
    "placeholder",
    "example",
    "changeme",
)


def _resolve_api_key(config_key: str) -> str:
    """Return the AIRS API key from config, then env vars (AIRS_API_KEY / PANW_API_KEY).

    Filters out obvious placeholder values (strings that start with ``your_``,
    ``your-``, ``<``, etc.) so a copied-but-not-filled ``.env.example`` does not
    cause live API calls with a dummy key.
    """
    for candidate in (
        config_key.strip(),
        os.getenv("AIRS_API_KEY", "").strip(),
        os.getenv("PANW_API_KEY", "").strip(),
    ):
        if candidate and not any(
            candidate.lower().startswith(p) for p in _PLACEHOLDER_PREFIXES
        ):
            return candidate
    return ""


def _format_flags(detected: dict, label_map: dict[str, str], details: dict | None = None) -> str:
    """Return a comma-separated list of triggered threat labels.

    Enriches ``toxic_content`` with sub-category names when available in
    ``toxic_content_details.toxic_categories`` (AIRS v1 format).
    """
    toxic_cats: list[str] = []
    if details:
        toxic_cats = (
            details.get("toxic_content_details", {}).get("toxic_categories", [])
        )
    parts: list[str] = []
    for key, v in detected.items():
        if not v:
            continue
        label = label_map.get(key, key)
        if key == "toxic_content" and toxic_cats:
            label = f"Toxic Content ({', '.join(toxic_cats)})"
        parts.append(label)
    return ", ".join(parts) if parts else "none"


def _airs_request(
    api_key: str,
    profile: str,
    contents: list[dict],
    ai_model: str = "",
    timeout: float = 30.0,
    max_retries: int = 2,
) -> dict:
    """POST to the AIRS sync-scan endpoint with retry logic.

    Retries up to ``max_retries`` times on 5xx errors with a 500 ms fixed
    delay.  4xx errors (auth, bad request) are not retried.

    Returns
    -------
    dict
        Parsed JSON response body.

    Raises
    ------
    httpx.HTTPStatusError
        On 4xx responses.
    Exception
        On persistent 5xx or network failure after all retries.
    """
    tr_id = f"wb-{int(time.time() * 1000)}"
    body = {
        "tr_id":       tr_id,
        "ai_profile":  {"profile_name": profile},
        "metadata":    {"ai_model": ai_model or "unknown", "app_name": "LLM Security Workbench"},
        "contents":    contents,
    }
    headers = {
        "Content-Type": "application/json",
        "x-pan-token":  api_key,
    }

    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            resp = httpx.post(_AIRS_ENDPOINT, json=body, headers=headers, timeout=timeout)
            if resp.status_code >= 500 and attempt < max_retries:
                last_exc = httpx.HTTPStatusError(
                    f"AIRS HTTP {resp.status_code}",
                    request=resp.request,
                    response=resp,
                )
                time.sleep(0.5)
                continue
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError:
            raise                  # 4xx — surface immediately, don't retry
        except Exception as exc:   # timeout, network, etc.
            last_exc = exc
            if attempt < max_retries:
                time.sleep(0.5)
    raise last_exc or RuntimeError("AIRS request failed")


# ── Gate implementations ──────────────────────────────────────────────────────

class AIRSInletGate(SecurityGate):
    """Input gate — cloud prompt scan via Palo Alto Networks AIRS.

    Evaluates the user prompt against the configured AI security profile
    BEFORE it reaches the LLM.  Covers threat categories not detectable
    locally: URL/IP reputation, cloud DLP policy, agent abuse patterns, and
    custom AIRS profile rules.

    Fail behaviour — CLOSED
    -----------------------
    On any API error (network failure, 5xx, auth, parse error) the gate sets
    ``is_blocked=True`` and records an ERROR metric.

    - **ENFORCE mode** (recommended for production): pipeline halts.  The error
      surfaces immediately so misconfigured credentials are not silently ignored.
    - **AUDIT mode**: the PipelineManager clears ``is_blocked`` (standard AUDIT
      semantics) and the pipeline continues.

    Contrast with all local gates, which are fail-OPEN.

    Graceful degradation
    --------------------
    When no API key is available (``api_key`` config, ``AIRS_API_KEY`` env,
    and ``PANW_API_KEY`` env are all empty), the gate appends a SKIP metric
    and returns immediately — no network call is made.

    Config keys
    -----------
    api_key : str   x-pan-token.  Falls back to ``AIRS_API_KEY`` / ``PANW_API_KEY``
                    env vars when empty.
    profile : str   AI security profile name (Strata Cloud Manager).
                    Default: ``"default"``.
    timeout : float HTTP timeout in seconds.  Default: ``30.0``.
    ai_model: str   Target model name forwarded to AIRS metadata (informational).
    """

    @property
    def name(self) -> str:
        return "airs_inlet"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        t_start  = time.perf_counter()
        api_key  = _resolve_api_key(str(self.config.get("api_key", "")))
        profile  = str(self.config.get("profile",  "default")).strip() or "default"
        timeout  = float(self.config.get("timeout", 30.0))
        ai_model = str(self.config.get("ai_model", ""))

        # ── No API key → SKIP ─────────────────────────────────────────────────
        if not api_key:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": 0,
                "score":      0.0,
                "verdict":    "SKIP",
                "detail":     (
                    "AIRS Inlet: no API key configured. "
                    "Set AIRS_API_KEY in .env or enter it in the sidebar "
                    "to activate cloud prompt scanning."
                ),
            })
            return payload

        # ── API call ──────────────────────────────────────────────────────────
        try:
            result = _airs_request(
                api_key  = api_key,
                profile  = profile,
                contents = [{"prompt": payload.original_input}],
                ai_model = ai_model,
                timeout  = timeout,
            )
        except httpx.HTTPStatusError as exc:
            latency_ms = round((time.perf_counter() - t_start) * 1000, 2)
            status_code = exc.response.status_code if exc.response is not None else 0
            if status_code in (401, 403):
                # Auth failure = key invalid/missing → degrade to SKIP, not fail-closed ERROR.
                # This prevents a bad placeholder key from hard-blocking in ENFORCE mode.
                payload.metrics.append({
                    "gate_name":  self.name,
                    "latency_ms": latency_ms,
                    "score":      0.0,
                    "verdict":    "SKIP",
                    "detail":     (
                        f"AIRS Inlet: authentication failed (HTTP {status_code}) — "
                        "check that AIRS_API_KEY in .env is a valid x-pan-token."
                    ),
                })
                payload.raw_traces[self.name] = {
                    "request":  {"profile": profile},
                    "response": {"error": f"HTTP {status_code} Forbidden/Unauthorized"},
                }
            else:
                # Other 4xx (bad request, etc.) → fail-closed ERROR
                error_detail = f"AIRS Inlet API error — HTTP {status_code}: {exc}"
                payload.is_blocked   = True
                payload.block_reason = error_detail
                payload.metrics.append({
                    "gate_name":  self.name,
                    "latency_ms": latency_ms,
                    "score":      1.0,
                    "verdict":    "ERROR",
                    "detail":     error_detail,
                })
                payload.raw_traces[self.name] = {
                    "request":  {"profile": profile},
                    "response": {"error": str(exc)},
                }
            return payload
        except Exception as exc:
            # Network / timeout / 5xx exhausted retries → fail-CLOSED
            latency_ms   = round((time.perf_counter() - t_start) * 1000, 2)
            error_detail = f"AIRS Inlet API error — {type(exc).__name__}: {exc}"
            payload.is_blocked   = True
            payload.block_reason = error_detail
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      1.0,
                "verdict":    "ERROR",
                "detail":     error_detail,
            })
            payload.raw_traces[self.name] = {
                "request":  {"profile": profile, "prompt_chars": len(payload.original_input)},
                "response": {"error": str(exc)},
            }
            return payload

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)
        action     = str(result.get("action",   "allow")).lower()
        category   = str(result.get("category", "benign"))
        scan_id    = str(result.get("scan_id",  ""))
        detected   = result.get("prompt_detected",           {}) or {}
        details    = result.get("prompt_detection_details",  {}) or {}
        flags_str  = _format_flags(detected, _PROMPT_FLAG_LABELS, details)

        payload.raw_traces[self.name] = {
            "request":  {
                "profile":      profile,
                "prompt_chars": len(payload.original_input),
                "tr_id":        result.get("tr_id", ""),
            },
            "response": {
                "action":   action,
                "category": category,
                "scan_id":  scan_id,
                "detected": detected,
                "flags":    flags_str,
            },
        }

        if action == "block":
            detail = (
                f"AIRS Inlet blocked — category: {category}, "
                f"threats: {flags_str}. Scan ID: {scan_id}"
            )
            payload.is_blocked   = True
            payload.block_reason = detail
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      1.0,
                "verdict":    "BLOCK",
                "detail":     detail,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      0.0,
                "verdict":    "PASS",
                "detail":     (
                    f"AIRS Inlet: prompt clean — action=allow, category={category}. "
                    f"Scan ID: {scan_id}"
                ),
            })

        return payload


class AIRSDualGate(SecurityGate):
    """Output gate — cloud response scan + DLP masking via Palo Alto Networks AIRS.

    Evaluates the LLM response (with original prompt as context) against the
    configured AI security profile AFTER generation.  Uniquely, AIRS can apply
    DLP masking: when ``response_masked_data`` is present, ``payload.output_text``
    is replaced with the redacted version before display — even when
    ``action`` is ``"allow"``.

    Fail behaviour — OPEN
    ---------------------
    On any API error the gate records an ERROR metric but does NOT set
    ``is_blocked`` — inference already happened, withholding the response
    silently would confuse the user.  The error is visible in Gate Trace.

    DLP masking verdict
    -------------------
    When AIRS masks data without blocking, the gate records a ``DLP_MASK``
    verdict (score 0.5).  The response shown to the user is the AIRS-redacted
    version; the UI renders a distinct notice for this case.

    Config keys
    -----------
    api_key : str   x-pan-token.  Falls back to ``AIRS_API_KEY`` / ``PANW_API_KEY``
                    env vars when empty.
    profile : str   AI security profile name.  Default: ``"default"``.
    timeout : float HTTP timeout in seconds.  Default: ``30.0``.
    ai_model: str   Target model name forwarded to AIRS metadata (informational).
    """

    @property
    def name(self) -> str:
        return "airs_dual"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        t_start  = time.perf_counter()
        api_key  = _resolve_api_key(str(self.config.get("api_key", "")))
        profile  = str(self.config.get("profile",  "default")).strip() or "default"
        timeout  = float(self.config.get("timeout", 30.0))
        ai_model = str(self.config.get("ai_model", ""))

        # ── No API key → SKIP ─────────────────────────────────────────────────
        if not api_key:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": 0,
                "score":      0.0,
                "verdict":    "SKIP",
                "detail":     (
                    "AIRS Dual: no API key configured. "
                    "Set AIRS_API_KEY in .env or enter it in the sidebar "
                    "to activate cloud response scanning."
                ),
            })
            return payload

        # ── No response text → SKIP (stream error, input-blocked turn) ────────
        response_text = (payload.output_text or "").strip()
        if not response_text:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": 0,
                "score":      0.0,
                "verdict":    "SKIP",
                "detail":     "AIRS Dual: no response text to scan.",
            })
            return payload

        # ── API call ──────────────────────────────────────────────────────────
        try:
            result = _airs_request(
                api_key  = api_key,
                profile  = profile,
                contents = [{"prompt": payload.original_input, "response": response_text}],
                ai_model = ai_model,
                timeout  = timeout,
            )
        except httpx.HTTPStatusError as exc:
            latency_ms  = round((time.perf_counter() - t_start) * 1000, 2)
            status_code = exc.response.status_code if exc.response is not None else 0
            if status_code in (401, 403):
                # Auth failure → SKIP (same as no key configured)
                payload.metrics.append({
                    "gate_name":  self.name,
                    "latency_ms": latency_ms,
                    "score":      0.0,
                    "verdict":    "SKIP",
                    "detail":     (
                        f"AIRS Dual: authentication failed (HTTP {status_code}) — "
                        "check that AIRS_API_KEY in .env is a valid x-pan-token."
                    ),
                })
            else:
                # Other 4xx → fail-open ERROR (response still shown)
                payload.metrics.append({
                    "gate_name":  self.name,
                    "latency_ms": latency_ms,
                    "score":      0.0,
                    "verdict":    "ERROR",
                    "detail":     f"AIRS Dual API error — HTTP {status_code}: {exc}",
                })
            payload.raw_traces[self.name] = {
                "request":  {"profile": profile},
                "response": {"error": f"HTTP {status_code}"},
            }
            return payload
        except Exception as exc:
            # Network / timeout / 5xx exhausted retries → fail-OPEN
            latency_ms = round((time.perf_counter() - t_start) * 1000, 2)
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      0.0,
                "verdict":    "ERROR",
                "detail":     f"AIRS Dual API error — {type(exc).__name__}: {exc}",
            })
            payload.raw_traces[self.name] = {
                "request":  {"profile": profile},
                "response": {"error": str(exc)},
            }
            return payload

        latency_ms    = round((time.perf_counter() - t_start) * 1000, 2)
        action        = str(result.get("action",   "allow")).lower()
        category      = str(result.get("category", "benign"))
        scan_id       = str(result.get("scan_id",  ""))
        detected      = result.get("response_detected",           {}) or {}
        details       = result.get("response_detection_details",  {}) or {}
        masked_obj    = result.get("response_masked_data")
        flags_str     = _format_flags(detected, _RESPONSE_FLAG_LABELS, details)

        # ── DLP masking — replace output_text with redacted version ───────────
        dlp_masked = False
        if masked_obj and isinstance(masked_obj, dict):
            masked_text = masked_obj.get("data", "").strip()
            if masked_text:
                payload.output_text = masked_text
                dlp_masked = True

        payload.raw_traces[self.name] = {
            "request":  {
                "profile":        profile,
                "prompt_chars":   len(payload.original_input),
                "response_chars": len(response_text),
            },
            "response": {
                "action":     action,
                "category":   category,
                "scan_id":    scan_id,
                "detected":   detected,
                "flags":      flags_str,
                "dlp_masked": dlp_masked,
            },
        }

        if action == "block":
            detail = (
                f"AIRS Dual blocked this response — category: {category}, "
                f"threats: {flags_str}. Scan ID: {scan_id}"
            )
            payload.is_blocked   = True
            payload.block_reason = detail
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      1.0,
                "verdict":    "BLOCK",
                "detail":     detail,
            })
        elif dlp_masked:
            # DLP masking without a hard block — response shown in redacted form
            detail = (
                f"AIRS Dual — DLP masking applied (action=allow). "
                f"Sensitive data patterns detected and redacted in the response above. "
                f"Threats: {flags_str}. Scan ID: {scan_id}"
            )
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      0.5,
                "verdict":    "DLP_MASK",
                "detail":     detail,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      0.0,
                "verdict":    "PASS",
                "detail":     (
                    f"AIRS Dual: response clean — action=allow, category={category}. "
                    f"Scan ID: {scan_id}"
                ),
            })

        return payload
