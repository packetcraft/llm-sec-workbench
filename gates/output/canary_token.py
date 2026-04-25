"""
gates/output/canary_token.py
────────────────────────────
CanaryTokenGate — Output gate to detect exfiltration of sensitive tokens.

Purpose
-------
Scans the LLM response for predefined "canary tokens" (e.g., mock API keys,
internal IP addresses, or project codenames). If any of these tokens are
found in the output, the gate flags a BLOCK verdict. This is a critical
defense against Indirect Prompt Injection (IPI) where an attacker tries
to leak data retrieved from a RAG store.

Configuration
-------------
Pass a ``config`` dict with a ``"tokens"`` key containing a list of strings
to scan for::

    CanaryTokenGate(config={"tokens": ["SECRET_123", "IP_10.0.0.1"]})
"""

from __future__ import annotations

import time

from core.payload import PipelinePayload
from gates.base_gate import SecurityGate


class CanaryTokenGate(SecurityGate):
    """Scans LLM output for sensitive canary tokens."""

    @property
    def name(self) -> str:
        return "canary_token"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        """Check the LLM output against the configured canary tokens.

        Appends one metrics entry with verdict:
          - ``SKIP``  — no tokens configured; gate is a no-op.
          - ``PASS``  — tokens configured, none matched.
          - ``BLOCK`` — one or more tokens matched.
        """
        t_start = time.perf_counter()

        tokens: list[str] = self.config.get("tokens", [])

        # ── No-op path ────────────────────────────────────────────────────────
        if not tokens:
            payload.metrics.append({
                "gate_name": self.name,
                "latency_ms": round((time.perf_counter() - t_start) * 1000, 2),
                "score": 0.0,
                "verdict": "SKIP",
                "detail": "No canary tokens configured.",
            })
            return payload

        # ── Detection ─────────────────────────────────────────────────────────
        # Output gates check payload.output_text
        haystack = payload.output_text
        matched = [t for t in tokens if t in haystack]

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        # ── Record raw trace for API Inspector ────────────────────────────────
        payload.raw_traces[self.name] = {
            "request": {
                "text_checked": haystack,
                "tokens_monitored": tokens,
            },
            "response": {
                "matched": matched,
                "blocked": bool(matched),
            },
        }

        if matched:
            payload.is_blocked = True
            quoted = ", ".join('"' + t + '"' for t in matched)
            payload.block_reason = f"Detected sensitive canary token(s) in output: {quoted}"
            payload.metrics.append({
                "gate_name": self.name,
                "latency_ms": latency_ms,
                "score": 1.0,
                "verdict": "BLOCK",
                "detail": payload.block_reason,
            })
        else:
            payload.metrics.append({
                "gate_name": self.name,
                "latency_ms": latency_ms,
                "score": 0.0,
                "verdict": "PASS",
                "detail": f"Checked {len(tokens)} token(s) — no exfiltration detected.",
            })

        return payload
