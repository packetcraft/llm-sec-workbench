"""
gates/regex_gate.py
───────────────────
CustomRegexGate — lightweight WAF hot-patch gate (Gate 0 / pre-scan).

Purpose
-------
Provides an operator-controlled blocklist of phrases that are evaluated
against the raw user input before any AI model is invoked.  This simulates
a Web Application Firewall (WAF) hot-patch: an instant, zero-ML response
to a newly discovered attack pattern.

Because it runs pure Python with no model loading, this gate executes in
microseconds and is therefore placed first in the input chain, before
heavier classifiers like Prompt-Guard (Gate 2) or Llama-Guard (Gate 3).

Configuration
-------------
Pass a ``config`` dict with a ``"phrases"`` key containing a
comma-separated string of case-insensitive block phrases::

    CustomRegexGate(config={"phrases": "ignore all previous, do anything now, DAN"})

The gate is a no-op (verdict: SKIP) when no phrases are configured.

Detection logic
---------------
The gate checks ``payload.original_input`` (never ``current_text``), so
that upstream masking by earlier gates cannot cause a bypass.  Matching is
case-insensitive substring search — no regex compilation overhead.
"""

from __future__ import annotations

import re
import time

from core.payload import PipelinePayload
from gates.base_gate import SecurityGate


class CustomRegexGate(SecurityGate):
    """Operator-defined keyword blocklist gate.

    Inherits the fail-open ``scan()`` wrapper from ``SecurityGate``.
    All detection logic lives in ``_scan()`` below.
    """

    @property
    def name(self) -> str:
        return "custom_regex"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        """Check the original input against the configured block phrases.

        Appends one metrics entry with verdict:
          - ``SKIP``  — no phrases configured; gate is a no-op.
          - ``PASS``  — phrases configured, none matched.
          - ``BLOCK`` — one or more phrases matched.
        """
        t_start = time.perf_counter()

        # Parse pattern list from config
        raw: str = self.config.get("phrases", "")
        patterns = [p.strip() for p in raw.split(",") if p.strip()]

        # ── No-op path ────────────────────────────────────────────────────────
        if not patterns:
            payload.metrics.append({
                "gate_name": self.name,
                "latency_ms": round((time.perf_counter() - t_start) * 1000, 2),
                "score": 0.0,
                "verdict": "SKIP",
                "detail": "No block phrases configured.",
            })
            return payload

        # ── Compile patterns (case-insensitive) ───────────────────────────────
        compiled: list[tuple[str, re.Pattern[str]]] = []
        bad: list[str] = []
        for p in patterns:
            try:
                compiled.append((p, re.compile(p, re.IGNORECASE)))
            except re.error:
                bad.append(p)

        # ── Detection ─────────────────────────────────────────────────────────
        # Always scan original_input — never current_text — so upstream
        # sanitisation cannot create a bypass.
        haystack = payload.original_input
        matched = [p for p, rx in compiled if rx.search(haystack)]

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        # ── Record raw trace for API Inspector ────────────────────────────────
        payload.raw_traces[self.name] = {
            "request": {
                "text_checked": payload.original_input,
                "patterns": patterns,
                "invalid_patterns": bad,
            },
            "response": {
                "matched": matched,
                "blocked": bool(matched),
            },
        }

        if matched:
            payload.is_blocked = True
            quoted = ", ".join('"' + p + '"' for p in matched)
            payload.block_reason = f"Matched block phrase(s): {quoted}"
            payload.metrics.append({
                "gate_name": self.name,
                "latency_ms": latency_ms,
                "score": 1.0,
                "verdict": "BLOCK",
                "detail": payload.block_reason,
            })
        else:
            detail = f"Checked {len(compiled)} pattern(s) — no matches."
            if bad:
                detail += f" Invalid regex skipped: {bad}"
            payload.metrics.append({
                "gate_name": self.name,
                "latency_ms": latency_ms,
                "score": 0.0,
                "verdict": "PASS",
                "detail": detail,
            })

        return payload
