"""
core/payload.py
───────────────
The single source of truth for pipeline state.

Design rationale
----------------
``PipelinePayload`` is threaded through every gate and the inference step.
Two text fields exist intentionally:

  original_input  — the raw user prompt, NEVER modified after creation.
                    All classifiers (Gate 1, Gate 2) run against this field
                    so that upstream masking (e.g. PII replacement) cannot
                    cause a jailbreak classifier to see sanitised text and
                    produce a false negative.

  current_text    — what actually reaches the LLM. Input gates may replace
                    PII tokens here (e.g. "4111…" → "[CREDIT_CARD]") before
                    the inference step.

``is_blocked`` is set to True by any gate that detects a violation.
The PipelineManager checks ``is_blocked`` AFTER each gate and, if the
gate mode is ENFORCE, halts the pipeline immediately.  In AUDIT mode the
manager resets ``is_blocked`` after logging, so the pipeline continues.

``raw_traces`` accumulates the exact request/response JSON from each gate
(keyed by gate name) for the API Inspector tab (Phase 5).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PipelinePayload:
    # ── Core text fields ──────────────────────────────────────────────────────
    original_input: str                 # Raw user prompt — NEVER modified
    current_text: str                   # Text passed to LLM (may be sanitised)

    # ── Execution state ───────────────────────────────────────────────────────
    is_blocked: bool = False            # True when a gate detected a violation
    block_reason: str = ""              # Human-readable reason from the gate

    # ── Telemetry ─────────────────────────────────────────────────────────────
    # Each gate appends one dict:
    #   {"gate_name": str, "latency_ms": float, "score": float,
    #    "verdict": str, "detail": str}
    metrics: list = field(default_factory=list)

    # ── Inference output ──────────────────────────────────────────────────────
    output_text: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    tokens_per_second: float = 0.0

    # ── Ollama timing breakdown (Phase 5 — Live Telemetry Panel) ─────────────
    load_ms: float = 0.0          # model load time (ms); 0 when already warm
    prompt_eval_ms: float = 0.0   # prompt encoding time (ms)
    generation_ms: float = 0.0    # token generation time (ms)
    done_reason: str = ""         # "stop" | "length" | "context" | ""
    ttft_ms: float = 0.0          # time from request start to first token (ms)

    # ── Raw API traces (for API Inspector, Phase 5) ───────────────────────────
    # Keyed by gate name; each value is {"request": {...}, "response": {...}}
    raw_traces: dict = field(default_factory=dict)

    # ── PII Vault (shared across input→output boundary) ───────────────────────
    # Holds the llm_guard Vault instance created by FastScanGate so that
    # DeanonymizeGate can restore original PII values in the LLM response.
    # None when FastScanGate has not run or found no PII.
    vault: Any = None
