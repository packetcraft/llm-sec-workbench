"""
gates/base_gate.py
──────────────────
Abstract base class for all security gates.

Architecture: scan() / _scan() split
--------------------------------------
The public ``scan()`` method is **concrete** and lives here in the base class.
It owns two cross-cutting concerns that every gate must have:

  1. Wall-clock timing  — latency_ms is recorded even on failure.
  2. Fail-open error handling — if _scan() raises for any reason (model
     load error, API timeout, corrupt input), scan() catches the exception,
     appends an ERROR metric, and returns the payload UNCHANGED.
     ``is_blocked`` is NEVER set by the error handler — a broken gate must
     never silently deny legitimate traffic.

Concrete subclasses implement ``_scan()`` (the private workhorse) and the
``name`` property.  They must NOT override ``scan()``.

Gate contract (enforced by this class, documented for implementors)
-------------------------------------------------------------------
Inside ``_scan()`` a gate must:
  1. Run its detection logic against ``payload.original_input`` for pure
     classification (never against ``current_text``, which may be masked).
  2. If sanitising / masking: modify ``payload.current_text`` only.
  3. Append exactly ONE dict to ``payload.metrics``::

         {
             "gate_name":  str,    # self.name
             "latency_ms": float,  # wall-clock time for this gate
             "score":      float,  # 0.0–1.0 confidence / severity
             "verdict":    str,    # "PASS" | "BLOCK" | "AUDIT" | "SKIP"
             "detail":     str,    # human-readable explanation
         }

  4. Write raw request/response JSON to
     ``payload.raw_traces[self.name]`` where applicable.
  5. Set ``payload.is_blocked = True`` and ``payload.block_reason`` if a
     violation is found.  The PipelineManager checks ``is_blocked`` and
     decides whether to halt based on the gate's configured mode.
  6. Return ``payload``.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

from core.payload import PipelinePayload


class SecurityGate(ABC):
    """Stateless security gate base class.

    Args:
        config: Gate-specific configuration dict (thresholds, model names,
                API endpoints, etc.).  Passed through from the pipeline
                initialiser.
    """

    def __init__(self, config: dict) -> None:
        self.config = config

    # ── Identity ──────────────────────────────────────────────────────────────

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique, stable identifier for this gate.

        Used as the key in ``payload.raw_traces`` and in the ``gate_name``
        field of every metrics dict this gate appends.  Must be a short
        snake_case string, e.g. ``"fast_scan"``, ``"custom_regex"``.
        """

    # ── Public entry point (do NOT override in subclasses) ────────────────────

    def scan(self, payload: PipelinePayload) -> PipelinePayload:
        """Run the gate with timing and fail-open error protection.

        This method is **final** — subclasses implement ``_scan()`` instead.

        On any unhandled exception from ``_scan()``:
          - Latency is recorded.
          - An ERROR metric is appended to ``payload.metrics``.
          - ``payload.is_blocked`` is left unchanged (fail-open guarantee).
          - The exception is NOT re-raised.
        """
        t_start = time.perf_counter()
        try:
            payload = self._scan(payload)
        except Exception as exc:  # noqa: BLE001
            latency_ms = round((time.perf_counter() - t_start) * 1000, 2)
            payload.metrics.append({
                "gate_name": self.name,
                "latency_ms": latency_ms,
                "score": 0.0,
                "verdict": "ERROR",
                "detail": f"{type(exc).__name__}: {exc}",
            })
            # Deliberately do NOT set payload.is_blocked — broken gate = open gate.
        return payload

    # ── Protected implementation hook ─────────────────────────────────────────

    @abstractmethod
    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        """Gate logic.  See module docstring for the full contract."""
