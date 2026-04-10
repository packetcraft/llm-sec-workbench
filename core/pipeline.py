"""
core/pipeline.py
────────────────
PipelineManager — the Chain of Responsibility orchestrator.

Execution model
---------------
The pipeline follows a Cost/Latency Funnel: cheapest gates first, heaviest
last.  Gates are registered as ordered lists of ``(name, gate_instance)``
tuples — the order determines execution sequence.

Gate modes are NOT baked into the gate objects; they are passed at execution
time from ``st.session_state.gate_modes``.  This allows the UI to change a
gate's mode without rebuilding the pipeline.

Mode semantics
--------------
  OFF     — gate is skipped entirely; 0 ms overhead.
  AUDIT   — gate scans and appends its verdict to metrics, but
            ``is_blocked`` is reset to False after the check so the
            pipeline continues.  The BLOCK verdict is still visible in
            the telemetry panel.
  ENFORCE — gate scans; if ``is_blocked`` is True after the scan, the
            pipeline halts immediately and returns the blocked payload.

The AUDIT reset ensures that ``payload.is_blocked`` is True only when a
halt should actually occur, so callers can do a simple ``if payload.is_blocked``
check without needing to track gate modes themselves.

Streaming vs blocking
---------------------
``execute()``         — fully blocking; used by tests and the red-team engine.
``run_input_gates()`` — runs only the input chain; returns the payload.
``run_output_gates()``— runs only the output chain; mutates and returns payload.

The Streamlit chat view calls ``run_input_gates`` first, then streams the
LLM inference directly (preserving the token-by-token UX), then calls
``run_output_gates`` on the complete response.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.payload import PipelinePayload

if TYPE_CHECKING:
    from core.llm_client import BaseLLMClient
    from gates.base_gate import SecurityGate


class PipelineManager:
    """Orchestrates the full security pipeline around a target LLM.

    Args:
        client:        An instance of ``BaseLLMClient`` (typically OllamaClient).
        input_gates:   Ordered list of ``(gate_name, SecurityGate)`` pairs that
                       run BEFORE inference.
        output_gates:  Ordered list of ``(gate_name, SecurityGate)`` pairs that
                       run AFTER inference.
    """

    def __init__(
        self,
        client: "BaseLLMClient",
        input_gates: list[tuple[str, "SecurityGate"]],
        output_gates: list[tuple[str, "SecurityGate"]],
    ) -> None:
        self.client = client
        self.input_gates = input_gates
        self.output_gates = output_gates

    # ── Input gate chain ──────────────────────────────────────────────────────

    def run_input_gates(
        self,
        user_text: str,
        gate_modes: dict[str, str],
    ) -> PipelinePayload:
        """Run all input gates against ``user_text``.

        Returns a ``PipelinePayload`` with:
          - ``is_blocked = True``  if an ENFORCE gate detected a violation
            (pipeline should halt).
          - ``is_blocked = False`` in all other cases, including when an
            AUDIT gate flagged a violation — the caller should proceed with
            inference.  The BLOCK verdict is still visible in ``metrics``.
        """
        payload = PipelinePayload(
            original_input=user_text,
            current_text=user_text,
        )

        for gate_name, gate_instance in self.input_gates:
            mode = gate_modes.get(gate_name, "AUDIT")

            if mode == "OFF":
                continue

            payload = gate_instance.scan(payload)

            if mode == "ENFORCE" and payload.is_blocked:
                # Hard stop — return immediately with block flag set.
                return payload

            if mode == "AUDIT" and payload.is_blocked:
                # Soft flag — keep the BLOCK in metrics but clear the halt flag
                # so the pipeline continues.
                payload.is_blocked = False
                payload.block_reason = ""

        return payload

    # ── Output gate chain ─────────────────────────────────────────────────────

    def run_output_gates(
        self,
        payload: PipelinePayload,
        gate_modes: dict[str, str],
    ) -> PipelinePayload:
        """Run all output gates against ``payload.output_text``.

        Applies the same ENFORCE / AUDIT / OFF logic as the input chain.
        """
        for gate_name, gate_instance in self.output_gates:
            mode = gate_modes.get(gate_name, "AUDIT")

            if mode == "OFF":
                continue

            payload = gate_instance.scan(payload)

            if mode == "ENFORCE" and payload.is_blocked:
                return payload

            if mode == "AUDIT" and payload.is_blocked:
                payload.is_blocked = False
                payload.block_reason = ""

        return payload

    # ── Blocking full-pipeline execution (tests / red-team) ──────────────────

    def execute(
        self,
        user_text: str,
        gate_modes: dict[str, str],
        system_prompt: str = "",
        rag_context: str = "",
        history: list[dict] | None = None,
        options: dict | None = None,
    ) -> PipelinePayload:
        """Fully blocking end-to-end pipeline execution.

        Intended for unit tests and the red-team batch runner where
        streaming is not needed.  The Streamlit chat view uses
        ``run_input_gates`` + streaming inference + ``run_output_gates``
        instead to preserve the token-by-token UX.

        Args:
            user_text:     The raw user prompt.
            gate_modes:    Dict mapping gate name → "OFF" | "AUDIT" | "ENFORCE".
            system_prompt: Optional system instruction for the LLM.
            rag_context:   Optional retrieved document to append to system context.
            history:       Prior conversation turns as ``[{"role": ..., "content": ...}]``.
            options:       LLM generation options (temperature, top_p, etc.).

        Returns:
            The final ``PipelinePayload`` — check ``is_blocked`` to determine
            whether inference occurred.
        """
        # ── Input gates ───────────────────────────────────────────────────────
        payload = self.run_input_gates(user_text, gate_modes)
        if payload.is_blocked:
            return payload

        # ── Inference ─────────────────────────────────────────────────────────
        messages = self._build_messages(
            current_text=payload.current_text,
            system_prompt=system_prompt,
            rag_context=rag_context,
            history=history or [],
        )
        result = self.client.generate(messages, options or {})
        payload.output_text = result.output_text
        payload.prompt_tokens = result.prompt_tokens
        payload.completion_tokens = result.completion_tokens
        payload.tokens_per_second = result.tokens_per_second

        # ── Output gates ──────────────────────────────────────────────────────
        payload = self.run_output_gates(payload, gate_modes)
        return payload

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_messages(
        self,
        current_text: str,
        system_prompt: str,
        rag_context: str,
        history: list[dict],
    ) -> list[dict]:
        """Assemble the Ollama-format message list.

        Combines the system prompt, optional RAG context, conversation
        history, and the (possibly sanitised) current user turn.
        """
        system_parts: list[str] = []
        if system_prompt.strip():
            system_parts.append(system_prompt.strip())
        if rag_context.strip():
            system_parts.append(f"## Context Document:\n{rag_context.strip()}")

        messages: list[dict] = []
        if system_parts:
            messages.append({"role": "system", "content": "\n\n".join(system_parts)})

        for msg in history:
            messages.append({"role": msg["role"], "content": msg["content"]})

        messages.append({"role": "user", "content": current_text})
        return messages
