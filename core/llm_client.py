"""
core/llm_client.py
──────────────────
Abstract LLM client interface and the Ollama concrete implementation.

Architecture note
-----------------
``BaseLLMClient`` is an ABC so that cloud-API clients (OpenAI-compatible,
Anthropic, etc.) can be added in future phases without touching the pipeline
or UI code.  The pipeline always calls ``client.generate()`` or
``client.generate_stream()``; it never imports ``OllamaClient`` directly.

``OllamaClient`` wraps the ``ollama`` Python SDK and:
  - Routes to a configurable Ollama host (reads ``OLLAMA_HOST`` from env).
  - Supports streaming generation via a generator that also captures token
    telemetry as a side-effect, accessible via ``get_stream_result()``.
  - Provides ``pull_model()`` for the First Run bootstrap screen.
  - Always uses ``getattr(..., default)`` on SDK response objects so that
    minor Ollama SDK version differences do not raise AttributeErrors.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterator


# ── Value object returned by every generation call ────────────────────────────

@dataclass
class GenerationResult:
    """Telemetry captured from a completed generation.

    ``output_text`` is populated by ``generate()``.
    For ``generate_stream()``, callers accumulate text themselves; retrieve
    token counts afterward via ``OllamaClient.get_stream_result()``.

    Ollama timing fields (Phase 5 — Live Telemetry Panel)
    ------------------------------------------------------
    All three timing fields are converted from nanoseconds to milliseconds
    on capture so callers never deal with raw ns values.

    load_ms         Time Ollama spent loading the model into VRAM/RAM.
                    Near-zero when the model was already warm; significant
                    on first use or after an idle unload.
    prompt_eval_ms  Time spent evaluating (encoding) the input prompt tokens.
    generation_ms   Pure token generation time (eval phase).
    done_reason     Why Ollama stopped: ``"stop"`` (natural end-of-sequence),
                    ``"length"`` (max_tokens hit), ``"context"`` (context
                    window exhausted), or ``""`` if not reported.
    """

    output_text: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    tokens_per_second: float = 0.0

    # ── Ollama timing breakdown (Phase 5) ─────────────────────────────────────
    load_ms: float = 0.0
    prompt_eval_ms: float = 0.0
    generation_ms: float = 0.0
    done_reason: str = ""
    ttft_ms: float = 0.0   # time from request to first token (ms)


# ── Abstract base ──────────────────────────────────────────────────────────────

class BaseLLMClient(ABC):
    """Common interface for all LLM backends.

    Future concrete subclasses (e.g. ``OpenAIClient``, ``AnthropicClient``)
    must implement every abstract method below.
    """

    @abstractmethod
    def generate(
        self,
        messages: list[dict],
        options: dict | None = None,
    ) -> GenerationResult:
        """Blocking generation.  Returns the full response as a
        ``GenerationResult`` including token telemetry."""

    @abstractmethod
    def generate_stream(
        self,
        messages: list[dict],
        options: dict | None = None,
    ) -> Iterator[str]:
        """Streaming generation.  Yields text chunks as they arrive.

        Token telemetry is captured as a side-effect and is accessible via
        ``get_stream_result()`` *after* the generator is fully exhausted.
        """

    @abstractmethod
    def get_stream_result(self) -> GenerationResult:
        """Return telemetry from the most recent ``generate_stream()`` call.

        Must be called *after* the stream generator is fully consumed.
        Returns zeroed ``GenerationResult`` if no stream has run yet.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """Return ``True`` if the backend is reachable."""

    @abstractmethod
    def list_models(self) -> list[str]:
        """Return the list of locally available model names (e.g. ``['llama3:latest']``)."""

    @abstractmethod
    def pull_model(self, model_name: str) -> Iterator[dict]:
        """Stream the download progress for ``model_name``.

        Each yielded dict has the keys::

            {
                "status":    str,   # e.g. "pulling manifest", "downloading"
                "completed": int,   # bytes downloaded so far
                "total":     int,   # total bytes (0 if unknown)
            }
        """


# ── Ollama implementation ──────────────────────────────────────────────────────

class OllamaClient(BaseLLMClient):
    """Concrete LLM client backed by a local Ollama instance.

    Args:
        model:  The default model name to use for generation
                (e.g. ``"llama3"`` or ``"llama3:latest"``).
        host:   Ollama server URL.  Defaults to the ``OLLAMA_HOST``
                environment variable, falling back to ``http://localhost:11434``.
    """

    def __init__(
        self,
        model: str,
        host: str | None = None,
    ) -> None:
        self.model = model
        self.host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self._last_stream_meta: dict = {}

        from ollama import Client  # lazy — allows app to load before pip install
        self._client = Client(host=self.host)

    # ── Availability & model management ───────────────────────────────────────

    def is_available(self) -> bool:
        """Ping Ollama; return False on any connection error."""
        try:
            self._client.list()
            return True
        except Exception:  # noqa: BLE001
            return False

    def list_models(self) -> list[str]:
        """Return model tag strings for every locally available model."""
        try:
            response = self._client.list()
            models = getattr(response, "models", []) or []
            return [getattr(m, "model", "") for m in models if getattr(m, "model", "")]
        except Exception:  # noqa: BLE001
            return []

    def pull_model(self, model_name: str) -> Iterator[dict]:
        """Stream pull progress for ``model_name``.

        Yields normalised progress dicts (see ``BaseLLMClient.pull_model``).
        """
        for chunk in self._client.pull(model_name, stream=True):
            yield {
                "status": getattr(chunk, "status", "") or "",
                "completed": int(getattr(chunk, "completed", 0) or 0),
                "total": int(getattr(chunk, "total", 0) or 0),
            }

    # ── Blocking generation ────────────────────────────────────────────────────

    def generate(
        self,
        messages: list[dict],
        options: dict | None = None,
    ) -> GenerationResult:
        """Call Ollama chat (non-streaming) and return the full result."""
        response = self._client.chat(
            model=self.model,
            messages=messages,
            stream=False,
            options=options or {},
        )
        return self._result_from_response(response)

    # ── Streaming generation ───────────────────────────────────────────────────

    def generate_stream(
        self,
        messages: list[dict],
        options: dict | None = None,
    ) -> Iterator[str]:
        """Yield text tokens as they arrive from Ollama.

        Token telemetry is stored on the final chunk and retrievable via
        ``get_stream_result()`` after the generator is exhausted.

        Usage with Streamlit::

            full_text = st.write_stream(client.generate_stream(messages, opts))
            result    = client.get_stream_result()
        """
        import time as _time
        self._last_stream_meta = {}
        _request_start  = _time.perf_counter()
        _ttft_ms        = 0.0
        _ttft_recorded  = False

        for chunk in self._client.chat(
            model=self.model,
            messages=messages,
            stream=True,
            options=options or {},
        ):
            content: str = getattr(chunk.message, "content", "") or ""
            if content:
                if not _ttft_recorded:
                    _ttft_ms       = (_time.perf_counter() - _request_start) * 1000
                    _ttft_recorded = True
                yield content

            # The final chunk carries token counts and timing but empty content.
            if getattr(chunk, "done", False):
                eval_ns         = int(getattr(chunk, "eval_duration",        0) or 0)
                load_ns         = int(getattr(chunk, "load_duration",        0) or 0)
                prompt_eval_ns  = int(getattr(chunk, "prompt_eval_duration", 0) or 0)
                completion      = int(getattr(chunk, "eval_count",           0) or 0)
                self._last_stream_meta = {
                    "prompt_tokens":     int(getattr(chunk, "prompt_eval_count", 0) or 0),
                    "completion_tokens": completion,
                    "tokens_per_second": (
                        completion / (eval_ns / 1e9) if eval_ns > 0 else 0.0
                    ),
                    "load_ms":           load_ns        / 1_000_000,
                    "prompt_eval_ms":    prompt_eval_ns / 1_000_000,
                    "generation_ms":     eval_ns        / 1_000_000,
                    "done_reason":       str(getattr(chunk, "done_reason", "") or ""),
                    "ttft_ms":           _ttft_ms,
                }

    def get_stream_result(self) -> GenerationResult:
        """Return telemetry captured during the last ``generate_stream()`` call.

        Call this *after* the stream generator is fully consumed (e.g. after
        ``st.write_stream()`` returns).
        """
        m = self._last_stream_meta
        return GenerationResult(
            output_text="",  # caller accumulates this from the stream
            prompt_tokens=m.get("prompt_tokens", 0),
            completion_tokens=m.get("completion_tokens", 0),
            tokens_per_second=m.get("tokens_per_second", 0.0),
            load_ms=m.get("load_ms", 0.0),
            prompt_eval_ms=m.get("prompt_eval_ms", 0.0),
            generation_ms=m.get("generation_ms", 0.0),
            done_reason=m.get("done_reason", ""),
            ttft_ms=m.get("ttft_ms", 0.0),
        )

    # ── Internal helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _result_from_response(response) -> GenerationResult:
        """Extract a ``GenerationResult`` from a non-streaming Ollama response."""
        eval_ns        = int(getattr(response, "eval_duration",        0) or 0)
        load_ns        = int(getattr(response, "load_duration",        0) or 0)
        prompt_eval_ns = int(getattr(response, "prompt_eval_duration", 0) or 0)
        completion     = int(getattr(response, "eval_count",           0) or 0)
        return GenerationResult(
            output_text=response.message.content,
            prompt_tokens=int(getattr(response, "prompt_eval_count", 0) or 0),
            completion_tokens=completion,
            tokens_per_second=(
                completion / (eval_ns / 1e9) if eval_ns > 0 else 0.0
            ),
            load_ms=load_ns        / 1_000_000,
            prompt_eval_ms=prompt_eval_ns / 1_000_000,
            generation_ms=eval_ns  / 1_000_000,
            done_reason=str(getattr(response, "done_reason", "") or ""),
        )
