"""
gates/ollama_gates.py
─────────────────────
Security gates backed by local Ollama models (LLM-as-judge pattern).

Gates defined here call a *separate* auxiliary Ollama model (not the target
LLM) to classify the conversation.  They are placed at the end of the input
chain because they are the most expensive gates — full LLM inference runs for
every user message.

Design principles
-----------------
- Each gate creates its own cached Ollama client keyed by host string so
  guard-model calls never share a connection pool with the target LLM.
- Temperature is forced to 0 and ``num_predict`` is kept small (50 tokens)
  since guard model responses are always short structured outputs.
- All gates respect the fail-open guarantee from ``SecurityGate.scan()``.
  If Ollama is unreachable or the model is not pulled, the gate records an
  ERROR metric and the pipeline continues — a broken guard never hard-blocks
  legitimate traffic.

Llama Guard 3 response format
------------------------------
The ``llama-guard3`` Ollama model (Meta, Apache 2.0) outputs:

  - ``"safe"``                → the content complies with the policy
  - ``"unsafe\\n<codes>"``    → violated categories, comma-separated

Safety category codes (Llama Guard 3 taxonomy, MLCommons 0.5)
-----------------------------------------------
  S1  Violent Crimes              S8  Intellectual Property
  S2  Non-Violent Crimes          S9  Indiscriminate Weapons (CBRN)
  S3  Sex-Related Crimes          S10 Hate / Discrimination
  S4  Child Sexual Exploitation   S11 Suicide & Self-Harm
  S5  Defamation                  S12 Sexual Content
  S6  Specialized Advice          S13 Elections
  S7  Privacy                     S14 Code Interpreter Abuse
"""

from __future__ import annotations

import functools
import time

from core.payload import PipelinePayload
from gates.base_gate import SecurityGate


# ── Safety category lookup ─────────────────────────────────────────────────────

_LLAMA_GUARD_CATEGORIES: dict[str, str] = {
    "S1":  "Violent Crimes",
    "S2":  "Non-Violent Crimes",
    "S3":  "Sex-Related Crimes",
    "S4":  "Child Sexual Exploitation",
    "S5":  "Defamation",
    "S6":  "Specialized Advice",
    "S7":  "Privacy",
    "S8":  "Intellectual Property",
    "S9":  "Indiscriminate Weapons (CBRN)",
    "S10": "Hate / Discrimination",
    "S11": "Suicide & Self-Harm",
    "S12": "Sexual Content",
    "S13": "Elections",
    "S14": "Code Interpreter Abuse",
}


# ── Cached Ollama client ───────────────────────────────────────────────────────

@functools.lru_cache(maxsize=4)
def _get_ollama_client(host: str):
    """Return a cached ``ollama.Client`` for the given host.

    Cached per host string so repeated calls from the same gate share one
    HTTP connection pool.  The cache is process-scoped, not per-request.
    """
    from ollama import Client  # lazy — avoids hard import at module load
    return Client(host=host)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_categories(raw: str) -> str:
    """Map ``"S1,S9"`` → ``"S1 (Violent Crimes), S9 (Indiscriminate Weapons (CBRN))"``.

    Unknown codes are preserved as-is so future taxonomy additions do not
    cause information loss.
    """
    codes = [c.strip().upper() for c in raw.split(",") if c.strip()]
    if not codes:
        return raw or "unspecified"
    labels = [
        f"{c} ({_LLAMA_GUARD_CATEGORIES[c]})" if c in _LLAMA_GUARD_CATEGORIES else c
        for c in codes
    ]
    return ", ".join(labels)


# ── Gate implementation ───────────────────────────────────────────────────────

class LlamaGuardGate(SecurityGate):
    """Input gate — classifies user prompts with Meta's Llama Guard 3 model.

    Sends ``payload.original_input`` (the raw, unmasked user prompt) to the
    ``llama-guard3`` Ollama model and parses the structured binary verdict.

    The gate is intentionally placed **last** in the input chain so that
    all cheap, fast gates (regex, token limit, invisible text, PII scan,
    injection classifier, toxicity, topic restriction) have already had a
    chance to short-circuit before this expensive LLM call is made.

    Verdict logic
    -------------
    - Ollama returns ``"safe"``        → verdict **PASS**, pipeline continues.
    - Ollama returns ``"unsafe\\n…"`` → ``is_blocked = True``, verdict **BLOCK**
      with category codes resolved to human-readable names.
    - Ollama unreachable / times out   → verdict **ERROR**, pipeline continues
      (fail-open — handled automatically by ``SecurityGate.scan()``).

    Config keys
    -----------
    host    : str   Ollama server URL. Default: ``http://localhost:11434``.
    model   : str   Model tag. Default: ``llama-guard3``.
    timeout : float Seconds before the HTTP call is considered failed.
                    Default: 30.0.  The gate always fails open on timeout so
                    safe traffic is never permanently blocked.
    """

    @property
    def name(self) -> str:
        return "mod_llm"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        t_start = time.perf_counter()

        host    = str(self.config.get("host",    "http://localhost:11434"))
        model   = str(self.config.get("model",   "llama-guard3"))

        client = _get_ollama_client(host)

        response = client.chat(
            model=model,
            messages=[{"role": "user", "content": payload.original_input}],
            stream=False,
            options={
                "temperature": 0,
                "num_predict": 50,   # guard output is always very short
                "num_ctx":     8192,
            },
        )

        raw_output = (response.message.content or "").strip()
        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        payload.raw_traces[self.name] = {
            "request": {
                "model":        model,
                "host":         host,
                "text_checked": payload.original_input,
            },
            "response": {
                "raw": raw_output,
            },
        }

        # Parse verdict — first line is always "safe" or "unsafe"
        lines = raw_output.split("\n")
        verdict_line = lines[0].strip().lower()

        if verdict_line == "unsafe":
            raw_cats  = lines[1].strip() if len(lines) > 1 else ""
            categories = _resolve_categories(raw_cats)

            payload.is_blocked   = True
            payload.block_reason = (
                f"Llama Guard 3 flagged this prompt as unsafe. "
                f"Violated categories: {categories}."
            )
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      1.0,
                "verdict":    "BLOCK",
                "detail":     payload.block_reason,
            })

        else:
            # Treat "safe" and any unexpected output as pass (fail-open)
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      0.0,
                "verdict":    "PASS",
                "detail":     f"Llama Guard 3: {raw_output or 'safe'}.",
            })

        return payload
