"""
gates/local_scanners.py
──────────────────────
Gate 1b TokenLimitGate   — Rejects prompts exceeding a token budget (tiktoken).
Gate 1c InvisibleTextGate — Detects hidden Unicode characters used in injection attacks.
Gate 1a FastScanGate     — PII and secrets detection via llm-guard (CPU/Presidio).
Gate 1f GibberishGate    — Noise-flood / token-waste detection via llm-guard Gibberish
         (madhurjindal/autonlp-Gibberish-Detector). Quality gate — defaults to AUDIT.
Gate 1g LanguageGate     — Enforces language policy via llm-guard Language
         (papluca/xlm-roberta-base-language-detection). Blocks non-English by default.
         Prevents multilingual jailbreak bypass. Quality gate — defaults to AUDIT.
Gate 2  PromptGuardGate  — Injection/jailbreak classification via
         protectai/deberta-v3-base-prompt-injection-v2 (CPU).
Gate 1d ToxicityInputGate — Detects hostile/abusive/toxic input tone (Toxicity +
         Sentiment sub-scanners). Quality gate — defaults to AUDIT.
Gate 1e BanTopicsGate    — Blocks prompts that fall into operator-defined forbidden
         subject areas using zero-shot classification (roberta-base-c-v2 via
         llm-guard BanTopics). No-op when no topics are configured.
Gate A  DeanonymizeGate  — Restores PII placeholders in LLM responses via Vault.
Gate B  SensitiveGate    — Output-side PII scanner; catches PII the LLM generates
         on its own that the input-side Anonymize can never see.
Gate C  MaliciousURLsGate — Detects and removes malicious URLs from LLM responses.
Gate D  NoRefusalGate    — Detects when the model refuses to answer; surfaces as
         a signal for red-team and over-blocking analysis.
Gate E  BiasOutputGate   — Detects biased or toxic content in model responses
         (Bias + Toxicity sub-scanners). Quality gate — defaults to AUDIT.
Gate F  RelevanceGate    — Detects off-topic or hallucinated responses using
         BAAI embedding similarity. Quality gate — defaults to AUDIT.
Gate G  LanguageSameGate — Ensures response language matches prompt language via
         llm-guard LanguageSame (papluca/xlm-roberta-base-language-detection).
         Catches multilingual response drift. Quality gate — defaults to AUDIT.

Gates 1b and 1c are zero-ML (pure Python / tiktoken) and run in < 1 ms.
They sit before FastScanGate in the pipeline so oversized or tampered prompts
are rejected before heavier scanners are invoked.

All ML-based gates are stateless — all mutable state lives in PipelinePayload.
Heavy ML models are loaded lazily and cached at module level so Streamlit
re-runs do not reload models on every request.

CPU-only constraint
-------------------
All model inference runs on CPU to preserve GPU VRAM exclusively for the
Ollama inference engine.  deberta-v3-base-prompt-injection-v2 (184 M parameters)
typically completes in < 500 ms on CPU.  ONNX-Runtime acceleration is available
by swapping ``AutoModelForSequenceClassification`` for an ONNX pipeline in a
future phase.

Model note
----------
The default classifier is ``protectai/deberta-v3-base-prompt-injection-v2``,
a publicly accessible binary classifier (SAFE / INJECTION) from ProtectAI.
It replaces ``meta-llama/Prompt-Guard-86M`` which requires a gated HuggingFace
account.  The model can be overridden via the ``model_name`` config key.
"""

from __future__ import annotations

import functools
import time

from core.payload import PipelinePayload
from gates.base_gate import SecurityGate


# ── Optional llm-guard dependency ────────────────────────────────────────────
# llm_guard is a heavy ML dependency (Presidio, HuggingFace, etc.).  When it
# is not installed every gate that depends on it degrades gracefully to SKIP
# rather than raising ModuleNotFoundError (which the base class catches as an
# ERROR verdict).  Gates that are pure-Python (TokenLimitGate, InvisibleText-
# Gate, CustomRegexGate) are completely unaffected.

try:
    import llm_guard as _llm_guard_check  # noqa: F401
    _LLM_GUARD_OK: bool = True
except ImportError:
    _LLM_GUARD_OK = False


def _llm_guard_skip(gate_name: str, t_start: float, payload: PipelinePayload) -> PipelinePayload:
    """Append a SKIP metric and return when llm-guard is not installed."""
    payload.metrics.append({
        "gate_name":  gate_name,
        "latency_ms": round((time.perf_counter() - t_start) * 1000, 2),
        "score":      0.0,
        "verdict":    "SKIP",
        "detail":     "llm-guard not installed — run: pip install llm-guard",
    })
    return payload


# ── Module-level model cache ──────────────────────────────────────────────────

@functools.lru_cache(maxsize=4)
def _load_prompt_guard(model_name: str):
    """Download and cache Prompt-Guard tokenizer + model (once per process).

    Uses ``lru_cache`` keyed on *model_name* so switching models in config
    is supported while still avoiding repeated disk/network loads.  Forces
    CPU placement so GPU VRAM is never consumed.
    """
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    model.eval()
    model = model.to(torch.device("cpu"))   # hard-lock to CPU
    return model, tokenizer


# ── Gate 1b: TokenLimitGate ──────────────────────────────────────────────────

class TokenLimitGate(SecurityGate):
    """Rejects prompts that exceed a configurable token budget.

    Runs tiktoken tokenisation (same encoder OpenAI uses) against
    ``payload.original_input``.  Zero ML — completes in < 1 ms.

    Oversized prompts are a common vector for:
      - Context-window exhaustion attacks (denial of service).
      - Hiding malicious instructions deep inside very long inputs.
      - Bypassing sliding-window classifiers that only see the tail.

    Config keys
    -----------
    limit         : int  (default 512)  — max allowed tokens.
    encoding_name : str  (default "cl100k_base") — tiktoken encoding.
                    "cl100k_base" covers GPT-3.5/4 and most modern LLMs.
    """

    @property
    def name(self) -> str:
        return "token_limit"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        import tiktoken

        t_start = time.perf_counter()

        limit         = int(self.config.get("limit", 512))
        encoding_name = str(self.config.get("encoding_name", "cl100k_base"))

        enc         = tiktoken.get_encoding(encoding_name)
        token_count = len(enc.encode(payload.original_input))
        is_valid    = token_count <= limit
        risk_score  = round(min(1.0, token_count / limit) if limit > 0 else 1.0, 4)

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        payload.raw_traces[self.name] = {
            "request": {
                "text_checked": payload.original_input,
                "limit":        limit,
                "encoding":     encoding_name,
            },
            "response": {
                "token_count": token_count,
                "is_valid":    is_valid,
                "risk_score":  risk_score,
            },
        }

        if not is_valid:
            payload.is_blocked   = True
            payload.block_reason = (
                f"Prompt too long: {token_count} tokens exceeds limit of {limit}."
            )
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      risk_score,
                "verdict":    "BLOCK",
                "detail":     payload.block_reason,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      risk_score,
                "verdict":    "PASS",
                "detail":     f"{token_count} tokens — within limit of {limit}.",
            })

        return payload


# ── Gate 1c: InvisibleTextGate ────────────────────────────────────────────────

class InvisibleTextGate(SecurityGate):
    """Detects hidden Unicode characters used in prompt injection attacks.

    Scans ``payload.original_input`` for Unicode characters in categories
    that are invisible to the human eye but interpreted by the LLM:

      - Cf  (Format)    — zero-width joiners, directional overrides, soft hyphens
      - Cc  (Control)   — ASCII control characters outside normal whitespace
      - Co  (Private)   — private use area characters
      - Cn  (Unassigned) — unassigned code points

    These are used in "Unicode steganography" attacks to hide instructions
    inside seemingly-blank text that the user cannot see.  Zero ML — < 1 ms.

    Config keys
    -----------
    None — no configurable parameters.
    """

    @property
    def name(self) -> str:
        return "invisible_text"

    # Unicode categories that are invisible to humans but interpretable by LLMs.
    # Cf = Format (zero-width joiners, directional overrides, soft hyphens)
    # Cc = Control (ASCII controls outside normal whitespace)
    # Co = Private Use Area
    # Cn = Unassigned code points
    _INVISIBLE_CATS: frozenset = frozenset({"Cf", "Cc", "Co", "Cn"})
    # Normal whitespace control chars that are always allowed.
    _ALLOWED_CC: frozenset = frozenset({"\t", "\n", "\r"})

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        import unicodedata as _ud

        t_start = time.perf_counter()

        invisible = [
            ch for ch in payload.original_input
            if _ud.category(ch) in self._INVISIBLE_CATS
            and ch not in self._ALLOWED_CC
        ]
        is_valid   = len(invisible) == 0
        risk_score = round(min(1.0, len(invisible) / 10), 4) if invisible else 0.0

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        payload.raw_traces[self.name] = {
            "request":  {"text_checked": payload.original_input},
            "response": {
                "is_valid":   is_valid,
                "risk_score": risk_score,
            },
        }

        if not is_valid:
            payload.is_blocked   = True
            payload.block_reason = (
                "Invisible Unicode characters detected — possible steganography attack."
            )
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      risk_score,
                "verdict":    "BLOCK",
                "detail":     payload.block_reason,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      0.0,
                "verdict":    "PASS",
                "detail":     "No invisible Unicode characters detected.",
            })

        return payload


# ── Gate 1a: FastScanGate ──────────────────────────────────────────────────────

class FastScanGate(SecurityGate):
    """PII and secrets detection via llm-guard (CPU).

    Runs two sub-scanners sequentially against ``current_text``:

    1. **Anonymize** — detects PII entities (names, emails, phone numbers,
       credit-card numbers, etc.) via Microsoft Presidio.  Matched entities
       are replaced with ``[ENTITY_TYPE]`` placeholders in ``current_text``.
       ``original_input`` is **never modified** so downstream classifiers
       still operate on the raw text.

    2. **Secrets** — detects API keys, tokens, and other credentials using
       ``detect-secrets`` under the hood.

    A ``BLOCK`` verdict is recorded whenever either sub-scanner fires.  In
    ``AUDIT`` mode the pipeline continues with the sanitised ``current_text``;
    in ``ENFORCE`` mode the pipeline halts.

    Config keys
    -----------
    scan_pii      : bool  (default True)  — enable Anonymize scanner.
    scan_secrets  : bool  (default True)  — enable Secrets scanner.
    pii_threshold : float (default 0.5)   — Presidio entity confidence cutoff.
    """

    @property
    def name(self) -> str:
        return "fast_scan"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        t_start = time.perf_counter()

        if not _LLM_GUARD_OK:
            return _llm_guard_skip(self.name, t_start, payload)

        from llm_guard.input_scanners import Anonymize, Secrets
        from llm_guard.vault import Vault

        scan_pii      = bool(self.config.get("scan_pii", True))
        scan_secrets  = bool(self.config.get("scan_secrets", True))
        pii_threshold = float(self.config.get("pii_threshold", 0.5))

        findings: list[str] = []
        text = payload.current_text  # working copy — only this mutates

        # ── Sub-scan 1: PII Anonymize ─────────────────────────────────────
        pii_result: dict = {"enabled": scan_pii}
        if scan_pii:
            vault = Vault()
            payload.vault = vault   # share with DeanonymizeGate via payload
            anon = Anonymize(vault, threshold=pii_threshold)
            sanitized, _is_valid, risk_score = anon.scan(text)
            # Only treat as a finding if risk_score meets the threshold.
            # llm-guard may partially redact text even for low-confidence
            # entities (e.g. "Paris" detected as PERSON at score 0.40),
            # so we gate on risk_score here rather than trusting sanitized != text.
            pii_masked = sanitized != text and float(risk_score) >= pii_threshold
            pii_result.update({
                "sanitized_text": sanitized if pii_masked else text,
                "risk_score":     round(float(risk_score), 4),
                "pii_masked":     pii_masked,
            })
            if pii_masked:
                text = sanitized   # propagate masked text for secrets scan
                findings.append(f"PII masked (score={float(risk_score):.2f})")

        # ── Sub-scan 2: Secrets ───────────────────────────────────────────
        secrets_result: dict = {"enabled": scan_secrets}
        if scan_secrets:
            sec_scanner = Secrets()
            _sanitized_sec, sec_valid, sec_score = sec_scanner.scan(text)
            secrets_found = not sec_valid
            secrets_result.update({
                "is_valid":    sec_valid,
                "risk_score":  round(float(sec_score), 4),
                "secrets_found": secrets_found,
            })
            if secrets_found:
                findings.append(
                    f"Secret/credential detected (score={float(sec_score):.2f})"
                )

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        # ── Record raw trace for API Inspector ────────────────────────────
        payload.raw_traces[self.name] = {
            "request": {
                "text_checked":  payload.current_text,
                "pii_threshold": pii_threshold,
            },
            "response": {
                "pii":     pii_result,
                "secrets": secrets_result,
            },
        }

        # ── Propagate masked text + write verdict ─────────────────────────
        score = max(
            float(pii_result.get("risk_score", 0.0)),
            float(secrets_result.get("risk_score", 0.0)),
        )

        if findings:
            payload.current_text = text   # write sanitised version
            payload.is_blocked   = True
            payload.block_reason = "; ".join(findings)
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(score, 4),
                "verdict":    "BLOCK",
                "detail":     payload.block_reason,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(score, 4),
                "verdict":    "PASS",
                "detail":     "No PII or secrets detected.",
            })

        return payload


# ── Gate 1f: GibberishGate ───────────────────────────────────────────────────

class GibberishGate(SecurityGate):
    """Detects incoherent, garbled, or noise-flood input.

    Uses llm-guard's ``Gibberish`` input scanner
    (``madhurjindal/autonlp-Gibberish-Detector-492513457``) to classify input
    into four quality levels: ``clean``, ``mild gibberish``, ``noise``, and
    ``word salad``.  Any label other than ``clean`` that exceeds the threshold
    triggers a BLOCK verdict.

    Catches token-waste attacks and random-character floods that could:
      - Exhaust model context with noise.
      - Confuse downstream ML gates by making their input ambiguous.
      - Disguise injection payloads inside entropy.

    Quality gate — defaults to AUDIT.  Hard-blocking on gibberish alone can
    cause false positives on unusual but legitimate technical prompts (code
    snippets, command-line text, non-Latin scripts) — monitor first.

    Config keys
    -----------
    threshold : float (default 0.97) — gibberish confidence cutoff.
                Very high by default to minimise false positives on technical
                content.  Lower to 0.80 to catch more borderline inputs.
    """

    @property
    def name(self) -> str:
        return "gibberish"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        t_start = time.perf_counter()

        if not _LLM_GUARD_OK:
            return _llm_guard_skip(self.name, t_start, payload)

        from llm_guard.input_scanners import Gibberish

        threshold = float(self.config.get("threshold", 0.97))

        scanner = Gibberish(threshold=threshold)
        _, is_valid, risk_score = scanner.scan(payload.original_input)

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        payload.raw_traces[self.name] = {
            "request": {
                "text_checked": payload.original_input,
                "threshold":    threshold,
            },
            "response": {
                "is_valid":   is_valid,
                "risk_score": round(float(risk_score), 4),
            },
        }

        if not is_valid:
            payload.is_blocked   = True
            payload.block_reason = (
                f"Gibberish / noise-flood input detected "
                f"(score={float(risk_score):.2f} \u2265 threshold={threshold:.2f})."
            )
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(float(risk_score), 4),
                "verdict":    "BLOCK",
                "detail":     payload.block_reason,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(float(risk_score), 4),
                "verdict":    "PASS",
                "detail":     f"Input is coherent (gibberish score={float(risk_score):.2f}).",
            })

        return payload


# ── Gate 1g: LanguageGate ────────────────────────────────────────────────────

class LanguageGate(SecurityGate):
    """Enforces language policy on user prompts.

    Uses llm-guard's ``Language`` input scanner
    (``papluca/xlm-roberta-base-language-detection``) to identify the prompt
    language and block inputs whose detected language is not on the allow-list.

    Prevents multilingual jailbreak bypass — attacks phrased in Arabic,
    Chinese, Russian, etc. to evade English-trained safety classifiers
    (Toxicity, BanTopics, Injection Detect) that run downstream.

    Quality gate — defaults to AUDIT.  Enable ENFORCE only after confirming
    that your user base is genuinely monolingual; multilingual deployments
    should widen ``valid_languages`` rather than disable the gate.

    Config keys
    -----------
    valid_languages : list[str] (default ["en"]) — ISO 639-1 language codes
                      that are allowed through.  E.g. ["en", "fr", "de"].
    threshold       : float     (default 0.6)    — minimum classifier
                      confidence for a language detection to count.  Inputs
                      below this confidence pass through (ambiguous text is
                      treated as valid to avoid blocking very short prompts).
    """

    @property
    def name(self) -> str:
        return "language_in"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        t_start = time.perf_counter()

        if not _LLM_GUARD_OK:
            return _llm_guard_skip(self.name, t_start, payload)

        from llm_guard.input_scanners import Language

        valid_languages = self.config.get("valid_languages", ["en"])
        threshold       = float(self.config.get("threshold", 0.6))

        scanner = Language(valid_languages=valid_languages, threshold=threshold)
        _, is_valid, risk_score = scanner.scan(payload.original_input)

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        payload.raw_traces[self.name] = {
            "request": {
                "text_checked":    payload.original_input,
                "valid_languages": valid_languages,
                "threshold":       threshold,
            },
            "response": {
                "is_valid":   is_valid,
                "risk_score": round(float(risk_score), 4),
            },
        }

        if not is_valid:
            payload.is_blocked   = True
            payload.block_reason = (
                f"Prompt language not in allowed list {valid_languages} "
                f"(score={float(risk_score):.2f})."
            )
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(float(risk_score), 4),
                "verdict":    "BLOCK",
                "detail":     payload.block_reason,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(float(risk_score), 4),
                "verdict":    "PASS",
                "detail":     f"Prompt language is within allowed list {valid_languages}.",
            })

        return payload


# ── Gate 2: PromptGuardGate ───────────────────────────────────────────────────

class PromptGuardGate(SecurityGate):
    """Injection/jailbreak classification via ProtectAI DeBERTa (CPU).

    Always classifies ``payload.original_input`` — the unmodified user text —
    so that upstream PII masking cannot inadvertently strip injection markers
    and allow a bypass.

    The model outputs softmax probabilities for two classes: ``SAFE`` and
    ``INJECTION``.  The threat score is ``P(INJECTION)``.  If it exceeds
    the configured threshold the verdict is ``BLOCK``.

    Default model: ``protectai/deberta-v3-base-prompt-injection-v2``
    Publicly accessible — no HuggingFace account or token required.

    Config keys
    -----------
    model_name : str   (default "protectai/deberta-v3-base-prompt-injection-v2")
    threshold  : float (default 0.80) — threat score above which to block.
    max_length : int   (default 512)  — tokeniser truncation limit.
    """

    @property
    def name(self) -> str:
        return "classify"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        import torch
        import torch.nn.functional as F

        t_start = time.perf_counter()

        model_name = self.config.get(
            "model_name", "protectai/deberta-v3-base-prompt-injection-v2"
        )
        threshold  = float(self.config.get("threshold", 0.80))
        max_length = int(self.config.get("max_length", 512))

        model, tokenizer = _load_prompt_guard(model_name)

        # Always use original_input — bypass-resistant (masking ≠ sanitising)
        inputs = tokenizer(
            payload.original_input,
            return_tensors="pt",
            truncation=True,
            max_length=max_length,
        )
        with torch.no_grad():
            logits = model(**inputs).logits

        probs    = F.softmax(logits, dim=-1)[0]
        id2label = model.config.id2label   # e.g. {0: "SAFE", 1: "INJECTION"}

        label_scores: dict[str, float] = {
            id2label[i].upper(): round(float(p), 4)
            for i, p in enumerate(probs)
        }

        # Support both naming conventions across models:
        #   protectai model → SAFE / INJECTION
        #   meta model      → BENIGN / INJECTION / JAILBREAK
        safe_score   = label_scores.get("SAFE", label_scores.get("BENIGN", 1.0))
        threat_score = round(1.0 - safe_score, 4)

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        # ── Record raw trace for API Inspector ────────────────────────────
        payload.raw_traces[self.name] = {
            "request": {
                "text_checked": payload.original_input,
                "model":        model_name,
                "threshold":    threshold,
            },
            "response": {
                "label_scores": label_scores,
                "threat_score": threat_score,
                "blocked":      threat_score >= threshold,
            },
        }

        if threat_score >= threshold:
            payload.is_blocked   = True
            payload.block_reason = (
                f"Injection classifier: prompt injection detected "
                f"(threat={threat_score:.2f} \u2265 threshold={threshold:.2f})"
            )
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      threat_score,
                "verdict":    "BLOCK",
                "detail":     payload.block_reason,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      threat_score,
                "verdict":    "PASS",
                "detail":     f"Injection classifier: safe (threat={threat_score:.2f})",
            })

        return payload


# ── Gate 1d: ToxicityInputGate ────────────────────────────────────────────────

class ToxicityInputGate(SecurityGate):
    """Detects hostile, abusive, or toxic tone in user input.

    Runs two sub-scanners against ``payload.original_input``:

    1. **Toxicity** — HuggingFace classifier that scores abusive language,
       threats, insults, and obscenity.  Flags when the toxicity score
       exceeds ``toxicity_threshold``.

    2. **Sentiment** — Scores overall sentiment from -1 (very negative) to
       1 (very positive).  Flags when the score falls below
       ``sentiment_threshold`` (default -0.5) indicating extreme negativity
       that may signal a hostile actor.

    Quality gate — defaults to AUDIT.  Hard-blocking users for tone alone
    is rarely appropriate; AUDIT surfaces the signal without refusing service.

    Config keys
    -----------
    toxicity_threshold  : float (default 0.5)  — toxicity classifier cutoff.
    sentiment_threshold : float (default -0.5) — sentiment score floor.
    """

    @property
    def name(self) -> str:
        return "toxicity_in"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        t_start = time.perf_counter()

        if not _LLM_GUARD_OK:
            return _llm_guard_skip(self.name, t_start, payload)

        from llm_guard.input_scanners import Toxicity, Sentiment

        tox_threshold  = float(self.config.get("toxicity_threshold",  0.5))
        sent_threshold = float(self.config.get("sentiment_threshold", -0.5))

        text     = payload.original_input
        findings: list[str] = []

        # ── Sub-scan 1: Toxicity ──────────────────────────────────────────────
        tox_scanner = Toxicity(threshold=tox_threshold)
        _, tox_valid, tox_score = tox_scanner.scan(text)
        tox_result = {
            "is_valid":   tox_valid,
            "risk_score": round(float(tox_score), 4),
        }
        if not tox_valid:
            findings.append(f"Toxic language detected (score={float(tox_score):.2f})")

        # ── Sub-scan 2: Sentiment ─────────────────────────────────────────────
        sent_scanner = Sentiment(threshold=sent_threshold)
        _, sent_valid, sent_score = sent_scanner.scan(text)
        sent_result = {
            "is_valid":        sent_valid,
            "sentiment_score": round(float(sent_score), 4),
        }
        if not sent_valid:
            findings.append(f"Extremely negative sentiment (score={float(sent_score):.2f})")

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        payload.raw_traces[self.name] = {
            "request":  {"text_checked": text},
            "response": {"toxicity": tox_result, "sentiment": sent_result},
        }

        top_score = max(float(tox_score), max(0.0, -float(sent_score)))

        if findings:
            payload.is_blocked   = True
            payload.block_reason = "; ".join(findings)
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(top_score, 4),
                "verdict":    "BLOCK",
                "detail":     payload.block_reason,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(top_score, 4),
                "verdict":    "PASS",
                "detail":     (
                    f"No toxicity or hostile sentiment detected "
                    f"(tox={float(tox_score):.2f}, sent={float(sent_score):.2f})."
                ),
            })

        return payload


# ── Gate 1e: BanTopicsGate ───────────────────────────────────────────────────

class BanTopicsGate(SecurityGate):
    """Blocks prompts that fall into operator-defined forbidden subject areas.

    Uses llm-guard's ``BanTopics`` input scanner, which applies a zero-shot
    text classification model (``MoritzLaurer/deberta-v3-base-zeroshot-v1.1-all-33``)
    to score the input against each configured topic.  If any topic exceeds the
    configured threshold the prompt is blocked.

    This gate is a **no-op** (verdict: SKIP) when no topics are configured, so
    enabling it without configuring topics has no effect on the pipeline.

    Use cases
    ---------
    - Restrict a customer-service bot to only discuss the company's products.
    - Prevent a coding assistant from discussing politics or religion.
    - Enforce subject-matter constraints in regulated environments (e.g. legal,
      medical) without writing exhaustive keyword lists.

    Compared to ``CustomRegexGate``
    --------------------------------
    CustomRegexGate matches exact phrases — fast but brittle (easily paraphrased).
    BanTopicsGate understands semantic meaning — "how do I make a bomb" and
    "explain explosive synthesis" both hit a "weapons" topic even though they
    share no keywords.  The tradeoff is latency (500 ms–2 s on CPU vs < 1 ms).

    Gate ordering note
    ------------------
    Runs last in the input chain because it is the most expensive CPU-bound
    scanner (zero-shot model inference).  Cheaper gates (regex, token limit,
    invisible text, fast scan, classify, toxicity) run first and may short-circuit
    before this gate is reached.

    Config keys
    -----------
    topics    : list[str]  (required) — forbidden subject areas, e.g.
                ["weapons", "self-harm", "politics"].  Empty list → SKIP.
    threshold : float      (default 0.5) — zero-shot classification confidence
                cutoff above which a topic match is treated as a violation.
    """

    @property
    def name(self) -> str:
        return "ban_topics"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        t_start = time.perf_counter()

        topics    = self.config.get("topics", [])
        threshold = float(self.config.get("threshold", 0.5))

        # No-op path — no topics configured
        if not topics:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": round((time.perf_counter() - t_start) * 1000, 2),
                "score":      0.0,
                "verdict":    "SKIP",
                "detail":     "No banned topics configured.",
            })
            return payload

        if not _LLM_GUARD_OK:
            return _llm_guard_skip(self.name, t_start, payload)

        from llm_guard.input_scanners import BanTopics

        scanner = BanTopics(topics=topics, threshold=threshold)
        _, is_valid, risk_score = scanner.scan(payload.original_input)

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        payload.raw_traces[self.name] = {
            "request": {
                "text_checked": payload.original_input,
                "topics":       topics,
                "threshold":    threshold,
            },
            "response": {
                "is_valid":   is_valid,
                "risk_score": round(float(risk_score), 4),
            },
        }

        if not is_valid:
            payload.is_blocked   = True
            payload.block_reason = (
                f"Prompt covers a restricted topic "
                f"(score={float(risk_score):.2f} \u2265 threshold={threshold:.2f}). "
                f"Configured topics: {', '.join(topics)}."
            )
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(float(risk_score), 4),
                "verdict":    "BLOCK",
                "detail":     payload.block_reason,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(float(risk_score), 4),
                "verdict":    "PASS",
                "detail":     (
                    f"No restricted topics detected (score={float(risk_score):.2f}). "
                    f"Topics checked: {', '.join(topics)}."
                ),
            })

        return payload


# ── Gate B: SensitiveGate ────────────────────────────────────────────────────

class SensitiveGate(SecurityGate):
    """Output-side PII scanner — catches PII the LLM generates on its own.

    The input-side ``FastScanGate`` (Anonymize) can only mask PII that the
    *user* typed.  If the model hallucinates a real person's details, invents
    a plausible phone number, or regurgitates training data that contains PII,
    none of that is captured by the input chain.  This gate closes that gap.

    Runs Microsoft Presidio (via llm-guard's ``Sensitive`` output scanner)
    against ``payload.output_text`` after inference.  When PII is detected:

    - ``payload.output_text`` is updated with the redacted version
      (e.g. ``[PERSON]``, ``[US_SSN]``).
    - ``payload.is_blocked`` is set to True so the pipeline manager can apply
      the configured mode (AUDIT clears the flag and logs; ENFORCE halts).

    Gate ordering note
    ------------------
    This gate must run BEFORE ``DeanonymizeGate`` in the output chain.
    Deanonymize restores the user's own PII placeholders (e.g. from FastScan);
    SensitiveGate should see the still-placeholder-filled output so it only
    flags PII the *model* introduced, not PII the user already provided.

    Config keys
    -----------
    entity_types  : list[str] | None (default None — all Presidio entities).
    pii_threshold : float (default 0.5) — Presidio confidence cutoff.
    """

    @property
    def name(self) -> str:
        return "sensitive_out"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        t_start = time.perf_counter()

        if not _LLM_GUARD_OK:
            return _llm_guard_skip(self.name, t_start, payload)

        from llm_guard.output_scanners import Sensitive

        if not payload.output_text:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": round((time.perf_counter() - t_start) * 1000, 2),
                "score":      0.0,
                "verdict":    "SKIP",
                "detail":     "No output text to scan.",
            })
            return payload

        entity_types  = self.config.get("entity_types", None)
        pii_threshold = float(self.config.get("pii_threshold", 0.5))

        scanner = Sensitive(entity_types=entity_types, threshold=pii_threshold, redact=True)
        # llm-guard output scanners: scan(prompt, output) → (sanitized, is_valid, risk_score)
        sanitized, is_valid, risk_score = scanner.scan(
            payload.current_text,   # prompt (the masked user input the model saw)
            payload.output_text,    # model's raw response
        )

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        pii_found = not is_valid

        payload.raw_traces[self.name] = {
            "request": {
                "output_text":    payload.output_text,
                "pii_threshold":  pii_threshold,
                "entity_types":   entity_types,
            },
            "response": {
                "sanitized_text": sanitized,
                "is_valid":       is_valid,
                "risk_score":     round(float(risk_score), 4),
                "pii_found":      pii_found,
            },
        }

        if pii_found:
            payload.output_text  = sanitized   # replace with redacted version
            payload.is_blocked   = True
            payload.block_reason = (
                f"LLM-generated PII detected and redacted in response "
                f"(score={float(risk_score):.2f})."
            )
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(float(risk_score), 4),
                "verdict":    "BLOCK",
                "detail":     payload.block_reason,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(float(risk_score), 4),
                "verdict":    "PASS",
                "detail":     "No PII detected in model response.",
            })

        return payload


# ── Gate E: BiasOutputGate ───────────────────────────────────────────────────

class BiasOutputGate(SecurityGate):
    """Detects biased or toxic content in model responses.

    Runs two sub-scanners against ``payload.output_text``:

    1. **Bias** — distilroberta-bias classifier that detects biased language
       across protected characteristics (race, gender, religion, etc.).

    2. **Toxicity** — output-side toxicity classifier; the same model family
       as the input Toxicity gate but applied to the response.

    Neither sub-scanner modifies the output text — this gate is a monitoring
    and flagging tool, not a sanitiser.  ENFORCE mode halts the pipeline if
    either sub-scanner fires.

    Quality gate — defaults to AUDIT.

    Config keys
    -----------
    threshold : float (default 0.5) — shared cutoff for both sub-scanners.
    """

    @property
    def name(self) -> str:
        return "bias_out"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        t_start = time.perf_counter()

        if not _LLM_GUARD_OK:
            return _llm_guard_skip(self.name, t_start, payload)

        from llm_guard.output_scanners import Bias, Toxicity as ToxicityOutput

        if not payload.output_text:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": round((time.perf_counter() - t_start) * 1000, 2),
                "score":      0.0,
                "verdict":    "SKIP",
                "detail":     "No output text to scan.",
            })
            return payload

        threshold = float(self.config.get("threshold", 0.5))
        text      = payload.output_text
        findings: list[str] = []

        # ── Sub-scan 1: Bias ──────────────────────────────────────────────────
        bias_scanner = Bias(threshold=threshold)
        _, bias_valid, bias_score = bias_scanner.scan(payload.current_text, text)
        bias_result = {"is_valid": bias_valid, "risk_score": round(float(bias_score), 4)}
        if not bias_valid:
            findings.append(f"Biased content detected (score={float(bias_score):.2f})")

        # ── Sub-scan 2: Toxicity (output-side) ───────────────────────────────
        tox_scanner = ToxicityOutput(threshold=threshold)
        _, tox_valid, tox_score = tox_scanner.scan(payload.current_text, text)
        tox_result = {"is_valid": tox_valid, "risk_score": round(float(tox_score), 4)}
        if not tox_valid:
            findings.append(f"Toxic output detected (score={float(tox_score):.2f})")

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)
        top_score  = max(float(bias_score), float(tox_score))

        payload.raw_traces[self.name] = {
            "request":  {"output_text": text, "threshold": threshold},
            "response": {"bias": bias_result, "toxicity": tox_result},
        }

        if findings:
            payload.is_blocked   = True
            payload.block_reason = "; ".join(findings)
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(top_score, 4),
                "verdict":    "BLOCK",
                "detail":     payload.block_reason,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(top_score, 4),
                "verdict":    "PASS",
                "detail":     (
                    f"No bias or toxicity detected in response "
                    f"(bias={float(bias_score):.2f}, tox={float(tox_score):.2f})."
                ),
            })

        return payload


# ── Gate F: RelevanceGate ─────────────────────────────────────────────────────

class RelevanceGate(SecurityGate):
    """Detects off-topic or hallucinated responses using embedding similarity.

    Embeds both the original user prompt and the model's response using
    BAAI/bge-base-en-v1.5 (via llm-guard's ``Relevance`` output scanner) and
    computes cosine similarity.  A low score means the model drifted from the
    question — a common hallucination signal and an indicator that a jailbreak
    may have succeeded in redirecting the model.

    Does NOT modify ``payload.output_text`` — the response is always shown.
    This gate is a monitoring tool.

    Gate ordering note
    ------------------
    Runs before ``DeanonymizeGate`` so the similarity comparison uses the
    placeholder-filled output (which is what the model actually responded to).

    Quality gate — defaults to AUDIT.

    Config keys
    -----------
    threshold  : float (default 0.5)   — minimum cosine similarity to PASS.
    head_chars : int   (default 300)   — number of leading characters of the
                 response to embed.  Using the full response inflates similarity
                 when the model appends meta-comments that reference the original
                 topic (e.g. "Note: your query was about X…"), producing false
                 PASSes even when the actual content is off-topic.
    """

    @property
    def name(self) -> str:
        return "relevance"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        t_start = time.perf_counter()

        if not _LLM_GUARD_OK:
            return _llm_guard_skip(self.name, t_start, payload)

        from llm_guard.output_scanners import Relevance

        if not payload.output_text:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": round((time.perf_counter() - t_start) * 1000, 2),
                "score":      0.0,
                "verdict":    "SKIP",
                "detail":     "No output text to scan.",
            })
            return payload

        threshold    = float(self.config.get("threshold", 0.5))
        head_chars   = int(self.config.get("head_chars", 300))

        # Truncate to the first `head_chars` characters of the response before
        # embedding.  Whole-document similarity is easily inflated by meta-
        # comments the model appends (e.g. "Note: your query was about X…"),
        # which pull the embedding back toward the prompt even when the actual
        # response content is completely off-topic.  Checking only the leading
        # content captures what the model *led with* — the true answer signal.
        response_head = payload.output_text[:head_chars]

        scanner = Relevance(threshold=threshold)
        # Use original_input as the reference prompt — most semantically
        # complete representation of the user's intent.
        _, is_valid, risk_score = scanner.scan(
            payload.original_input,
            response_head,
        )

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)
        # risk_score from Relevance: high = irrelevant, low = relevant.
        # Similarity = 1 - risk_score for the detail message.
        similarity = round(1.0 - float(risk_score), 4)

        payload.raw_traces[self.name] = {
            "request": {
                "prompt":        payload.original_input,
                "response_head": response_head,
                "head_chars":    head_chars,
                "threshold":     threshold,
            },
            "response": {
                "is_valid":   is_valid,
                "risk_score": round(float(risk_score), 4),
                "similarity": similarity,
            },
        }

        if not is_valid:
            payload.is_blocked   = True
            payload.block_reason = (
                f"Response may be off-topic or hallucinated "
                f"(similarity={similarity:.2f} < threshold={threshold:.2f})."
            )
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(float(risk_score), 4),
                "verdict":    "BLOCK",
                "detail":     payload.block_reason,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(float(risk_score), 4),
                "verdict":    "PASS",
                "detail":     f"Response is on-topic (similarity={similarity:.2f}).",
            })

        return payload


# ── Gate G: LanguageSameGate ─────────────────────────────────────────────────

class LanguageSameGate(SecurityGate):
    """Ensures the model responds in the same language as the user prompt.

    Uses llm-guard's ``LanguageSame`` output scanner to detect the language of
    both the prompt and the response, then checks for overlap.  A mismatch
    signals:
      - The LLM silently switched language mid-response.
      - A multilingual jailbreak succeeded in redirecting the model's output.
      - The model drifted to a training-data language after an unusual prompt.

    Shares the ``papluca/xlm-roberta-base-language-detection`` model weights
    with ``LanguageGate`` (input) — no additional memory is consumed when both
    gates are active.

    Quality gate — defaults to AUDIT.

    Config keys
    -----------
    threshold : float (default 0.1) — minimum classifier confidence for a
                language detection to count in either prompt or response.
                Low by default to catch weak language signals; raise to 0.5+
                to reduce false positives on very short or mixed-language text.
    """

    @property
    def name(self) -> str:
        return "language_same"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        t_start = time.perf_counter()

        if not _LLM_GUARD_OK:
            return _llm_guard_skip(self.name, t_start, payload)

        from llm_guard.output_scanners import LanguageSame

        if not payload.output_text:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": round((time.perf_counter() - t_start) * 1000, 2),
                "score":      0.0,
                "verdict":    "SKIP",
                "detail":     "No output text to scan.",
            })
            return payload

        threshold = float(self.config.get("threshold", 0.1))

        scanner = LanguageSame(threshold=threshold)
        _, is_valid, risk_score = scanner.scan(
            payload.original_input,
            payload.output_text,
        )

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        payload.raw_traces[self.name] = {
            "request": {
                "prompt":    payload.original_input,
                "response":  payload.output_text[:200],  # truncate for trace readability
                "threshold": threshold,
            },
            "response": {
                "is_valid":   is_valid,
                "risk_score": round(float(risk_score), 4),
            },
        }

        if not is_valid:
            payload.is_blocked   = True
            payload.block_reason = (
                f"Response language does not match prompt language "
                f"(score={float(risk_score):.2f})."
            )
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(float(risk_score), 4),
                "verdict":    "BLOCK",
                "detail":     payload.block_reason,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(float(risk_score), 4),
                "verdict":    "PASS",
                "detail":     "Response language matches prompt language.",
            })

        return payload


# ── Gate A: DeanonymizeGate ───────────────────────────────────────────────────

class DeanonymizeGate(SecurityGate):
    """Restores PII placeholders in the LLM response using the shared Vault.

    Must run as an output gate after inference.  Reads ``payload.vault`` —
    the same ``Vault`` instance that ``FastScanGate`` populated during the
    input scan — and replaces placeholders like ``[REDACTED_PERSON_1]`` with
    the original PII values so the user-visible response is natural.

    If ``payload.vault`` is None (FastScanGate did not run, or found no PII),
    this gate is a no-op (verdict: SKIP).

    Config keys
    -----------
    None — this gate has no configurable parameters.
    """

    @property
    def name(self) -> str:
        return "deanonymize"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        import time

        t_start = time.perf_counter()

        if not _LLM_GUARD_OK:
            return _llm_guard_skip(self.name, t_start, payload)

        from llm_guard.output_scanners import Deanonymize

        if payload.vault is None or not payload.output_text:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": round((time.perf_counter() - t_start) * 1000, 2),
                "score":      0.0,
                "verdict":    "SKIP",
                "detail":     "No vault — FastScanGate did not run or found no PII.",
            })
            return payload

        scanner = Deanonymize(payload.vault)
        restored, _is_valid, risk_score = scanner.scan(
            payload.output_text,
            payload.output_text,   # llm-guard output scanners take (prompt, output)
        )

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        payload.raw_traces[self.name] = {
            "request": {"output_text": payload.output_text},
            "response": {"restored_text": restored},
        }

        changed = restored != payload.output_text
        payload.output_text = restored

        payload.metrics.append({
            "gate_name":  self.name,
            "latency_ms": latency_ms,
            "score":      round(float(risk_score), 4),
            "verdict":    "PASS" if changed else "SKIP",
            "detail":     (
                "PII placeholders restored to original values."
                if changed else
                "No placeholders found in response."
            ),
        })

        return payload


# ── URL heuristics (module-level, zero-ML) ────────────────────────────────────

import re as _re
from urllib.parse import urlparse as _urlparse

_URL_RE = _re.compile(r"https?://[^\s\]<>\"']+", _re.IGNORECASE)

# Digits / symbols that visually substitute letters in brand impersonation
_DIGIT_SUB = str.maketrans("01358@", "olssba")

_KNOWN_BRANDS = frozenset({
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "twitter", "netflix", "dropbox", "linkedin", "github",
    "gitlab", "wellsfargo", "bankofamerica", "chase", "citibank",
    "steam", "discord", "twitch", "youtube",
})

_SUSPICIOUS_EXTENSIONS = frozenset({
    ".exe", ".bat", ".ps1", ".vbs", ".jar", ".msi",
    ".scr", ".dll", ".cmd", ".hta", ".pif", ".sh",
})

_IP_RE = _re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _check_url_heuristics(url: str) -> tuple[bool, str]:
    """Return (is_suspicious, reason).  Runs in < 1 ms per URL."""
    try:
        parsed  = _urlparse(url)
        host    = (parsed.hostname or "").lower()
        path    = (parsed.path or "").lower()
    except Exception:
        return False, ""

    # 1. Bare IP address as host
    if _IP_RE.match(host):
        return True, f"IP address used as host ({host})"

    # 2. Suspicious executable extension in path
    if any(path.endswith(ext) for ext in _SUSPICIOUS_EXTENSIONS):
        return True, f"Executable file extension in URL path"

    # 3. Punycode / IDN domain (xn--)
    if "xn--" in host:
        return True, f"Internationalized (IDN/punycode) domain: {host}"

    # 4. Brand impersonation via digit/symbol substitution
    # Strip port, split on dots, take the registrable domain label
    labels        = host.split(".")
    domain_label  = labels[-2] if len(labels) >= 2 else labels[0]
    normalised    = domain_label.translate(_DIGIT_SUB).replace("-", "")
    for brand in _KNOWN_BRANDS:
        # Flag when: the normalised form contains the brand name AND the
        # original label was actually modified by the translation (i.e. a
        # substitution was made).  Checking `domain_label != normalised`
        # rather than `normalised != brand` correctly handles cases like
        # "g00gle" → "google" where normalised equals the brand exactly.
        if brand in normalised and domain_label != normalised:
            return True, f"Possible brand impersonation of '{brand}' in: {host}"

    # 5. Excessive subdomains (> 3 dots in host → likely abuse of free subdomain)
    if host.count(".") > 3:
        return True, f"Excessive subdomains in host: {host}"

    return False, ""


def _redact_urls(text: str, bad_urls: set[str]) -> str:
    """Replace each bad URL in *text* with ``[REDACTED_URL]``."""
    for url in bad_urls:
        text = text.replace(url, "[REDACTED_URL]")
    return text


# ── Gate C: MaliciousURLsGate ─────────────────────────────────────────────────

class MaliciousURLsGate(SecurityGate):
    """Detects and removes malicious URLs from LLM responses.

    Two-layer detection — belt-and-suspenders:

    **Layer 1 — Heuristics (zero-ML, < 1 ms)**
    Extracts every URL in ``payload.output_text`` with a regex and tests each
    against structural rules that catch the patterns ML models often miss:

      - Bare IP address as host (e.g. ``http://192.168.1.1/payload.exe``)
      - Executable file extensions (.exe, .bat, .ps1, .sh, …)
      - Punycode / IDN domains (``xn--`` prefix — Unicode spoofing)
      - Brand impersonation via digit/symbol substitution
        (``paypa1.com``, ``g00gle.com``, ``micros0ft.net``)
      - Excessive subdomains (> 3 dots) — common in free-subdomain abuse

    **Layer 2 — llm-guard ML scanner**
    Runs the llm-guard ``MaliciousURLs`` output scanner (HuggingFace CNN URL
    classifier) over the full output text for patterns heuristics may miss.

    Either layer triggering produces a BLOCK verdict; detected URLs are
    replaced with ``[REDACTED_URL]`` in ``payload.output_text``.

    Config keys
    -----------
    threshold : float (default 0.5) — ML scanner confidence cutoff.
    """

    @property
    def name(self) -> str:
        return "malicious_urls"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        t_start = time.perf_counter()

        if not payload.output_text:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": round((time.perf_counter() - t_start) * 1000, 2),
                "score":      0.0,
                "verdict":    "SKIP",
                "detail":     "No output text to scan.",
            })
            return payload

        threshold = float(self.config.get("threshold", 0.5))

        # ── Layer 1: heuristic scan (zero-ML, always runs) ───────────────────
        # Deduplicate URLs so a URL appearing twice in the output is only checked once.
        seen: set[str] = set()
        all_urls: list[str] = []
        for u in _URL_RE.findall(payload.output_text):
            if u not in seen:
                seen.add(u)
                all_urls.append(u)

        heuristic_hits: list[str] = []
        bad_urls: set[str] = set()

        for url in all_urls:
            suspicious, reason = _check_url_heuristics(url)
            if suspicious:
                heuristic_hits.append(f"{url} → {reason}")
                bad_urls.add(url)

        heuristic_blocked = bool(bad_urls)
        working_text = _redact_urls(payload.output_text, bad_urls) if heuristic_blocked else payload.output_text

        # ── Layer 2: llm-guard ML scanner (optional — skipped if not installed) ─
        ml_sanitized, ml_is_valid, ml_risk_score = working_text, True, 0.0
        if _LLM_GUARD_OK:
            from llm_guard.output_scanners import MaliciousURLs
            scanner = MaliciousURLs(threshold=threshold)
            ml_sanitized, ml_is_valid, ml_risk_score = scanner.scan(
                payload.current_text,
                working_text,
            )

        latency_ms   = round((time.perf_counter() - t_start) * 1000, 2)
        ml_blocked   = not ml_is_valid
        final_text   = ml_sanitized if ml_blocked else working_text
        any_blocked  = heuristic_blocked or ml_blocked
        top_score    = max(1.0 if heuristic_blocked else 0.0, float(ml_risk_score))

        payload.raw_traces[self.name] = {
            "request": {"output_text": payload.output_text, "threshold": threshold},
            "response": {
                "urls_found":        all_urls,
                "heuristic_hits":    heuristic_hits,
                "heuristic_blocked": heuristic_blocked,
                "ml_is_valid":       ml_is_valid,
                "ml_risk_score":     round(float(ml_risk_score), 4),
                "final_text":        final_text,
            },
        }

        if any_blocked:
            payload.output_text = final_text
            payload.is_blocked  = True

            # block_reason: short summary for the generic "Output blocked" banner
            source_tags: list[str] = []
            if heuristic_blocked:
                source_tags.append("heuristic")
            if ml_blocked:
                source_tags.append(f"ML score={float(ml_risk_score):.2f}")
            payload.block_reason = (
                f"Malicious URL detected and removed ({', '.join(source_tags)})."
            )

            # metric detail: full per-URL breakdown for the custom notice / API Inspector
            detail_parts: list[str] = []
            if heuristic_hits:
                detail_parts.extend(heuristic_hits)
            if ml_blocked:
                detail_parts.append(f"ML classifier score={float(ml_risk_score):.2f}")
            full_detail = "; ".join(detail_parts)

            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(top_score, 4),
                "verdict":    "BLOCK",
                "detail":     full_detail,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(float(ml_risk_score), 4),
                "verdict":    "PASS",
                "detail":     (
                    f"No malicious URLs detected ({len(all_urls)} URL(s) checked)."
                    if all_urls else "No URLs found in response."
                ),
            })

        return payload


# ── Gate D: NoRefusalGate ─────────────────────────────────────────────────────

class NoRefusalGate(SecurityGate):
    """Detects when the model declines to answer.

    Uses llm-guard's ``NoRefusal`` output scanner (a text classifier) to
    identify refusal patterns such as "I cannot help with that", "I'm sorry,
    I'm not able to", "As an AI I must decline", etc.

    This gate does NOT modify ``payload.output_text`` — a refusal is a valid
    (if unwanted) response and the user should still see it.  The gate simply
    sets ``is_blocked = True`` so the pipeline manager can apply the configured
    mode:

      AUDIT (default) — records a BLOCK verdict in telemetry so the workbench
        surfaces a "Model refused" badge.  Useful for red-team analysis:
        "did this attack trigger a safety refusal or slip through?"

      ENFORCE — additionally shows an error banner.  Use this in automated
        red-team test runs where a refusal should be treated as a hard failure.

    Config keys
    -----------
    threshold  : float (default 0.5) — refusal confidence cutoff.
    model_name : str   (optional)    — override the llm-guard default classifier.
    """

    @property
    def name(self) -> str:
        return "no_refusal"

    def _scan(self, payload: PipelinePayload) -> PipelinePayload:
        t_start = time.perf_counter()

        if not _LLM_GUARD_OK:
            return _llm_guard_skip(self.name, t_start, payload)

        from llm_guard.output_scanners import NoRefusal

        if not payload.output_text:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": round((time.perf_counter() - t_start) * 1000, 2),
                "score":      0.0,
                "verdict":    "SKIP",
                "detail":     "No output text to scan.",
            })
            return payload

        threshold = float(self.config.get("threshold", 0.5))

        kwargs: dict = {"threshold": threshold}
        if "model_name" in self.config:
            kwargs["model"] = self.config["model_name"]

        scanner = NoRefusal(**kwargs)
        # NoRefusal: is_valid=False means a refusal was detected
        _output, is_valid, risk_score = scanner.scan(
            payload.current_text,
            payload.output_text,
        )
        # Never replace output_text — the refusal message is shown to the user.

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)
        refusal_detected = not is_valid

        payload.raw_traces[self.name] = {
            "request": {
                "output_text": payload.output_text,
                "threshold":   threshold,
            },
            "response": {
                "is_valid":         is_valid,
                "risk_score":       round(float(risk_score), 4),
                "refusal_detected": refusal_detected,
            },
        }

        if refusal_detected:
            payload.is_blocked   = True
            payload.block_reason = (
                f"Model refused to answer "
                f"(confidence={float(risk_score):.2f})."
            )
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(float(risk_score), 4),
                "verdict":    "BLOCK",
                "detail":     payload.block_reason,
            })
        else:
            payload.metrics.append({
                "gate_name":  self.name,
                "latency_ms": latency_ms,
                "score":      round(float(risk_score), 4),
                "verdict":    "PASS",
                "detail":     f"No refusal detected (score={float(risk_score):.2f}).",
            })

        return payload
