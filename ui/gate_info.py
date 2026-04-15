"""
ui/gate_info.py
───────────────
Shared gate metadata — consumed by:
  • ui/chat_view.py      → sidebar ⓘ popovers on every gate toggle
  • ui/howto_view.py     → Pipeline Reference page

Each entry is keyed by the gate_key used in session_state.gate_modes.
"""

from __future__ import annotations

# method tag → (display label, badge colour)
METHOD_STYLES: dict[str, tuple[str, str]] = {
    "static": ("Static / Rules",  "#9ECE6A"),   # green  — no ML, < 1 ms
    "ml":     ("ML Model (CPU)", "#7AA2F7"),    # blue   — local model, ms range
    "llm":    ("LLM / Ollama",   "#BB9AF7"),    # purple — Ollama call, seconds
}

# Ordered list of (gate_key, metadata) so the How It Works page preserves
# pipeline execution order without having to sort.
GATE_INFO: dict[str, dict] = {

    # ── Input gates ───────────────────────────────────────────────────────────

    "custom_regex": {
        "label":       "Regex Hot-Patch",
        "category":    "Input",
        "method":      "static",
        "latency":     "< 1 ms",
        "description": (
            "Scans the raw prompt against a user-defined list of block phrases "
            "using case-insensitive substring matching. Zero ML — pure Python, "
            "no dependencies. Hot-patch known attack strings without redeploying "
            "the application."
        ),
        "block_means": "A configured phrase was found verbatim in the prompt.",
    },

    "token_limit": {
        "label":       "Token Limit",
        "category":    "Input",
        "method":      "static",
        "latency":     "< 1 ms",
        "description": (
            "Counts prompt tokens with OpenAI's tiktoken (cl100k_base encoding) "
            "and rejects inputs that exceed the configured budget. Runs before any "
            "ML gate to save compute. Guards against token-stuffing and "
            "context-window overflow attacks."
        ),
        "block_means": "Prompt token count exceeded the configured limit.",
    },

    "invisible_text": {
        "label":       "Invisible Text",
        "category":    "Input",
        "method":      "static",
        "latency":     "< 1 ms",
        "description": (
            "Detects zero-width characters, homoglyph substitutions, and other "
            "Unicode steganography techniques used to hide instructions from human "
            "reviewers while the model still processes them. Pure character-set "
            "analysis — no ML needed."
        ),
        "block_means": "Hidden Unicode characters were found in the prompt.",
    },

    "fast_scan": {
        "label":       "PII / Secrets",
        "category":    "Input",
        "method":      "ml",
        "latency":     "10 – 200 ms",
        "description": (
            "Uses Microsoft Presidio (NER + rules) to detect PII (names, SSNs, "
            "emails, credit cards) and a secrets scanner for API keys and tokens. "
            "In AUDIT mode, detected PII is anonymised with [REDACTED_*] "
            "placeholders before the prompt reaches the LLM."
        ),
        "block_means": "PII or credentials were detected in the prompt.",
    },

    "classify": {
        "label":       "Injection Detect",
        "category":    "Input",
        "method":      "ml",
        "latency":     "50 – 500 ms",
        "description": (
            "Runs the prompt through a DeBERTa-v3 model fine-tuned on prompt "
            "injection and jailbreak examples "
            "(protectai/deberta-v3-base-prompt-injection-v2). Produces a 0–1 "
            "confidence score with a configurable threshold. Strong CPU-only "
            "detection for adversarial instruction injection."
        ),
        "block_means": "Injection or jailbreak confidence score exceeded the threshold.",
    },

    "toxicity_in": {
        "label":       "Toxicity (Input)",
        "category":    "Input",
        "method":      "ml",
        "latency":     "20 – 100 ms",
        "description": (
            "Combines a Hugging Face toxicity classifier with VADER sentiment "
            "analysis to flag hostile or abusive input tone. AUDIT mode is "
            "recommended — tone alone rarely warrants a hard block, but high "
            "toxicity scores are a useful signal during red-team analysis."
        ),
        "block_means": "Input toxicity or extreme negative sentiment exceeded threshold.",
    },

    "ban_topics": {
        "label":       "Ban Topics",
        "category":    "Input",
        "method":      "ml",
        "latency":     "100 – 500 ms",
        "description": (
            "Uses zero-shot NLI (Natural Language Inference) to detect semantically "
            "forbidden topics — genuine topic understanding, not keyword matching. "
            "Catches paraphrased attempts that easily bypass regex-based filters."
        ),
        "block_means": "Prompt topic matched a configured forbidden subject area.",
    },

    "mod_llm": {
        "label":       "Llama Guard 3",
        "category":    "Input",
        "method":      "llm",
        "latency":     "1 – 10 s",
        "description": (
            "Sends the prompt to Meta's Llama Guard 3 safety classifier running "
            "locally in Ollama. Evaluates 14 harm categories (S1–S14) covering "
            "violence, self-harm, sexual content, privacy violations, and more. "
            "Highest accuracy of all input gates — placed last to run only when "
            "cheaper gates pass."
        ),
        "block_means": "Llama Guard 3 classified the prompt as unsafe (categories S1–S14).",
    },

    # ── Output gates ──────────────────────────────────────────────────────────

    "sensitive_out": {
        "label":       "PII (Output)",
        "category":    "Output",
        "method":      "ml",
        "latency":     "10 – 200 ms",
        "description": (
            "Applies the Presidio PII scanner to the LLM's response. Catches PII "
            "the model fabricated or inferred that was never present in the original "
            "prompt — a hallucination risk that input-side scanning cannot detect."
        ),
        "block_means": "PII was detected in the model's response.",
    },

    "malicious_urls": {
        "label":       "Malicious URLs",
        "category":    "Output",
        "method":      "ml",
        "latency":     "5 – 50 ms",
        "description": (
            "Extracts all URLs from the model response and scores each using "
            "heuristics and an ML classifier (suspicious TLDs, path patterns, "
            "redirect chains). In ENFORCE mode, detected URLs are removed to "
            "prevent the model directing users to harmful sites."
        ),
        "block_means": "A malicious or suspicious URL was detected in the response.",
    },

    "no_refusal": {
        "label":       "Refusal Detect",
        "category":    "Output",
        "method":      "ml",
        "latency":     "20 – 100 ms",
        "description": (
            "Detects when the model declines to answer. Used during red-team "
            "sessions to measure how often attacks trigger safety refusals and "
            "to identify over-blocking. This is a monitoring gate, not a user-facing "
            "safety block — AUDIT mode is the intended use."
        ),
        "block_means": "Model refused to answer (red-team signal, not a user-facing block).",
    },

    "bias_out": {
        "label":       "Bias / Toxicity",
        "category":    "Output",
        "method":      "ml",
        "latency":     "20 – 100 ms",
        "description": (
            "Scores the model response for bias, hate speech, and toxic language "
            "using a Hugging Face classifier. Catches responses that passed all "
            "safety gates but contain subtle bias or harmful framing. Primarily a "
            "quality and compliance monitoring signal."
        ),
        "block_means": "Response toxicity or bias score exceeded threshold.",
    },

    "relevance": {
        "label":       "Relevance",
        "category":    "Output",
        "method":      "ml",
        "latency":     "50 – 200 ms",
        "description": (
            "Computes semantic similarity between the user question and model "
            "response using sentence embeddings. A low score indicates off-topic "
            "drift, hallucination, or that a prompt injection attack redirected the "
            "model to answer a completely different question."
        ),
        "block_means": "Response similarity to the original question fell below threshold.",
    },

    "deanonymize": {
        "label":       "PII Restore",
        "category":    "Output",
        "method":      "static",
        "latency":     "< 1 ms",
        "description": (
            "The final output gate — swaps [REDACTED_*] placeholders introduced by "
            "the PII/Secrets gate back to the original values before the response is "
            "shown to the user. Requires the PII/Secrets gate to be active in AUDIT "
            "mode. Zero ML — pure dictionary lookup."
        ),
        "block_means": "Passthrough only — restores redacted values, never blocks.",
    },
}

# Execution-ordered list of gate keys (matches pipeline construction in app.py)
INPUT_GATE_KEYS: list[str] = [
    "custom_regex", "token_limit", "invisible_text",
    "fast_scan", "classify", "toxicity_in", "ban_topics", "mod_llm",
]
OUTPUT_GATE_KEYS: list[str] = [
    "sensitive_out", "malicious_urls", "no_refusal",
    "bias_out", "relevance", "deanonymize",
]
ALL_GATE_KEYS: list[str] = INPUT_GATE_KEYS + OUTPUT_GATE_KEYS
