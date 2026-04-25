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
    "cloud":  ("Cloud API",      "#FFB86C"),    # orange — outbound AIRS API call
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

    "gibberish": {
        "label":       "Gibberish Detect",
        "category":    "Input",
        "method":      "ml",
        "latency":     "20 – 100 ms",
        "description": (
            "Classifies the prompt into four quality levels — clean, mild gibberish, "
            "noise, and word salad — using a fine-tuned HuggingFace classifier "
            "(madhurjindal/autonlp-Gibberish-Detector). Catches noise-flood and "
            "token-waste attacks. Threshold is set high (0.97) by default to avoid "
            "false positives on unusual but legitimate technical inputs."
        ),
        "block_means": "Input classified as gibberish, noise, or word salad above threshold.",
    },

    "language_in": {
        "label":       "Language Enforce",
        "category":    "Input",
        "method":      "ml",
        "latency":     "50 – 200 ms",
        "description": (
            "Detects the prompt language using XLM-RoBERTa "
            "(papluca/xlm-roberta-base-language-detection) and blocks inputs not "
            "in the configured allow-list (default: English only). Prevents "
            "multilingual jailbreak bypass — attacks phrased in other languages to "
            "evade English-trained safety classifiers downstream."
        ),
        "block_means": "Prompt language was not in the configured allow-list.",
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

    "semantic_guard": {
        "label":       "Semantic Guard",
        "category":    "Input",
        "method":      "llm",
        "latency":     "0.5 – 5 s",
        "description": (
            "LLM-as-judge with a fully user-editable safety system prompt. "
            "Sends the prompt to a configurable Ollama model and expects a "
            "structured JSON verdict {safe, confidence, reason}. Catches "
            "intent-level threats — nuanced jailbreaks, social engineering, "
            "false authority framing, and novel phrasing — that fixed "
            "classifier models trained on labelled datasets may miss. "
            "Recommended models: shieldgemma:2b (safety-fine-tuned, fastest) "
            "or llama3.2:3b (general-purpose fallback). Fails open — any "
            "error logs a metric but never blocks legitimate traffic."
        ),
        "block_means": "LLM judge classified prompt as unsafe with confidence ≥ threshold.",
    },

    "little_canary": {
        "label":       "Little Canary",
        "category":    "Input",
        "method":      "llm",
        "latency":     "1 – 5 s",
        "description": (
            "Behavioral prompt-injection probe using the little-canary library "
            "(Hermes Labs). Three layers: (1) structural regex filter — 16 pattern "
            "groups + base64/hex/ROT13/reverse decoders, ~1 ms, no Ollama needed; "
            "(2) sandboxed canary Ollama probe — feeds the raw input to a small, "
            "intentionally-weak model at temperature=0 so attacks produce visible "
            "compromise residue; (3) BehavioralAnalyzer — examines the canary "
            "response for persona shifts, instruction echoes, refusal collapses, and "
            "authority granting. Recommended canary: qwen2.5:1.5b. "
            "Requires `pip install little-canary`."
        ),
        "block_means": "Canary response showed compromise residue — injection detected.",
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

    "airs_inlet": {
        "label":       "AIRS Inlet",
        "category":    "Input",
        "method":      "cloud",
        "latency":     "0.5 – 2 s",
        "description": (
            "Cloud-tier prompt scan via Palo Alto Networks AI Runtime Security "
            "(AIRS). Evaluates the user prompt against a configurable AI security "
            "profile in Strata Cloud Manager. Covers threat categories not "
            "detectable locally: URL reputation, IP reputation, agent system abuse, "
            "and policy-defined custom rules. Requires an AIRS API key and outbound "
            "HTTPS to Palo Alto Networks cloud. Degrades to SKIP when no key is "
            "configured — all local gates run unaffected. "
            "FAIL-CLOSED: API errors block in ENFORCE mode (vs. fail-open for all "
            "local gates) — ensures misconfigured credentials surface immediately."
        ),
        "block_means": "AIRS cloud scan returned action=block for the user prompt.",
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

    "canary_token": {
        "label":       "Canary Tokens",
        "category":    "Output",
        "method":      "static",
        "latency":     "< 1 ms",
        "description": (
            "Scans the LLM response for predefined sensitive strings (canary tokens) "
            "such as internal IP addresses, mock API keys, or project codenames. "
            "Zero ML — pure Python exact matching. This is a critical defense "
            "against Data Exfiltration and Indirect Prompt Injection (IPI) "
            "where an attacker tries to trick the model into leaking retrieved "
            "data from a RAG store."
        ),
        "block_means": "A sensitive canary token was detected in the model's response.",
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

    "language_same": {
        "label":       "Language Match",
        "category":    "Output",
        "method":      "ml",
        "latency":     "50 – 200 ms",
        "description": (
            "Detects whether the model responded in the same language as the prompt "
            "using XLM-RoBERTa (papluca/xlm-roberta-base-language-detection). "
            "Flags silent language switches and multilingual jailbreaks that redirect "
            "the model's output language. Reuses model weights already loaded by the "
            "Language Enforce gate — no additional memory cost when both are active."
        ),
        "block_means": "Response language did not match the detected prompt language.",
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

    "airs_dual": {
        "label":       "AIRS Dual",
        "category":    "Output",
        "method":      "cloud",
        "latency":     "0.5 – 2 s",
        "description": (
            "Cloud-tier response scan via Palo Alto Networks AI Runtime Security "
            "(AIRS). Evaluates the LLM response (with the original prompt as context) "
            "against the configured AI security profile. Uniquely, AIRS can apply DLP "
            "masking: when sensitive data is detected in the response, the gate "
            "replaces the displayed text with an AIRS-redacted version — even when "
            "the overall action is 'allow'. Covers response-side URL cats, DLP, "
            "toxic content, database security risk, and hallucination/ungrounded flags. "
            "Requires an AIRS API key. Degrades to SKIP when no key is configured. "
            "FAIL-OPEN: API errors log an error metric but never suppress the response."
        ),
        "block_means": "AIRS cloud scan returned action=block for the LLM response.",
    },
}

# Execution-ordered list of gate keys (matches pipeline construction in app.py)
INPUT_GATE_KEYS: list[str] = [
    "custom_regex", "token_limit", "invisible_text",
    "fast_scan", "gibberish", "language_in",
    "classify", "toxicity_in", "ban_topics",
    "semantic_guard", "little_canary", "mod_llm",
    "airs_inlet",
]
OUTPUT_GATE_KEYS: list[str] = [
    "sensitive_out", "canary_token", "malicious_urls", "no_refusal",
    "bias_out", "relevance", "language_same", "deanonymize",
    "airs_dual",
]
ALL_GATE_KEYS: list[str] = INPUT_GATE_KEYS + OUTPUT_GATE_KEYS
