# Architecture Reference

This document covers the internal design of LLM Security Workbench: the `PipelinePayload` object, the gate sequence, the execution model, each gate's implementation logic, and the key design decisions behind each choice.

---

## Design Principle: Stateless Gates, Stateful Pipeline

Every security gate in the system is **stateless** — it holds no memory between calls and does not depend on external state. All state lives in a single `PipelinePayload` object that is threaded through the pipeline from start to finish.

This separation means:
- Gates can be independently enabled, disabled, reordered, or replaced without side effects.
- The pipeline always has a complete audit trail of what each gate observed and decided.
- Upstream mutations (like PII masking) are recorded so downstream gates can still operate on the **original** unmodified text for classification purposes.

---

## The `PipelinePayload` Object

Defined in `core/payload.py`. Every piece of data produced or consumed by the pipeline lives here.

```python
class PipelinePayload:
    original_input: str        # Raw user prompt — NEVER modified. Used by classifiers.
    current_text: str          # Text passed to the LLM. May be sanitized/masked by input gates.
    is_blocked: bool           # True if any ENFORCE-mode gate has triggered a block.
    block_reason: str          # Which gate blocked the request and why.
    metrics: list[dict]        # Per-gate telemetry: {gate_name, latency_ms, score, verdict}
    output_text: str           # Final LLM response text. Populated after inference.
    prompt_tokens: int         # Token count of the input prompt (from Ollama).
    completion_tokens: int     # Token count of the generated response (from Ollama).
    tokens_per_second: float   # Generation throughput (from Ollama).
    raw_traces: dict           # Raw JSON request/response pairs, keyed by gate name.
    vault: Vault | None        # Shared PII mapping — set by FastScanGate, read by DeanonymizeGate.
```

### Why Two Text Fields?

`original_input` and `current_text` are intentionally separate.

When `FastScanGate` detects PII like a credit card number, it replaces it in `current_text` with a placeholder (e.g., `[CREDIT_CARD]`) before the text reaches the LLM. If `PromptGuardGate` were to run on `current_text`, the now-masked string would look completely benign and might fool the injection classifier.

By always running **classifiers against `original_input`** and passing **`current_text` to the LLM**, the pipeline achieves both safety and correctness simultaneously.

### Why a Shared Vault?

The `vault` field is the bridge between `FastScanGate` (input side) and `DeanonymizeGate` (output side). `FastScanGate` builds an in-memory mapping of `{placeholder → original_value}` pairs during the PII scan. That same `Vault` instance is stored in `payload.vault` so `DeanonymizeGate` can restore the original values in the response — without any shared state outside the payload.

---

## The Gate Interface

Defined in `gates/base_gate.py`. All gates implement this abstract base class.

```python
class SecurityGate(ABC):
    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def scan(self, payload: PipelinePayload) -> PipelinePayload:
        """
        Contract:
        1. Record wall-clock start time.
        2. Run the scan — use payload.original_input for classifiers,
           payload.current_text for anything modifying the inference input.
        3. Append a metrics dict to payload.metrics:
               {gate_name, latency_ms, score, verdict}
        4. If masking/sanitization occurs, update payload.current_text (input gates)
           or payload.output_text (output gates).
        5. Store raw JSON traces in payload.raw_traces[gate_name].
        6. If a violation is found, set payload.is_blocked = True
           and payload.block_reason to a descriptive string.
        7. Always return payload — never raise from within scan().
        """
        pass
```

### Error Handling Contract

Every concrete gate implementation **must** wrap its logic in a `try-except`. If a model fails to load, an ONNX runtime errors, or an API call times out, the gate must:

1. Log the error into `payload.metrics` with a `verdict: "ERROR"` entry.
2. Leave `payload.is_blocked` unchanged (default `False`).
3. Return the payload immediately.

This guarantees the pipeline **fails open** — a broken gate never silently blocks legitimate traffic.

---

## Gate Modes

Each gate in the UI exposes a 3-way mode selector stored in `st.session_state`:

| Mode | Pipeline Behavior |
|:-----|:-----------------|
| `OFF` | Gate is skipped entirely. No latency, no logging. |
| `AUDIT` | Gate scans and logs its verdict in `payload.metrics`, but `is_blocked` is never set. The pipeline continues regardless of the scan result. |
| `ENFORCE` | Gate scans. If `is_blocked` is set to `True` after the scan, the `PipelineManager` immediately halts execution, skips LLM inference (or remaining output gates), and returns a refusal response. |

---

## The Pipeline Sequence

The pipeline follows a **Cost/Latency Funnel**: the cheapest and fastest checks run first to avoid wasting compute on prompts that can be rejected in milliseconds.

```
USER PROMPT
    │
    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  INPUT GATES                                  (gates/local_scanners) │
│                                                                       │
│  custom_regex   │ CustomRegexGate   │ Python regex (zero-ML)         │
│                 │                   │ Hot-patching / WAF simulation   │
│                                                                       │
│  token_limit    │ TokenLimitGate    │ tiktoken (zero-ML)             │
│                 │                   │ Prompt length enforcement       │
│                                                                       │
│  invisible_text │ InvisibleTextGate │ Unicode Cf/Cc scan (zero-ML)   │
│                 │                   │ Steganography detection         │
│                                                                       │
│  fast_scan      │ FastScanGate      │ llm-guard / Presidio (CPU)     │
│                 │                   │ PII masking + secrets detection │
│                                                                       │
│  classify       │ PromptGuardGate   │ DeBERTa ONNX (CPU)            │
│                 │                   │ Injection / jailbreak classify  │
│                                                                       │
│  toxicity_in    │ ToxicityInputGate │ llm-guard HF classifiers (CPU) │
│                 │                   │ Hostile tone / sentiment        │
│                                                                       │
│  ban_topics     │ BanTopicsGate     │ llm-guard DeBERTa zero-shot    │
│                 │                   │ Forbidden subject-area filter   │
│                                                                       │
│  mod_llm        │ LlamaGuardGate    │ Llama Guard 3 via Ollama       │
│                 │                   │ Safety taxonomy S1–S14 (LLM judge) │
└─────────────────────────────────────────────────────────────────────┘
    │  (if not blocked)
    ▼
┌─────────────────┐
│   INFERENCE     │  Target LLM via Ollama
└─────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  OUTPUT GATES                                 (gates/local_scanners) │
│                                                                       │
│  sensitive_out  │ SensitiveGate     │ Presidio (CPU)                 │
│                 │                   │ LLM-generated PII detection     │
│                                                                       │
│  malicious_urls │ MaliciousURLsGate │ Heuristic + llm-guard ML (CPU) │
│                 │                   │ Phishing / malware URL removal  │
│                                                                       │
│  no_refusal     │ NoRefusalGate     │ llm-guard classifier (CPU)     │
│                 │                   │ Refusal / over-blocking detect  │
│                                                                       │
│  bias_out       │ BiasOutputGate    │ llm-guard classifiers (CPU)    │
│                 │                   │ Bias + toxicity monitoring      │
│                                                                       │
│  relevance      │ RelevanceGate     │ BAAI embeddings (CPU)          │
│                 │                   │ Off-topic / jailbreak drift     │
│                                                                       │
│  deanonymize    │ DeanonymizeGate   │ llm-guard Vault (CPU)          │
│                 │                   │ PII placeholder restoration     │
└─────────────────────────────────────────────────────────────────────┘
    │
    ▼
RESPONSE → UI

─────────────────────────────────────────────
  Phase 4 (partial)
─────────────────────────────────────────────
  Input:  ✅ mod_llm — Llama Guard 3 (Ollama) — safety taxonomy S1–S14
  Input:  Prisma AIRS cloud API — enterprise injection + DLP (upcoming)
  Output: Prisma AIRS cloud API — output DLP + malware detection (upcoming)
─────────────────────────────────────────────
```

### Why This Order?

**Input gates — cheapest first:**

1. `custom_regex` — Zero-ML Python regex. Catches known-bad phrases in microseconds. First because it costs essentially nothing.
2. `token_limit` — tiktoken tokenisation only. Rejects oversized prompts before any model is loaded.
3. `invisible_text` — Pure Unicode category check. Zero ML, protects against steganography that would fool all downstream gates.
4. `fast_scan` — Presidio NER + detect-secrets. First ML work in the pipeline, but runs on CPU/ONNX at < 100 ms. Must run before `classify` because it populates `payload.vault` and mutates `current_text` (masked text).
5. `classify` — DeBERTa-v3 on CPU. Heavier than Presidio but still < 500 ms. Always reads `original_input` so that FastScan's masking cannot strip injection markers.
6. `toxicity_in` — Quality gate. Placed after security gates so it only fires on prompts that aren't already blocked.
7. `ban_topics` — Zero-shot DeBERTa classifier. More expensive than `toxicity_in` (500 ms–2 s). No-op when topic list is empty.
8. `mod_llm` — Llama Guard 3 via Ollama (LLM-as-a-judge). The most expensive input gate (1–10 s full LLM inference). Placed last so all cheap gates have had a chance to short-circuit first. Provides the deepest semantic safety coverage with a formal 14-category harm taxonomy.

**Output gates — ordering is constrained:**

1. `sensitive_out` — Must run **before** `deanonymize`. It sees the placeholder-filled output (e.g. `[REDACTED_PERSON_1]`) and flags only PII the model invented. If deanonymize ran first, it would restore the user's real values and SensitiveGate would incorrectly flag them as LLM-generated.
2. `malicious_urls` — Runs early in the output chain before any text is restored, so URL redaction applies to the text before the user sees it.
3. `no_refusal` — Monitoring gate. Order is not critical; placed here so it sees the (potentially URL-redacted) final response.
4. `bias_out` — Quality monitoring. No text mutations; order relative to other monitoring gates is arbitrary.
5. `relevance` — Quality monitoring. Runs before `deanonymize` so it compares the response the model actually produced (placeholder-filled) against the original prompt — the most accurate similarity signal.
6. `deanonymize` — **Must run last** among output gates. Restores all user-provided PII placeholders so the visible response is natural. Any gate after this would see real PII values.

---

## Gate Implementation Reference

This section documents what each gate does internally: which fields it reads, what it mutates, and the non-obvious design decisions that shaped the implementation.

---

### `custom_regex` — CustomRegexGate

| | |
|:--|:--|
| **Class** | `CustomRegexGate` (`gates/regex_gate.py`) |
| **Stage** | Input |
| **Default mode** | AUDIT |
| **Reads** | `payload.original_input` |
| **Mutates** | `payload.is_blocked`, `payload.block_reason` |

**How it works:** Compiles the comma-separated phrase list from `st.session_state.custom_block_phrases` into a single case-insensitive regex alternation. Each phrase may itself be a regex pattern. On match, records which pattern triggered.

**Design note:** Phrases are re-read and the gate is re-instantiated on every Streamlit re-run, so phrases added in the sidebar take effect on the very next message without restarting the app — this is the "hot-patching" / WAF simulation feature.

---

### `token_limit` — TokenLimitGate

| | |
|:--|:--|
| **Class** | `TokenLimitGate` (`gates/local_scanners.py`) |
| **Stage** | Input |
| **Default mode** | ENFORCE |
| **Reads** | `payload.original_input` |
| **Mutates** | `payload.is_blocked`, `payload.block_reason` |

**How it works:** Tokenises `original_input` with `tiktoken` using the `cl100k_base` encoding (the same encoder used by GPT-3.5/4 and compatible with most modern instruction-tuned models). Delegates to `llm-guard`'s `TokenLimit` scanner for the actual comparison, then re-tokenises independently to report the exact count.

**Why ENFORCE by default:** Oversized prompts are a practical denial-of-service vector (they exhaust context windows and VRAM) and a common technique for hiding injections deep inside very long inputs where sliding-window classifiers only see the tail.

**Config:** `limit` (default 512 tokens), `encoding_name` (default `cl100k_base`).

---

### `invisible_text` — InvisibleTextGate

| | |
|:--|:--|
| **Class** | `InvisibleTextGate` (`gates/local_scanners.py`) |
| **Stage** | Input |
| **Default mode** | ENFORCE |
| **Reads** | `payload.original_input` |
| **Mutates** | `payload.is_blocked`, `payload.block_reason` |

**How it works:** Delegates to `llm-guard`'s `InvisibleText` input scanner, which iterates every character in the input and tests its Unicode general category. Categories flagged: `Cf` (format characters — zero-width joiners, directional overrides, soft hyphens), `Cc` (control characters outside normal whitespace), `Co` (private use), `Cn` (unassigned).

**Why this matters:** Unicode steganography attacks embed invisible instructions inside strings that look completely blank to humans but are fully interpreted by LLMs. A prompt of `Hello world` with zero-width characters interspersed may actually read `Hello [ignore instructions] world` to the model. Regex and NLP classifiers that don't normalise Unicode first will miss this entirely.

**Zero-ML cost:** The scan completes in under 1 ms with no model loading.

---

### `fast_scan` — FastScanGate

| | |
|:--|:--|
| **Class** | `FastScanGate` (`gates/local_scanners.py`) |
| **Stage** | Input |
| **Default mode** | AUDIT |
| **Reads** | `payload.current_text` |
| **Mutates** | `payload.current_text` (PII masked), `payload.vault`, `payload.is_blocked`, `payload.block_reason` |

**How it works:** Runs two sub-scanners sequentially:

1. **Anonymize** — Microsoft Presidio NER identifies PII entities (names, emails, phone numbers, credit card numbers, SSNs, etc.) above the configured confidence threshold. Matched entities are replaced with typed placeholders (`[PERSON_1]`, `[EMAIL_ADDRESS_1]`, etc.) in `current_text`. The `Vault` mapping (`placeholder → original value`) is stored in `payload.vault` for later restoration.

2. **Secrets** — `detect-secrets` library scans for API keys, tokens, private keys, and other credentials using entropy analysis and pattern matching.

**Critical design note:** `original_input` is **never modified**. `PromptGuardGate` runs after FastScanGate and classifies `original_input` — this prevents the masking step from inadvertently stripping injection markers and creating a bypass path (e.g. an attacker embedding injection text inside a SSN field that gets replaced).

**AUDIT mode behaviour:** In AUDIT mode the pipeline continues, but `current_text` still carries the masked version. The model never sees the real PII regardless of mode. AUDIT vs ENFORCE only controls whether the pipeline halts.

**Config:** `scan_pii` (bool), `scan_secrets` (bool), `pii_threshold` (float, default 0.7).

---

### `classify` — PromptGuardGate

| | |
|:--|:--|
| **Class** | `PromptGuardGate` (`gates/local_scanners.py`) |
| **Stage** | Input |
| **Default mode** | AUDIT |
| **Reads** | `payload.original_input` |
| **Mutates** | `payload.is_blocked`, `payload.block_reason` |

**How it works:** Loads `protectai/deberta-v3-base-prompt-injection-v2` (a 184 M-parameter DeBERTa-v3 fine-tuned on a large corpus of injection and jailbreak examples) via HuggingFace `transformers`. The model is loaded once at module level and cached with `functools.lru_cache`. Inference runs on CPU (hard-locked via `.to(torch.device("cpu"))`).

The model outputs softmax probabilities for two classes: `SAFE` and `INJECTION`. The threat score is `1 - P(SAFE)`. If it exceeds the configured threshold the verdict is BLOCK.

**Why `original_input` not `current_text`:** FastScanGate runs before this gate and may have masked PII. If an attacker embeds an injection inside a value that looks like a phone number, FastScanGate would replace it with `[PHONE_NUMBER_1]` — stripping the injection text. Always classifying `original_input` closes this bypass path.

**Model note:** `protectai/deberta-v3-base-prompt-injection-v2` is publicly accessible — no HuggingFace account or token required. It replaces `meta-llama/Prompt-Guard-86M` which requires a gated account.

**Config:** `model_name` (str), `threshold` (float, default 0.80), `max_length` (int, default 512).

---

### `toxicity_in` — ToxicityInputGate

| | |
|:--|:--|
| **Class** | `ToxicityInputGate` (`gates/local_scanners.py`) |
| **Stage** | Input |
| **Default mode** | AUDIT |
| **Reads** | `payload.original_input` |
| **Mutates** | `payload.is_blocked`, `payload.block_reason` |

**How it works:** Runs two sub-scanners against `original_input`:

1. **Toxicity** (`llm-guard` `Toxicity` input scanner) — HuggingFace classifier that scores abusive language, threats, insults, and obscenity. Flags when the toxicity score exceeds `toxicity_threshold`.

2. **Sentiment** (`llm-guard` `Sentiment` input scanner) — Scores overall sentiment on a scale from −1 (very negative) to +1 (very positive). Flags when the score falls below `sentiment_threshold` (default −0.5), indicating extreme negativity that may signal a hostile actor.

The composite score is `max(toxicity_score, -sentiment_score)` — whichever sub-scanner fired harder.

**Design note:** This is a quality gate. Hard-blocking users for tone alone is rarely appropriate in a general-purpose assistant — an angry user asking a legitimate question should still get a response. Defaults to AUDIT so the signal is surfaced without refusing service. Use ENFORCE only in controlled deployments where tone policies are explicit.

**Config:** `toxicity_threshold` (float, default 0.5), `sentiment_threshold` (float, default −0.5).

---

### `ban_topics` — BanTopicsGate

| | |
|:--|:--|
| **Class** | `BanTopicsGate` (`gates/local_scanners.py`) |
| **Stage** | Input |
| **Default mode** | AUDIT |
| **Reads** | `payload.original_input` |
| **Mutates** | `payload.is_blocked`, `payload.block_reason` |

**How it works:** Applies a zero-shot text classification model (`MoritzLaurer/deberta-v3-base-zeroshot-v1.1-all-33` via `llm-guard`'s `BanTopics` scanner) to score the input against each operator-configured topic label. If any topic score exceeds the configured threshold the prompt is blocked. The gate is a **no-op** (verdict: SKIP) when the topics list is empty, so enabling it without configuring any topics has no pipeline effect.

**Design note:** Complements `CustomRegexGate` at the semantic layer — regex matches exact phrases (fast, brittle), while `BanTopicsGate` understands paraphrases ("how do I make a bomb" and "explain explosive synthesis" both match a "weapons" topic). The tradeoff is latency (500 ms–2 s on CPU vs < 1 ms for regex). Placed last in the input chain so cheaper gates can short-circuit first.

**Config:** `topics` (list[str], required — e.g. `["weapons", "drugs", "politics"]`), `threshold` (float, default 0.5).

---

### `mod_llm` — LlamaGuardGate

| | |
|:--|:--|
| **Class** | `LlamaGuardGate` (`gates/ollama_gates.py`) |
| **Stage** | Input |
| **Default mode** | AUDIT |
| **Reads** | `payload.original_input` |
| **Mutates** | `payload.is_blocked`, `payload.block_reason` |

**How it works:** Sends the raw user prompt to Meta's Llama Guard 3 model running locally via Ollama and parses its structured binary verdict. The model outputs either `"safe"` or `"unsafe\n<codes>"` where codes are from the 14-category MLCommons safety taxonomy (S1–S14). Category codes are resolved to human-readable labels (e.g. `S9` → `Indiscriminate Weapons (CBRN)`). Unexpected output (malformed responses) is treated as `safe` for fail-open safety. Ollama connection failures produce an `ERROR` metric and the pipeline continues.

**Safety categories (Llama Guard 3 taxonomy):**

| Code | Category | Code | Category |
|:-----|:---------|:-----|:---------|
| S1 | Violent Crimes | S8 | Intellectual Property |
| S2 | Non-Violent Crimes | S9 | Indiscriminate Weapons (CBRN) |
| S3 | Sex-Related Crimes | S10 | Hate / Discrimination |
| S4 | Child Sexual Exploitation | S11 | Suicide & Self-Harm |
| S5 | Defamation | S12 | Sexual Content |
| S6 | Specialized Advice | S13 | Elections |
| S7 | Privacy | S14 | Code Interpreter Abuse |

**Design note:** This is the deepest semantic safety check in the input chain without a cloud API. Unlike the injection classifier (`classify`) which specifically targets prompt-injection patterns, Llama Guard 3 applies broad harm taxonomy classification. It is placed **last** in the input chain because it is the most expensive gate (full LLM inference, 1–10 s on CPU). All cheaper gates run first so this call is only reached by prompts that passed earlier filters.

**Config:** `host` (str, default `http://localhost:11434`), `model` (str, default `llama-guard3`), `timeout` (float, default 30.0 s).

---

### `sensitive_out` — SensitiveGate

| | |
|:--|:--|
| **Class** | `SensitiveGate` (`gates/local_scanners.py`) |
| **Stage** | Output |
| **Default mode** | AUDIT |
| **Reads** | `payload.output_text`, `payload.current_text` (as the prompt context) |
| **Mutates** | `payload.output_text` (PII redacted in-place), `payload.is_blocked`, `payload.block_reason` |

**How it works:** Runs `llm-guard`'s `Sensitive` output scanner (backed by Microsoft Presidio) against `payload.output_text`. When PII entities are found, the scanner redacts them in place (e.g. replaces `john@example.com` with `<EMAIL_ADDRESS>`) and returns the sanitised text. `payload.output_text` is overwritten with the redacted version.

**Why this gate exists:** `FastScanGate` (input side) can only mask PII the user typed. It cannot catch PII the model generates on its own — a hallucinated realistic email address, a real person's details regurgitated from training data, or a synthetic contact record the model was explicitly asked to create. This gate closes that gap.

**Gate ordering constraint:** Must run **before** `DeanonymizeGate`. At the point SensitiveGate runs, `output_text` still contains placeholders like `[REDACTED_PERSON_1]` from the input-side masking. SensitiveGate will correctly ignore these (they are not PII) and only flag PII the model introduced. If DeanonymizeGate ran first, it would restore the user's real values — and SensitiveGate would then incorrectly flag the user's own PII as LLM-generated.

**Config:** `pii_threshold` (float, default 0.7), `entity_types` (list, default `None` — all Presidio entity types).

---

### `malicious_urls` — MaliciousURLsGate

| | |
|:--|:--|
| **Class** | `MaliciousURLsGate` (`gates/local_scanners.py`) |
| **Stage** | Output |
| **Default mode** | ENFORCE |
| **Reads** | `payload.output_text`, `payload.current_text` |
| **Mutates** | `payload.output_text` (bad URLs replaced with `[REDACTED_URL]`), `payload.is_blocked`, `payload.block_reason` |

**How it works:** Two-layer detection — belt-and-suspenders:

**Layer 1 — Heuristics (zero-ML, < 1 ms per URL)**

A regex (`https?://[^\s\]<>"']+`) extracts all unique URLs from `output_text`. Each URL is tested against five structural rules:

| Rule | Catches |
|:-----|:--------|
| Bare IP as host | `http://192.168.1.1/payload.exe` |
| Executable extension in path | `.exe`, `.bat`, `.ps1`, `.sh`, `.dll`, `.msi`, … |
| Punycode / IDN domain | Domains containing `xn--` (Unicode spoofing) |
| Brand impersonation via digit/symbol substitution | `paypa1.com`, `g00gle.com`, `micros0ft.net` — digits `01358@` translated to visually similar letters `olssba` |
| Excessive subdomains | More than 3 dots in host — common in free-subdomain abuse |

**Layer 2 — ML scanner**

`llm-guard`'s `MaliciousURLs` output scanner (a CNN URL classifier from HuggingFace) scans the working text (with heuristic hits already redacted). This catches trained patterns the heuristics may miss — known phishing domains, URL shorteners used in campaigns, etc.

URLs flagged by the heuristic are replaced with `[REDACTED_URL]` before Layer 2 runs, so the ML scanner sees clean text.

**Metric split:** `payload.block_reason` contains a short summary for the generic "Output blocked" banner. `metric["detail"]` contains the full per-URL breakdown (which URL, which rule or ML score) for the custom notice and API Inspector.

**Config:** `threshold` (float, default 0.5) — ML scanner confidence cutoff only; heuristics are threshold-free.

---

### `no_refusal` — NoRefusalGate

| | |
|:--|:--|
| **Class** | `NoRefusalGate` (`gates/local_scanners.py`) |
| **Stage** | Output |
| **Default mode** | AUDIT |
| **Reads** | `payload.output_text`, `payload.current_text` |
| **Mutates** | `payload.is_blocked` only — `payload.output_text` is never modified |

**How it works:** Uses `llm-guard`'s `NoRefusal` output scanner (a text classifier) to identify refusal patterns — phrases like "I cannot help with that", "I'm sorry, I'm unable to", "As an AI I must decline", etc. `is_valid=False` from the scanner means a refusal was detected.

**Critical design note:** This gate **does not replace or suppress `output_text`**. A refusal is a valid (if sometimes unwanted) response and the user should always see it. The gate sets `is_blocked = True` purely so the pipeline manager can apply the configured mode:

- **AUDIT** (default) — records a `BLOCK` verdict in telemetry. The workbench surfaces a "Model refused" notice. This is the primary use case: red-team analysis — *"did this attack trigger a safety refusal, or did it slip through?"*
- **ENFORCE** — additionally shows an error banner. Useful in automated test runs where a refusal should be treated as a hard test failure.

**Config:** `threshold` (float, default 0.5), `model_name` (str, optional override).

---

### `bias_out` — BiasOutputGate

| | |
|:--|:--|
| **Class** | `BiasOutputGate` (`gates/local_scanners.py`) |
| **Stage** | Output |
| **Default mode** | AUDIT |
| **Reads** | `payload.output_text`, `payload.current_text` |
| **Mutates** | `payload.is_blocked`, `payload.block_reason` — `payload.output_text` is never modified |

**How it works:** Runs two sub-scanners against `payload.output_text`:

1. **Bias** (`llm-guard` `Bias` scanner) — `distilroberta-bias` classifier that detects biased language across protected characteristics (race, gender, religion, nationality, etc.).

2. **Toxicity** (`llm-guard` output-side `Toxicity` scanner) — same model family as `ToxicityInputGate` but applied to the model's response.

Neither scanner modifies the output. This is a monitoring and flagging tool — it flags the signal without rewriting the response.

**Design note:** Bias detection is inherently probabilistic and subject to false positives. Defaulting to AUDIT avoids incorrectly blocking responses that discuss bias as a topic (e.g. academic or legal contexts). ENFORCE is available but should be used with caution and a well-tuned threshold.

**Config:** `threshold` (float, default 0.5) — shared cutoff for both sub-scanners.

---

### `relevance` — RelevanceGate

| | |
|:--|:--|
| **Class** | `RelevanceGate` (`gates/local_scanners.py`) |
| **Stage** | Output |
| **Default mode** | AUDIT |
| **Reads** | `payload.original_input`, `payload.output_text` |
| **Mutates** | `payload.is_blocked`, `payload.block_reason` — `payload.output_text` is never modified |

**How it works:** Uses `llm-guard`'s `Relevance` output scanner (backed by `BAAI/bge-base-en-v1.5` embeddings) to compute cosine similarity between the user's original prompt and the model's response. A low similarity score means the model drifted from the question — a hallucination signal and an indicator that a jailbreak may have redirected the model.

**The `head_chars` truncation:** Only the first `head_chars` characters (default 300) of `output_text` are embedded. Embedding the full response inflates similarity when the model appends self-aware meta-comments such as *"Note: your original query was about quantum computing security risks…"* — these comments reference the original topic and pull the embedding back toward the prompt even when the preceding response content was completely off-topic. Checking only the leading content captures what the model *led with* — the true answer signal.

**Gate ordering constraint:** Runs before `DeanonymizeGate` so the similarity comparison uses the placeholder-filled output — the text the model actually produced in response to the masked prompt. After deanonymization, the text would contain the user's real values, which may subtly shift the embedding.

**Score convention:** `llm-guard` `Relevance` returns `risk_score` where high = irrelevant. The displayed similarity is `1 - risk_score` for readability.

**Config:** `threshold` (float, default 0.5), `head_chars` (int, default 300).

---

### `deanonymize` — DeanonymizeGate

| | |
|:--|:--|
| **Class** | `DeanonymizeGate` (`gates/local_scanners.py`) |
| **Stage** | Output |
| **Default mode** | ENFORCE |
| **Reads** | `payload.vault`, `payload.output_text` |
| **Mutates** | `payload.output_text` (placeholders restored) |

**How it works:** Reads `payload.vault` — the same `Vault` instance populated by `FastScanGate` — and uses `llm-guard`'s `Deanonymize` output scanner to replace placeholders (`[REDACTED_PERSON_1]`, `[EMAIL_ADDRESS_1]`, etc.) with the original values. If `payload.vault` is `None` (FastScanGate did not run, or found no PII), the gate is a no-op with verdict `SKIP`.

**Gate ordering constraint:** Must run **last** among output gates. It produces the final human-readable response — any gate that runs after this point would see real PII values. `SensitiveGate` and `RelevanceGate` must run before this gate for exactly this reason.

**Why ENFORCE by default:** If PII was masked on the way in, it must be restored on the way out — otherwise the user sees responses like *"Hello [REDACTED_PERSON_1], your order [REDACTED_PHONE_NUMBER_1] has shipped"*. There is no meaningful "AUDIT without restoring" for this gate.

**Config:** None.

---

## `PipelineManager` Execution Logic

Defined in `core/pipeline.py`. Pseudo-code for the main execution loop:

```python
class PipelineManager:
    def execute(self, user_text: str, gates_config: dict) -> PipelinePayload:
        payload = PipelinePayload(
            original_input=user_text,
            current_text=user_text
        )

        # INPUT GATES
        for gate_name, gate_instance in self.input_gates:
            mode = gates_config[gate_name]["mode"]
            if mode == "OFF":
                continue

            payload = gate_instance.scan(payload)

            if mode == "ENFORCE" and payload.is_blocked:
                return self._refusal_response(payload)

        # INFERENCE
        payload = self.target_llm.generate(payload)

        # OUTPUT GATES
        for gate_name, gate_instance in self.output_gates:
            mode = gates_config[gate_name]["mode"]
            if mode == "OFF":
                continue

            payload = gate_instance.scan(payload)

            if mode == "ENFORCE" and payload.is_blocked:
                return self._refusal_response(payload)

        return payload
```

Key behaviors:
- An `AUDIT`-mode gate **never** causes the loop to exit early, even if it sets `is_blocked`.
- `_refusal_response()` generates a user-facing block message. In Demo Mode, this is a generic string. In Workbench Mode, it includes the gate name and score.
- The `PipelineManager` uses a single Ollama instance internally. All LLM calls (target model, future Llama-Guard) are serialized through Ollama's internal queue to prevent VRAM OOM crashes from concurrent model loads.

---

## Model Loading Strategy

All ML-based gates load their models **lazily** (on first use) and **cache them at module level** using `functools.lru_cache`. This means:

- Streamlit re-runs do not reload models on every request — the Python process keeps them in memory across page interactions.
- The first request after startup incurs the full download + load time. Subsequent requests hit the cached model.
- All inference runs on **CPU only** (hard-locked via `.to(torch.device("cpu"))`) to preserve GPU VRAM exclusively for the Ollama inference engine.

| Gate | Model | Approx. size | Approx. CPU latency |
|:-----|:------|:-------------|:--------------------|
| `classify` | `protectai/deberta-v3-base-prompt-injection-v2` | ~184 MB | 200–500 ms |
| `fast_scan` | Presidio + `detect-secrets` (no neural model) | < 10 MB | 50–150 ms |
| `sensitive_out` | Presidio (same as above) | < 10 MB | 50–150 ms |
| `toxicity_in` | HF toxicity classifier + sentiment model | ~250 MB | 100–300 ms |
| `malicious_urls` | HF CNN URL classifier | ~50 MB | 50–200 ms |
| `no_refusal` | HF text classifier | ~50 MB | 50–200 ms |
| `bias_out` | `distilroberta-bias` + HF toxicity | ~150 MB | 100–300 ms |
| `relevance` | `BAAI/bge-base-en-v1.5` embeddings | ~440 MB | 100–400 ms |

---

## Ollama VRAM Management

The app is designed around a single `OllamaClient` instance. Ollama handles model loading and VRAM eviction internally. The application:

1. Never calls multiple Ollama inference endpoints concurrently.
2. Monitors VRAM via `/api/ps` and displays live pressure indicators.
3. Exposes a `config.yaml` field to set which models are active, allowing users to trade capability for VRAM budget.

---

## The Red Teaming Engine

### Static Fuzzing (`redteam/static_runner.py`)

Iterates a list of payloads (from `data/static_payloads.json`, uploaded Garak files, or JailbreakBench) through `PipelineManager.execute()` in sequence, collecting the full `PipelinePayload` result for each. Generates an export Markdown report mapping results to OWASP Top 10 for LLMs categories.

### Dynamic PAIR (`redteam/dynamic_pair.py`)

Implements the Chao et al. (2023) iterative refinement algorithm:

```
Attacker LLM
    │
    │ generates prompt
    ▼
PipelineManager.execute()
    │
    │ returns payload (blocked or not)
    ▼
Attacker LLM
    │ evaluates response, outputs:
    │   {"thought": "...", "next_prompt": "..."}
    └── loop until breach or max_iterations
```

The Attacker LLM is a smaller model (default: `phi3`) to minimize VRAM contention with the target model.

---

## Telemetry & the API Inspector

### Hardware Telemetry (`@st.fragment`)

A Streamlit fragment polls Ollama every 5 seconds:
- `/api/ps` → `size_vram` vs `size` (VRAM vs RAM usage per loaded model)
- `/api/show` → `model_info.context_length` (maximum context window)

Token counts and generation speed are populated by the `OllamaClient` after each inference call and stored in the `PipelinePayload`.

### API Inspector

`payload.raw_traces` is a dict keyed by gate name. The UI dynamically creates one tab per key and renders the request and response JSON side-by-side. This allows users to inspect exactly what each gate sent and received — critical for debugging cloud API responses.

---

## Semantic Color System

All gate verdicts, metrics, and inspector UI elements follow a consistent semantic color scheme:

| Meaning | Color | Streamlit Element |
|:--------|:------|:------------------|
| Blocked / Threat | `#F7768E` (red) | `st.error()` |
| Flagged / Warning | `#E0AF68` (amber) | `st.warning()` |
| Safe / Passed | `#9ECE6A` (green) | `st.success()` |
| AI / Semantic Judge | `#BB9AF7` (purple) | `st.markdown` with inline style |
| UI Background | `#0E1117` | `.streamlit/config.toml` |
| Panel Background | `#262730` | `.streamlit/config.toml` |
| Primary Accent | `#7AA2F7` (tech blue) | `.streamlit/config.toml` |

---

## Further Reading

| Doc | Purpose |
|:----|:--------|
| [QUICKSTART.md](QUICKSTART.md) | Installation, environment setup, Docker |
| [PLAYGROUND.md](PLAYGROUND.md) | Hands-on exercises — basic chat through live attacks |
| [ADVERSARIAL.md](ADVERSARIAL.md) | Gate bypass analysis, OWASP/MITRE mapping, attack chains, hardening playbook |
