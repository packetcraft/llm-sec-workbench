# Gate Expansion & Architecture Plan

> **Status:** In Progress — items 1–4 complete, items 5–6 pending.
> **Based on:** Review of `GATE-LLM-GUARD.md`, `GATE-SEMANTIC-GUARD.md`, `GATE-LITTLE-CANARY.md`, `GATE-AIRS.md` against the current 14-gate pipeline in `gates/local_scanners.py` and `gates/ollama_gates.py`.

---

## Current State

The project has **14 gates** across two phases, grouped into a flat input/output split:

| Phase | Gates | Detection Tier |
|---|---|---|
| Input | custom_regex, token_limit, invisible_text | Static (pure Python) |
| Input | fast_scan, classify, toxicity_in, ban_topics | ML (HuggingFace / Presidio, CPU) |
| Input | mod_llm | LLM (Ollama / Llama Guard 3) |
| Output | sensitive_out, malicious_urls, no_refusal, bias_out, relevance | ML |
| Output | deanonymize | Static |

The inspiration docs describe a richer pipeline with additional ML gates not yet wired in, two new LLM Judge layers, and a cloud-based AIRS tier at the outermost position.

---

## Gaps Identified — New Gates to Add

### Gap 1 — Gibberish Detection (Input, ML)

**Source:** `GATE-LLM-GUARD.md` — scanner 6 (`Gibberish`)
**Model:** `madhurjindal/autonlp-Gibberish-Detector-492513457`

**What it catches:** Noise-flood and token-waste attacks — random characters, keyboard mash, or word salad designed to consume context, confuse the LLM, or disguise payload inside entropy.

**Why it's missing:** The LLM-Guard reference doc lists it, but it was never wired into `local_scanners.py`. The `llm-guard` package already includes it — zero new dependencies.

**Placement:** After `token_limit`, before `classify`. Cheap (66M params), fast on CPU.

---

### Gap 2 — Language Enforcement (Input, ML)

**Source:** `GATE-LLM-GUARD.md` — scanner 7 (`Language`)
**Model:** `papluca/xlm-roberta-base-language-detection`

**What it catches:** Multilingual jailbreak bypass — phrasing attacks in Arabic, Chinese, Russian, etc. to evade English-trained safety classifiers. Example: sending a DAN prompt in French to bypass the Toxicity or BanTopics gate.

**Why it's missing:** Same as Gibberish — documented in the reference, not yet wired in.

**Placement:** After `fast_scan`, before `classify`. Shares model weights with the output LanguageSame gate so marginal RAM cost on the second load is near zero.

---

### Gap 3 — Language Consistency (Output, ML)

**Source:** `GATE-LLM-GUARD.md` — output scanner 6 (`LanguageSame`)
**Model:** `papluca/xlm-roberta-base-language-detection` (same as Gap 2)

**What it catches:** Response language drift — the LLM silently switching language mid-response, or a multilingual jailbreak causing the model to respond in a different language than the prompt.

**Placement:** After `relevance`, before `deanonymize`. Reuses the already-loaded Language model from the input gate, so marginal memory cost is near zero.

---

### Gap 4 — Semantic Guard / LLM-as-Judge with Configurable Prompt (Input, LLM)

**Source:** `GATE-SEMANTIC-GUARD.md`
**Model:** Any pulled Ollama model — recommended `shieldgemma:2b` or `llama3.2:3b`

**What it adds:** A user-tunable LLM judge with a free-text system prompt. Catches intent-level threats — nuanced jailbreaks, social engineering, false authority framing, novel phrasing — that fixed classifier models trained on labelled datasets may miss. Returns structured JSON `{safe, confidence, reason}`.

**Key differentiator from `mod_llm`:** Llama Guard 3 uses a fixed MLCommons S1–S14 harm taxonomy. Semantic Guard is domain-customizable — operators can write their own safety policy (e.g., "do not discuss competitor products", children's content rules, medical/legal scope restrictions). The two LLM-based approaches are complementary, not redundant.

**Placement:** Between `ban_topics` and `mod_llm` — after the ML classifier tier, before Llama Guard. With a small model like `shieldgemma:2b` it is faster than Llama Guard 3.

**Verdict schema:**
```json
{ "safe": false, "confidence": 0.91, "reason": "Jailbreak pattern detected" }
```

Block condition: `safe == false AND confidence >= threshold`

**Fail behavior:** Fail-open — any exception (network, timeout, parse error) records an error metric but never hard-blocks legitimate traffic.

---

### Gap 5 — Little Canary / Behavioral Injection Probe (Input, LLM)

**Source:** `GATE-LITTLE-CANARY.md` — Hermes Labs `little-canary` library
**Library:** `pip install little-canary`

**What it adds:** A three-layer injection detector:

1. **Structural** — 16 regex pattern groups + 4 encoding decoders (base64, hex, ROT13, reverse). Runs in ~1 ms. Short-circuits the probe when a structural match fires.
2. **Canary Probe** — feeds the raw input (no sanitisation) to a small, intentionally-weak Ollama model (the "canary") at temperature=0, seed=42 for deterministic output. The canary has zero permissions — its response is never shown to the user or forwarded to the main LLM.
3. **Behavioral Analysis** — examines the canary's response for compromise residue: persona shifts, instruction echoes, refusal collapses, prompt leakage, and authority granting. Weighted risk score; hard-block categories trigger immediately.

**Key differentiator from `classify`:** The DeBERTa injection classifier asks "does this look like an attack?" against a trained dataset. Little Canary asks "did this input actually compromise a model?" — using live LLM reasoning rather than a labelled training set. Catches novel jailbreaks that no fixed classifier has seen.

**Recommended canary model:** `qwen2.5:1.5b` — small and reliably hijacked by obvious attacks (resistance would defeat the purpose).

**Placement:** Between `classify` and `ban_topics` — after the ML classifier tier, before Semantic Guard and Llama Guard.

---

### Gap 6 — AIRS-Inlet (Input, Cloud)

**Source:** `GATE-AIRS.md`
**API:** `https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request`
**Requires:** `AIRS_API_KEY` + a Prisma AI Runtime Security subscription

**What it adds:** Cloud-based prompt scanning via Palo Alto Networks AIRS (AI Runtime Security). A single API call evaluates the user prompt against a configurable AI security profile and returns a binary `action: allow / block` verdict with per-category detection flags.

**Threat categories covered:**

| Flag | What it detects |
|---|---|
| `injection` | Prompt injection and jailbreak attempts |
| `malicious_code` | Code generation for malware, exploits, shells |
| `toxic_content` | Hate speech, threats, abusive language |
| `dlp` | PII, credentials, and sensitive data (Data Loss Prevention) |
| `url_cats` | URLs matching malicious or policy-violating categories |
| `ip_reputation` | References to IPs with poor reputation (C2, scanners) |
| `malware` | Known malware signatures or indicators |

**What makes it distinct from local gates:** AIRS runs cloud-side threat intelligence (URL reputation, IP reputation, policy databases) that cannot be replicated locally. It also evaluates against an operator-defined AI security profile configured in Strata Cloud Manager — giving enterprise teams centralized policy control outside the application codebase.

**Placement:** Last in the input chain, after `mod_llm`. AIRS is the most capable but most latent gate (500ms–2s network round-trip). Running it last means the cheaper local gates catch obvious threats first, and AIRS only sees prompts that passed all local checks.

**Fail behavior:** Fail-closed — if the AIRS API call fails (network error, 5xx, credential problem), the pipeline blocks. This is intentional: an AIRS error likely indicates a configuration or credential issue that should surface, not be silently bypassed. Contrast with Semantic Guard which is fail-open.

**Request schema:**
```json
{
  "tr_id": "wb-1711234567890",
  "ai_profile": { "profile_name": "default" },
  "metadata": { "ai_model": "llama3", "app_name": "LLM Security Workbench" },
  "contents": [{ "prompt": "<user message>" }]
}
```

---

### Gap 7 — AIRS-Dual (Output, Cloud)

**Source:** `GATE-AIRS.md`
**API:** Same endpoint as AIRS-Inlet — `contents[0]` includes both `prompt` and `response`

**What it adds:** Cloud-based response scanning. Evaluates the LLM's generated output (with the original prompt as context) against the same threat categories as AIRS-Inlet — but on the response side. Uniquely, AIRS-Dual can apply **DLP masking**: when sensitive data is detected, `response_masked_data` contains a redacted version of the response text that replaces the original before display.

**Key difference from `sensitive_out`:** The `sensitive_out` gate uses Presidio NER (local, CPU). AIRS-Dual applies cloud-side DLP policy that can cover organization-specific data patterns defined in Strata Cloud Manager — structured financial data, internal code names, custom entity types that Presidio templates do not cover out of the box.

**Placement:** Last in the output chain, after `deanonymize`. AIRS-Dual requires the full LLM response to exist before it can run, and should be the final gate so DLP masking has the last word on the response text shown to the user.

**On block (Strict mode):** The response is withheld entirely and replaced with a block notice.
**On DLP mask (allow + maskedData present):** The response text is replaced with the AIRS-redacted version even when the overall action is `allow`.

**Request schema:**
```json
{
  "contents": [{ "prompt": "<user message>", "response": "<LLM response>" }]
}
```

**Implementation note — shared mode:** Both AIRS-Inlet and AIRS-Dual share a single mode selector in the reference implementation. They are always configured together. Consider whether to preserve this pairing or expose them as independent gate switches in the sidebar.

---

## Architecture Restructuring Proposal

The current flat "8 input + 6 output" grouping works but does not communicate the cost/complexity funnel. Adding AIRS and the new LLM Oracle layers creates a natural 6-layer pipeline.

### Proposed Layer Model

```
Layer 0 — Pre-flight              < 1 ms       Static, no dependencies
  token_limit
  custom_regex
  invisible_text

Layer 1 — Pattern Scanning        1–10 ms      Static ML (Presidio / detect-secrets)
  fast_scan                        (PII + Secrets)
  [new] gibberish

Layer 2 — ML Classifiers          50–500 ms    HuggingFace CPU models
  [new] language Enforce           (language enforcement — XLM-RoBERTa)
  classify                         (injection / jailbreak — DeBERTa)
  toxicity_in                      (hostile tone — RoBERTa)
  ban_topics                       (zero-shot topic filter)

Layer 3 — LLM Judge: General      0.5–3 s      Ollama, configurable system prompt
  [new] semantic_guard             (ShieldGemma / any model, editable policy)
  [new] little_canary              (behavioral canary probe — qwen2.5:1.5b)

Layer 4 — LLM Judge: Specialized  1–10 s       Ollama, fixed taxonomy
  mod_llm                          (Llama Guard 3, S1–S14)

Layer 5 — Cloud                   0.5–2 s      AIRS cloud API, requires API key
  [new] airs_inlet                 (Palo Alto AIRS — prompt scan, fail-closed)

── LLM Inference ─────────────────────────────────────────────────────────────

Output Layer 1 — ML Scanners      50–500 ms
  sensitive_out
  malicious_urls
  no_refusal
  bias_out
  relevance
  [new] language_match          (response language consistency — XLM-RoBERTa)

Output Layer 2 — Static Post-processing  < 1 ms
  deanonymize

Output Layer 3 — Cloud            0.5–2 s      AIRS cloud API, requires API key
  [new] airs_dual                  (Palo Alto AIRS — response scan + DLP masking)
```

### Benefits of the Restructuring

1. **Educational clarity** — the Pipeline Reference page currently shows a 3-tier cost funnel (Static / ML / LLM). Explicit layers within the LLM Judge and Cloud tiers make the full escalation logic visible and teachable.
2. **Cloud tier is clearly optional** — AIRS gates live in their own layer so it is obvious they require an external dependency (API key). All layers 0–4 remain fully offline.
3. **Two distinct LLM Judge approaches** — separating "general LLM judge" (Layer 3, configurable system prompt) from "specialised LLM judge" (Layer 4, fixed taxonomy) makes the design tradeoff explicit. Layer 3 gates run first because they are faster (smaller models) and more tunable. Layer 4 (Llama Guard) runs last in the local chain because it is the most accurate but most expensive.
4. **Placement guide** — when adding future gates, the correct position in the chain is self-evident from which layer they belong to.

---

## Summary Table

| Gate | Status | Source | Layer | Effort |
|---|---|---|---|---|
| Gibberish | ✅ **Done** (2026-04-15) | GATE-LLM-GUARD.md | Input ML | Low — already in llm-guard package |
| Language (input) | ✅ **Done** (2026-04-15) | GATE-LLM-GUARD.md | Input ML | Low — shared model with LanguageSame |
| LanguageSame (output) | ✅ **Done** (2026-04-15) | GATE-LLM-GUARD.md | Output ML | Low — shared model with Language |
| Semantic Guard | ✅ **Done** (2026-04-16) | GATE-SEMANTIC-GUARD.md | Input LLM Judge — General | Medium — new OllamaGate with configurable prompt |
| Little Canary | ✅ **Done** (2026-04-16) | GATE-LITTLE-CANARY.md | Input LLM Judge — General | Medium — `pip install little-canary`, thin wrapper |
| AIRS-Inlet | ✅ **Done** (2026-04-16) | GATE-AIRS.md | Input Cloud | Medium — new CloudGate subclass + API key required |
| AIRS-Dual | ✅ **Done** (2026-04-16) | GATE-AIRS.md | Output Cloud | Medium — paired with Inlet, DLP masking logic |
| Architecture re-layering | **Restructure** | All docs | howto_view + PipelineManager | Low — rename/reorder, no logic change |

---

## Recommended Priority Order

1. ✅ **Gibberish + Language + LanguageSame** *(Done — 2026-04-15)* — lowest effort, zero new dependencies, closes obvious gaps in the ML tier. All three models are already bundled with `llm-guard`.

2. ✅ **Semantic Guard** *(Done — 2026-04-16)* — high research and educational value. Demonstrates the LLM-as-judge pattern with a user-editable policy prompt. Complements Llama Guard with a customizable, domain-specific dimension. Implemented as a new `OllamaGate` subclass using the existing `LlamaGuardGate` structure as a template. Default judge model: `shieldgemma:2b`.

3. ✅ **Little Canary** *(Done — 2026-04-16)* — most novel addition conceptually. Demonstrates a fundamentally different detection philosophy (behavioral probe vs. trained classifier). The `little-canary` library is mature; a thin `SecurityGate` wrapper calling it inline is the simplest path — no separate sidecar needed for a local Streamlit app. Recommended canary model `qwen2.5:1.5b` auto-selected and pulled by setup/start scripts.

4. ✅ **AIRS-Inlet + AIRS-Dual** *(Done — 2026-04-16)* — adds the cloud tier. Both gates degrade gracefully to SKIP when no `AIRS_API_KEY` is configured. `AIRSInletGate` is fail-closed (API errors block in ENFORCE mode); `AIRSDualGate` is fail-open. DLP masking: when AIRS Dual returns `response_masked_data`, the response shown to the user is the AIRS-redacted version (recorded as `DLP_MASK` verdict in gate trace). API key and profile configurable via sidebar or `.env`.

5. **Architecture re-layering** — can be done incrementally alongside any of the above. The Pipeline Reference page (`ui/howto_view.py`) is the primary place where the layer model is documented and shown to users. The PipelineManager gate ordering in `app.py` should be updated to reflect the 6-layer structure when the new gates are wired in.

6. **Visualise the 6-layer model in the Pipeline Reference UI** — three self-contained changes to `ui/howto_view.py`, no logic changes elsewhere:
   - **Mermaid diagram** (Section 1) — replace the current `Input Gates x8 → LLM → Output Gates x6` flowchart with a stepped subgraph funnel that names each input layer and shows its latency range. Makes the escalation cost visible at a glance.
   - **Cost / Latency Funnel** (Section 5) — expand from the current 3 cards (Static / ML / LLM) to 6 cards matching the new layer model, with sub-tiers shown explicitly for LLM Judge and Cloud.
   - **Gate Reference table** (Section 3) — add a `Layer` badge column (`L0`–`L5`) alongside the existing Input/Output and Static/ML/LLM badges, so each gate row shows which layer it belongs to without requiring the reader to cross-reference the funnel.

---

## Files Affected (when implemented)

| File | Change |
|---|---|
| `gates/local_scanners.py` | Add `GibberishGate`, `LanguageGate`, `LanguageSameGate` |
| `gates/ollama_gates.py` | Add `SemanticGuardGate`, `LittleCanaryGate` |
| `gates/cloud_gates.py` | New file — `AIRSInletGate`, `AIRSDualGate` (cloud tier, optional dependency) |
| `core/pipeline.py` | Register new gates in input/output chain |
| `app.py` | Add gate session defaults + pipeline wiring for all new gates |
| `ui/chat_view.py` | Sidebar controls for new gates (model selector for Semantic Guard; API key indicator for AIRS) |
| `ui/howto_view.py` | Update Gate Reference table, pipeline diagram, and Cost/Latency Funnel to reflect 6-layer model |
| `ui/gate_info.py` | Add metadata entries for all new gates |
