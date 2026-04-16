# Plan — Pipeline Reference UI: 6-Layer Architecture Visualization

> **Status:** Pending implementation
> **Implements:** GATE-PLAN.md items 5 & 6
> **Scope:** `ui/howto_view.py` only — no logic changes elsewhere

---

## Overview

Items 5 and 6 from GATE-PLAN.md are both pure UI/documentation changes. All 22 gates are already wired into the pipeline; these changes make the Pipeline Reference page reflect that reality.

| Item | Description |
|---|---|
| 5 | Architecture re-layering — update text and metadata to reflect 22-gate, 6-layer pipeline |
| 6 | Visualise the 6-layer model — Mermaid diagram, Layer column, expanded funnel |

---

## Changes

### Change 1 — Section 0: Project intent text

**What:** Update the intro `st.info()` banner.

- `"14-gate"` → `"22-gate"`
- Remove `"nothing leaves to external services"` — AIRS Inlet and AIRS Dual are now an optional cloud tier
- Add note: _"Cloud-tier gates (AIRS) degrade to SKIP when no API key is configured — all local processing stays on your machine."_
- Update the **Prerequisites** column: mention `shieldgemma:2b` and `qwen2.5:1.5b` as the recommended judge / canary models alongside the existing `llama-guard3` note.

---

### Change 2 — `_DEFAULT_MODES` dict

**What:** Add 7 gates missing from the dict. Without this, the Gate Reference table renders a blank Default badge for every new gate row.

```python
# Add to _DEFAULT_MODES:
"gibberish":      "AUDIT",
"language_in":    "AUDIT",
"semantic_guard": "AUDIT",
"little_canary":  "AUDIT",
"airs_inlet":     "AUDIT",
"language_same":  "AUDIT",
"airs_dual":      "AUDIT",
```

---

### Change 3 — Section 1: Mermaid diagram

**What:** Replace the flat left-to-right flowchart with a vertical stepped funnel that shows all 6 input layers, output tiers, latency ranges, and gate names. All BLOCK branches converge on a single `([Blocked])` node.

```
flowchart TD
    U([User Prompt]) --> L0

    L0["<b>L0 — Pre-flight</b><br/>< 1 ms<br/>Regex · Token Limit · Invisible Text"]
    L0 -->|BLOCK| H([Pipeline Halted])
    L0 --> L1

    L1["<b>L1 — Pattern Scanning</b><br/>1–10 ms<br/>PII / Secrets · Gibberish"]
    L1 -->|BLOCK| H
    L1 --> L2

    L2["<b>L2 — ML Classifiers</b><br/>50–500 ms<br/>Language · Injection · Toxicity · Ban Topics"]
    L2 -->|BLOCK| H
    L2 --> L3

    L3["<b>L3 — LLM Judge: General</b><br/>0.5–3 s<br/>Semantic Guard · Little Canary"]
    L3 -->|BLOCK| H
    L3 --> L4

    L4["<b>L4 — LLM Judge: Specialised</b><br/>1–10 s<br/>Llama Guard 3"]
    L4 -->|BLOCK| H
    L4 --> L5

    L5["<b>L5 — Cloud</b><br/>0.5–2 s<br/>AIRS Inlet ☁ · optional"]
    L5 -->|BLOCK| H
    L5 --> LLM([LLM Inference])

    LLM --> OML["<b>Output — ML Scanners</b><br/>50–500 ms<br/>PII Out · URLs · Refusal · Bias · Relevance · Lang Match"]
    OML -->|BLOCK| RB([Response Blocked])
    OML --> OST["<b>Output — Post-process</b><br/>< 1 ms<br/>PII Restore"]
    OST --> OCL["<b>Output — Cloud</b><br/>0.5–2 s<br/>AIRS Dual ☁ · optional"]
    OCL -->|BLOCK| RB
    OCL --> D([Response Delivered])
```

---

### Change 4 — Section 2: Detection Methods

**What:** The `cloud` method is already in `METHOD_STYLES` in `gate_info.py` but is silently dropped by the current `zip([d1, d2, d3], METHOD_STYLES.items())` call.

- `d1, d2, d3 = st.columns(3)` → `d1, d2, d3, d4 = st.columns(4)`
- Add `"cloud"` key to `method_descs`:
  ```python
  "cloud": (
      "Outbound call to Palo Alto Networks AI Runtime Security (AIRS). "
      "Requires an API key and internet access. Covers URL reputation, IP reputation, "
      "and enterprise DLP patterns not available locally. "
      "Both cloud gates degrade to SKIP when no key is configured — "
      "all local layers (L0–L4) run unaffected."
  ),
  ```
- Update zip: `zip([d1, d2, d3, d4], METHOD_STYLES.items())`

---

### Change 5 — Section 3: Gate Reference table — Layer column

**What:** Add a `Layer` badge as the 2nd column (after Gate name) showing which pipeline layer each gate belongs to. Reuses `_METHOD_COLOR` so no new color system is needed — the badge color matches the gate's method type.

**`_LAYER_MAP` to add in `howto_view.py`:**

```python
_LAYER_MAP: dict[str, str] = {
    # Input layers
    "custom_regex":   "L0",
    "token_limit":    "L0",
    "invisible_text": "L0",
    "fast_scan":      "L1",
    "gibberish":      "L1",
    "language_in":    "L2",
    "classify":       "L2",
    "toxicity_in":    "L2",
    "ban_topics":     "L2",
    "semantic_guard": "L3",
    "little_canary":  "L3",
    "mod_llm":        "L4",
    "airs_inlet":     "L5",
    # Output layers
    "sensitive_out":  "O·ML",
    "malicious_urls": "O·ML",
    "no_refusal":     "O·ML",
    "bias_out":       "O·ML",
    "relevance":      "O·ML",
    "language_same":  "O·ML",
    "deanonymize":    "O·Static",
    "airs_dual":      "O·Cloud",
}
```

**Table changes:**
- Add `<th>Layer</th>` as 2nd column header
- Add `_badge(_LAYER_MAP[key], _METHOD_COLOR[method_key])` as 2nd `<td>` in each row
- Widen the Output Gates separator `colspan` from `6` → `7`
- Widen the table header colspan from `6` → `7`

---

### Change 6 — Section 5: Cost / Latency Funnel

**What:** Replace the 3-tier `funnel` list with 6 entries matching the layer model. Each entry is `(title, latency, gates, note)` rendered as a `st.container(border=True)` row — same layout as today.

```python
funnel = [
    (
        "L0 — Pre-flight",
        "< 1 ms each",
        "Regex Hot-Patch · Token Limit · Invisible Text",
        "Pure Python — no model loading, no GPU. Run first to eliminate obvious bad inputs "
        "before any dependencies are touched. Always-on regardless of hardware.",
    ),
    (
        "L1 — Pattern Scanning",
        "1 – 10 ms",
        "PII / Secrets · Gibberish Detect",
        "Static ML (Presidio NER + detect-secrets + small HuggingFace classifier). "
        "No GPU needed. Catches structured leaks and noise-flood attacks before heavier models run.",
    ),
    (
        "L2 — ML Classifiers",
        "50 – 500 ms",
        "Language Enforce · Injection Detect · Toxicity · Ban Topics",
        "Local HuggingFace CPU models. First call loads the model into RAM; subsequent calls "
        "are significantly faster. Covers multilingual bypass, injection patterns, tone, and topic scope.",
    ),
    (
        "L3 — LLM Judge: General",
        "0.5 – 3 s",
        "Semantic Guard · Little Canary",
        "Configurable Ollama judge with an editable safety prompt, plus a behavioral canary probe. "
        "Catches intent-level threats and novel jailbreaks that fixed classifier datasets have never seen. "
        "Runs before Llama Guard because smaller models (shieldgemma:2b, qwen2.5:1.5b) are faster.",
    ),
    (
        "L4 — LLM Judge: Specialised",
        "1 – 10 s",
        "Llama Guard 3",
        "Fixed MLCommons S1–S14 harm taxonomy. Highest local accuracy — placed last in the local "
        "chain so it only evaluates prompts that cleared all cheaper gates. "
        "Requires `ollama pull llama-guard3`.",
    ),
    (
        "L5 — Cloud (optional)",
        "0.5 – 2 s",
        "AIRS Inlet",
        "Palo Alto Networks AI Runtime Security. Adds URL/IP reputation and enterprise DLP policy "
        "that cannot be replicated locally. Placed last — cloud round-trip cost is only paid when "
        "all local gates (L0–L4) pass. Degrades to SKIP when no AIRS_API_KEY is configured.",
    ),
]
```

---

## Files Affected

| File | Changes |
|---|---|
| `ui/howto_view.py` | All 6 changes above — Section 0 text, `_DEFAULT_MODES`, Mermaid diagram, Detection Methods columns, Gate Reference Layer column, Cost/Latency Funnel tiers |

No other files require changes. `gate_info.py`, `app.py`, `chat_view.py`, and `metrics_panel.py` are already up to date.

---

## Before / After Summary

| Section | Before | After |
|---|---|---|
| Project intent | "14-gate", "nothing leaves to external services" | "22-gate", optional cloud tier noted |
| Section 1 diagram | Flat `Input Gates x8 → LLM → Output Gates x6` | Stepped L0→L5 funnel with gate names + latency at every layer |
| Section 2 methods | 3 cards: Static / ML / LLM | 4 cards: + Cloud API |
| Section 3 table | 6 cols: Gate / Type / Method / Latency / Default / Description | 7 cols: + Layer badge (L0–L5 / O·ML / O·Static / O·Cloud) |
| Section 5 funnel | 3 tiers: Static / ML / LLM | 6 tiers: L0 Pre-flight / L1 Pattern / L2 ML / L3 LLM General / L4 LLM Specialised / L5 Cloud |
