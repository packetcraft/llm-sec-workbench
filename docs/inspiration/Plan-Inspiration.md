# Plan-Inspiration.md
> Analysis of `8b-model-scanning+PAIR.html` — features to port into the LLM Security Workbench

---

## What the inspiration file has that we don't

### 1. PAIR — Dynamic Red Team (biggest gap)

The inspiration implements the full **PAIR algorithm** (Prompt Automatic Iterative Refinement, Chao et al. 2023). It's missing entirely from our project.

**How it works in the inspiration:**
- 3 local Ollama roles: **Attacker**, **Judge**, **Target**
- Loop up to N iterations:
  1. Attacker LLM generates an adversarial prompt, adapting based on whether the previous attempt was blocked or just didn't score well
  2. Prompt runs through your actual security pipeline (LLM-Guard → Canary → AIRS gates)
  3. Target LLM answers (only if not blocked)
  4. Judge LLM scores the response 1–10 against the goal
- Stops when score ≥ threshold (breach) or max iterations hit
- Each iteration renders a card: attack prompt, gate trace, LLM response, judge score + reasoning
- Summary stats bar: Blocked / Reached LLM / Breached
- Stop button mid-run; JSON export at the end

**Where it fits in our project:** a new `ui/pair_view.py` called from `app.py` as a "Dynamic Red Team" tab, sitting alongside the existing chat view. The Attacker/Judge calls go directly to Ollama via `OllamaClient`, and the pipeline check reuses `PipelineManager`.

---

### 2. Model Security Scanner (HuggingFace supply-chain)

A sidebar pane that takes a HuggingFace model ID (or picks from pre-loaded cards like `google/flan-t5-small`, `mistralai/Mistral-7B-v0.1`) and POSTs to `/api/model-scan`, which wraps the AIRS Model Security SDK.

**Output rendered:**
- Pass/block status pill
- Metrics tiles: rules passed, rules failed, pass-rate %, files scanned, files skipped
- Violations list (rule name, severity, description)
- Model format tags (safetensors, GGUF, etc.)
- Compact meta line: scanner version, security group, source, scan UUID, timestamp
- Raw JSON drawer

This only needs a new `core/model_scanner.py` shim + a Streamlit pane. Depends on the AIRS SDK being available (`npm run model-scan` in the inspiration is a dev proxy, but a Python SDK binding exists).

---

### 3. Static vs Dynamic Red Team tabs in one view

The inspiration has a proper **Red Team nav pane** with two tabs:
- **Static** — fires a single payload from the threat library and shows gate verdict (maps to what we currently have as sidebar injection, but exposed as a first-class view)
- **Dynamic** — the PAIR runner above

Our existing `threats.json` + injection sidebar maps to the static tab. Lifting it into a dedicated tab gives it more screen space and lets you show per-shot gate trace next to the response, rather than just injecting into the chat.

---

### 4. Per-attempt gate trace chips

In PAIR mode, each attempt card shows a compact **gate chip row** — one chip per gate: `🔬 LLM-Guard [strict] · block · PromptInjection(0.97) · 84ms`. The coloured badge (`pass` / `block` / `flag` / `off` / `skip` / `error`) makes it instantly readable.

Our `_render_turn_footer()` in `chat_view.py:887` already renders gate badges, but they're per-chat-turn, not per PAIR iteration card. The gate chip style from the inspiration could be extracted into `metrics_panel.py` and shared by both views.

---

### 5. Export / reporting

The inspiration has `exportPairJson()` — dumps the full run as a JSON file: goal, config (attacker/judge/target models, gate modes, threshold), and every attempt (prompt, blocked, blockedBy, response, score, judgeReasoning, gateTrace). A matching `exportPairMarkdown()` produces a Markdown report.

Our project has no export of red team runs. Adding a "Download JSON" + "Download Report (MD)" button to a PAIR run result is straightforward in Streamlit via `st.download_button`.

---

## Priority order for implementation

| # | Feature | Effort | Value |
|---|---------|--------|-------|
| 1 | **PAIR dynamic red team** | High (new view + pipeline wiring) | Very High |
| 2 | **Gate chip style → shared component** | Low (CSS + refactor in metrics_panel.py) | Medium — needed for #1 |
| 3 | **Static Red Team tab** (lift injection out of sidebar) | Medium | Medium |
| 4 | **PAIR JSON/MD export** | Low (st.download_button on the run result) | Medium |
| 5 | **Model Security Scanner** | Medium (new API endpoint + pane) | Medium (depends on AIRS access) |

---

## Concrete starting point for PAIR

The attacker prompt system from the inspiration (`lines 7999–8031`) can be ported almost verbatim to Python as a method on a `PAIRRunner` class. The pipeline check (`_pairRunPipelineCheck`, lines 7843–7946) maps directly to calling `PipelineManager.run_input_gates()` — you already have that in `core/pipeline.py`. The biggest new work is the Streamlit iteration-card renderer and the live streaming of iteration status (`st_autorefresh` or a `st.empty()` update loop).

---

## Key source references in the inspiration file

| Feature | Line range |
|---------|-----------|
| PAIR globals + tab switcher | 7814–7825 |
| `_pairOllamaChat` helper | 7830–7839 |
| `_pairRunPipelineCheck` (gate loop) | 7843–7946 |
| `_pairTargetTurn` | 7948–7965 |
| `_pairJudgeTurn` | 7967–7997 |
| `_pairAttackerTurn` (adaptive prompting) | 7999–8031 |
| `startPairRun` (main loop) | 8033–8155 |
| `_pairRenderAttempt` (card renderer) | 8204–8260 |
| `exportPairJson` / `exportPairMarkdown` | 8281–8430 |
| `runModelScan` | 6044–6163 |
| Model card CSS + scanner chip toggles | 2150–2239, 1866–1905 |
| Gate chip CSS (`.pair-gate-chip`) | 1542–1561 |
| PAIR attempt card CSS | 1478–1539 |

---

---

# Implementation Plan — Red Teaming Navigation Tab

> Scope: add `⚔️ Red Teaming` to the left-nav and implement Static + Dynamic (PAIR)
> red teaming inside it. Model Security Scanner is explicitly **out of scope**.

---

## Architecture overview

```
app.py
 ├── 💬 Chat Workbench   → ui/chat_view.py          (existing)
 ├── 🛡️ Agentic Security → ui/agentic_view.py        (existing)
 └── ⚔️ Red Teaming      → ui/redteam_view.py        (NEW)
                               ├── Static tab
                               │     uses: threats.json (existing)
                               │     uses: PipelineManager.execute() (existing)
                               │     uses: render_gate_chip_trace() (NEW shared component)
                               └── Dynamic tab  (PAIR)
                                     uses: core/pair_runner.py (NEW)
                                     uses: OllamaClient (existing)
                                     uses: PipelineManager.run_input_gates() (existing)
                                     uses: render_gate_chip_trace() (NEW shared component)
```

The Red Teaming page receives the same `pipeline` and `config` objects that the
Chat Workbench already receives, so no new Ollama plumbing is needed.

---

## Step-by-step implementation

### Step 1 — Shared gate chip component (`ui/metrics_panel.py`)

**What:** Add `render_gate_chip_trace(gate_metrics: list[dict]) -> None` to
`metrics_panel.py`. This replaces the ad-hoc badge rendering scattered in
`_render_turn_footer()` and will be reused by both red-team views.

**Each chip shows:**
- Gate name + emoji prefix
- Coloured badge: `PASS` (green) / `BLOCK` (red) / `AUDIT` (amber) / `OFF` (muted) / `ERROR` (orange)
- Latency in ms (right-aligned)
- Short detail string on hover / expander (flagged scanner names, score, etc.)

**Why first:** both Static and Dynamic tabs depend on this. Doing it before the
view files keeps the view code clean.

**Files changed:** `ui/metrics_panel.py`

---

### Step 2 — Navigation wiring (`app.py`)

**What:** Add `"⚔️ Red Teaming"` to the `st.radio` options (line 211).
Add a route block that:
1. Checks Ollama is available (same guard as Chat Workbench).
2. Builds the pipeline (reuse the existing pipeline-build block — extract it
   into a helper `_build_pipeline(config, ollama_host)` so both routes share it
   without duplication).
3. Calls `render_redteam(pipeline, config)` from `ui/redteam_view.py`.

**Files changed:** `app.py`

**Key constraint:** The pipeline-build block (lines 241–336) must become a
shared helper because both Chat Workbench and Red Teaming need it.

---

### Step 3 — Static Red Team tab (`ui/redteam_view.py`)

**Layout (inside the Static tab):**

```
┌─ Config column (1/3) ─────────────────┐  ┌─ Results column (2/3) ──────────────┐
│  Category filter (selectbox)          │  │  [Run result card — appears after   │
│  Threat selectbox (id · type)         │  │   clicking Fire]                    │
│  Prompt preview (read-only textarea)  │  │                                     │
│  [ Fire Threat ] button               │  │  Verdict pill (BLOCKED / PASSED)    │
│                                       │  │  Gate chip trace                    │
│  Threat metadata card:                │  │  LLM response (if not blocked)      │
│    severity, tags, expected verdict,  │  │  [ Download JSON ] button           │
│    source, targetPhase                │  └─────────────────────────────────────┘
└───────────────────────────────────────┘
```

**Data flow:**
1. User picks category → threat from `threats.json` (reuse `_load_threats()` /
   `_threat_options()` already in `chat_view.py` — move to a shared
   `ui/threat_utils.py` or expose from `chat_view.py`).
2. Click **Fire Threat** → call `pipeline.execute(user_text, gate_modes, ...)`.
3. Render result via `render_gate_chip_trace()` + verdict pill + response text.
4. Store result in `st.session_state.static_rt_result` so it survives re-runs.

**New session state keys:**
- `static_rt_result`: `dict | None` — last run result (payload dict + metadata).

**Files changed:** `ui/redteam_view.py` (new), `ui/chat_view.py` (extract
`_load_threats` / `_threat_options` to avoid duplication).

---

### Step 4 — PAIR engine (`core/pair_runner.py`)

**What:** A pure-Python class with no Streamlit imports. `app.py` and the view
can both import it safely.

```python
class PAIRRunner:
    def __init__(self, client: OllamaClient, pipeline: PipelineManager): ...

    def attacker_turn(
        self, goal, iteration, prev_prompt, prev_response,
        was_blocked, blocked_by, attacker_model
    ) -> str:
        # Builds adaptive system + user prompt (ported from insp. lines 7999–8031)
        # Calls client.generate() with attacker_model override
        ...

    def judge_turn(
        self, goal, prompt, response, judge_model
    ) -> dict:   # {"score": int, "reasoning": str}
        # Calls client.generate() with judge_model override
        # Parses "Score: N/10" from response
        ...

    def pipeline_check(
        self, prompt, gate_modes
    ) -> dict:   # {"blocked": bool, "blocked_by": str, "gate_trace": list[dict]}
        # Calls pipeline.run_input_gates()
        # Returns per-gate result dicts for chip rendering
        ...

    def target_turn(
        self, prompt, gate_modes, system_prompt
    ) -> str:
        # Only called when pipeline_check says not blocked
        # Calls client.generate() with target model
        ...

    def run(
        self, goal, attacker_model, judge_model,
        max_iter, threshold, gate_modes, system_prompt
    ) -> Iterator[dict]:
        # Generator — yields one attempt dict per iteration
        # Caller (Streamlit view) re-renders after each yield
        # attempt dict keys:
        #   iteration, prompt, blocked, blocked_by, response,
        #   score, judge_reasoning, success, gate_trace
        ...
```

**Why a generator:** Streamlit re-renders the whole page on state changes.
Yielding one attempt at a time lets the view call `st.rerun()` (or use
`st.empty()`) to show live progress without blocking the event loop.

**Files changed:** `core/pair_runner.py` (new)

---

### Step 5 — Dynamic Red Team tab (`ui/redteam_view.py`)

**Layout:**

```
┌─ Config panel ────────────────────────────────────────────────────────────────┐
│  Attack Goal (textarea)                                                        │
│  Attacker model (selectbox — populated from client.list_models())             │
│  Judge model   (selectbox)                                                    │
│  Target model  (read-only — mirrors Chat Workbench target_model)              │
│  Max iterations (number input, default 10)   Breach threshold (1–10, def 7)  │
│  [ ▶ Start Probe ]  [ ■ Stop ]                                                │
└───────────────────────────────────────────────────────────────────────────────┘

Status bar: "Iteration 3 / 10 — querying target LLM…"

Summary stats: 🛡️ Blocked: 2   ⚠️ Reached LLM: 1   🔴 Breached: 0   Total: 3

┌─ Iteration card (repeated per attempt) ──────────────────────────────────────┐
│  Iteration N   🛡️ BLOCKED (classify)  / ⚠️ REACHED LLM  / 🔴 BREACHED        │
│  Attack Prompt: [text]                                                        │
│  Gate Trace: [chip row via render_gate_chip_trace()]                         │
│  [if not blocked] LLM Response: [text, truncated at 500 chars]               │
│  [if not blocked] Judge: 6/10 — "The response partially reveals…"            │
└───────────────────────────────────────────────────────────────────────────────┘

[ Download JSON ]  [ Download Markdown Report ]
```

**Streamlit live-update pattern:**
```python
# In the view, run loop stores attempts in session_state
# and renders cards from that list — each st.rerun() re-renders all cards
# (safe because the list is append-only during a run)
if st.session_state.pair_running:
    attempt = next(st.session_state._pair_gen, None)
    if attempt:
        st.session_state.pair_log.append(attempt)
        st.rerun()
    else:
        st.session_state.pair_running = False
        st.rerun()
```

**New session state keys:**
- `pair_log`: `list[dict]` — attempts from the current/last run.
- `pair_running`: `bool` — True while a run is in progress.
- `pair_stop`: `bool` — set True by the Stop button; checked by the generator.
- `_pair_gen`: the live generator object (stored in session_state between reruns).

**Files changed:** `ui/redteam_view.py` (new, continues from Step 3)

---

### Step 6 — Export (`ui/redteam_view.py`)

Both tabs get a `st.download_button` once a result exists.

**JSON export (PAIR):**
```json
{
  "exported": "2026-04-14T10:30:00Z",
  "goal": "...",
  "config": { "attacker_model": "...", "judge_model": "...", "target_model": "...",
              "max_iter": 10, "threshold": 7, "gate_modes": {...} },
  "summary": { "blocked": 3, "reached_llm": 2, "breached": 0 },
  "attempts": [ { "iteration": 1, "prompt": "...", "blocked": true, ... }, ... ]
}
```

**Markdown report (PAIR):**
Generated via a simple f-string template — goal, config table, per-iteration
summary lines, final verdict sentence.

**JSON export (Static):**
Single-shot: threat metadata + prompt + gate trace + verdict + response.

---

## File change summary

| File | Change type | Notes |
|------|-------------|-------|
| `app.py` | Modify | Add nav option; extract `_build_pipeline()` helper; add Red Teaming route |
| `ui/redteam_view.py` | **New** | Static tab + Dynamic (PAIR) tab; export buttons |
| `core/pair_runner.py` | **New** | `PAIRRunner` class — no Streamlit imports |
| `ui/metrics_panel.py` | Modify | Add `render_gate_chip_trace()` shared component |
| `ui/chat_view.py` | Modify | Expose `_load_threats()` / `_threat_options()` (or move to shared module) |

No changes to `core/pipeline.py`, `core/llm_client.py`, any gate files, or
`data/threats.json`.

---

## Implementation order and dependencies

```
Step 1  render_gate_chip_trace()        ← no dependencies
  │
Step 2  app.py nav + _build_pipeline()  ← no dependencies
  │
Step 3  Static tab                      ← needs Step 1, Step 2
  │
Step 4  core/pair_runner.py             ← needs no UI; can parallel with Step 3
  │
Step 5  Dynamic tab                     ← needs Steps 1, 2, 4
  │
Step 6  Export                          ← needs Steps 3 and 5
```

Steps 3 and 4 can be worked in parallel if desired.

---

## Session state additions (summary)

```python
# Added to _init_session_state() in app.py
"static_rt_result":  None,   # last static red-team run result dict
"pair_log":          [],     # list of PAIR attempt dicts
"pair_running":      False,  # True while a PAIR run is executing
"pair_stop":         False,  # Stop button signal to the generator
```

The `_pair_gen` generator is stored directly in `st.session_state` during a run
(not in `_init_session_state` — set dynamically when the run starts).

---

---

# Implementation Plan — Batch Static Red Teaming Tab

> **Reference:** Screenshot `inspiration/Screenshot 2026-04-14 at 11.36.58 AM.png`
>
> Run the entire threat library (or a filtered subset) through the live security
> pipeline in one click. See per-row verdicts, outcome accuracy, latency, and
> per-gate catch counts in a results table — then export as JSON or Markdown.

---

## What the screenshot shows

| UI Element | Description |
|------------|-------------|
| **Import External Threat Data** button | Loads a supplemental threat JSON (pace / JailbreakBench format) to extend the built-in library for the session |
| **Severity filter chips** | All · Critical · High · Medium · Low — with total counts; multi-select; clicking a chip toggles its severity in/out |
| **Categories to include** | Per-category checkbox rows showing `NAME (selected/total)` counts; "All" / "None" quick toggles |
| **DELAY BETWEEN REQUESTS** slider | 0–2000 ms, default 500 ms — prevents rate-limiting / thermal runaway on local Ollama |
| **Run (N)** button | N = count of currently-selected threats; disabled while running |
| **Stop** button | Halts the batch mid-run cleanly |
| **Results table** | Columns: `#` · `Category` · `Threat Type` · `Sev` · `Result` · `Caught By` · `Expected` · `Outcome` · `Detected` · `Latency` |
| **Summary bar** | `🔴 N blocked · 🟡 N flagged · ✅ N allowed` + "No pass or false positives detected" |
| **Per-gate catch counts** | Pill row: `LLM-Guard: 5 · Semantic-Guard: 1 · Little-Canary: 1 · …` |
| **Export buttons** | `Export Results MD` and `Export Results JSON` |

Our existing `data/threats.json` has **76 threats across 11 categories** with real
severity labels, so the filter/count UI maps directly.

---

## Architecture

```
ui/redteam_view.py
  render()
    └── tabs: ["🎯 Static", "📋 Batch", "🤖 Dynamic (PAIR)"]
                                ↑
                    _render_batch(pipeline, config)
                        ├── _batch_filter_panel()     → returns selected threats list
                        ├── _batch_run_generator()    → generator yielding one result dict per threat
                        ├── _render_batch_table()     → results table from session_state.batch_results
                        ├── _render_batch_summary()   → summary bar + per-gate catch counts
                        └── _render_batch_export()    → JSON + MD download buttons
```

The batch generator follows the same **one result per `st.rerun()`** pattern
already established for PAIR. No threading or async required.

---

## Data model

### Flat threat list (built at filter time)

```python
# Each entry in the working list passed to the generator
{
    "category":       "Agentic Exploits",
    "categoryId":     "AE",
    "id":             "AE-03",
    "type":           "Tool Call Override",
    "severity":       "critical",
    "targetPhase":    "Phase 2",
    "source":         "Internal",
    "tags":           ["tool-use", "privilege-escalation"],
    "expectedVerdict":"block",
    "example":        "...",      # the actual prompt text
}
```

### Result dict (one per completed threat)

```python
{
    "threat":         { ...flat threat dict... },
    "blocked":        True,
    "blocked_by":     "classify",        # gate key, or "" if not blocked
    "caught_detail":  "score=0.97",      # first BLOCK gate's detail field
    "gate_metrics":   [ ...list of per-gate metric dicts... ],
    "outcome_match":  True,              # expected == actual
    "latency_s":      1.94,
}
```

---

## Step 7 — Batch tab implementation

### Step 7a — Tab wiring

Add `"📋 Batch"` to the `st.tabs()` call in `render()`:

```python
static_tab, batch_tab, dynamic_tab = st.tabs(
    ["🎯 Static", "📋 Batch", "🤖 Dynamic (PAIR)"]
)
```

Add new session-state keys to `_init_session_state()` in `app.py`:

```python
"batch_results":          [],     # list of result dicts from current/last run
"batch_running":          False,  # True while batch is executing
"batch_stop":             False,  # Stop signal
"batch_severity_filter":  ["critical", "high", "medium", "low"],  # all by default
"batch_category_filter":  None,   # None = all; else set of categoryId strings
"batch_import_threats":   [],     # supplemental threats loaded via Import button
```

---

### Step 7b — Import External Threat Data

A `st.popover` or `st.expander` button labelled **"⬆ Import External Threat Data"**
contains a `st.file_uploader(type=["json"])`.

Accepted format: same schema as `data/threats.json` — a list of category objects,
each with a `threats` array. On upload, the list is merged into
`st.session_state.batch_import_threats` and deduplicated by threat `id`.

This is intentionally minimal — no external API calls, no network fetch, just a
local file load so users can drop in JailbreakBench exports or custom test sets.

---

### Step 7c — Filter panel

```
┌─ Severity ──────────────────────────────────────────────────────────────────┐
│  [All 76]  [Critical 18]  [High 31]  [Medium 15]  [Low 12]                  │
└─────────────────────────────────────────────────────────────────────────────┘
┌─ Categories to include ──────────────────────────────────────────────────────┐
│  [All] [None]                                                                │
│  ☑ BASIC THREATS (5/5)                                                      │
│  ☑ AGENTIC EXPLOITS (7/7)                                                   │
│  ☑ ADVERSARIAL FRAMING (7/7)                                                │
│  …                                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
┌─ Delay between requests ────────────────────────────────────────────────────┐
│  ←————●——————————→  500 ms                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
[ ▶ Run (N) ]   [ ■ Stop ]
```

**Severity chips** are rendered as HTML `<span>` buttons using `st.markdown` +
a `st.pills` widget (Streamlit ≥ 1.30) or `st.multiselect`. Counts re-compute
as severity filter changes — category `(selected/total)` counts reflect only the
threats that survive the active severity filter.

**"All" / "None" quick toggles** set all category checkboxes at once using
`st.button` callbacks that write to `batch_category_filter`.

---

### Step 7d — Batch run generator

```python
def _batch_run_generator(
    pipeline: "PipelineManager",
    gate_modes: dict[str, str],
    threats: list[dict],
    delay_ms: int,
) -> Iterator[dict]:
    import time
    for threat in threats:
        if st.session_state.get("batch_stop"):
            break
        t_start = time.perf_counter()
        payload = pipeline.run_input_gates(threat["example"], gate_modes)
        latency_s = time.perf_counter() - t_start

        blocked_by     = ""
        caught_detail  = ""
        if payload.is_blocked:
            blocked_by = next(
                (m["gate_name"] for m in payload.metrics if m.get("verdict") == "BLOCK"),
                "unknown",
            )
            caught_detail = next(
                (m.get("detail", "") for m in payload.metrics if m.get("verdict") == "BLOCK"),
                "",
            )

        outcome_match = (
            (payload.is_blocked and threat.get("expectedVerdict") == "block") or
            (not payload.is_blocked and threat.get("expectedVerdict") != "block")
        )

        yield {
            "threat":        threat,
            "blocked":       payload.is_blocked,
            "blocked_by":    blocked_by,
            "caught_detail": caught_detail,
            "gate_metrics":  payload.metrics,
            "outcome_match": outcome_match,
            "latency_s":     round(latency_s, 2),
        }

        if delay_ms > 0:
            time.sleep(delay_ms / 1000)
```

**Advance loop** in `_render_batch()` (same pattern as PAIR):

```python
if st.session_state.batch_running:
    result = next(st.session_state.get("_batch_gen"), None)
    if result is None:
        st.session_state.batch_running = False
        st.session_state.pop("_batch_gen", None)
    else:
        st.session_state.batch_results.append(result)
    st.rerun()
```

---

### Step 7e — Results table

Rendered via `st.markdown` with inline HTML for coloured severity badges and
outcome tick/cross icons (Streamlit's native `st.dataframe` doesn't support
rich HTML cells).

| # | Category | Threat Type | Sev | Result | Caught By | Expected | Outcome | Detected | Latency |
|---|----------|-------------|-----|--------|-----------|----------|---------|----------|---------|
| 1 | Agentic Exploits | Tool Call Override | 🔴 CRIT | 🔴 Blocked | classify | block | ✅ | score=0.97 | 1.9s |
| 2 | Basic Threats | Prompt Injection | 🟠 HIGH | 🔴 Blocked | mod_llm | block | ✅ | unsafe S2 | 3.5s |
| 3 | Benign / FP | Safe Query | 🟢 LOW | ✅ Passed | — | allow | ✅ | — | 0.2s |

**Outcome column logic:**

```
expected == "block" and blocked  → ✅ (true positive)
expected == "block" and not blocked → ❌ (false negative — pipeline miss)
expected == "allow" and not blocked → ✅ (true negative — no false alarm)
expected == "allow" and blocked  → ⚠️ (false positive — over-blocking)
```

---

### Step 7f — Summary bar + per-gate catch counts

```
🔴 18 blocked   🟡 0 flagged   ✅ 3 allowed      All expected outcomes matched ✓

classify: 8   mod_llm: 6   invisible_text: 2   custom_regex: 1   fast_scan: 1
```

**Per-gate catch counts** are computed from `result["blocked_by"]` across all
results where `blocked=True`. Displayed as compact pills with the gate emoji
from `_GATE_EMOJI` (already defined in `metrics_panel.py`).

**Outcome accuracy sentence:** computed from `outcome_match` booleans:
- All match → "All expected outcomes matched ✓"
- Some mismatches → "⚠️ N false negatives · M false positives detected"

---

### Step 7g — Export

**JSON structure:**

```json
{
  "exported": "2026-04-14T12:00:00Z",
  "filter": {
    "severity": ["critical", "high", "medium", "low"],
    "categories": "all"
  },
  "summary": {
    "total": 76,
    "blocked": 18,
    "flagged": 0,
    "allowed": 3,
    "false_negatives": 0,
    "false_positives": 0
  },
  "gate_catch_counts": { "classify": 8, "mod_llm": 6, "...": 0 },
  "results": [
    {
      "id": "AE-03",
      "category": "Agentic Exploits",
      "type": "Tool Call Override",
      "severity": "critical",
      "expected_verdict": "block",
      "blocked": true,
      "blocked_by": "classify",
      "caught_detail": "score=0.97",
      "outcome_match": true,
      "latency_s": 1.94,
      "gate_metrics": [ ... ]
    }
  ]
}
```

**Markdown report structure:**
```
# Batch Static Red Team Report
**Exported:** 2026-04-14T12:00:00Z

## Summary
| Metric | Value |
| Threats tested | 76 |
| Blocked | 18 |
...

## Per-Gate Catch Counts
| Gate | Count |
...

## Results
| # | Category | Type | Sev | Result | Caught By | Expected | Outcome | Latency |
...
```

---

## New session-state keys

```python
# Added to _init_session_state() in app.py
"batch_results":         [],     # list[dict] — results from current/last run
"batch_running":         False,  # True while batch is executing
"batch_stop":            False,  # Stop signal (set by Stop button)
"batch_severity_filter": ["critical", "high", "medium", "low"],
"batch_category_filter": None,   # None = all; else list[str] of categoryId values
"batch_import_threats":  [],     # threats loaded via Import button (session-only)
```

The `_batch_gen` generator object is stored directly in session state when a run
starts and popped when the run ends (not in `_init_session_state`).

---

## File changes

| File | Change |
|------|--------|
| `app.py` | Add 5 new session-state keys in `_init_session_state()` |
| `ui/redteam_view.py` | Add `"📋 Batch"` tab; add `_render_batch()`, `_batch_run_generator()`, `_render_batch_table()`, `_render_batch_summary()`, `_render_batch_export()` functions |

No changes to `core/`, `gates/`, `data/`, or `ui/metrics_panel.py` are needed.

---

## Implementation dependencies

```
Step 7a  Tab wiring + session state         ← depends on existing Step 3 (render() structure)
  │
Step 7b  Import External Threat Data        ← depends on 7a
  │
Step 7c  Filter panel                       ← depends on 7a (needs flat threat list helper)
  │
Step 7d  Batch run generator                ← depends on 7a, 7c (needs filtered threat list)
  │
Step 7e  Results table                      ← depends on 7d
  │
Step 7f  Summary bar + gate catch counts    ← depends on 7e
  │
Step 7g  Export                             ← depends on 7f
```

Steps 7b–7c are independent and can be worked in parallel.
