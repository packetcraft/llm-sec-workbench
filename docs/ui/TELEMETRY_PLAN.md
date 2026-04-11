# Live Telemetry Panel — Plan

## 1. Overview

**Feature name:** Live Telemetry Panel (Phase 5 upgrade)
**Parent project:** LLM Security Workbench ([master plan](../../plan.md))

### What this is

A persistent, right-side telemetry column in the Chat Workbench that displays
structured, real-time instrumentation for every prompt/response cycle.
It replaces the current inline badge-and-caption approach with a dedicated
panel modelled on the design reference below.

### Design reference

The reference panel (from a companion app) shows six sections in a fixed
right column alongside the chat:

```
┌─────────────────────────────┐
│ 📡 LIVE TELEMETRY           │
├─────────────────────────────┤
│ GATE LATENCY                │
│ 🟢 token_limit      0.3 ms  │
│ 🟡 fast_scan       84.1 ms  │
│ 🔴 mod_llm      2,269.0 ms  │
│ ─ sensitive_out   off       │
├─────────────────────────────┤
│ PIPELINE                    │
│ Total time       2,555 ms   │
│ Gates run            5 / 7  │
│ Blocked by       mod_llm    │
├─────────────────────────────┤
│ TOKENS                      │
│ Prompt               61     │
│ Completion          914     │
│ Total               975     │
│ Speed            42.0 t/s   │
│ ████░░  Prompt / Completion │
├─────────────────────────────┤
│ OLLAMA TIMING               │
│ Model load          111 ms  │
│ Prompt eval         611 ms  │
│ Generation       21,786 ms  │
│ Ollama total     22,683 ms  │
│ Stop reason          stop   │
│ ▌Load ░░Eval ░░░░░░░░Gen    │
├─────────────────────────────┤
│ MODEL INFO                  │
│ [qwen3] [4.0B] [Q4_K_M]    │
│ Context window   262,144    │
│ 61 / 262,144 used (0%)      │
├─────────────────────────────┤
│ MEMORY          (live, 5s)  │
│ VRAM               5.3 GB   │
│ ████████████░░░░░           │
│ Unloads in        4m 49s    │
└─────────────────────────────┘
```

### How it differs from the current Phase 5 panel

| Aspect | Current (Phase 5 as built) | This plan |
|:-------|:--------------------------|:----------|
| Layout | Badges inline under messages; telemetry in sidebar | Persistent right column alongside chat |
| Gate latency | Compact badge row | Named rows with ms values, colour icons, `off` label for disabled gates |
| Pipeline summary | Not present | Total pipeline ms, gates run (N/total), blocked-by gate name |
| Token chart | Caption line only | Stacked bar — prompt vs completion proportions |
| Ollama timing | Not captured | Load / Prompt eval / Generation split with stacked bar and stop reason |
| Model info | Context bar only (tokens/size) | Pill tags: model name, param count, quantization; context window + used count |
| Memory | VRAM bar | VRAM GB value + bar, unloads-in countdown from `expires_at` |

---

## 2. Settled Design Decisions

### 2.1 Panel Location

**Decision:** Right column alongside the chat, implemented with `st.columns([3, 1])`.

**Rationale:** Sidebar is already dense with gate controls and hardware telemetry.
A dedicated column keeps telemetry always visible without competing with controls.
The 3:1 split gives the chat area adequate width on typical 1440px screens.

**Demo Mode:** The telemetry column is hidden entirely in Demo Mode — the chat
expands to full width. Same pattern as existing gate badges.

### 2.2 State Persistence Between Re-runs

**Decision:** All telemetry data is stored in `st.session_state.last_telemetry`
(a single dict) after each generation. The panel reads from this dict, not from
the Ollama API directly, so it displays the last-known values during idle re-runs.

**Rationale:** Streamlit re-runs the entire script on every interaction. If the
panel queried Ollama on each re-run it would add latency to unrelated interactions
(e.g., toggling a gate mode). Reading from session_state is free.

**Dict shape:**
```python
st.session_state.last_telemetry = {
    "gate_metrics":    [...],   # payload.metrics list
    "gate_modes":      {...},   # active modes at time of generation
    "prompt_tokens":   61,
    "completion_tokens": 914,
    "tokens_per_second": 42.0,
    "load_ms":         111.0,
    "prompt_eval_ms":  611.0,
    "generation_ms":   21786.0,
    "done_reason":     "stop",
    "model_name":      "qwen3:latest",
    "context_size":    262144,
}
```

### 2.3 Ollama Timing Capture

**Decision:** Extend `GenerationResult` and `OllamaClient` to capture
`load_duration`, `prompt_eval_duration`, `eval_duration`, and `done_reason`
from the Ollama API response.

These fields are already present on every Ollama response (streaming final chunk
and non-streaming) — they are currently discarded. No API change required.

**New `GenerationResult` fields:**
```python
load_ms: float = 0.0            # model load time (ns → ms conversion)
prompt_eval_ms: float = 0.0     # prompt evaluation time
generation_ms: float = 0.0      # pure token generation time
done_reason: str = ""           # "stop" | "length" | "context"
```

### 2.4 Model Info Source

**Decision:** Use `ollama.show(model_name)` to fetch parameter size and
quantization level. Cache the result with `@functools.lru_cache(maxsize=8)`
keyed on `(model_name, ollama_host)`.

**Fields used:**
```python
info = client.show(model_name)
info.details.parameter_size       # "4.0B"
info.details.quantization_level   # "Q4_K_M"
info.details.family               # "qwen3"
```

The context window size is already fetched the same way (existing
`_fetch_context_size()` function in `metrics_panel.py`). Consolidate both
into a single `_fetch_model_info()` call.

### 2.5 Unloads-In Countdown

**Decision:** Compute the unload countdown from `expires_at` returned by
`ollama.ps()`. Display as `Xm Ys`. Update every 5 seconds via the existing
`@st.fragment(run_every=5)` Memory section.

**Rationale:** Developers running large models (8B+) are frequently caught off-guard
when Ollama unloads an idle model mid-session. A visible countdown lets them
trigger a dummy request before the model drops.

**Behaviour when `expires_at` is None:** Display `—` (model may be permanently
loaded or Ollama version does not report it).

### 2.6 Gate Latency Colour Thresholds

**Decision:** Three colour bands for the gate latency rows:

| Colour | Threshold | Meaning |
|:-------|:----------|:--------|
| Green `#9ECE6A` | < 100 ms | Fast — zero-ML or CPU classifier |
| Amber `#E0AF68` | 100 ms – 1,000 ms | Moderate — ML gate, acceptable |
| Red `#F7768E` | > 1,000 ms | Slow — LLM judge or overloaded |

Disabled gates (`mode == "OFF"`) shown as dim `— off` with no colour.

### 2.7 Stacked Bar Charts (Pure HTML/CSS)

**Decision:** Implement all bar charts as inline HTML `<div>` elements, not
Streamlit `st.bar_chart` or Plotly. CSS `display:flex` with proportional widths.

**Rationale:** `st.bar_chart` adds significant vertical whitespace and renders
a full Vega-Lite chart — overkill for a two-segment usage bar. HTML divs match
the compact visual style of the reference panel and render in < 1 ms.

**Token bar:** Prompt segment (blue `#7AA2F7`) + Completion segment (green `#9ECE6A`).
**Ollama timing bar:** Load (amber) + Eval (blue) + Generation (green) segments.

### 2.8 Sidebar Cleanup

**Decision:** When the new telemetry column is added, remove the existing
Hardware Telemetry section from the sidebar (`render_hw_telemetry` call in
`_render_sidebar`). Memory and VRAM move into the new panel's Memory section.

The sidebar retains: navigation, Demo Mode toggle, model selector, persona,
generation params, gate controls, session controls.

---

## 3. Gap Analysis — What Needs to Change

### 3.1 `core/llm_client.py`

- Add `load_ms`, `prompt_eval_ms`, `generation_ms`, `done_reason` to `GenerationResult`
- Capture `load_duration`, `prompt_eval_duration`, `eval_duration`, `done_reason`
  from the streaming final chunk in `generate_stream()` and from the blocking
  response in `generate()`
- Convert nanosecond durations to milliseconds on capture (`ns / 1_000_000`)

### 3.2 `ui/metrics_panel.py`

Full rewrite of the public API:

| Old function | New function | Change |
|:-------------|:-------------|:-------|
| `render_api_inspector()` | `render_api_inspector()` | Unchanged — keep as expander under messages |
| `render_context_bar()` | *(removed from inline position)* | Absorbed into `render_telemetry_panel()` Model Info section |
| `render_hw_telemetry()` | *(removed from sidebar)* | Absorbed into `render_telemetry_panel()` Memory section |
| *(new)* | `render_telemetry_panel()` | Full panel: Gate Latency, Pipeline, Tokens, Ollama Timing, Model Info, Memory |

`render_telemetry_panel(ollama_host, model_name)` reads exclusively from
`st.session_state.last_telemetry`. The Memory section is wrapped in
`@st.fragment(run_every=5)` for the live countdown; all other sections are
static (update only after a new generation).

Private helpers to add:

```python
_render_gate_latency(metrics, gate_modes)    # coloured rows, off labels
_render_pipeline_summary(metrics)            # total ms, run count, blocked-by
_render_token_bar(prompt_t, completion_t, tps)  # stacked bar + stats
_render_ollama_timing(load_ms, eval_ms, gen_ms, done_reason)  # stacked bar
_render_model_info(model_name, host, prompt_tokens)  # pills + context row
_render_memory_section(host)                 # @st.fragment VRAM + countdown
_fetch_model_info(model_name, host)          # consolidate show() + context_size
```

### 3.3 `ui/chat_view.py`

- `_render_chat_area()`: wrap existing chat markup in a `st.columns([3, 1])` split
- Left column: existing chat messages + input (unchanged)
- Right column: `render_telemetry_panel(ollama_host, model_name)` — always rendered
- After each generation: populate `st.session_state.last_telemetry` with the
  full telemetry dict before the script completes
- Remove inline `render_context_bar()` calls (absorbed into panel)
- Keep `render_api_inspector()` calls inline under messages (different purpose)

### 3.4 `app.py`

- Add `last_telemetry: {}` to `_init_session_state()` defaults
- Remove `last_tps` key (replaced by `last_telemetry["tokens_per_second"]`)

---

## 4. Implementation Phases

### Phase A — Data layer (`core/llm_client.py`)
Capture the four new fields from Ollama responses. No UI changes. Covered by
existing tests if `GenerationResult` fields are added with defaults.

**Deliverables:**
- `GenerationResult`: add `load_ms`, `prompt_eval_ms`, `generation_ms`, `done_reason`
- `OllamaClient.generate()`: extract new fields from non-streaming response
- `OllamaClient.generate_stream()`: extract from final streaming chunk
- `OllamaClient.get_stream_result()`: return new fields

### Phase B — Panel layout (`ui/chat_view.py`)
Restructure `_render_chat_area` into two columns. Panel renders empty/placeholder
state until a generation completes.

**Deliverables:**
- `st.columns([3, 1])` split in `_render_chat_area`
- `st.session_state.last_telemetry` populated after each generation
- `render_telemetry_panel()` called in right column
- Sidebar `render_hw_telemetry()` call removed

### Phase C — Panel sections (`ui/metrics_panel.py`)
Implement all six sections using the HTML/CSS approach. Each section is an
independent private function so they can be developed and tested in isolation.

**Deliverables:**
- `render_telemetry_panel()` public entry point
- All six `_render_*` private helpers
- `_fetch_model_info()` consolidating existing `_fetch_context_size()`
- `_render_memory_section()` with `@st.fragment(run_every=5)` countdown
- Remove `render_context_bar()` and `render_hw_telemetry()` (or keep as
  deprecated wrappers until callers are updated)

### Phase D — Cleanup & polish
- Remove `last_tps` from session state, update `app.py`
- Update `docs/QUICKSTART.md` if the UI layout description changes
- Manual smoke test against the test checklist in `docs/ui/TELEMETRY_PLAN.md`

---

## 5. Test Checklist

After implementation, verify each section manually:

| Section | Test | Expected |
|:--------|:-----|:---------|
| Gate Latency | Send prompt with all gates ON | All gate rows shown, correct ms values |
| Gate Latency | Set `mod_llm` to OFF | Row shows `— off` in dim colour |
| Gate Latency colour | ML gate takes > 1s | Row colour is red |
| Pipeline | Send prompt blocked by `classify` | "Blocked by: classify" shown |
| Pipeline | No block | "Blocked by" row absent or shows `—` |
| Tokens | Send prompt, check bar | Prompt segment narrower than completion (typical) |
| Ollama Timing | Check load_ms | Near 0 if model already loaded; > 0 on cold start |
| Ollama Timing bar | Visually | Three segments proportional to Load/Eval/Gen values |
| Stop reason | Normal reply | `stop` |
| Stop reason | max_tokens hit | `length` |
| Model Info pills | Switch model in dropdown | Pills update to new model name/size/quant |
| Context window | Send large prompt | Used count increases, bar fills |
| Memory VRAM | Model loaded | GB value matches `ollama ps` output |
| Memory countdown | Watch for 5s | Countdown decrements |
| Memory countdown | Model unloaded | Shows `—` or section clears |
| Demo Mode | Toggle ON | Entire right column hidden, chat expands |
| Panel persistence | Toggle a gate mode | Panel retains last telemetry values |
| Cold start | First page load, no generation yet | Panel shows placeholder state |

---

## 6. File Structure

```
llm-sec-workbench/
├── core/
│   └── llm_client.py           # Phase A — new GenerationResult fields
├── ui/
│   ├── chat_view.py            # Phase B — column layout, last_telemetry population
│   └── metrics_panel.py        # Phase C — full panel rewrite
├── app.py                      # Phase D — last_telemetry init, last_tps removal
└── docs/
    └── ui/
        └── TELEMETRY_PLAN.md   # This document
```

---

## 7. Open Items

| Item | Notes |
|:-----|:-------|
| Column width on small screens | 3:1 split may be too narrow on 1024px laptops. Consider collapsing the panel to an expander below the chat at `st.session_state.screen_width < 1200` — needs investigation. |
| Ollama `load_duration` on streaming | Needs verification that `load_duration` is present on the streaming final chunk. It is documented but behaviour may differ across Ollama versions. |
| `done_reason` values | Ollama docs list `stop`, `length`, `context`. Verify exhaustive list — may also return `cancelled`. |
| Panel when Ollama unreachable | Memory section should degrade gracefully if `/api/ps` fails (currently it does — `running = []`). Confirm this still works after the sidebar removal. |
