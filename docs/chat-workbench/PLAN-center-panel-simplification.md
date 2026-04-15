# Chat Workbench — Center Panel Simplification Plan

## Goal

Reduce visual clutter in the center chat column by separating conversation content from pipeline instrumentation. The center column should feel like a clean chat interface; all monitoring widgets belong in the sidebar or right telemetry panel.

---

## Current Layout (Problem State)

The center `chat_col` (5:2 column split, `chat_view.py:798`) currently stacks:

1. Custom HTML header — "LLM Security Workbench / WORKBENCH" badge
2. RAG / System Context expander — full text area
3. `---` divider
4. **Pipeline banner** — `_render_pipeline_banner()` — 14-gate status board
5. Threat staging area — editable text area + Send/Cancel buttons
6. Chat history loop — per-message bubbles
   - Inside each assistant bubble: gate badges (`_render_turn_footer`), context bar, Gate Trace (`render_api_inspector`)
   - After messages: **7 flat `st.warning`/`st.info` security scan notices** at full width

The pipeline banner and security notices in particular push conversation content down and create a wall of chrome that obscures the actual chat.

---

## Proposed Changes

### Change 1 — Move Pipeline Banner to Telemetry Panel

**File:** `ui/chat_view.py`

**Current:** `_render_pipeline_banner(pipeline)` is called at line ~848 inside `_render_chat_content()`, placing it in the center column above the first message.

**Change:** Remove the call from `_render_chat_content()`. Add it inside `_render_chat_area()` in the `tel_col` block, above `render_telemetry_panel()`:

```python
with tel_col:
    _render_pipeline_banner(pipeline)   # ← move here
    render_telemetry_panel(_ollama_host, _model)
```

**Rationale:** The pipeline banner is a live monitoring widget (gate mode status board), not chat content. It belongs in the telemetry column with the other pipeline state displays.

---

### Change 2 — Move RAG Expander to Sidebar

**File:** `ui/chat_view.py`

**Current:** `📄 System Context / RAG Document` expander sits in `_render_chat_content()` above the pipeline banner, occupying full center-column width.

**Change:** Move the text area into `_render_sidebar()` under the existing `CONTEXT` section (line ~598, where the Persona/System Prompt expander already lives). Replace the in-chat expander with a single `st.caption` indicator when context is active:

```python
# In chat content — replace expander with status indicator only
if st.session_state.rag_context.strip():
    st.caption(
        f"⚡ RAG context active — {len(st.session_state.rag_context.split())} words injected"
    )
```

**Rationale:** RAG context is configuration, not conversation. Expanding it in-place pushes all messages down. The sidebar already holds all other pipeline configuration (model, gates, generation params, persona).

---

### Change 3 — Remove / Shrink Center Header

**File:** `ui/chat_view.py`

**Current:** Custom HTML header (lines 813–823) renders "LLM Security Workbench" + "WORKBENCH" badge at the top of every chat render.

**Change:** Remove the header in workbench mode entirely. If an empty-state placeholder is useful, replace with a simple `st.caption("Send a prompt to begin.")` that only shows when `st.session_state.messages` is empty.

**Rationale:** The page title is shown in the sidebar navigation. The "WORKBENCH" badge conveys no information the user doesn't already know. Three layers of chrome (header → RAG → pipeline banner) before the first message is too much.

---

### Change 4 — Consolidate Security Scan Notices into One Expander

**File:** `ui/chat_view.py`

**Current:** Lines 1037–1177 contain 7 independent `st.warning`/`st.info` calls, one per gate event. When multiple gates fire, these stack into a wall of yellow banners inside the assistant bubble.

**Change:** Collect all fired notices into a list, then render them inside a single `st.expander`:

```python
notices = []   # list of (icon, headline, body, is_block)

if fast_scan_block:
    notices.append(("🛡️", "PII detected, masked, and restored", "...", False))
if sensitive_block:
    notices.append(("🔍", "LLM-generated PII detected and redacted", "...", True))
# ... etc for all 7 gates

if notices:
    any_block = any(n[3] for n in notices)
    label = f"🔍 Security Scan Results ({len(notices)} event{'s' if len(notices)>1 else ''})"
    with st.expander(label, expanded=any_block):
        for icon, headline, body, is_blk in notices:
            fn = st.warning if is_blk else st.info
            fn(f"**{headline}** — {body}", icon=icon)
```

**Expander open/closed default:**
- **Open** if any notice is a hard BLOCK (user must see why the response was suppressed)
- **Closed** if all notices are AUDIT-mode monitoring signals (informational, non-blocking)

**Rationale:** A single collapsible entry takes one line when closed. The user can expand on demand. This matches the existing Gate Trace pattern (`render_api_inspector`) which is already a collapsible expander.

---

### Change 5 (Optional) — Gate Badge Footer as Popover

**File:** `ui/chat_view.py` — `_render_turn_footer()`

**Current:** Renders a horizontal row of up to 14 gate badges per assistant turn. At full pipeline, this is a wide strip under every message.

**Change (Optional):** Collapse the 14-badge strip into a single summary badge (e.g. `"✓ 12 passed · ⚠ 2 flagged"`) that opens a popover on click with the full per-gate breakdown.

**Note:** This is lower priority — the badge row is already compact and informative. Only pursue if the chat history feels visually noisy with many turns.

---

## Resulting Center Column Layout

```
chat_col (5 parts):
  [chat history — messages only]
    └── user bubble: [prompt text]
    └── assistant bubble:
          [response text]
          [⚡ RAG context active — N words]  ← only if active
          [_render_turn_footer: gate badges]
          [context bar]
          [🔍 Security Scan Results (N) — expander, closed/open by BLOCK]
          [▶ Gate Trace — expander, open for latest turn]
  [st.chat_input — sticky bottom]

tel_col (2 parts):
  [_render_pipeline_banner — gate mode status board]  ← moved here
  [render_telemetry_panel — tokens, TPS, latency]

sidebar:
  [MODEL]
  [CONTEXT → Persona + RAG document]  ← RAG moved here
  [INPUT GATES]
  [OUTPUT GATES]
  [GENERATION]
  [SESSION]
```

---

## Implementation Order

1. **Change 3** (remove header) — trivial, no logic change
2. **Change 1** (move pipeline banner) — move one function call
3. **Change 2** (move RAG to sidebar) — move text area + add caption indicator
4. **Change 4** (consolidate notices) — refactor 7 independent calls into list + expander

Each change is independently deployable and does not depend on the others.

---

## Files Affected

| File | Changes |
|------|---------|
| `ui/chat_view.py` | All changes — `_render_chat_content()`, `_render_chat_area()`, `_render_sidebar()` |
| No other files | Pipeline banner, telemetry panel, and gate trace components are unchanged |
