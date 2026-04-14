# UI Improvement Plan — LLM Security Workbench

**Scope:** Visual coherence, hierarchy, and learnability audit based on current workbench state (April 2026).  
**Audience:** This is a *learning and garage-testing* tool — used by one or a small group of practitioners to understand LLM security concepts hands-on. It is not a production dashboard. The UI must teach, not just display.

---

## 1. Design Principles (for this tool)

| # | Principle | What it means here |
|---|-----------|---------------------|
| 1 | **Teach, not just display** | Every widget and badge should help the user understand *what is happening and why*. Labels > icons alone. Truncated values are a failure mode. |
| 2 | **Clarity over density** | A learner scanning the UI for the first time should immediately understand the three-zone layout: *configure (sidebar) → observe (chat) → measure (telemetry)*. Remove anything that obscures this. |
| 3 | **Consistent signal language** | The same colour, icon, or shape should always mean the same thing. Green = safe/pass. Red = blocked/danger. Amber = audit/monitor. Blue = informational accent. Nowhere should red mean "avatar colour". |

---

## 2. Inspiration Audit — Reference App Observations

*(Source: screenshot of a comparable local LLM security workbench, April 2026)*

### 2.1 Left sidebar — pipeline as a visual node list

The reference app replaces a flat gate-selector list with a vertical stack of **agent/gate cards**. Each card shows:
- Gate name + icon
- A coloured status dot (green = active, grey = off)
- A compact verdict badge (SAFE / AUDIT / BLOCK) that updates after each turn
- Mode buttons (OFF / Audit / Enforce) inline on the card

Effect: the user can read the pipeline topology at a glance rather than scanning gate names in a list. The current workbench has the gate list but no live-verdict summary per gate in the sidebar.

### 2.2 Chat messages — verdict badges in message header, not footer

In the reference app, gate verdict pills are displayed **at the top of each message bubble** (inline with the timestamp), not below it. Format: `🔒 SAFE-WIRE  🟡 SAFE-S/O  🔒 Guard`. This keeps the "what happened to this message" verdict visible without scrolling past the message body.

### 2.3 Block notification — gate name + timing on one line

The block banner reads: `🛡️ LLM-GUARD OUTPUT — BLOCKED · 3.0s` — a single coloured line rather than a multi-line callout box. The gate name and latency are both present. Cleaner than a large callout box for a binary block event.

### 2.4 Threat injection bar (red-team feature)

A dedicated **INSERT THREAT** control sits at the bottom of the chat area (above the send button). It offers a quick-select dropdown of common attack patterns (jailbreaks, DAN prompts, injection templates). This is a major teaching feature missing from the current workbench — it removes the need to remember or type attack prompts manually.

### 2.5 GATE LATENCY with horizontal bar chart

The reference app renders latency as a **mini horizontal bar** beside each gate name in the telemetry panel, with the ms value to the right. The bar length encodes relative cost at a glance. The current GATE RESULTS table uses only numeric values — adding a visual bar would make bottlenecks immediately obvious.

### 2.6 Message header — speed inline with sender

Each assistant message header shows `⚡ 13.7/s` directly after the model name, on the same line. The current workbench shows this in a separate footer card below the message body. Moving it to the header reduces vertical space and keeps the context tight.

### 2.7 Audit Mode as a top-level mode switch

The reference app has a prominent **Audit Mode** button in the top-right of the chat header. This acts like the current Demo Mode toggle but is more discoverable. Consider renaming or repositioning Demo Mode to a top-of-page toggle.

---

## 3. Improvement Proposals (Next Wave)

### 3.1 Threat Injection Panel (high value, new feature)

Add a **threat injection control** to the bottom of the chat area:

```
[ INSERT THREAT ▾ ──────────── No threat selected ────── ] [ Inject ]
```

- Dropdown categories: Jailbreaks, DAN variants, Prompt injection, Role-play bypass, Data exfiltration templates.
- On "Inject": pre-fills the chat input with the selected template. User can edit before sending.
- Benefits: turns the workbench into a proper red-team drill tool; learners can see exactly which prompts trigger which gates without typing them.
- Implementation: a `st.selectbox` + `st.button` row rendered below the pipeline banner; on click, writes the template to `st.session_state.prefill_prompt` and triggers a rerun that populates `st.chat_input`.

### 3.2 Sidebar Gate Cards — Live Verdict Summary

Replace the plain gate label + selectbox row with a compact **gate card** that also shows the verdict from the last turn:

```
● Injection Detect   [AUDIT ▾]   🟡 0.31
● Bias / Toxicity    [AUDIT ▾]   🔴 0.46  ← last verdict inline
● Llama Guard        [AUDIT ▾]   🟢 PASS
```

- The verdict dot/score updates on each rerun from `st.session_state.last_telemetry`.
- No new API calls — purely reads existing session state.
- Teaches: the user can see which gates are currently "hot" without opening the telemetry panel.

### 3.3 GATE RESULTS — Mini Latency Bar per Row

Add a thin horizontal bar (0–100% of max gate latency) to each row in the GATE RESULTS table, replacing or augmenting the raw ms value:

```
Injection   AUD  0.31  AUDIT  ████░░░░ 1,705 ms
Llama Guard AUD   —    PASS   ████████ 4,587 ms  ← slowest
PII/Secrets AUD   —    PASS   █░░░░░░░   124 ms
```

- Bar width = `gate_latency / max_gate_latency * 100%`.
- Colour: green <100 ms, amber <1000 ms, red ≥1000 ms (same as old GATE LATENCY).
- Allows instant identification of the pipeline bottleneck without reading numbers.

### 3.4 Block Notification — Compact Inline Banner

Replace the large multi-line `_violation_callout` box for binary gate blocks with a single-line coloured banner:

```
🛡️  Blocked by Injection Detect · 1,705 ms — input never reached the model
```

Keep the multi-line callout only for AUDIT-flagged content (where the message IS shown and the user needs the detail). This reduces visual weight for hard blocks where the message is simply stopped.

### 3.5 Message Header — Speed and Model Inline

Move `⚡ N prompt · N completion · N t/s` from the footer card to the **assistant message header** line (rendered by Streamlit's `st.chat_message` via an HTML caption injected just after the avatar). This frees up vertical space per turn and keeps the performance signal next to the message it describes.

---

## 4. Implementation

### Completed — Phases UI-1 → UI-5 + post-phase fixes (2026-04-12)

| Phase | Summary |
|-------|---------|
| UI-1 | CSS design tokens; ERROR colour differentiated; custom violation callouts; `block_reason` stored. |
| UI-2 | Sidebar restructured: promoted headers, gate child controls attached, expander groups, Demo Mode moved, nav active-state. |
| UI-3 | Pipeline banner: 3-count summary + expandable detail; dot-badge result format; token stat + badges unified card. |
| UI-4 | GATE RESULTS merged table; threat gauge context line; secondary sections collapsed; panel `[5, 2]`. |
| UI-5 | Pipeline Trace rename; tab labels with latency + score; most-recent turn expanded. |
| Post | Sticky telemetry column; top padding reduction; sidebar row compaction; dropdown width fix; ms comma separators + right padding; LLM inference separator row in GATE RESULTS. |

### Phase UI-6a — Complete (2026-04-12)

| # | Task | Notes |
|---|------|-------|
| 21 | GATE RESULTS mini latency bars | 2px bar above ms number; all bars share same scale (max active latency); colour green/amber/red by speed; SKIP rows show `—` with no bar. |
| 22 | Compact block banner | `_block_banner(gate, ms, context)` — single-line red strip. Three hard-block call sites replaced. `_violation_callout` kept only for AUDIT notices (malicious URL redaction) where content is shown and detail is needed. |

### Phase UI-6c — Complete (2026-04-12)

| # | Task | Notes |
|---|------|-------|
| 19 | Threat injection panel | `data/threats.json` — 11 categories, 76 threats (editable). Flat selectbox `ID · Type (Category)`. Inject → pre-fills staging text area above chat with amber banner. Send → routes through normal pipeline (no special badge). Cancel → clears staging. Hidden in Demo Mode. `_load_threats()` uses `lru_cache` so JSON is read once per process. |

### Planned — Phase UI-6b, UI-6d

| # | Task | Phase | Proposal | Files |
|---|------|-------|-----------|-------|
| 20 | Sidebar gate cards — live verdict | UI-6b | Add last-turn verdict dot + score beside each gate selectbox row, read from `last_telemetry` | `ui/chat_view.py` |
| 23 | Message header speed inline | UI-6d | Move t/s + token counts to assistant message header line, remove footer card | `ui/chat_view.py` |

---

## 5. What NOT to Change

- The 3-zone layout (sidebar / chat / telemetry) is fundamentally correct for a teaching tool.
- Gate logic, modes (OFF / AUDIT / ENFORCE), and the pipeline architecture — these are the pedagogical core.
- The compact `_gate_row()` pattern (label + selectbox in one row) is the right approach.
- The existing colour palette (TokyoNight-derived) is coherent for a dark security tool. Extend it, don't replace it.

---

## 6. Non-Goals

- Mobile / responsive layout — this is a desktop-only garage tool.
- Theming / light mode — dark is the deliberate choice for a security workbench.
- Accessibility (WCAG) full compliance — nice-to-have but not a priority for a single-user lab tool.
- Animations or transition effects — add latency and distraction in a tool where latency numbers are a key learning signal.

---

*Last updated: 2026-04-12 (UI-6c complete)*  
*Author: packetcraft*
