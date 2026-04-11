# UI Improvement Plan — LLM Security Workbench

**Scope:** Visual coherence, hierarchy, and learnability audit based on current workbench state (April 2026).  
**Audience:** This is a *learning and garage-testing* tool — used by one or a small group of practitioners to understand LLM security concepts hands-on. It is not a production dashboard. The UI must teach, not just display.

---

## 1. Design Principles (for this tool)

Before listing fixes, establish the three principles every change should serve:

| # | Principle | What it means here |
|---|-----------|---------------------|
| 1 | **Teach, not just display** | Every widget and badge should help the user understand *what is happening and why*. Labels > icons alone. Truncated values are a failure mode. |
| 2 | **Clarity over density** | A learner scanning the UI for the first time should immediately understand the three-zone layout: *configure (sidebar) → observe (chat) → measure (telemetry)*. Remove anything that obscures this. |
| 3 | **Consistent signal language** | The same colour, icon, or shape should always mean the same thing. Green = safe/pass. Red = blocked/danger. Amber = audit/monitor. Blue = informational accent. Nowhere should red mean "avatar colour". |

---

## 2. Audit Findings — Section by Section

### 2.1 Left Sidebar

#### Symptoms
- **Font size regression (P0):** Selectbox dropdown text renders at the browser default (~14px / 0.875rem). Custom HTML gate labels are at 0.72rem. The mismatch is immediately visible as an inconsistency and makes the AUDIT / ENFORCE / OFF values look like a different UI.
- **Structural clutter:** 13 gate rows are presented as a flat list with the same visual weight. Sliders and text inputs appear *between* gate rows rather than being visually attached to their parent gate, making the flow hard to follow.
- **Section headers not prominent enough:** `INPUT GATES` and `OUTPUT GATES` section dividers are thin (0.65rem, gray) and nearly invisible when the sidebar is scanned quickly.
- **Navigation links lack active-state styling:** "Chat Workbench" and "Agentic Security" links look identical whether active or not.
- **Demo Mode toggle placement:** Sitting between MODEL and CONTEXT without its own section header makes it easy to miss and contextually confusing.
- **No sticky summary:** When the user scrolls past the gate list, they lose visibility of what mode the top gates are in. There is no fixed-position gate-status summary.
- **Gate child controls not visually grouped:** The Token Limit slider and the Regex Hot-Patch text input float independently below their gate row. A user who scrolls past the header row has no visual cue that the slider belongs to "Token Limit".

#### Root causes in code
- `_gate_row()` returns a mode value, and the caller `if tok_mode != "OFF": st.slider(...)` renders the slider as a sibling element — no visual nesting.
- CSS injection targets `[data-baseweb="select"] span/div` but the BaseWeb value element is `[data-baseweb="single-value"]`, which was missed.
- Section headers use `border-top` for separation but no `background` differentiation.

---

### 2.2 Pipeline Status Banner (chat area, top)

#### Symptoms
- The banner renders **all active gates as inline `<span>` badges** in a single horizontal line. With 10+ active gates this wraps into 2–3 dense rows of tiny coloured pills that are unreadable at normal viewing distance (see image: "custom_regex: AUDIT ... token_limit: AUDIT ... invisible_text: ENFORCE...").
- The banner shows **gate configuration** (what mode each gate is *set to*), but visually resembles the gate **result** badges shown below each assistant message. A learner cannot tell the difference at a glance.
- The left border (`#7AA2F7`) and the violation alert orange background are from entirely different visual vocabularies, yet they sit adjacent in the chat.

#### Root cause
- `gate_badges` is built with a `" ".join(...)` of `<span>` elements — no max-width or collapse logic. All active gates are enumerated regardless of count.

---

### 2.3 Chat Messages

#### Symptoms
- **User avatar colour is orange/reddish** (Streamlit's default avatar for "user" role in dark theme). Red is the established signal colour for BLOCK/danger in this UI. A user who sees a red bubble next to their message may momentarily assume a gate fired.
- **Gate metric badges below assistant messages** use the same visual language as the pipeline status banner (coloured pills), creating confusion between *what mode a gate is in* vs *what verdict it produced*.
- **Violation alert box** uses `st.error()` (Streamlit's built-in red box). The icon and background colour are styled for a generic Streamlit error, not for the workbench's security-specific colour system. The message text is long and wraps awkwardly within the red box.
- **"⚡ 11 prompt · 24 completion · 85.4 t/s" caption** is valuable but visually disconnected from the gate badges above it and the API Inspector below it. It appears to float.

---

### 2.4 Right Panel — Live Telemetry

#### Symptoms
- **Ten sections with no hierarchy.** THREAT LEVEL, GATE LATENCY, SECURITY SIGNALS, PIPELINE, SESSION STATS, TOKENS, OLLAMA TIMING, CONTEXT TREND, MODEL INFO, MEMORY are all shown sequentially with minimal visual separation. This is a reference panel, not a narrative, so the user's eye has no anchor.
- **GATE LATENCY table truncates gate names** to ~8 characters (the column is too narrow). "injection_" and "malicious_" become unidentifiable.
- **SECURITY SIGNALS and GATE LATENCY repeat gate names.** The user sees the same list of gates twice in close proximity with slightly different data (ms vs score). The relationship between the two views is not explained.
- **THREAT LEVEL gauge** is the most visually prominent element — a full-width red bar — but the score it represents (max gate score) is not labeled clearly enough for a learner to understand what "68%" means.
- **Right panel is 1/4 of the screen width** in a `[3, 1]` column split. On a 1440px display this is ~360px, which is too narrow for the density of content.

---

### 2.5 API Inspector

#### Symptoms
- **Collapsed by default** with label "API Inspector — see gate tracks." The phrase "gate tracks" is developer jargon. Learners will not know what to expect inside.
- **Tab labels are now emoji-prefixed** (🟢 PII Scanner, 🔴 Bias / Toxicity) which is good, but the tab row is cramped and the emojis are small.
- **Export buttons** (JSON / MD) are now in the header — good placement — but the exported content structure (especially the MD format) needs verification that it reads naturally as a learning artifact.

---

### 2.6 Typography and Colour Inconsistency (Cross-cutting)

#### Token scale gaps
| Context | Current size | Status |
|---------|-------------|--------|
| Section headers | 0.65rem | OK (intentionally small, uppercase) |
| Gate labels | 0.72rem | OK |
| Selectbox values | ~0.875rem (browser default) | **Bug — too large** |
| Alert text | 0.82rem | OK |
| Caption (t/s line) | Streamlit default caption | Slightly large |
| Right panel labels | 0.72rem custom HTML | OK |
| Navigation links | Streamlit default | Too large |

There is no single declared `--font-sm` token — sizes are hardcoded in multiple places.

#### Colour signal collisions
| Element | Colour used | Intended meaning | Conflict |
|---------|-------------|-----------------|----------|
| User chat avatar | Orange-red (Streamlit default) | Identity | Collides with BLOCK red |
| AUDIT mode badge | Amber `#E0AF68` | "monitoring" | Amber also used for ERROR — ambiguous |
| Violation `st.error()` | Streamlit red | Gate block | Same red as BLOCK but from a different palette |
| ENFORCE mode | `#F7768E` (pink-red) | Blocking mode | Different red from `st.error()` red |
| Blue left-border banner | `#7AA2F7` | Informational | Blue is also the title accent |

---

## 3. Improvement Proposals

### 3.1 Design Token Consolidation (foundational)

Define and use a single set of CSS variables that every custom HTML element references. This eliminates the current situation where the same intent is expressed with 3 different hex values across 2 files.

```css
:root {
  /* Semantic colours */
  --c-pass:    #9ECE6A;   /* gate pass, safe */
  --c-block:   #F7768E;   /* gate block, danger */
  --c-audit:   #E0AF68;   /* monitor/audit mode */
  --c-error:   #FF9E64;   /* system error (distinct from block) */
  --c-skip:    #555566;   /* gate skipped / OFF */
  --c-info:    #7AA2F7;   /* informational accent, headings */
  --c-purple:  #BB9AF7;   /* secondary accent */

  /* Backgrounds */
  --bg-base:   #1e1e2e;   /* main page */
  --bg-surface:#262730;   /* cards, banners */
  --bg-sidebar:#1a1a2e;   /* sidebar */
  --bg-raise:  #2e2e3e;   /* elevated surfaces */

  /* Typography */
  --font-xs:   0.65rem;   /* section headers */
  --font-sm:   0.72rem;   /* all sidebar controls, gate labels, telemetry values */
  --font-md:   0.82rem;   /* alert text, captions */
  --font-base: 0.875rem;  /* body (should match this globally) */

  /* Spacing */
  --gap-xs: 2px;
  --gap-sm: 4px;
  --gap-md: 8px;
  --gap-lg: 16px;
}
```

**Implementation:** Inject these once in the page `<head>` via `st.markdown(..., unsafe_allow_html=True)` before any column is created. All custom HTML throughout `chat_view.py` and `metrics_panel.py` should reference `var(--c-pass)` etc. rather than hardcoded hex values.

---

### 3.2 Left Sidebar

#### 3.2.1 Fix selectbox font size (P0 — ongoing bug)

The correct selectors for the BaseWeb Select component are:

```css
section[data-testid="stSidebar"] [data-baseweb="single-value"],
section[data-testid="stSidebar"] [data-baseweb="placeholder"],
section[data-testid="stSidebar"] [data-baseweb="select"] * {
    font-size: var(--font-sm) !important;
    line-height: 1.3 !important;
}
```

Adding `[data-baseweb="select"] *` (universal child selector) ensures every element type inside the control is covered regardless of which HTML tag BaseWeb chooses.

#### 3.2.2 Visually attach child controls to their parent gate

Wrap the gate row and its optional child (slider / text input) in a single `<div>` with a subtle left-border accent matching the gate's mode colour:

```
┌─────────────────────────────────────┐
│ ● Token Limit              [ENFORCE]│  ← gate row (_gate_row)
│   ───────────────────────────── 512 │  ← slider (indented, attached)
└─────────────────────────────────────┘
```

In code: render the child inside a `st.container()` with injected CSS `margin-left: 8px; border-left: 2px solid {mode_color}; padding-left: 6px;`.

#### 3.2.3 Promote section headers

Increase `INPUT GATES` and `OUTPUT GATES` to a more prominent style:
- Background: `var(--bg-raise)` strip across the full sidebar width
- Text: 0.68rem, uppercase, `letter-spacing: 0.12em`, white (not gray)
- Remove the `border-top` in favour of `background` + `padding`

This creates a scannable visual anchor even when the user has scrolled past the gate list.

#### 3.2.4 Gate group collapsibility

Wrap INPUT GATES rows and OUTPUT GATES rows each in `st.expander(expanded=True)`. The user can collapse an entire gate group when focusing on the other. Keep the section header as the expander label.

#### 3.2.5 Navigation active state

Add a `background: var(--bg-raise); border-radius: 4px;` highlight to the active nav link. This can be done by injecting CSS that targets the active `st.page_link` element.

#### 3.2.6 Demo Mode placement

Move the Demo Mode toggle to the very bottom of the sidebar under a `SESSION` section (where "Clear Chat History" already lives). It is a mode switch, not a model setting.

---

### 3.3 Pipeline Status Banner

Replace the all-gates badge flood with a **3-number summary + on-demand detail**:

```
🔒 Pipeline active   AUDIT: 9   ENFORCE: 2   OFF: 1   [details ▾]
```

- The three counts are coloured (amber / pink / gray) matching mode colours.
- Clicking `[details ▾]` expands a compact table showing individual gates — same visual as the API Inspector tabs, not a badge flood.
- This teaches the user the *distribution* of gate posture at a glance, without requiring them to read 12 badge labels.

For the all-OFF case, keep the existing dimmed banner — it is the right UX.

---

### 3.4 Chat Messages

#### 3.4.1 Gate metric badges — differentiate from mode badges

Current: both mode badges (pipeline banner) and result badges (post-message) use coloured pill shapes with text.

Proposal: result badges use a **circle dot + gate name + score** format, not a pill:

```
🟢 Regex  🔴 Bias 0.46  🟡 PII  ⚫ Invis
```

The score is shown only when non-zero, surfacing exactly why a gate fired without visual noise. Clicking a badge scrolls to or expands the relevant API Inspector tab.

#### 3.4.2 Violation alert — replace `st.error()` with custom callout

`st.error()` uses Streamlit's generic error box which is stylistically disconnected from the dark workbench theme. Replace with a custom HTML callout block:

```
┌─  🔴 Gate violation: Bias / Toxicity (score: 0.46)  ─────────────────┐
│  Biased content detected in the model response. The response is shown  │
│  as-is. Switch the gate to ENFORCE to suppress future violations.      │
└───────────────────────────────────────────────────────────────────────┘
```

Styled: `background: rgba(247, 118, 142, 0.08); border-left: 3px solid var(--c-block); border-radius: 4px; padding: 8px 12px;`

This keeps the red signal without the jarring Streamlit default box.

#### 3.4.3 Token stat line — anchor it visually

Wrap the `⚡ N prompt · N completion · N t/s` caption in the same surface card (`var(--bg-surface)`) as the gate metric badges. They belong to the same assistant turn — they should look like one block.

---

### 3.5 Right Panel — Live Telemetry

#### 3.5.1 Collapse secondary sections by default

Show only the three most valuable sections expanded on load:
1. **THREAT LEVEL** — always visible (one-line gauge)
2. **GATE LATENCY** — the table learners use to understand which gate costs how much
3. **SESSION STATS** — cumulative counts

Collapse: SECURITY SIGNALS, PIPELINE, TOKENS, OLLAMA TIMING, CONTEXT TREND, MODEL INFO, MEMORY.

Add a "Expand all" toggle at the top of the panel.

#### 3.5.2 Fix GATE LATENCY truncation

The gate name column is too narrow. Options:
- Increase column ratio from `[3, 2]` (name:value) to `[4, 2]`
- Or: use abbreviated canonical names that are always ≤ 12 chars (e.g. "Injection" not "injection_detect_gate")
- Show the full name in a `title` tooltip on hover

#### 3.5.3 Merge GATE LATENCY and SECURITY SIGNALS

These two sections describe the same 10 gates with different metrics. Merge them into a single **GATE RESULTS** table with columns: `Gate | Mode | Score | Verdict | ms`.

```
Gate            Mode     Score  Verdict   ms
──────────────  ───────  ─────  ────────  ─────
Regex           AUDIT    0.00   PASS       0.3
Token Limit     ENFORCE  —      PASS      <1
Invisible Text  ENFORCE  —      PASS      <1
PII Scanner     AUDIT    0.12   PASS     124
Injection       AUDIT    0.31   AUDIT    124
Toxicity (in)   AUDIT    0.08   PASS      44
Bias/Toxicity   AUDIT    0.46   AUDIT    178  ← flagged row in amber
Malicious URL   ENFORCE  0.00   PASS      47
```

This is the single table a learner needs to understand the full pipeline for any given turn. Colour the Verdict cell, not the whole row.

#### 3.5.4 THREAT LEVEL — add context

The gauge is `68%` but a learner does not know what `68%` means. Add a one-line explanation:

> `Threat: 68% — driven by Bias/Toxicity (0.46) + Injection (0.31)`

This directly connects the gauge to the contributing gates, teaching the composite logic.

#### 3.5.5 Widen the right panel split

Change `st.columns([3, 1], gap="medium")` to `st.columns([5, 2], gap="medium")` to give the telemetry panel more breathing room. On narrow displays (< 1200px) consider hiding the panel behind a `st.expander` in the chat column instead.

---

### 3.6 API Inspector

#### 3.6.1 Rename and repromote

Rename "API Inspector — see gate tracks" to **"Gate Trace"** or **"Pipeline Trace"**.  
Change default to `expanded=True` for the most recent message only (previous messages collapsed).

#### 3.6.2 Tab label improvements

Current tabs: `🟢 PII Scanner`, `🔴 Bias / Toxicity`  
Proposed: `🟢 PII · 0ms · 0.12`, `🔴 Bias · 178ms · 0.46`

Score and latency in the tab label allow the user to see at a glance which gate is interesting without expanding its content.

---

### 3.7 Colour System Clean-up

| Element | Current | Proposed |
|---------|---------|----------|
| User chat avatar | Orange-red (Streamlit default) | Neutral blue `#7AA2F7` via `st.chat_message` avatar CSS override |
| AUDIT mode badge | Amber `#E0AF68` | Amber `#E0AF68` — keep, but label as "MONITOR" in UI text for clarity |
| ERROR (system) | Amber `#E0AF68` (same as AUDIT) | Orange `#FF9E64` — distinct from AUDIT |
| Violation callout | `st.error()` red box | Custom callout: `rgba(247,118,142,0.08)` background + red left border |
| ENFORCE mode | Pink-red `#F7768E` | Keep — matches BLOCK colour (mode → likely to block) |

---

## 4. Implementation Phases

### Phase UI-1 — Fix P0 defects (1–2 sessions)

| # | Task | Files |
|---|------|-------|
| 1 | Fix selectbox font via `[data-baseweb="single-value"]` universal selector | `ui/chat_view.py` |
| 2 | Inject CSS design tokens (`--c-pass`, `--font-sm`, etc.) as `:root` block | `ui/chat_view.py` |
| 3 | Differentiate ERROR colour from AUDIT colour in `_VERDICT_COLORS` | `ui/metrics_panel.py` |
| 4 | Replace `st.error()` violation boxes with custom callout HTML | `ui/chat_view.py` |

### Phase UI-2 — Sidebar restructure (1 session)

| # | Task | Files |
|---|------|-------|
| 5 | Promote section headers (background strip, white text) | `ui/chat_view.py` |
| 6 | Wrap gate + child control in a visually attached container | `ui/chat_view.py` |
| 7 | Wrap INPUT / OUTPUT gate groups in `st.expander` | `ui/chat_view.py` |
| 8 | Move Demo Mode toggle to SESSION section | `ui/chat_view.py` |
| 9 | Add active-state CSS for navigation links | `ui/chat_view.py` |

### Phase UI-3 — Pipeline banner and gate badges (1 session)

| # | Task | Files |
|---|------|-------|
| 10 | Replace badge flood with 3-number summary + expandable detail | `ui/chat_view.py` |
| 11 | Redesign post-message gate result badges (dot + name + score) | `ui/chat_view.py` |
| 12 | Anchor token stat line in same surface as gate badges | `ui/chat_view.py` |

### Phase UI-4 — Right panel consolidation (1–2 sessions)

| # | Task | Files |
|---|------|-------|
| 13 | Merge GATE LATENCY + SECURITY SIGNALS into single GATE RESULTS table | `ui/metrics_panel.py` |
| 14 | Add composite threat explanation line below THREAT LEVEL gauge | `ui/metrics_panel.py` |
| 15 | Collapse secondary sections by default; add "Expand all" | `ui/metrics_panel.py` |
| 16 | Widen panel split to `[5, 2]` | `ui/chat_view.py` |

### Phase UI-5 — API Inspector polish (0.5 session)

| # | Task | Files |
|---|------|-------|
| 17 | Rename to "Pipeline Trace"; show score + latency in tab labels | `ui/metrics_panel.py` |
| 18 | Expand most-recent message by default, collapse prior | `ui/chat_view.py` |

---

## 5. What NOT to Change

- The 3-zone layout (sidebar / chat / telemetry) is fundamentally correct for a teaching tool. Do not collapse it into tabs or a single-column view.
- Gate logic, modes (OFF / AUDIT / ENFORCE), and the pipeline architecture — these are the pedagogical core. UI changes should illuminate them, not abstract them away.
- The compact `_gate_row()` pattern (label + selectbox in one row) is the right approach — fix the font size, not the pattern.
- The existing colour palette (TokyoNight-derived) is coherent for a dark security tool. Extend it, don't replace it.

---

## 6. Non-Goals

- Mobile / responsive layout — this is a desktop-only garage tool.
- Theming / light mode — dark is the deliberate choice for a security workbench.
- Accessibility (WCAG) full compliance — nice-to-have but not a priority for a single-user lab tool.
- Animations or transition effects — add latency and distraction in a tool where latency numbers are a key learning signal.

---

*Last updated: 2026-04-11*  
*Author: packetcraft*
