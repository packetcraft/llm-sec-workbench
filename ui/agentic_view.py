"""
ui/agentic_view.py
──────────────────
Streamlit view for the Agentic Security Monitor.

Public entry point
------------------
render(config)   Called by app.py when the user navigates to Agentic Security.

Three tabs
----------
Live Feed      — auto-refreshing table of the most recent 50 hook events.
Audit Explorer — filterable, searchable historical view with per-row detail panels.
Dashboard      — aggregate statistics and trend charts across all sessions.

Data source
-----------
Reads per-session JSONL files from audit_path (configured in config.yaml under
agentic.audit_path). The loader globs all *.jsonl files, parses them, and
separates SESSION_START records from TOOL_CALL records.

Full specification: docs/agentic/ARCHITECTURE.md §6
"""

from __future__ import annotations

import glob
import json
from pathlib import Path

import pandas as pd
import streamlit as st

# ── Verdict styling ───────────────────────────────────────────────────────────

_VERDICT_COLOUR = {
    "ALLOW":       "#9ECE6A",   # green
    "ALLOWLISTED": "#7AA2F7",   # blue
    "BLOCK":       "#F7768E",   # red
    "ERROR":       "#E0AF68",   # amber
}

_VERDICT_ICON = {
    "ALLOW":       "ALLOW",
    "ALLOWLISTED": "SKIP",
    "BLOCK":       "BLOCK",
    "ERROR":       "ERROR",
}

_METHOD_COLOUR = {
    "LLM":       "#BB9AF7",   # purple
    "REGEX":     "#FF9E64",   # orange
    "ALLOWLIST": "#7AA2F7",   # blue
    "PATH":      "#2AC3DE",   # teal
}


def _badge(verdict: str) -> str:
    colour = _VERDICT_COLOUR.get(verdict, "#888888")
    label  = _VERDICT_ICON.get(verdict, verdict)
    return f'<span style="background:{colour};color:#1a1b26;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:700;">{label}</span>'


def _method_badge(method: str) -> str:
    colour = _METHOD_COLOUR.get(method, "#888888")
    return f'<span style="background:{colour};color:#1a1b26;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:700;">{method}</span>'


# ── Data loading ──────────────────────────────────────────────────────────────

def _load_audit(audit_path: str) -> tuple[pd.DataFrame, dict]:
    """Glob all session JSONL files and return (records_df, sessions_dict).

    records_df  — all TOOL_CALL records, sorted ascending by timestamp.
    sessions    — dict[session_id → SESSION_START record dict].
    """
    pattern = str(Path(audit_path) / "*.jsonl")
    all_records: list[dict] = []
    sessions:    dict[str, dict] = {}

    for fpath in glob.glob(pattern):
        try:
            with open(fpath, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if rec.get("event_type") == "SESSION_START":
                        sessions[rec["session_id"]] = rec
                    elif rec.get("event_type") == "TOOL_CALL":
                        all_records.append(rec)
        except OSError:
            continue

    if not all_records:
        return pd.DataFrame(), sessions

    df = pd.DataFrame(all_records)
    import datetime as _dt
    _local_tz = _dt.datetime.now().astimezone().tzinfo
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce").dt.tz_convert(_local_tz)

    # Ensure Agent column is consistent across all tabs.
    # Use "unknown" not "Claude" — misattributing a Gemini event as Claude
    # would corrupt the agent breakdown charts and filter.
    if "agent" not in df.columns:
        df["agent"] = "unknown"
    else:
        df["agent"] = df["agent"].fillna("unknown")

    df = df.sort_values("timestamp").reset_index(drop=True)
    return df, sessions


def _short_session(session_id: str) -> str:
    """Return the first 8 characters of a session ID for display."""
    return session_id[:8] if session_id else "—"


def _tool_input_preview(row: pd.Series) -> str:
    """Return a short, readable preview of tool_input for table display."""
    ti = row.get("tool_input") or {}
    if isinstance(ti, str):
        return ti[:80]
    cmd = ti.get("command") or ti.get("url") or ti.get("file_path") or ""
    return str(cmd)[:80]


# ── Coverage matrix (static) ─────────────────────────────────────────────────

_COVERAGE_ROWS = [
    ("Bash",        "PreToolUse + PostToolUse", "Yes",     "Primary risk surface"),
    ("Edit",        "PreToolUse",               "Yes",     "File modification"),
    ("Write",       "PreToolUse",               "Yes",     "File creation / overwrite"),
    ("WebFetch",    "PreToolUse",               "Yes",     "Network egress, indirect injection"),
    ("Read",        "—",                        "No",      "Read-only, no state change"),
    ("Glob",        "—",                        "No",      "Read-only filesystem search"),
    ("Grep",        "—",                        "No",      "Read-only content search"),
    ("WebSearch",   "—",                        "No",      "No side effects"),
    ("Agent",       "—",                        "Partial", "Worktree isolation may break inheritance"),
    ("mcp__*",      "PreToolUse",               "Yes",     "Full tool_input JSON sent to guard model"),
    ("NotebookEdit","—",                        "No",      "Out of scope"),
]

# ── Tab: Live Feed ────────────────────────────────────────────────────────────

def _render_live_feed(audit_path: str) -> None:
    st.caption("Auto-refreshes every 10 seconds. Shows the 50 most recent hook events across all sessions.")

    @st.fragment(run_every=10)
    def _feed() -> None:
        df, sessions = _load_audit(audit_path)

        if df.empty:
            st.info("No audit records found yet. Start a Claude Code or Gemini CLI session with hooks enabled.")
            return

        recent = df.tail(50).iloc[::-1].reset_index(drop=True)

        col_ts, col_agent, col_sess, col_tool, col_verdict, col_method, col_preview = st.columns([2, 1, 1, 1, 1, 1, 4])
        col_ts.markdown("**Timestamp**")
        col_agent.markdown("**Agent**")
        col_sess.markdown("**Session**")
        col_tool.markdown("**Tool**")
        col_verdict.markdown("**Verdict**")
        col_method.markdown("**Method**")
        col_preview.markdown("**Command / Input preview**")
        st.divider()

        for _, row in recent.iterrows():
            ts      = row["timestamp"].strftime("%H:%M:%S") if pd.notnull(row["timestamp"]) else "—"
            agent   = str(row.get("agent", "Claude"))
            sess    = _short_session(str(row.get("session_id", "")))
            tool    = str(row.get("tool_name", ""))
            verdict = str(row.get("verdict", ""))
            method  = str(row.get("inspection_method", "—")) if row.get("inspection_method") else "—"
            preview = _tool_input_preview(row)

            c1, c2, c3, c4, c5, c6, c7 = st.columns([2, 1, 1, 1, 1, 1, 4])
            c1.text(ts)
            c2.text(agent)
            c3.text(sess)
            c4.text(tool)
            c5.markdown(_badge(verdict), unsafe_allow_html=True)
            c6.markdown(_method_badge(method) if method != "—" else "—", unsafe_allow_html=True)
            c7.text(preview)

    _feed()


# ── Tab: Audit Explorer ───────────────────────────────────────────────────────

def _render_audit_explorer(audit_path: str) -> None:
    df, sessions = _load_audit(audit_path)

    if df.empty:
        st.info("No audit records found yet. Start a Claude Code session with hooks enabled.")
        return

    # ── Sidebar filters ───────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("### Audit Filters")

        # Date range
        min_date = df["timestamp"].min().date()
        max_date = df["timestamp"].max().date()
        date_range = st.date_input(
            "Date range",
            value=(min_date, max_date),
            min_value=min_date,
            max_value=max_date,
            key="ae_date_range",
        )

        # Agent selector
        agents = sorted(df["agent"].fillna("Claude").unique().tolist()) if "agent" in df.columns else ["Claude"]
        selected_agents = st.multiselect(
            "Agents",
            options=agents,
            default=[],
            key="ae_agents",
            placeholder="All agents",
        )

        # Session selector
        session_ids = sorted(df["session_id"].dropna().unique().tolist())
        session_labels = {sid: f"{_short_session(sid)} — {sessions.get(sid, {}).get('git_branch', '?')}" for sid in session_ids}
        selected_sessions = st.multiselect(
            "Sessions",
            options=session_ids,
            format_func=lambda x: session_labels.get(x, x),
            default=[],
            key="ae_sessions",
            placeholder="All sessions",
        )

        # Tool type
        tools = sorted(df["tool_name"].dropna().unique().tolist())
        selected_tools = st.multiselect(
            "Tool type",
            options=tools,
            default=[],
            key="ae_tools",
            placeholder="All tools",
        )

        # Verdict
        verdicts = sorted(df["verdict"].dropna().unique().tolist())
        selected_verdicts = st.multiselect(
            "Verdict",
            options=verdicts,
            default=[],
            key="ae_verdicts",
            placeholder="All verdicts",
        )

        # Inspection method
        methods = sorted(df["inspection_method"].dropna().unique().tolist()) if "inspection_method" in df.columns else []
        selected_methods = st.multiselect(
            "Inspection Method",
            options=methods,
            default=[],
            key="ae_methods",
            placeholder="All methods",
        )

        # Keyword search
        keyword = st.text_input("Search tool input", key="ae_keyword", placeholder="e.g. rm -rf, curl, .env")

        st.divider()

    # ── Apply filters ─────────────────────────────────────────────────────────
    filtered = df.copy()

    if isinstance(date_range, (list, tuple)) and len(date_range) == 2:
        start, end = pd.Timestamp(date_range[0], tz="UTC"), pd.Timestamp(date_range[1], tz="UTC") + pd.Timedelta(days=1)
        filtered = filtered[(filtered["timestamp"] >= start) & (filtered["timestamp"] < end)]

    if selected_agents:
        filtered = filtered[filtered["agent"].isin(selected_agents)]

    if selected_sessions:
        filtered = filtered[filtered["session_id"].isin(selected_sessions)]

    if selected_tools:
        filtered = filtered[filtered["tool_name"].isin(selected_tools)]

    if selected_verdicts:
        filtered = filtered[filtered["verdict"].isin(selected_verdicts)]

    if selected_methods and "inspection_method" in filtered.columns:
        filtered = filtered[filtered["inspection_method"].isin(selected_methods)]

    if keyword:
        mask = filtered["tool_input"].astype(str).str.contains(keyword, case=False, na=False)
        filtered = filtered[mask]

    # ── Session metadata banner ───────────────────────────────────────────────
    if len(selected_sessions) == 1:
        sid  = selected_sessions[0]
        meta = sessions.get(sid, {})
        with st.container(border=True):
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Session", _short_session(sid))
            m2.metric("Branch", meta.get("git_branch") or "—")
            m3.metric("Commit", meta.get("git_commit") or "—")
            m4.metric("Guard model", meta.get("hook_model") or "—")
            st.caption(f"cwd: `{meta.get('cwd', '—')}`  •  started: {meta.get('timestamp', '—')}")

    # ── Results summary ───────────────────────────────────────────────────────
    st.markdown(f"**{len(filtered):,} events** match current filters")

    if filtered.empty:
        st.warning("No events match the current filters.")
        return

    # ── Paginated event table (newest first) ──────────────────────────────────
    PAGE_SIZE = 25
    filtered_desc = filtered.iloc[::-1].reset_index(drop=True)
    total_pages = max(1, (len(filtered_desc) - 1) // PAGE_SIZE + 1)
    page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="ae_page")
    page_df = filtered_desc.iloc[(page - 1) * PAGE_SIZE : page * PAGE_SIZE].reset_index(drop=True)

    # Header row
    h1, h2, h3, h4, h5, h6, h7, h8 = st.columns([2, 1, 1, 1, 1, 1, 1, 3])
    for col, label in zip([h1, h2, h3, h4, h5, h6, h7, h8], ["Timestamp", "Agent", "Session", "Hook", "Tool", "Verdict", "Method", "Input preview"]):
        col.markdown(f"**{label}**")
    st.divider()

    for i, (_, row) in enumerate(page_df.iterrows()):
        ts      = row["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if pd.notnull(row["timestamp"]) else "—"
        agent   = str(row.get("agent", "Claude"))
        sess    = _short_session(str(row.get("session_id", "")))
        hook_ev = str(row.get("hook_event", "Pre"))[:3]
        tool    = str(row.get("tool_name", ""))
        verdict = str(row.get("verdict", ""))
        method  = str(row.get("inspection_method", "")) if row.get("inspection_method") else "—"
        preview = _tool_input_preview(row)

        c1, c2, c3, c4, c5, c6, c7, c8 = st.columns([2, 1, 1, 1, 1, 1, 1, 3])
        c1.text(ts)
        c2.text(agent)
        c3.text(sess)
        c4.text(hook_ev)
        c5.text(tool)
        c6.markdown(_badge(verdict), unsafe_allow_html=True)
        c7.markdown(_method_badge(method) if method != "—" else "—", unsafe_allow_html=True)
        c8.text(preview)

        # ── Expandable detail panel ───────────────────────────────────────────
        with st.expander(f"Details — row {(page - 1) * PAGE_SIZE + i + 1}"):
            d1, d2 = st.columns(2)
            with d1:
                st.markdown("**Tool input (redacted)**")
                st.json(row.get("tool_input") or {})
                st.markdown(f"**Redactions applied:** `{row.get('redactions_applied', 0)}`")
            with d2:
                st.markdown("**Guard model verdict**")
                st.markdown(_badge(verdict), unsafe_allow_html=True)
                st.markdown(
                    f"**Inspection Method:** {_method_badge(method) if method != '—' else '`—`'}",
                    unsafe_allow_html=True,
                )
                if row.get("block_reason"):
                    st.error(f"Block reason: {row['block_reason']}")
                if row.get("guard_raw_output"):
                    st.code(row["guard_raw_output"], language=None)
                st.markdown(f"**Model:** `{row.get('guard_model') or '—'}`")
                st.markdown(f"**Latency:** `{row.get('latency_ms', 0)} ms`")


# ── Tab: Dashboard ────────────────────────────────────────────────────────────

def _render_dashboard(audit_path: str) -> None:
    df, sessions = _load_audit(audit_path)

    # ── Coverage indicator (always visible even when no data) ─────────────────
    with st.sidebar:
        with st.expander("Hook coverage", expanded=False):
            cov_df = pd.DataFrame(
                _COVERAGE_ROWS,
                columns=["Tool", "Hook type", "Covered", "Notes"],
            )
            st.dataframe(
                cov_df,
                width="stretch",
                hide_index=True,
                column_config={
                    "Covered": st.column_config.TextColumn(width="small"),
                },
            )
            st.caption("MCP tools and subagent worktrees are not covered in Phase 1.")

    if df.empty:
        st.info("No audit records yet. Start a Claude Code session with hooks configured.")
        return

    # ── Top-level KPIs ────────────────────────────────────────────────────────
    total       = len(df)
    blocks      = (df["verdict"] == "BLOCK").sum()
    errors      = (df["verdict"] == "ERROR").sum()
    block_rate  = blocks / total * 100 if total else 0
    session_cnt = df["session_id"].nunique()
    agent_cnt   = df["agent"].nunique() if "agent" in df.columns else 1
    avg_latency = df.loc[df["verdict"].isin(["ALLOW", "BLOCK"]), "latency_ms"].mean()

    k1, k2, k3, k4, k5, k6 = st.columns(6)
    k1.metric("Total events",   f"{total:,}")
    k2.metric("Sessions",       f"{session_cnt:,}")
    k3.metric("Agents",         f"{agent_cnt:,}")
    k4.metric("Blocks",         f"{blocks:,}")
    k5.metric("Block rate",     f"{block_rate:.1f}%")
    k6.metric("Avg guard latency", f"{avg_latency:.0f} ms" if not pd.isna(avg_latency) else "—")

    st.divider()

    col_left, col_mid, col_right = st.columns(3)

    # ── Events by Agent ───────────────────────────────────────────────────────
    with col_left:
        st.markdown("**Events by Agent**")
        agent_counts = df["agent"].fillna("Claude").value_counts().reset_index()
        agent_counts.columns = ["Agent", "Count"]
        st.bar_chart(agent_counts.set_index("Agent"), width="stretch")

    # ── Block rate over time (by day) ─────────────────────────────────────────
    with col_mid:
        st.markdown("**Block rate over time (daily)**")
        daily = df.copy()
        daily["date"] = daily["timestamp"].dt.date
        by_day = daily.groupby("date").apply(
            lambda g: pd.Series({
                "total":  len(g),
                "blocks": (g["verdict"] == "BLOCK").sum(),
            })
        ).reset_index()
        by_day["block_rate_%"] = (by_day["blocks"] / by_day["total"] * 100).round(1)
        st.line_chart(by_day.set_index("date")["block_rate_%"], width="stretch")

    # ── Verdict distribution ──────────────────────────────────────────────────
    with col_right:
        st.markdown("**Verdict distribution**")
        verdict_counts = df["verdict"].value_counts().reset_index()
        verdict_counts.columns = ["Verdict", "Count"]
        st.bar_chart(verdict_counts.set_index("Verdict"), width="stretch")

    col_left2, col_mid2, col_right2 = st.columns(3)

    # ── Inspection Method distribution ───────────────────────────────────────
    with col_left2:
        st.markdown("**Inspection method distribution**")
        if "inspection_method" in df.columns:
            method_counts = df["inspection_method"].fillna("unknown").value_counts().reset_index()
            method_counts.columns = ["Method", "Count"]
            st.bar_chart(method_counts.set_index("Method"), width="stretch")
        else:
            st.caption("No inspection_method data yet.")

    # ── Tool type breakdown ───────────────────────────────────────────────────
    with col_mid2:
        st.markdown("**Events by tool type**")
        tool_counts = df["tool_name"].value_counts().reset_index()
        tool_counts.columns = ["Tool", "Count"]
        st.bar_chart(tool_counts.set_index("Tool"), width="stretch")

    # ── Top blocked inputs ────────────────────────────────────────────────────
    with col_right2:
        st.markdown("**Top 10 blocked inputs**")
        blocked_df = df[df["verdict"] == "BLOCK"].copy()
        if blocked_df.empty:
            st.success("No blocks recorded yet.")
        else:
            blocked_df["preview"] = blocked_df.apply(_tool_input_preview, axis=1)
            top_blocked = blocked_df["preview"].value_counts().head(10).reset_index()
            top_blocked.columns = ["Input preview", "Count"]
            st.dataframe(top_blocked, width="stretch", hide_index=True)

    # ── Hook latency histogram ────────────────────────────────────────────────
    st.markdown("**Guard model latency distribution (ALLOW + BLOCK calls only)**")
    latency_df = df[df["verdict"].isin(["ALLOW", "BLOCK"]) & df["latency_ms"].notna()]
    if latency_df.empty:
        st.caption("No latency data yet.")
    else:
        p50 = latency_df["latency_ms"].quantile(0.50)
        p95 = latency_df["latency_ms"].quantile(0.95)
        p99 = latency_df["latency_ms"].quantile(0.99)
        lc1, lc2, lc3 = st.columns(3)
        lc1.metric("P50 latency", f"{p50:.0f} ms")
        lc2.metric("P95 latency", f"{p95:.0f} ms")
        lc3.metric("P99 latency", f"{p99:.0f} ms")
        st.bar_chart(
            latency_df["latency_ms"].value_counts().sort_index(),
            width="stretch",
        )

    # ── Session timeline ──────────────────────────────────────────────────────
    st.markdown("**Session summary**")
    if sessions:
        sess_rows = []
        for sid, meta in sessions.items():
            sess_df = df[df["session_id"] == sid]
            sess_rows.append({
                "Session":    _short_session(sid),
                "Branch":     meta.get("git_branch") or "—",
                "Commit":     meta.get("git_commit") or "—",
                "Events":     len(sess_df),
                "Blocks":     int((sess_df["verdict"] == "BLOCK").sum()),
                "Errors":     int((sess_df["verdict"] == "ERROR").sum()),
                "Started":    meta.get("timestamp", "—"),
                "Guard model": meta.get("hook_model") or "—",
            })
        st.dataframe(
            pd.DataFrame(sess_rows),
            width="stretch",
            hide_index=True,
        )


# ── Tab: How It Works ─────────────────────────────────────────────────────────

def _render_how_it_works() -> None:
    st.markdown("### Architecture Overview")
    st.info(
        "The Agentic Security Monitor is a real-time middleware layer that intercepts "
        "AI tool calls from **Claude Code** and **Gemini CLI**. It applies a "
        "**Hybrid Funnel** — cheap deterministic checks first, expensive LLM last — "
        "to reach a verdict with sub-500ms latency."
    )


    # LR layout keeps the funnel horizontal and fits within a fixed-height iframe.
    # \\n is not reliable in all Mermaid versions — use plain labels.
    mermaid_code = """
    graph LR
        A([Claude / Gemini]) -->|Tool JSON| B(agentic_guard.py)
        B --> C{ALLOWLIST?}
        C -->|Bash read-only| AL([ALLOWLISTED - 0ms])
        C -->|no match| D{PATH?}
        D -->|protected file| PA([BLOCK - 0ms])
        D -->|safe| E{REGEX?}
        E -->|IPI signature| RE([BLOCK - 0ms])
        E -->|no match| F[Pre-process]
        F --> G{LLM}
        G -->|verdict| LV([ALLOW / BLOCK])
        AL --> H[(audit JSONL)]
        PA --> H
        RE --> H
        LV --> H
    """

    st.html(
        f"""
        <div class="mermaid" style="display:flex;justify-content:center;">
            {mermaid_code}
        </div>
        <script type="module">
            import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
            mermaid.initialize({{
                startOnLoad: true,
                theme: 'dark',
                flowchart: {{ useMaxWidth: true, htmlLabels: true, curve: 'basis' }}
            }});
        </script>
        """
    )

    # ── Guard pipelines ───────────────────────────────────────────────────────
    st.divider()
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 🛡️ Action Guard (Pre-Execution)")
        st.write(
            "Fires **before** a tool runs. Prevents side effects:"
            "\n- **Data Destruction**: `rm -rf`, `DROP TABLE`."
            "\n- **Exfiltration**: Piping files to `curl` or `nc`."
            "\n- **Tampering**: Modifying the security hook configuration."
        )
        st.caption("**Trigger**: `PreToolUse` (Claude) / `BeforeTool` (Gemini)")

    with col2:
        st.markdown("#### 🔍 Injection Guard (Post-Execution)")
        st.write(
            "Fires **after** a tool runs. Monitors incoming data quality:"
            "\n- **Indirect Prompt Injection**: Malicious instructions in fetched URLs."
            "\n- **Instruction Overrides**: 'Ignore all previous instructions'."
            "\n- **Role-playing / Jailbreaks**: 'Act as DAN'."
        )
        st.caption("**Trigger**: `PostToolUse` (Claude) / `AfterTool` (Gemini)")

    # ── Inspection methods ────────────────────────────────────────────────────
    st.divider()
    st.markdown("#### Inspection Methods")
    st.caption(
        "Every audit record carries an `inspection_method` field that identifies "
        "exactly which layer made the decision. Methods are evaluated in priority order."
    )

    m1, m2, m3, m4 = st.columns(4)

    with m1:
        st.markdown(_method_badge("ALLOWLIST"), unsafe_allow_html=True)
        st.markdown("**Allowlist**")
        st.write(
            "Matches read-only Bash commands against a built-in regex list "
            "(`git log/status/diff`, `ls`, `cat`, `pwd`, `echo`, version flags). "
            "Any command containing shell-composition characters "
            "(`|`, `>`, `;`, `&`, `$(`) is disqualified and falls through."
        )
        st.caption("Latency: **0 ms** · Verdict: ALLOWLISTED · Guard: none")

    with m2:
        st.markdown(_method_badge("PATH"), unsafe_allow_html=True)
        st.markdown("**Protected Path**")
        st.write(
            "Hard-blocks any `Write` or `Edit` targeting security-critical files "
            "regardless of content. Prevents an agent from disabling its own hooks."
            "\n\nProtected files:"
            "\n- `hooks/agentic_guard.py`"
            "\n- `.claude/settings.json`"
            "\n- `config.yaml`"
        )
        st.caption("Latency: **0 ms** · Verdict: BLOCK · Guard: none")

    with m3:
        st.markdown(_method_badge("REGEX"), unsafe_allow_html=True)
        st.markdown("**Regex Blocklist**")
        st.write(
            "Scans `PostToolUse` tool output for high-confidence prompt-injection "
            "signatures before the LLM is invoked. Patterns include:"
            "\n- `ignore (all) previous instructions`"
            "\n- `forget your training`"
            "\n- `new system prompt`"
            "\n- `act as DAN` / `developer mode`"
            "\n- `[SYSTEM INSTRUCTION]`"
        )
        st.caption("Latency: **0 ms** · Verdict: BLOCK · Guard: none")

    with m4:
        st.markdown(_method_badge("LLM"), unsafe_allow_html=True)
        st.markdown("**LLM Classification**")
        st.write(
            "All events that pass the fast-path checks are sent to a local Ollama "
            "guard model (`qwen2.5:1.5b` by default). Two specialized prompts are used:"
            "\n- **Action Guard**: evaluates the *intent* of a command."
            "\n- **Injection Guard**: evaluates the *content* of tool output."
            "\n\nPayloads are redacted, Base64-decoded, and truncated before submission."
        )
        st.caption("Latency: **< 500 ms** · Verdict: ALLOW / BLOCK / ERROR · Fail-open on timeout")

    # ── Pre-processing pipeline ───────────────────────────────────────────────
    st.divider()
    st.markdown("#### Pre-Processing Pipeline")
    st.caption("Applied to every payload before LLM classification.")

    p1, p2, p3 = st.columns(3)
    with p1:
        st.markdown("**Secret Redaction**")
        st.write(
            "API keys, GitHub PATs, AWS access keys, Bearer tokens, and PEM blocks "
            "are replaced with `[REDACTED:type]` tokens before the payload is "
            "sent to the LLM or written to the audit log."
        )
    with p2:
        st.markdown("**Base64 Decoding**")
        st.write(
            "Base64 blobs (≥ 16 chars) are detected and decoded. If the decoded "
            "content is printable ASCII, it is appended to the LLM prompt and "
            "recorded in `decoded_segments`. Catches encoded exfiltration payloads."
        )
    with p3:
        st.markdown("**Safety Slicing**")
        st.write(
            "Payloads larger than 4,000 characters are sliced: first 2,000 + last 2,000 "
            "characters separated by `...[TRUNCATED]...`. This keeps LLM latency low "
            "while preserving content at document boundaries where injections hide."
        )


# ── Public entry point ────────────────────────────────────────────────────────

def render(config: dict) -> None:
    """Main entry point called by app.py for the Agentic Security view."""
    agentic_cfg = config.get("agentic", {})
    audit_path  = str(agentic_cfg.get("audit_path", "./audit"))

    st.markdown("## Agentic Security Monitor")
    st.caption(
        "Inspect and audit Claude Code and Gemini CLI hook events. "
        "Records are written to `audit/{session_id}.jsonl` by `hooks/agentic_guard.py`. "
        "See [ARCHITECTURE.md](docs/agentic/ARCHITECTURE.md) for schema details."
    )

    tab_how, tab_feed, tab_explorer, tab_dashboard = st.tabs([
        "📖 How It Works", "Live Feed", "Audit Explorer", "Dashboard",
    ])

    with tab_how:
        _render_how_it_works()

    with tab_feed:
        _render_live_feed(audit_path)

    with tab_explorer:
        _render_audit_explorer(audit_path)

    with tab_dashboard:
        _render_dashboard(audit_path)
