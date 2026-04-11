"""
ui/metrics_panel.py
───────────────────
Phase 5 — Metrics & Telemetry Panel for the Chat Workbench.

Public entry points
-------------------
render_api_inspector(raw_traces, metrics)
    Tabbed expander showing the raw JSON request and response logged by each
    gate that ran.  Uses payload.raw_traces keyed by gate name.

render_context_bar(prompt_tokens, model_name, ollama_host)
    Thin progress bar showing how much of the model's context window the
    current turn consumed.  Context size is fetched from Ollama's /api/show
    endpoint and cached.

render_hw_telemetry(ollama_host)
    Live hardware panel that polls Ollama's /api/ps endpoint every 5 seconds
    and displays running models, VRAM usage, and token throughput.
    Uses @st.fragment(run_every=5) so only this component re-renders.

All functions are no-ops when Demo Mode is active or relevant data is absent,
so callers do not need to guard calls themselves.
"""

from __future__ import annotations

import json
import functools

import streamlit as st


# ── Context-window size cache ─────────────────────────────────────────────────

@functools.lru_cache(maxsize=8)
def _fetch_context_size(model_name: str, ollama_host: str) -> int:
    """Return the context window size for *model_name* in tokens.

    Queries ``ollama.show()``; falls back to 4096 on any error.
    Cached per (model_name, host) so repeated calls are free.
    """
    try:
        from ollama import Client
        client = Client(host=ollama_host)
        info = client.show(model_name)

        # The field lives in model_info under a variety of key names depending
        # on model family.  Check the most common ones in priority order.
        model_info = getattr(info, "model_info", None) or {}
        if isinstance(model_info, dict):
            for key in (
                "llama.context_length",
                "general.context_length",
                "context_length",
            ):
                if key in model_info:
                    return int(model_info[key])

        # Older Ollama versions surface it in model_info as a flat attribute.
        ctx = getattr(model_info, "context_length", None)
        if ctx:
            return int(ctx)

    except Exception:  # noqa: BLE001
        pass

    return 4096  # safe default


# ── 1. API Inspector ──────────────────────────────────────────────────────────

def render_api_inspector(
    raw_traces: dict,
    metrics: list[dict],
) -> None:
    """Render a collapsible expander with one tab per gate that captured a trace.

    Each tab shows:
      - The request dict as pretty-printed JSON
      - The response dict as pretty-printed JSON
      - A copy of the metric record (latency, score, verdict, detail)

    If *raw_traces* is empty the expander is not rendered at all.
    """
    if not raw_traces:
        return

    # Build an ordered list of gate names that have traces, preserving the
    # pipeline execution order taken from the metrics list.
    ordered_names: list[str] = []
    seen: set[str] = set()
    for m in metrics:
        name = m.get("gate_name", "")
        if name in raw_traces and name not in seen:
            ordered_names.append(name)
            seen.add(name)
    # Append any traces not referenced in metrics (edge case — should not happen)
    for name in raw_traces:
        if name not in seen:
            ordered_names.append(name)

    with st.expander("🔍 API Inspector — raw gate traces", expanded=False):
        tabs = st.tabs([f"`{n}`" for n in ordered_names])
        for tab, gate_name in zip(tabs, ordered_names):
            with tab:
                trace = raw_traces[gate_name]

                # Metric record for this gate (if present)
                metric = next(
                    (m for m in metrics if m.get("gate_name") == gate_name),
                    None,
                )

                col_req, col_resp = st.columns(2)

                with col_req:
                    st.caption("**Request**")
                    req = trace.get("request", {})
                    st.code(
                        json.dumps(req, indent=2, default=str),
                        language="json",
                    )

                with col_resp:
                    st.caption("**Response**")
                    resp = trace.get("response", {})
                    st.code(
                        json.dumps(resp, indent=2, default=str),
                        language="json",
                    )

                if metric:
                    verdict = metric.get("verdict", "?")
                    latency = metric.get("latency_ms", 0.0)
                    score   = metric.get("score", 0.0)
                    detail  = metric.get("detail", "")

                    _VERDICT_COLOR: dict[str, str] = {
                        "PASS":  "#9ECE6A",
                        "BLOCK": "#F7768E",
                        "AUDIT": "#E0AF68",
                        "ERROR": "#E0AF68",
                        "SKIP":  "#555566",
                    }
                    color = _VERDICT_COLOR.get(verdict, "#888888")

                    st.markdown(
                        f"<span style='color:{color};font-weight:600'>"
                        f"verdict: {verdict}</span>"
                        f"&nbsp;&nbsp;|&nbsp;&nbsp;latency: **{latency:.1f} ms**"
                        f"&nbsp;&nbsp;|&nbsp;&nbsp;score: **{score:.3f}**",
                        unsafe_allow_html=True,
                    )
                    if detail:
                        st.caption(detail)


# ── 2. Context window utilisation ─────────────────────────────────────────────

def render_context_bar(
    prompt_tokens: int,
    model_name: str,
    ollama_host: str,
) -> None:
    """Display a thin progress bar showing context window utilisation.

    Shows prompt token count vs the model's max context length.  Colour
    transitions: green → amber → red as utilisation increases.
    """
    if prompt_tokens <= 0:
        return

    ctx_size = _fetch_context_size(model_name, ollama_host)
    pct = min(prompt_tokens / ctx_size, 1.0)

    if pct < 0.60:
        bar_color = "#9ECE6A"    # green
        label_color = "#9ECE6A"
    elif pct < 0.85:
        bar_color = "#E0AF68"    # amber
        label_color = "#E0AF68"
    else:
        bar_color = "#F7768E"    # red
        label_color = "#F7768E"

    bar_pct_px = max(int(pct * 100), 1)

    st.markdown(
        f"""
<div style="margin:4px 0 6px 0">
  <div style="display:flex;justify-content:space-between;
              font-size:0.72rem;color:#888;margin-bottom:2px">
    <span>Context window</span>
    <span style="color:{label_color}">
      {prompt_tokens:,} / {ctx_size:,} tokens ({pct*100:.0f}%)
    </span>
  </div>
  <div style="background:#2a2a3a;border-radius:3px;height:5px;overflow:hidden">
    <div style="background:{bar_color};width:{bar_pct_px}%;height:100%;
                border-radius:3px;transition:width 0.3s"></div>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )


# ── 3. Hardware Telemetry (sidebar fragment) ──────────────────────────────────

def render_hw_telemetry(ollama_host: str) -> None:
    """Auto-refreshing hardware telemetry panel.

    Uses @st.fragment(run_every=5) so only this component re-renders every
    5 seconds — the rest of the sidebar remains static.

    Displays:
      - Running Ollama models with VRAM usage bars
      - CPU-loaded model memory when VRAM = 0
      - Token throughput from the most recent generation (if available from
        session_state.last_tps)
    """

    @st.fragment(run_every=5)
    def _hw_panel() -> None:
        st.caption("HARDWARE TELEMETRY")

        try:
            from ollama import Client
            client = Client(host=ollama_host)
            ps_response = client.ps()
            running = getattr(ps_response, "models", []) or []
        except Exception:  # noqa: BLE001
            running = []

        if not running:
            st.caption(
                "<span style='color:#555566;font-size:0.72rem'>"
                "No models currently loaded in Ollama.</span>",
                unsafe_allow_html=True,
            )
        else:
            for model in running:
                name      = str(getattr(model, "model", "unknown"))
                size_vram = int(getattr(model, "size_vram", 0) or 0)
                size_ram  = int(getattr(model, "size",      0) or 0)

                short_name = name.split(":")[0]

                if size_vram > 0:
                    used_gb   = size_vram / (1024 ** 3)
                    medium    = "VRAM"
                    bar_color = "#7AA2F7"   # blue — GPU
                elif size_ram > 0:
                    used_gb   = size_ram / (1024 ** 3)
                    medium    = "RAM"
                    bar_color = "#9ECE6A"   # green — CPU
                else:
                    used_gb   = 0.0
                    medium    = "?"
                    bar_color = "#555566"

                st.markdown(
                    f"<div style='font-size:0.76rem;color:#cdd6f4;margin-bottom:1px'>"
                    f"<b>{short_name}</b>"
                    f"<span style='color:#555566;margin-left:6px;font-size:0.68rem'>"
                    f"{used_gb:.2f} GB {medium}</span></div>",
                    unsafe_allow_html=True,
                )

                # Simple usage bar — no max VRAM known, show absolute GB as
                # width capped at a nominal 16 GB reference so the bar is
                # visually meaningful even without querying GPU capacity.
                _REF_GB = 16.0
                bar_pct = min(int((used_gb / _REF_GB) * 100), 100) if used_gb > 0 else 0
                st.markdown(
                    f"<div style='background:#2a2a3a;border-radius:3px;height:4px;"
                    f"margin-bottom:8px;overflow:hidden'>"
                    f"<div style='background:{bar_color};width:{bar_pct}%;height:100%;"
                    f"border-radius:3px'></div></div>",
                    unsafe_allow_html=True,
                )

        # ── Token throughput from last generation ─────────────────────────────
        tps = st.session_state.get("last_tps", 0.0)
        if tps > 0:
            st.markdown(
                f"<div style='font-size:0.72rem;color:#888'>"
                f"Last gen: <b style='color:#9ECE6A'>{tps:.1f} t/s</b></div>",
                unsafe_allow_html=True,
            )

    _hw_panel()
