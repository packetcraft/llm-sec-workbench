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


# ── 0. Live Telemetry Panel (Phase B stub / Phase C full implementation) ─────

def render_telemetry_panel(ollama_host: str, model_name: str) -> None:
    """Right-side Live Telemetry Panel.

    Phase B: renders the panel skeleton — header, placeholder sections, and
    basic data from ``st.session_state.last_telemetry``.
    Phase C will replace this body with the full six-section implementation
    (gate latency rows, pipeline summary, token bar, Ollama timing bar,
    model info pills, memory countdown).

    Reads exclusively from ``st.session_state.last_telemetry`` so it never
    adds Ollama API latency to idle re-runs.
    """
    tel: dict = st.session_state.get("last_telemetry", {})

    _VERDICT_COLORS = {
        "PASS":  "#9ECE6A",
        "BLOCK": "#F7768E",
        "AUDIT": "#E0AF68",
        "ERROR": "#E0AF68",
        "SKIP":  "#555566",
    }

    with st.container(border=True):
        st.markdown(
            "<div style='font-size:0.72rem;font-weight:700;color:#7AA2F7;"
            "letter-spacing:0.08em;margin-bottom:6px'>📡 LIVE TELEMETRY</div>",
            unsafe_allow_html=True,
        )

        if not tel:
            st.caption("Waiting for first generation…")
            return

        # ── GATE LATENCY ──────────────────────────────────────────────────────
        st.markdown(
            "<div style='font-size:0.68rem;color:#555566;font-weight:600;"
            "letter-spacing:0.06em;margin:6px 0 3px 0'>GATE LATENCY</div>",
            unsafe_allow_html=True,
        )
        gate_modes: dict = tel.get("gate_modes", {})
        for m in tel.get("gate_metrics", []):
            name    = m.get("gate_name", "?")
            verdict = m.get("verdict", "?")
            latency = m.get("latency_ms", 0.0)
            color   = _VERDICT_COLORS.get(verdict, "#888888")
            mode    = gate_modes.get(name, "")
            if mode == "OFF":
                st.markdown(
                    f"<div style='display:flex;justify-content:space-between;"
                    f"font-size:0.72rem;color:#555566;margin:1px 0'>"
                    f"<span>{name}</span><span>off</span></div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"<div style='display:flex;justify-content:space-between;"
                    f"font-size:0.72rem;margin:1px 0'>"
                    f"<span style='color:#cdd6f4'>{name}</span>"
                    f"<span style='color:{color};font-variant-numeric:tabular-nums'>"
                    f"{latency:.0f}ms</span></div>",
                    unsafe_allow_html=True,
                )

        st.markdown("<div style='margin:6px 0;border-top:1px solid #2a2a3a'></div>",
                    unsafe_allow_html=True)

        # ── PIPELINE ──────────────────────────────────────────────────────────
        st.markdown(
            "<div style='font-size:0.68rem;color:#555566;font-weight:600;"
            "letter-spacing:0.06em;margin-bottom:3px'>PIPELINE</div>",
            unsafe_allow_html=True,
        )
        metrics      = tel.get("gate_metrics", [])
        total_ms     = sum(m.get("latency_ms", 0.0) for m in metrics)
        gates_run    = len([m for m in metrics if m.get("verdict") != "SKIP"])
        gates_total  = len(metrics)
        blocked_by   = next(
            (m["gate_name"] for m in metrics if m.get("verdict") == "BLOCK"),
            None,
        )
        _kv = [
            ("Total time",  f"{total_ms:,.0f} ms"),
            ("Gates run",   f"{gates_run} / {gates_total}"),
            ("Blocked by",  blocked_by or "—"),
        ]
        for label, value in _kv:
            color = "#F7768E" if label == "Blocked by" and blocked_by else "#cdd6f4"
            st.markdown(
                f"<div style='display:flex;justify-content:space-between;"
                f"font-size:0.72rem;margin:1px 0'>"
                f"<span style='color:#888'>{label}</span>"
                f"<span style='color:{color};font-variant-numeric:tabular-nums'>"
                f"{value}</span></div>",
                unsafe_allow_html=True,
            )

        st.markdown("<div style='margin:6px 0;border-top:1px solid #2a2a3a'></div>",
                    unsafe_allow_html=True)

        # ── TOKENS ────────────────────────────────────────────────────────────
        st.markdown(
            "<div style='font-size:0.68rem;color:#555566;font-weight:600;"
            "letter-spacing:0.06em;margin-bottom:3px'>TOKENS</div>",
            unsafe_allow_html=True,
        )
        prompt_t = tel.get("prompt_tokens", 0)
        compl_t  = tel.get("completion_tokens", 0)
        tps      = tel.get("tokens_per_second", 0.0)
        total_t  = prompt_t + compl_t
        for label, value in [
            ("Prompt",      str(prompt_t)),
            ("Completion",  str(compl_t)),
            ("Total",       str(total_t)),
            ("Speed",       f"{tps:.1f} t/s"),
        ]:
            st.markdown(
                f"<div style='display:flex;justify-content:space-between;"
                f"font-size:0.72rem;margin:1px 0'>"
                f"<span style='color:#888'>{label}</span>"
                f"<span style='color:#cdd6f4;font-variant-numeric:tabular-nums'>"
                f"{value}</span></div>",
                unsafe_allow_html=True,
            )
        if total_t > 0:
            p_pct = int(prompt_t / total_t * 100)
            c_pct = 100 - p_pct
            st.markdown(
                f"<div style='display:flex;height:5px;border-radius:3px;"
                f"overflow:hidden;margin:5px 0'>"
                f"<div style='background:#7AA2F7;width:{p_pct}%'></div>"
                f"<div style='background:#9ECE6A;width:{c_pct}%'></div>"
                f"</div>"
                f"<div style='display:flex;justify-content:space-between;"
                f"font-size:0.65rem;color:#555566'>"
                f"<span>■ Prompt</span><span>■ Completion</span></div>",
                unsafe_allow_html=True,
            )

        st.markdown("<div style='margin:6px 0;border-top:1px solid #2a2a3a'></div>",
                    unsafe_allow_html=True)

        # ── OLLAMA TIMING ─────────────────────────────────────────────────────
        st.markdown(
            "<div style='font-size:0.68rem;color:#555566;font-weight:600;"
            "letter-spacing:0.06em;margin-bottom:3px'>OLLAMA TIMING</div>",
            unsafe_allow_html=True,
        )
        load_ms    = tel.get("load_ms", 0.0)
        eval_ms    = tel.get("prompt_eval_ms", 0.0)
        gen_ms     = tel.get("generation_ms", 0.0)
        done       = tel.get("done_reason", "") or "—"
        ollama_total = load_ms + eval_ms + gen_ms
        for label, value in [
            ("Model load",   f"{load_ms:,.0f} ms"),
            ("Prompt eval",  f"{eval_ms:,.0f} ms"),
            ("Generation",   f"{gen_ms:,.0f} ms"),
            ("Ollama total", f"{ollama_total:,.0f} ms"),
            ("Stop reason",  done),
        ]:
            st.markdown(
                f"<div style='display:flex;justify-content:space-between;"
                f"font-size:0.72rem;margin:1px 0'>"
                f"<span style='color:#888'>{label}</span>"
                f"<span style='color:#cdd6f4;font-variant-numeric:tabular-nums'>"
                f"{value}</span></div>",
                unsafe_allow_html=True,
            )
        if ollama_total > 0:
            load_pct = int(load_ms / ollama_total * 100)
            eval_pct = int(eval_ms / ollama_total * 100)
            gen_pct  = 100 - load_pct - eval_pct
            st.markdown(
                f"<div style='display:flex;height:5px;border-radius:3px;"
                f"overflow:hidden;margin:5px 0'>"
                f"<div style='background:#E0AF68;width:{load_pct}%'></div>"
                f"<div style='background:#7AA2F7;width:{eval_pct}%'></div>"
                f"<div style='background:#9ECE6A;width:{gen_pct}%'></div>"
                f"</div>"
                f"<div style='display:flex;justify-content:space-between;"
                f"font-size:0.65rem;color:#555566'>"
                f"<span>■ Load</span><span>■ Eval</span><span>■ Gen</span></div>",
                unsafe_allow_html=True,
            )

        st.markdown("<div style='margin:6px 0;border-top:1px solid #2a2a3a'></div>",
                    unsafe_allow_html=True)

        # ── MODEL INFO ────────────────────────────────────────────────────────
        st.markdown(
            "<div style='font-size:0.68rem;color:#555566;font-weight:600;"
            "letter-spacing:0.06em;margin-bottom:3px'>MODEL INFO</div>",
            unsafe_allow_html=True,
        )
        _info = _fetch_model_info(model_name, ollama_host)
        _pill = (
            lambda text, color:
            f"<span style='background:{color}22;color:{color};"
            f"border:1px solid {color}55;padding:1px 7px;border-radius:10px;"
            f"font-size:0.68rem;margin-right:3px'>{text}</span>"
        )
        pills = _pill(_info["family"] or model_name.split(":")[0], "#7AA2F7")
        if _info["param_size"]:
            pills += _pill(_info["param_size"], "#9ECE6A")
        if _info["quant"]:
            pills += _pill(_info["quant"], "#E0AF68")
        st.markdown(
            f"<div style='margin-bottom:4px'>{pills}</div>",
            unsafe_allow_html=True,
        )
        ctx_size = _info["context_size"]
        used_pct = f"{prompt_t / ctx_size * 100:.1f}%" if ctx_size else "?"
        for label, value in [
            ("Context window", f"{ctx_size:,}" if ctx_size else "—"),
            (f"{prompt_t:,} / {ctx_size:,} used", used_pct),
        ]:
            st.markdown(
                f"<div style='display:flex;justify-content:space-between;"
                f"font-size:0.72rem;margin:1px 0'>"
                f"<span style='color:#888'>{label}</span>"
                f"<span style='color:#cdd6f4'>{value}</span></div>",
                unsafe_allow_html=True,
            )

        st.markdown("<div style='margin:6px 0;border-top:1px solid #2a2a3a'></div>",
                    unsafe_allow_html=True)

        # ── MEMORY (live, auto-refreshes every 5s) ────────────────────────────
        _render_memory_section(ollama_host)


@functools.lru_cache(maxsize=8)
def _fetch_model_info(model_name: str, ollama_host: str) -> dict:
    """Fetch model family, parameter size, quantization, and context window.

    Consolidates the two separate Ollama show() calls (previously split
    between _fetch_context_size and the Model Info section) into one cached
    call per (model_name, host).

    Returns a dict with keys: family, param_size, quant, context_size.
    All values default to empty string / 0 on any error.
    """
    result = {"family": "", "param_size": "", "quant": "", "context_size": 4096}
    try:
        from ollama import Client
        client = Client(host=ollama_host)
        info   = client.show(model_name)

        details    = getattr(info, "details", None) or {}
        model_info = getattr(info, "model_info", None) or {}

        if isinstance(details, dict):
            result["family"]     = details.get("family", "")
            result["param_size"] = details.get("parameter_size", "")
            result["quant"]      = details.get("quantization_level", "")
        else:
            result["family"]     = getattr(details, "family", "")
            result["param_size"] = getattr(details, "parameter_size", "")
            result["quant"]      = getattr(details, "quantization_level", "")

        if isinstance(model_info, dict):
            for key in ("llama.context_length", "general.context_length",
                        "context_length"):
                if key in model_info:
                    result["context_size"] = int(model_info[key])
                    break
        else:
            ctx = getattr(model_info, "context_length", None)
            if ctx:
                result["context_size"] = int(ctx)

    except Exception:  # noqa: BLE001
        pass

    return result


@st.fragment(run_every=5)
def _render_memory_section(ollama_host: str) -> None:
    """Live memory section — polls Ollama /api/ps every 5 seconds.

    Shows VRAM / RAM usage and an unloads-in countdown derived from
    the expires_at field returned by ollama.ps().
    """
    import datetime

    st.markdown(
        "<div style='font-size:0.68rem;color:#555566;font-weight:600;"
        "letter-spacing:0.06em;margin-bottom:3px'>MEMORY"
        "<span style='font-weight:400;margin-left:4px'>(live)</span></div>",
        unsafe_allow_html=True,
    )

    try:
        from ollama import Client
        running = getattr(Client(host=ollama_host).ps(), "models", []) or []
    except Exception:  # noqa: BLE001
        running = []

    if not running:
        st.markdown(
            "<div style='font-size:0.72rem;color:#555566'>No models loaded</div>",
            unsafe_allow_html=True,
        )
        return

    _REF_GB = 16.0
    for model in running:
        size_vram = int(getattr(model, "size_vram", 0) or 0)
        size_ram  = int(getattr(model, "size",      0) or 0)
        expires   = getattr(model, "expires_at", None)

        if size_vram > 0:
            used_gb, medium, bar_color = size_vram / 1024**3, "VRAM", "#7AA2F7"
        elif size_ram > 0:
            used_gb, medium, bar_color = size_ram  / 1024**3, "RAM",  "#9ECE6A"
        else:
            used_gb, medium, bar_color = 0.0, "?", "#555566"

        bar_pct = min(int(used_gb / _REF_GB * 100), 100) if used_gb > 0 else 0

        st.markdown(
            f"<div style='display:flex;justify-content:space-between;"
            f"font-size:0.72rem;margin:1px 0'>"
            f"<span style='color:#888'>{medium}</span>"
            f"<span style='color:#cdd6f4;font-variant-numeric:tabular-nums'>"
            f"{used_gb:.2f} GB</span></div>"
            f"<div style='background:#2a2a3a;border-radius:3px;height:4px;"
            f"margin-bottom:5px;overflow:hidden'>"
            f"<div style='background:{bar_color};width:{bar_pct}%;height:100%;"
            f"border-radius:3px'></div></div>",
            unsafe_allow_html=True,
        )

        if expires is not None:
            try:
                now       = datetime.datetime.now(datetime.timezone.utc)
                remaining = expires - now
                secs      = max(int(remaining.total_seconds()), 0)
                countdown = f"{secs // 60}m {secs % 60:02d}s" if secs > 0 else "unloading…"
            except Exception:  # noqa: BLE001
                countdown = "—"
        else:
            countdown = "—"

        st.markdown(
            f"<div style='display:flex;justify-content:space-between;"
            f"font-size:0.72rem;margin:1px 0'>"
            f"<span style='color:#888'>Unloads in</span>"
            f"<span style='color:#E0AF68;font-variant-numeric:tabular-nums'>"
            f"{countdown}</span></div>",
            unsafe_allow_html=True,
        )


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
