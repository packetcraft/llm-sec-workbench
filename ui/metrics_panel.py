"""
ui/metrics_panel.py
───────────────────
Phase 5 — Metrics & Telemetry Panel for the Chat Workbench.

Public entry points
-------------------
render_telemetry_panel(ollama_host, model_name)
    Right-side Live Telemetry Panel with ten sections:
      THREAT LEVEL    — composite risk gauge (max of security gate scores)
      GATE LATENCY    — per-gate ms, colour-coded by speed, off for disabled
      SECURITY SIGNALS— per-gate scores with mini bars (injection, toxicity, …)
      PIPELINE        — totals, gate overhead %, bottleneck, inference share
      SESSION STATS   — turns, block rate, cumulative tokens, avg t/s, duration
      TOKENS          — prompt / completion counts, speed, stacked bar
      OLLAMA TIMING   — TTFT, load / eval / gen breakdown, stacked bar, stop reason
      CONTEXT TREND   — unicode sparkline of context fill across last 10 turns
      MODEL INFO      — pill tags (family, param count, quantization), context window
      MEMORY          — live fragment: VRAM/RAM bar, GPU temp, unloads countdown

render_api_inspector(raw_traces, metrics)
    Tabbed expander showing raw gate request/response JSON.

render_context_bar(prompt_tokens, model_name, ollama_host)
    Inline context window utilisation bar (used in chat history replay).
"""

from __future__ import annotations

import json
import functools
import subprocess
import time as _time

import streamlit as st


# ── Colour constants ──────────────────────────────────────────────────────────

_C_GREEN  = "#9ECE6A"
_C_BLUE   = "#7AA2F7"
_C_AMBER  = "#E0AF68"
_C_RED    = "#F7768E"
_C_PURPLE = "#BB9AF7"
_C_DIM    = "#555566"
_C_TEXT   = "#cdd6f4"
_C_LABEL  = "#888888"

_VERDICT_COLORS = {
    "PASS":  _C_GREEN,
    "BLOCK": _C_RED,
    "AUDIT": _C_AMBER,
    "ERROR": _C_AMBER,
    "SKIP":  _C_DIM,
}

_SPARK_CHARS = "▁▂▃▄▅▆▇█"

_VERDICT_EMOJI: dict[str, str] = {
    "PASS":  "🟢",
    "BLOCK": "🔴",
    "ERROR": "🟠",
    "SKIP":  "⚫",
    "AUDIT": "🟡",
}


# ── Cached model-info fetcher ─────────────────────────────────────────────────

@functools.lru_cache(maxsize=8)
def _fetch_context_size(model_name: str, ollama_host: str) -> int:
    """Return context window size in tokens; falls back to 4096."""
    return _fetch_model_info(model_name, ollama_host)["context_size"]


@functools.lru_cache(maxsize=8)
def _fetch_model_info(model_name: str, ollama_host: str) -> dict:
    """Fetch family, param size, quantization, and context window via ollama.show().

    All values default gracefully on any error so the panel never crashes.
    """
    result: dict = {"family": "", "param_size": "", "quant": "", "context_size": 4096}
    try:
        from ollama import Client
        info       = Client(host=ollama_host).show(model_name)
        details    = getattr(info, "details",    None) or {}
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


# ── Low-level HTML building blocks ────────────────────────────────────────────

def _tel_divider() -> None:
    st.markdown(
        "<div style='margin:6px 0;border-top:1px solid #2a2a3a'></div>",
        unsafe_allow_html=True,
    )


def _tel_section(title: str, suffix: str = "") -> None:
    suf = f"<span style='font-weight:400;margin-left:4px'>{suffix}</span>" if suffix else ""
    st.markdown(
        f"<div style='font-size:0.68rem;color:{_C_DIM};font-weight:600;"
        f"letter-spacing:0.06em;margin-bottom:3px'>{title}{suf}</div>",
        unsafe_allow_html=True,
    )


def _tel_kv(label: str, value: str, color: str = _C_TEXT) -> None:
    st.markdown(
        f"<div style='display:flex;justify-content:space-between;"
        f"font-size:0.72rem;margin:1px 0'>"
        f"<span style='color:{_C_LABEL}'>{label}</span>"
        f"<span style='color:{color};font-variant-numeric:tabular-nums'>"
        f"{value}</span></div>",
        unsafe_allow_html=True,
    )


def _mini_bar(pct: float, color: str, height: int = 4,
              margin: str = "4px 0") -> None:
    w = max(min(int(pct * 100), 100), 0)
    st.markdown(
        f"<div style='background:#2a2a3a;border-radius:3px;height:{height}px;"
        f"overflow:hidden;margin:{margin}'>"
        f"<div style='background:{color};width:{w}%;height:100%;"
        f"border-radius:3px'></div></div>",
        unsafe_allow_html=True,
    )


def _score_color(score: float) -> str:
    if score < 0.3:
        return _C_GREEN
    if score < 0.7:
        return _C_AMBER
    return _C_RED


def _spark_char(pct: float) -> str:
    idx = min(int(pct * len(_SPARK_CHARS)), len(_SPARK_CHARS) - 1)
    return _SPARK_CHARS[max(idx, 0)]


# ── Section renderers ─────────────────────────────────────────────────────────

def _render_threat_gauge(metrics: list[dict]) -> None:
    """Composite risk gauge — max score across all security-relevant gates."""
    _SCORED = {"classify", "toxicity_in", "bias_out"}
    _BINARY = {"mod_llm", "fast_scan", "invisible_text"}

    scores: list[float] = []
    for m in metrics:
        name    = m.get("gate_name", "")
        score   = float(m.get("score", 0.0))
        verdict = m.get("verdict", "PASS")
        if name in _SCORED:
            scores.append(score)
        elif name in _BINARY:
            scores.append(1.0 if verdict == "BLOCK" else 0.0)
        elif name == "relevance":
            scores.append(max(0.0, 1.0 - score))  # invert: low relevance = threat

    if not scores:
        return

    threat = max(scores)
    color  = _score_color(threat)
    label  = "LOW" if threat < 0.3 else "MEDIUM" if threat < 0.7 else "HIGH"

    _tel_section("THREAT LEVEL")
    st.markdown(
        f"<div style='display:flex;justify-content:space-between;"
        f"align-items:center;margin-bottom:4px'>"
        f"<span style='font-size:0.85rem;font-weight:700;color:{color}'>"
        f"● {label}</span>"
        f"<span style='font-size:0.72rem;color:{color}'>{threat*100:.0f}%</span>"
        f"</div>",
        unsafe_allow_html=True,
    )
    _mini_bar(threat, color, height=6, margin="0 0 2px 0")


def _render_gate_latency(metrics: list[dict], gate_modes: dict) -> None:
    """Per-gate latency rows: ms value coloured by speed, 'off' for disabled."""
    _tel_section("GATE LATENCY")
    for m in metrics:
        name    = m.get("gate_name", "?")
        verdict = m.get("verdict", "?")
        latency = m.get("latency_ms", 0.0)
        mode    = gate_modes.get(name, "")
        if mode == "OFF":
            st.markdown(
                f"<div style='display:flex;justify-content:space-between;"
                f"font-size:0.72rem;color:{_C_DIM};margin:1px 0'>"
                f"<span>{name}</span><span>off</span></div>",
                unsafe_allow_html=True,
            )
        else:
            # Colour by speed: green <100ms, amber <1000ms, red >=1000ms
            lat_color = (
                _C_GREEN if latency < 100
                else _C_AMBER if latency < 1000
                else _C_RED
            )
            verdict_color = _VERDICT_COLORS.get(verdict, "#888")
            # Use verdict color for BLOCK/ERROR, speed color otherwise
            display_color = (
                verdict_color
                if verdict in ("BLOCK", "ERROR")
                else lat_color
            )
            st.markdown(
                f"<div style='display:flex;justify-content:space-between;"
                f"font-size:0.72rem;margin:1px 0'>"
                f"<span style='color:{_C_TEXT}'>{name}</span>"
                f"<span style='color:{display_color};"
                f"font-variant-numeric:tabular-nums'>"
                f"{latency:.0f}ms</span></div>",
                unsafe_allow_html=True,
            )


def _render_security_signals(metrics: list[dict]) -> None:
    """Per-gate security scores with mini bars."""
    # (gate_name, display_label, inverted, binary)
    _SIGNAL_GATES = [
        ("classify",    "Injection",  False, False),
        ("toxicity_in", "Toxicity",   False, False),
        ("relevance",   "Relevance",  True,  False),   # higher = better → inverted
        ("bias_out",    "Bias",       False, False),
        ("mod_llm",     "LG3",        False, True),    # binary verdict
        ("fast_scan",   "PII/Secret", False, True),    # binary verdict
    ]

    visible = [
        (label, m, inv, binary)
        for gate_name, label, inv, binary in _SIGNAL_GATES
        if (m := next(
            (x for x in metrics if x.get("gate_name") == gate_name), None
        )) is not None and m.get("verdict") != "SKIP"
    ]

    if not visible:
        return

    _tel_section("SECURITY SIGNALS")
    for label, m, inverted, binary in visible:
        verdict = m.get("verdict", "PASS")
        score   = float(m.get("score", 0.0))

        if binary:
            flagged   = verdict == "BLOCK"
            val_str   = "FLAGGED" if flagged else "safe"
            color     = _C_RED if flagged else _C_GREEN
            bar_width = 1.0 if flagged else 0.04
        else:
            display = max(0.0, 1.0 - score) if inverted else score
            color   = _score_color(display)
            val_str = f"{display:.2f}"
            bar_width = display

        arrow = " ↑" if inverted else ""
        bar_w = max(min(int(bar_width * 100), 100), 0)

        st.markdown(
            f"<div style='font-size:0.72rem;margin:2px 0'>"
            f"<div style='display:flex;justify-content:space-between'>"
            f"<span style='color:{_C_LABEL}'>{label}{arrow}</span>"
            f"<span style='color:{color};"
            f"font-variant-numeric:tabular-nums'>{val_str}</span></div>"
            f"<div style='background:#2a2a3a;border-radius:2px;height:3px;"
            f"overflow:hidden;margin:1px 0'>"
            f"<div style='background:{color};width:{bar_w}%;height:100%'>"
            f"</div></div></div>",
            unsafe_allow_html=True,
        )


def _render_pipeline_section(metrics: list[dict], generation_ms: float) -> None:
    """Pipeline totals plus efficiency stats (overhead %, bottleneck, inference share)."""
    _tel_section("PIPELINE")

    total_gate_ms = sum(m.get("latency_ms", 0.0) for m in metrics)
    gates_run     = len([m for m in metrics if m.get("verdict") != "SKIP"])
    gates_total   = len(metrics)
    blocked_by    = next(
        (m["gate_name"] for m in metrics if m.get("verdict") == "BLOCK"), None
    )
    bottleneck    = (
        max(metrics, key=lambda m: m.get("latency_ms", 0.0))
        if metrics else None
    )
    full_total    = total_gate_ms + generation_ms
    gate_pct      = total_gate_ms / full_total * 100 if full_total > 0 else 0.0
    infer_pct     = generation_ms / full_total * 100 if full_total > 0 else 0.0

    _tel_kv("Total time",      f"{total_gate_ms:,.0f} ms")
    _tel_kv("Gates run",       f"{gates_run} / {gates_total}")
    _tel_kv("Gate overhead",   f"{gate_pct:.0f}%",
            color=_C_AMBER if gate_pct > 30 else _C_TEXT)
    if bottleneck:
        _tel_kv("Bottleneck",
                f"{bottleneck['gate_name']} ({bottleneck['latency_ms']:.0f}ms)",
                color=_C_LABEL)
    _tel_kv("Inference share", f"{infer_pct:.0f}%")
    _tel_kv("Blocked by",      blocked_by or "—",
            color=_C_RED if blocked_by else _C_DIM)


def _render_session_stats_section() -> None:
    """Turn count, block rate, cumulative tokens, avg speed, session duration."""
    _tel_section("SESSION STATS")

    messages   = st.session_state.get("messages", [])
    user_turns = [m for m in messages if m.get("role") == "user"]
    asst_turns = [m for m in messages if m.get("role") == "assistant"]

    turn_count  = len(user_turns)
    block_count = sum(1 for m in asst_turns if m.get("blocked"))
    block_rate  = block_count / turn_count * 100 if turn_count > 0 else 0.0

    tels = [m["telemetry"] for m in asst_turns if m.get("telemetry")]
    total_tokens = sum(
        t.get("prompt_tokens", 0) + t.get("completion_tokens", 0) for t in tels
    )
    avg_tps = (
        sum(t.get("tokens_per_second", 0.0) for t in tels) / len(tels)
        if tels else 0.0
    )

    start_ts = st.session_state.get("session_start_ts", _time.time())
    secs     = max(0, int(_time.time() - start_ts))
    duration = f"{secs // 60}m {secs % 60:02d}s"

    _tel_kv("Turns",        str(turn_count))
    _tel_kv("Blocks",
            f"{block_count} ({block_rate:.0f}%)" if turn_count else "—",
            color=_C_RED if block_count > 0 else _C_DIM)
    _tel_kv("Total tokens", f"{total_tokens:,}")
    _tel_kv("Avg speed",    f"{avg_tps:.1f} t/s")
    _tel_kv("Duration",     duration)


def _render_tokens_section(tel: dict) -> None:
    """Prompt / completion counts, speed, stacked proportion bar."""
    prompt_t = tel.get("prompt_tokens", 0)
    compl_t  = tel.get("completion_tokens", 0)
    tps      = tel.get("tokens_per_second", 0.0)
    total_t  = prompt_t + compl_t

    _tel_section("TOKENS")
    _tel_kv("Prompt",     str(prompt_t))
    _tel_kv("Completion", str(compl_t))
    _tel_kv("Total",      str(total_t))
    _tel_kv("Speed",      f"{tps:.1f} t/s")

    if total_t > 0:
        p_pct = int(prompt_t / total_t * 100)
        c_pct = 100 - p_pct
        st.markdown(
            f"<div style='display:flex;height:5px;border-radius:3px;"
            f"overflow:hidden;margin:5px 0'>"
            f"<div style='background:{_C_BLUE};width:{p_pct}%'></div>"
            f"<div style='background:{_C_GREEN};width:{c_pct}%'></div></div>"
            f"<div style='display:flex;justify-content:space-between;"
            f"font-size:0.65rem;color:{_C_DIM}'>"
            f"<span>■ Prompt</span><span>■ Completion</span></div>",
            unsafe_allow_html=True,
        )


def _render_ollama_timing_section(tel: dict) -> None:
    """TTFT + load / prompt eval / generation breakdown with stacked bar."""
    load_ms  = tel.get("load_ms",        0.0)
    eval_ms  = tel.get("prompt_eval_ms", 0.0)
    gen_ms   = tel.get("generation_ms",  0.0)
    ttft_ms  = tel.get("ttft_ms",        0.0)
    done     = tel.get("done_reason",    "") or "—"
    total    = load_ms + eval_ms + gen_ms

    _tel_section("OLLAMA TIMING")
    if ttft_ms > 0:
        _tel_kv("TTFT",         f"{ttft_ms:,.0f} ms", color=_C_PURPLE)
    _tel_kv("Model load",   f"{load_ms:,.0f} ms")
    _tel_kv("Prompt eval",  f"{eval_ms:,.0f} ms")
    _tel_kv("Generation",   f"{gen_ms:,.0f} ms")
    _tel_kv("Ollama total", f"{total:,.0f} ms")
    _tel_kv("Stop reason",  done,
            color=_C_RED if done == "length" else _C_TEXT)

    if total > 0:
        load_pct = int(load_ms / total * 100)
        eval_pct = int(eval_ms / total * 100)
        gen_pct  = 100 - load_pct - eval_pct
        st.markdown(
            f"<div style='display:flex;height:5px;border-radius:3px;"
            f"overflow:hidden;margin:5px 0'>"
            f"<div style='background:{_C_AMBER};width:{load_pct}%'></div>"
            f"<div style='background:{_C_BLUE};width:{eval_pct}%'></div>"
            f"<div style='background:{_C_GREEN};width:{gen_pct}%'></div></div>"
            f"<div style='display:flex;justify-content:space-between;"
            f"font-size:0.65rem;color:{_C_DIM}'>"
            f"<span>■ Load</span><span>■ Eval</span><span>■ Gen</span></div>",
            unsafe_allow_html=True,
        )


def _render_context_trend(model_name: str, ollama_host: str) -> None:
    """Unicode sparkline of context window fill across last 10 assistant turns."""
    messages  = st.session_state.get("messages", [])
    asst_msgs = [
        m for m in messages
        if m.get("role") == "assistant" and m.get("telemetry")
    ]
    if not asst_msgs:
        return

    ctx_size = _fetch_model_info(model_name, ollama_host)["context_size"] or 4096
    last_10  = asst_msgs[-10:]

    chars:  list[str] = []
    colors: list[str] = []
    for m in last_10:
        pt  = m["telemetry"].get("prompt_tokens", 0)
        pct = min(pt / ctx_size, 1.0)
        chars.append(_spark_char(pct))
        colors.append(_score_color(pct))   # green/amber/red by fill level

    span_html = "".join(
        f"<span style='color:{c}'>{ch}</span>"
        for ch, c in zip(chars, colors)
    )
    cur_pct = (
        last_10[-1]["telemetry"].get("prompt_tokens", 0) / ctx_size * 100
    )

    _tel_section("CONTEXT TREND")
    st.markdown(
        f"<div style='font-size:1.05rem;letter-spacing:2px;margin:2px 0'>"
        f"{span_html}</div>"
        f"<div style='font-size:0.65rem;color:{_C_DIM}'>"
        f"last {len(last_10)} turns · now {cur_pct:.0f}% full</div>",
        unsafe_allow_html=True,
    )


def _render_model_info_section(
    model_name: str, ollama_host: str, prompt_tokens: int
) -> None:
    """Pill tags (family / param count / quantization) and context window row."""
    _tel_section("MODEL INFO")
    info = _fetch_model_info(model_name, ollama_host)

    def _pill(text: str, color: str) -> str:
        return (
            f"<span style='background:{color}22;color:{color};"
            f"border:1px solid {color}55;padding:1px 7px;border-radius:10px;"
            f"font-size:0.68rem;margin-right:3px'>{text}</span>"
        )

    pills  = _pill(info["family"] or model_name.split(":")[0], _C_BLUE)
    if info["param_size"]:
        pills += _pill(info["param_size"], _C_GREEN)
    if info["quant"]:
        pills += _pill(info["quant"], _C_AMBER)
    st.markdown(f"<div style='margin-bottom:4px'>{pills}</div>",
                unsafe_allow_html=True)

    ctx_size = info["context_size"]
    used_pct = f"{prompt_tokens / ctx_size * 100:.1f}%" if ctx_size else "?"
    _tel_kv("Context window",               f"{ctx_size:,}" if ctx_size else "—")
    _tel_kv(f"{prompt_tokens:,} / {ctx_size:,} used", used_pct)


@st.fragment(run_every=5)
def _render_memory_section(ollama_host: str) -> None:
    """Live memory: VRAM/RAM bar, GPU temperature, unloads-in countdown.

    Auto-refreshes every 5 seconds via @st.fragment.
    GPU temperature is queried via nvidia-smi; silently skipped on non-NVIDIA
    systems or when nvidia-smi is not in PATH.
    """
    import datetime

    _tel_section("MEMORY", suffix="(live)")

    try:
        from ollama import Client
        running = getattr(Client(host=ollama_host).ps(), "models", []) or []
    except Exception:  # noqa: BLE001
        running = []

    if not running:
        st.markdown(
            f"<div style='font-size:0.72rem;color:{_C_DIM}'>No models loaded</div>",
            unsafe_allow_html=True,
        )
        return

    _REF_GB = 16.0
    for model in running:
        size_vram = int(getattr(model, "size_vram", 0) or 0)
        size_ram  = int(getattr(model, "size",      0) or 0)
        expires   = getattr(model, "expires_at", None)

        if size_vram > 0:
            used_gb, medium, bar_color = size_vram / 1024**3, "VRAM", _C_BLUE
        elif size_ram > 0:
            used_gb, medium, bar_color = size_ram  / 1024**3, "RAM",  _C_GREEN
        else:
            used_gb, medium, bar_color = 0.0, "?", _C_DIM

        _tel_kv(medium, f"{used_gb:.2f} GB")
        _mini_bar(used_gb / _REF_GB, bar_color)

        # GPU temperature via nvidia-smi (best-effort, silent skip on failure)
        try:
            proc = subprocess.run(
                ["nvidia-smi",
                 "--query-gpu=temperature.gpu",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=2, check=False,
            )
            if proc.returncode == 0:
                temp_val  = int(proc.stdout.strip().split("\n")[0].strip())
                temp_color = (
                    _C_GREEN if temp_val < 70
                    else _C_AMBER if temp_val < 85
                    else _C_RED
                )
                _tel_kv("GPU Temp", f"{temp_val}°C", color=temp_color)
        except Exception:  # noqa: BLE001
            pass  # no nvidia-smi or AMD/Apple Silicon — silent

        # Unloads-in countdown
        if expires is not None:
            try:
                now       = datetime.datetime.now(datetime.timezone.utc)
                secs      = max(int((expires - now).total_seconds()), 0)
                countdown = f"{secs // 60}m {secs % 60:02d}s" if secs > 0 else "unloading…"
            except Exception:  # noqa: BLE001
                countdown = "—"
        else:
            countdown = "—"

        _tel_kv("Unloads in", countdown, color=_C_AMBER)


# ── 0. Live Telemetry Panel ───────────────────────────────────────────────────

def render_telemetry_panel(ollama_host: str, model_name: str) -> None:
    """Right-side Live Telemetry Panel.

    Reads exclusively from ``st.session_state.last_telemetry`` (populated by
    chat_view.py after each generation) so it never adds Ollama API latency to
    idle re-runs.  Renders a placeholder when no generation has occurred yet.
    """
    tel:       dict = st.session_state.get("last_telemetry", {})
    metrics:   list = tel.get("gate_metrics", [])
    gate_modes: dict = tel.get("gate_modes", {})

    with st.container(border=True):
        st.markdown(
            f"<div style='font-size:0.72rem;font-weight:700;color:{_C_BLUE};"
            f"letter-spacing:0.08em;margin-bottom:6px'>📡 LIVE TELEMETRY</div>",
            unsafe_allow_html=True,
        )

        if not tel:
            st.caption("Waiting for first generation…")
            return

        _render_threat_gauge(metrics)
        _tel_divider()
        _render_gate_latency(metrics, gate_modes)
        _tel_divider()
        _render_security_signals(metrics)
        _tel_divider()
        _render_pipeline_section(metrics, tel.get("generation_ms", 0.0))
        _tel_divider()
        _render_session_stats_section()
        _tel_divider()
        _render_tokens_section(tel)
        _tel_divider()
        _render_ollama_timing_section(tel)
        _tel_divider()
        _render_context_trend(model_name, ollama_host)
        _tel_divider()
        _render_model_info_section(
            model_name, ollama_host, tel.get("prompt_tokens", 0)
        )
        _tel_divider()
        _render_memory_section(ollama_host)


# ── 1. API Inspector ──────────────────────────────────────────────────────────

def _build_inspector_json(raw_traces: dict, metrics: list[dict]) -> str:
    """Serialize full conversation + telemetry + gate traces as JSON."""
    import datetime
    messages = st.session_state.get("messages", [])
    tel      = st.session_state.get("last_telemetry", {})
    export   = {
        "exported_at": datetime.datetime.now().isoformat(),
        "conversation": [
            {"role": m.get("role", ""), "content": m.get("content", "")}
            for m in messages
        ],
        "telemetry": {k: v for k, v in tel.items() if k != "gate_metrics"},
        "gate_metrics": metrics,
        "gate_traces":  raw_traces,
    }
    return json.dumps(export, indent=2, default=str)


def _build_inspector_md(raw_traces: dict, metrics: list[dict]) -> str:
    """Serialize full conversation + telemetry + gate traces as Markdown."""
    import datetime
    messages = st.session_state.get("messages", [])
    tel      = st.session_state.get("last_telemetry", {})

    lines: list[str] = [
        "# LLM Security Workbench — Session Export",
        f"*Exported: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
        "",
        "---",
        "",
        "## Conversation",
        "",
    ]
    for m in messages:
        role    = m.get("role", "")
        content = m.get("content", "")
        prefix  = "**User:**" if role == "user" else "**Assistant:**"
        lines.append(f"{prefix} {content}")
        lines.append("")

    lines += [
        "---",
        "",
        "## Gate Metrics",
        "",
        "| Gate | Verdict | Score | Latency (ms) | Detail |",
        "|:-----|:--------|------:|-------------:|:-------|",
    ]
    for m in metrics:
        emoji = _VERDICT_EMOJI.get(m.get("verdict", ""), "")
        lines.append(
            f"| {m.get('gate_name', '')} "
            f"| {emoji} {m.get('verdict', '')} "
            f"| {m.get('score', 0.0):.4f} "
            f"| {m.get('latency_ms', 0.0):.1f} "
            f"| {m.get('detail', '')} |"
        )

    lines += ["", "---", "", "## Telemetry", ""]
    tel_display = {k: v for k, v in tel.items() if k != "gate_metrics"}
    for k, v in tel_display.items():
        lines.append(f"- **{k}**: {v}")

    lines += ["", "---", "", "## Raw Gate Traces", ""]
    for gate_name, trace in raw_traces.items():
        metric  = next((m for m in metrics if m.get("gate_name") == gate_name), None)
        verdict = metric.get("verdict", "?") if metric else "?"
        emoji   = _VERDICT_EMOJI.get(verdict, "")
        lines += [
            f"### {emoji} {gate_name} ({verdict})",
            "",
            "**Request:**",
            "```json",
            json.dumps(trace.get("request", {}), indent=2, default=str),
            "```",
            "",
            "**Response:**",
            "```json",
            json.dumps(trace.get("response", {}), indent=2, default=str),
            "```",
            "",
        ]

    return "\n".join(lines)


def render_api_inspector(
    raw_traces: dict,
    metrics: list[dict],
) -> None:
    """Collapsible expander with one tab per gate — request/response JSON side by side.

    Tab labels are prefixed with a verdict emoji (🟢 PASS / 🔴 BLOCK / 🟠 ERROR / ⚫ SKIP).
    Export buttons in the header row produce a full-session JSON or Markdown download
    that includes the conversation, telemetry, gate metrics, and raw gate traces.
    """
    if not raw_traces:
        return

    # Build ordered gate list (pipeline order via metrics, then any extras)
    ordered_names: list[str] = []
    seen: set[str] = set()
    for m in metrics:
        name = m.get("gate_name", "")
        if name in raw_traces and name not in seen:
            ordered_names.append(name)
            seen.add(name)
    for name in raw_traces:
        if name not in seen:
            ordered_names.append(name)

    # Build a verdict lookup for tab labelling
    verdict_map: dict[str, str] = {
        m.get("gate_name", ""): m.get("verdict", "") for m in metrics
    }

    with st.expander("🔍 API Inspector — raw gate traces", expanded=False):

        # ── Export row ────────────────────────────────────────────────────────
        import datetime
        ts         = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        json_bytes = _build_inspector_json(raw_traces, metrics).encode()
        md_bytes   = _build_inspector_md(raw_traces, metrics).encode()

        exp_left, exp_right, _ = st.columns([1, 1, 5])
        with exp_left:
            st.download_button(
                label="⬇ JSON",
                data=json_bytes,
                file_name=f"workbench_trace_{ts}.json",
                mime="application/json",
                use_container_width=True,
                key=f"dl_json_{ts}",
            )
        with exp_right:
            st.download_button(
                label="⬇ MD",
                data=md_bytes,
                file_name=f"workbench_trace_{ts}.md",
                mime="text/markdown",
                use_container_width=True,
                key=f"dl_md_{ts}",
            )

        st.markdown(
            f"<div style='font-size:0.68rem;color:{_C_DIM};margin-bottom:6px'>"
            f"Export includes full conversation, telemetry and gate traces.</div>",
            unsafe_allow_html=True,
        )

        # ── Gate tabs ─────────────────────────────────────────────────────────
        # Tab label = verdict emoji + short gate name
        tab_labels = [
            f"{_VERDICT_EMOJI.get(verdict_map.get(n, ''), '⬜')} {n}"
            for n in ordered_names
        ]
        tabs = st.tabs(tab_labels)

        for tab, gate_name in zip(tabs, ordered_names):
            with tab:
                trace  = raw_traces[gate_name]
                metric = next(
                    (m for m in metrics if m.get("gate_name") == gate_name), None
                )
                col_req, col_resp = st.columns(2)
                with col_req:
                    st.caption("**Request**")
                    st.code(json.dumps(trace.get("request", {}),
                                       indent=2, default=str),
                            language="json")
                with col_resp:
                    st.caption("**Response**")
                    st.code(json.dumps(trace.get("response", {}),
                                       indent=2, default=str),
                            language="json")
                if metric:
                    verdict = metric.get("verdict", "?")
                    latency = metric.get("latency_ms", 0.0)
                    score   = metric.get("score", 0.0)
                    detail  = metric.get("detail", "")
                    color   = _VERDICT_COLORS.get(verdict, "#888888")
                    emoji   = _VERDICT_EMOJI.get(verdict, "")
                    st.markdown(
                        f"<span style='color:{color};font-weight:700'>"
                        f"{emoji} verdict: {verdict}</span>"
                        f"&nbsp;&nbsp;|&nbsp;&nbsp;latency: **{latency:.1f} ms**"
                        f"&nbsp;&nbsp;|&nbsp;&nbsp;score: **{score:.3f}**",
                        unsafe_allow_html=True,
                    )
                    if detail:
                        st.caption(detail)


# ── 2. Context window utilisation (inline, chat history) ─────────────────────

def render_context_bar(
    prompt_tokens: int,
    model_name: str,
    ollama_host: str,
) -> None:
    """Thin colour-coded progress bar rendered inline under each message."""
    if prompt_tokens <= 0:
        return

    ctx_size = _fetch_context_size(model_name, ollama_host)
    pct      = min(prompt_tokens / ctx_size, 1.0)
    color    = _score_color(pct)

    st.markdown(
        f"<div style='margin:4px 0 6px 0'>"
        f"<div style='display:flex;justify-content:space-between;"
        f"font-size:0.72rem;color:{_C_LABEL};margin-bottom:2px'>"
        f"<span>Context window</span>"
        f"<span style='color:{color}'>"
        f"{prompt_tokens:,} / {ctx_size:,} tokens ({pct*100:.0f}%)"
        f"</span></div>"
        f"<div style='background:#2a2a3a;border-radius:3px;height:5px;overflow:hidden'>"
        f"<div style='background:{color};width:{max(int(pct*100),1)}%;height:100%;"
        f"border-radius:3px;transition:width 0.3s'></div></div></div>",
        unsafe_allow_html=True,
    )


# ── 3. Legacy sidebar hw panel (no longer called, kept for reference) ─────────

def render_hw_telemetry(ollama_host: str) -> None:  # noqa: ARG001
    """Superseded by _render_memory_section inside render_telemetry_panel."""
