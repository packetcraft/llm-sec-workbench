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

render_gate_chip_trace(gate_metrics, gate_modes, *, title)
    Compact one-row-per-gate chip trace for red-team views.
    Each chip: emoji + name | VERDICT badge | [mode] | detail | latency ms.
    Shared by Static and Dynamic (PAIR) red-team tabs.
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
_C_ERROR  = "#FF9E64"   # system error — distinct from AUDIT amber
_C_RED    = "#F7768E"
_C_PURPLE = "#BB9AF7"
_C_DIM    = "#555566"
_C_TEXT   = "#cdd6f4"
_C_LABEL  = "#888888"

_VERDICT_COLORS = {
    "PASS":  _C_GREEN,
    "BLOCK": _C_RED,
    "AUDIT": _C_AMBER,
    "ERROR": _C_ERROR,   # orange, not amber — distinct from AUDIT
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

# Gate emoji map — used by render_gate_chip_trace()
_GATE_EMOJI: dict[str, str] = {
    "custom_regex":   "🔤",
    "token_limit":    "📏",
    "invisible_text": "👻",
    "fast_scan":      "🔍",
    "classify":       "🎯",
    "toxicity_in":    "☣️",
    "ban_topics":     "🚫",
    "mod_llm":        "🛡️",
    "sensitive_out":  "🔒",
    "malicious_urls": "🌐",
    "no_refusal":     "🤐",
    "bias_out":       "⚖️",
    "relevance":      "📎",
    "deanonymize":    "🔓",
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

# Friendly names used in the threat gauge context line
_GATE_DISPLAY_THREAT: dict[str, str] = {
    "classify":    "Injection",
    "toxicity_in": "Toxicity",
    "bias_out":    "Bias",
    "relevance":   "Relevance",
    "mod_llm":     "Llama Guard",
    "fast_scan":   "PII/Secrets",
}


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

    # Threat context: top 1-2 contributing gates by contribution score
    _CONTRIB_MAP = [
        ("classify",    False),
        ("toxicity_in", False),
        ("bias_out",    False),
        ("relevance",   True),   # inverted: low relevance = threat
        ("mod_llm",     False),  # binary: 1.0 if BLOCK
        ("fast_scan",   False),  # binary: 1.0 if BLOCK
    ]
    contributions: list[tuple[str, float]] = []
    for _gate_name, _inverted in _CONTRIB_MAP:
        _entry = next((x for x in metrics if x.get("gate_name") == _gate_name), None)
        if _entry is None or _entry.get("verdict") in ("SKIP", "OFF"):
            continue
        _raw     = float(_entry.get("score", 0.0))
        _verdict = _entry.get("verdict", "PASS")
        if _gate_name in ("mod_llm", "fast_scan"):
            _contrib = 1.0 if _verdict == "BLOCK" else 0.0
        elif _inverted:
            _contrib = max(0.0, 1.0 - _raw)
        else:
            _contrib = _raw
        if _contrib >= 0.05:
            contributions.append((_GATE_DISPLAY_THREAT.get(_gate_name, _gate_name), _contrib))

    contributions.sort(key=lambda x: x[1], reverse=True)
    if contributions:
        _parts = [f"{n} ({v:.2f})" for n, v in contributions[:2]]
        st.markdown(
            f"<div style='font-size:0.65rem;color:{_C_LABEL};margin-top:2px'>"
            f"Driven by: {' + '.join(_parts)}</div>",
            unsafe_allow_html=True,
        )


_GATE_DISPLAY: dict[str, str] = {
    "custom_regex":   "Regex",
    "token_limit":    "Token Limit",
    "invisible_text": "Invisible",
    "fast_scan":      "PII/Secrets",
    "classify":       "Injection",
    "toxicity_in":    "Toxicity",
    "ban_topics":     "Ban Topics",
    "mod_llm":        "Llama Guard",
    "sensitive_out":  "PII Out",
    "malicious_urls": "Bad URLs",
    "no_refusal":     "Refusal",
    "bias_out":       "Bias",
    "relevance":      "Relevance",
    "deanonymize":    "PII Restore",
}

# Gates that produce no continuous score — show "—" in the Score column
_BINARY_GATES = frozenset({
    "custom_regex", "token_limit", "invisible_text",
    "malicious_urls", "no_refusal", "deanonymize",
})

# For relevance the raw score is "goodness", so threat contribution is inverted
_INVERTED_GATES = frozenset({"relevance"})

# Output-side gate keys — used to insert the LLM inference separator row
_OUTPUT_GATE_KEYS = frozenset({
    "sensitive_out", "malicious_urls", "no_refusal",
    "bias_out", "relevance", "deanonymize",
})


def _render_gate_results(
    metrics: list[dict],
    gate_modes: dict,
    generation_ms: float = 0.0,
) -> None:
    """Merged GATE RESULTS table: Gate | Mode | Score | Verdict | ms.

    A centred LLM inference row separates input gates (above) from output
    gates (below), and shows the model's actual generation latency.
    ms values use comma separators for readability (e.g. 1,234).
    """
    if not metrics:
        return

    _MODE_BADGE = {
        "ENFORCE": (_C_RED,    "ENF"),
        "AUDIT":   (_C_AMBER,  "AUD"),
        "OFF":     (_C_DIM,    "OFF"),
    }

    # Pre-build the LLM inference separator row (inserted before first output gate)
    gen_ms_str = f"{generation_ms:,.0f}" if generation_ms > 0 else "—"
    _LLM_ROW = (
        f"<tr>"
        f"<td colspan='5' style='"
        f"padding:4px 6px 4px 0;"
        f"border-top:1px solid #2a2a3a;"
        f"border-bottom:1px solid #2a2a3a;"
        f"background:rgba(122,162,247,0.07)'>"
        f"<div style='display:flex;justify-content:space-between;align-items:center'>"
        f"<span style='color:{_C_BLUE};font-size:0.65rem;font-weight:600;"
        f"letter-spacing:0.04em'>⚡ LLM</span>"
        f"<span style='color:{_C_BLUE};font-variant-numeric:tabular-nums;"
        f"font-size:0.65rem;padding-right:4px'>{gen_ms_str} ms</span>"
        f"</div>"
        f"</td>"
        f"</tr>"
    )

    # Pre-compute max active latency so all bars share the same scale
    _max_lat = max(
        (m.get("latency_ms", 0.0) for m in metrics
         if m.get("verdict") != "SKIP"
         and gate_modes.get(m.get("gate_name", ""), "AUDIT") != "OFF"),
        default=1.0,
    ) or 1.0   # guard against all-zero latencies

    rows: list[str] = []
    llm_row_inserted = False

    for m in metrics:
        gate    = m.get("gate_name", "?")
        verdict = m.get("verdict", "PASS")
        latency = m.get("latency_ms", 0.0)
        score   = float(m.get("score", 0.0))
        mode    = gate_modes.get(gate, "AUDIT")

        # Insert the LLM row the first time we hit an output gate
        if gate in _OUTPUT_GATE_KEYS and not llm_row_inserted:
            rows.append(_LLM_ROW)
            llm_row_inserted = True

        label   = _GATE_DISPLAY.get(gate, gate[:12])
        v_color = _VERDICT_COLORS.get(verdict, _C_DIM)
        m_color, m_abbr = _MODE_BADGE.get(mode, (_C_DIM, mode[:3]))

        if mode == "OFF" or verdict == "SKIP":
            score_str = "—"
            v_color   = _C_DIM
            # ms column: dash, no bar
            ms_cell = (
                f"<td style='color:{_C_DIM};padding:2px 6px 2px 4px;"
                f"text-align:right'>—</td>"
            )
        else:
            if gate in _BINARY_GATES:
                score_str = "—"
            elif gate in _INVERTED_GATES:
                threat_score = max(0.0, 1.0 - score)
                score_str    = f"{threat_score:.2f}"
            else:
                score_str = f"{score:.2f}" if score >= 0.005 else "—"

            # ms column: stacked mini-bar + comma-formatted number
            lat_color = (
                _C_GREEN if latency < 100
                else _C_AMBER if latency < 1000
                else _C_RED
            )
            bar_pct = min(int(latency / _max_lat * 100), 100)
            ms_cell = (
                f"<td style='padding:2px 6px 2px 4px;text-align:right;"
                f"vertical-align:middle'>"
                f"<div style='background:#2a2a3a;border-radius:1px;height:2px;"
                f"overflow:hidden;margin-bottom:2px'>"
                f"<div style='background:{lat_color};width:{bar_pct}%;height:100%'>"
                f"</div></div>"
                f"<span style='color:{lat_color};"
                f"font-variant-numeric:tabular-nums'>{latency:,.0f}</span>"
                f"</td>"
            )

        rows.append(
            f"<tr>"
            f"<td style='color:{_C_TEXT};padding:2px 4px 2px 0' title='{gate}'>{label}</td>"
            f"<td style='color:{m_color};padding:2px 4px;font-size:0.65rem'>{m_abbr}</td>"
            f"<td style='color:{_C_LABEL};padding:2px 4px;font-variant-numeric:tabular-nums;"
            f"text-align:right'>{score_str}</td>"
            f"<td style='background:{v_color}22;color:{v_color};padding:1px 5px;"
            f"border-radius:3px;font-size:0.65rem;font-weight:600'>{verdict}</td>"
            f"{ms_cell}"
            f"</tr>"
        )

    _tel_section("GATE RESULTS")
    st.markdown(
        f"<table style='width:100%;border-collapse:collapse;font-size:0.72rem'>"
        f"<thead><tr>"
        f"<th style='color:{_C_DIM};font-weight:500;text-align:left;padding:1px 4px 3px 0;"
        f"border-bottom:1px solid #2a2a3a'>Gate</th>"
        f"<th style='color:{_C_DIM};font-weight:500;padding:1px 4px 3px;"
        f"border-bottom:1px solid #2a2a3a'>Mode</th>"
        f"<th style='color:{_C_DIM};font-weight:500;text-align:right;padding:1px 4px 3px;"
        f"border-bottom:1px solid #2a2a3a'>Score</th>"
        f"<th style='color:{_C_DIM};font-weight:500;padding:1px 4px 3px;"
        f"border-bottom:1px solid #2a2a3a'>Verdict</th>"
        f"<th style='color:{_C_DIM};font-weight:500;text-align:right;padding:1px 6px 3px 4px;"
        f"border-bottom:1px solid #2a2a3a'>ms</th>"
        f"</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        f"</table>",
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

        expand_all = st.toggle(
            "Expand all", value=False, key="tel_expand_all",
            help="Expand all collapsible telemetry sections",
        )

        # ── Always visible ────────────────────────────────────────────────────
        _render_threat_gauge(metrics)
        _tel_divider()
        _render_gate_results(metrics, gate_modes, tel.get("generation_ms", 0.0))
        _tel_divider()
        _render_session_stats_section()

        # ── Collapsible sections ──────────────────────────────────────────────
        _tel_divider()
        with st.expander("Pipeline", expanded=expand_all):
            _render_pipeline_section(metrics, tel.get("generation_ms", 0.0))

        with st.expander("Tokens", expanded=expand_all):
            _render_tokens_section(tel)

        with st.expander("Ollama Timing", expanded=expand_all):
            _render_ollama_timing_section(tel)

        with st.expander("Context Trend", expanded=expand_all):
            _render_context_trend(model_name, ollama_host)

        with st.expander("Model Info", expanded=expand_all):
            _render_model_info_section(
                model_name, ollama_host, tel.get("prompt_tokens", 0)
            )

        with st.expander("Memory", expanded=expand_all):
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
    *,
    idx: int | None = None,
    expanded: bool = False,
) -> None:
    """Collapsible expander with one tab per gate — request/response JSON side by side.

    Tab labels: verdict emoji + short gate name + latency + score
    (e.g. "🔴 Bias · 178ms · 0.46").  Binary gates omit the score field.
    Export buttons in the header row produce a full-session JSON or Markdown download
    that includes the conversation, telemetry, gate metrics, and raw gate traces.

    Parameters
    ----------
    expanded:
        When True the expander starts open (use for the most-recent turn).
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

    # Full metric lookup for tab labelling
    metric_map: dict[str, dict] = {
        m.get("gate_name", ""): m for m in metrics
    }

    with st.expander("🔍 Pipeline Trace", expanded=expanded):

        # ── Export row ────────────────────────────────────────────────────────
        import datetime
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        # Key must be stable and unique across all inspector instances on the page.
        # Use the message index when provided; fall back to a hash of the trace keys.
        key_id = (
            str(idx)
            if idx is not None
            else str(abs(hash(tuple(sorted(raw_traces.keys())))))
        )
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
                key=f"dl_json_{key_id}",
            )
        with exp_right:
            st.download_button(
                label="⬇ MD",
                data=md_bytes,
                file_name=f"workbench_trace_{ts}.md",
                mime="text/markdown",
                use_container_width=True,
                key=f"dl_md_{key_id}",
            )

        st.markdown(
            f"<div style='font-size:0.68rem;color:{_C_DIM};margin-bottom:6px'>"
            f"Export includes full conversation, telemetry and gate traces.</div>",
            unsafe_allow_html=True,
        )

        # ── Gate tabs ─────────────────────────────────────────────────────────
        # Tab label: emoji + short name + latency + score (binary gates skip score)
        def _tab_label(gate_name: str) -> str:
            m       = metric_map.get(gate_name, {})
            verdict = m.get("verdict", "")
            emoji   = _VERDICT_EMOJI.get(verdict, "⬜")
            short   = _GATE_DISPLAY.get(gate_name, gate_name[:12])
            latency = m.get("latency_ms", 0.0)
            score   = float(m.get("score", 0.0))
            if verdict in ("SKIP", "OFF") or not m:
                return f"{emoji} {short}"
            if gate_name in _BINARY_GATES:
                return f"{emoji} {short} · {latency:.0f}ms"
            return f"{emoji} {short} · {latency:.0f}ms · {score:.2f}"

        tab_labels = [_tab_label(n) for n in ordered_names]
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


# ── 3. Gate chip trace (red-team views) ──────────────────────────────────────

def render_gate_chip_trace(
    gate_metrics: list[dict],
    gate_modes: dict[str, str] | None = None,
    *,
    title: str = "GATE TRACE",
) -> None:
    """Compact gate chip trace — one row per gate.

    Shared by the Static Red Team and Dynamic (PAIR) red-team tabs.
    Each chip displays: emoji + gate name | VERDICT badge | [mode] | detail | ms.

    Args:
        gate_metrics:  List of metric dicts produced by PipelineManager.
                       Keys: ``gate_name``, ``verdict``, ``latency_ms``,
                       ``score``, ``detail``.
        gate_modes:    Session ``gate_modes`` dict for the mode badge.
                       Pass ``None`` to suppress the mode column.
        title:         Section header rendered above the chips.
                       Pass ``""`` to suppress.
    """
    if not gate_metrics:
        return

    import html as _html

    if title:
        _tel_section(title)

    chips: list[str] = []

    for m in gate_metrics:
        gate    = m.get("gate_name", "?")
        verdict = m.get("verdict", "PASS")
        latency = m.get("latency_ms", 0.0)
        score   = float(m.get("score", 0.0))
        detail  = m.get("detail", "")

        emoji   = _GATE_EMOJI.get(gate, "●")
        label   = _GATE_DISPLAY.get(gate, gate[:14])
        v_color = _VERDICT_COLORS.get(verdict, _C_DIM)

        mode_str = (
            f"[{gate_modes[gate]}]"
            if gate_modes and gate in gate_modes
            else ""
        )

        # Latency colour: green < 100 ms, amber < 1 000 ms, red ≥ 1 000 ms
        lat_color = (
            _C_GREEN if latency < 100
            else _C_AMBER if latency < 1000
            else _C_RED
        )
        lat_str = f"{latency:,.0f} ms" if latency > 0 else "—"

        # Fall back to score annotation when no detail string is present
        if not detail and gate not in _BINARY_GATES and score >= 0.005:
            detail = f"score {score:.3f}"

        detail_safe  = _html.escape(detail[:80]) if detail else "—"
        detail_title = _html.escape(detail) if detail else ""

        mode_cell = (
            f"<span style='color:{_C_DIM};font-size:0.63rem;"
            f"white-space:nowrap'>{mode_str}</span>"
            if mode_str else ""
        )

        chips.append(
            f"<div style='display:flex;align-items:center;gap:6px;"
            f"padding:4px 8px;border-radius:4px;"
            f"background:rgba(255,255,255,0.025);"
            f"border:1px solid #2a2a3a;"
            f"font-size:0.70rem;font-family:ui-monospace,monospace;"
            f"overflow:hidden;margin-bottom:3px'>"
            # name
            f"<span style='font-weight:600;min-width:100px;color:{_C_TEXT};"
            f"white-space:nowrap'>{emoji} {label}</span>"
            # verdict badge
            f"<span style='background:{v_color}22;color:{v_color};"
            f"padding:1px 6px;border-radius:3px;font-size:0.63rem;"
            f"font-weight:700;letter-spacing:0.04em;white-space:nowrap'>"
            f"{verdict}</span>"
            # mode (optional)
            f"{mode_cell}"
            # detail
            f"<span style='color:{_C_LABEL};flex:1;overflow:hidden;"
            f"text-overflow:ellipsis;white-space:nowrap;font-size:0.65rem'"
            f" title='{detail_title}'>{detail_safe}</span>"
            # latency
            f"<span style='color:{lat_color};font-size:0.63rem;"
            f"white-space:nowrap;margin-left:auto;padding-left:6px'>"
            f"{lat_str}</span>"
            f"</div>"
        )

    st.markdown(
        f"<div style='margin:4px 0'>{''.join(chips)}</div>",
        unsafe_allow_html=True,
    )


# ── 3. Legacy sidebar hw panel (no longer called, kept for reference) ─────────

def render_hw_telemetry(ollama_host: str) -> None:  # noqa: ARG001
    """Superseded by _render_memory_section inside render_telemetry_panel."""
