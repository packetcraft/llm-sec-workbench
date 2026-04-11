"""
tests/test_pipeline.py
──────────────────────
Unit tests for PipelineManager state mutations and execution flow.

All tests use real PipelinePayload and PipelineManager instances.
The OllamaClient is mocked so no live Ollama instance is required.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.payload import PipelinePayload
from core.pipeline import PipelineManager
from core.llm_client import GenerationResult
from gates.regex_gate import CustomRegexGate


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def mock_client():
    client = MagicMock()
    client.generate.return_value = GenerationResult(
        output_text="Test response",
        prompt_tokens=10,
        completion_tokens=5,
        tokens_per_second=20.0,
    )
    return client


@pytest.fixture()
def regex_gate():
    return CustomRegexGate(config={"phrases": "bad word, evil phrase"})


@pytest.fixture()
def empty_pipeline(mock_client):
    """Pipeline with no gates — passes everything through."""
    return PipelineManager(client=mock_client, input_gates=[], output_gates=[])


@pytest.fixture()
def pipeline_with_regex(mock_client, regex_gate):
    """Pipeline with one input gate (CustomRegexGate)."""
    return PipelineManager(
        client=mock_client,
        input_gates=[("custom_regex", regex_gate)],
        output_gates=[],
    )


# ── PipelinePayload contract ──────────────────────────────────────────────────

@pytest.mark.unit
def test_payload_original_input_never_mutated():
    payload = PipelinePayload(original_input="hello", current_text="hello")
    original = payload.original_input
    payload.current_text = "[REDACTED]"
    assert payload.original_input == original


@pytest.mark.unit
def test_payload_is_blocked_defaults_false():
    payload = PipelinePayload(original_input="hello", current_text="hello")
    assert payload.is_blocked is False


@pytest.mark.unit
def test_payload_metrics_starts_empty():
    payload = PipelinePayload(original_input="hello", current_text="hello")
    assert payload.metrics == []


@pytest.mark.unit
def test_payload_raw_traces_starts_empty():
    payload = PipelinePayload(original_input="hello", current_text="hello")
    assert payload.raw_traces == {}


# ── Gate mode: OFF ────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_off_mode_gate_skips_execution(pipeline_with_regex):
    gate_modes = {"custom_regex": "OFF"}
    payload = pipeline_with_regex.run_input_gates("bad word here", gate_modes)
    assert not payload.is_blocked
    assert len(payload.metrics) == 0


# ── Gate mode: AUDIT ──────────────────────────────────────────────────────────

@pytest.mark.unit
def test_audit_mode_does_not_block_pipeline(pipeline_with_regex):
    """AUDIT: gate detects violation, pipeline continues, is_blocked reset."""
    gate_modes = {"custom_regex": "AUDIT"}
    payload = pipeline_with_regex.run_input_gates("bad word in prompt", gate_modes)
    assert not payload.is_blocked           # pipeline was not halted
    assert len(payload.metrics) == 1
    assert payload.metrics[0]["verdict"] == "BLOCK"  # gate DID flag it


@pytest.mark.unit
def test_audit_mode_clean_prompt_passes(pipeline_with_regex):
    gate_modes = {"custom_regex": "AUDIT"}
    payload = pipeline_with_regex.run_input_gates("a perfectly fine prompt", gate_modes)
    assert not payload.is_blocked
    assert payload.metrics[0]["verdict"] == "PASS"


# ── Gate mode: ENFORCE ────────────────────────────────────────────────────────

@pytest.mark.unit
def test_enforce_mode_halts_on_block(pipeline_with_regex):
    gate_modes = {"custom_regex": "ENFORCE"}
    payload = pipeline_with_regex.run_input_gates("bad word in here", gate_modes)
    assert payload.is_blocked is True
    assert "bad word" in payload.block_reason


@pytest.mark.unit
def test_enforce_mode_continues_when_safe(pipeline_with_regex):
    gate_modes = {"custom_regex": "ENFORCE"}
    payload = pipeline_with_regex.run_input_gates("a perfectly safe prompt", gate_modes)
    assert not payload.is_blocked


# ── Full pipeline execute() ───────────────────────────────────────────────────

@pytest.mark.unit
def test_blocked_pipeline_skips_inference(pipeline_with_regex, mock_client):
    """When ENFORCE gate blocks, client.generate must never be called."""
    gate_modes = {"custom_regex": "ENFORCE"}
    payload = pipeline_with_regex.execute("bad word", gate_modes)
    assert payload.is_blocked
    mock_client.generate.assert_not_called()


@pytest.mark.unit
def test_unblocked_pipeline_calls_inference(pipeline_with_regex, mock_client):
    gate_modes = {"custom_regex": "ENFORCE"}
    payload = pipeline_with_regex.execute("a safe prompt", gate_modes)
    assert not payload.is_blocked
    mock_client.generate.assert_called_once()
    assert payload.output_text == "Test response"


@pytest.mark.unit
def test_execute_populates_token_telemetry(empty_pipeline, mock_client):
    payload = empty_pipeline.execute("hello", gate_modes={})
    assert payload.prompt_tokens == 10
    assert payload.completion_tokens == 5
    assert payload.tokens_per_second == 20.0


@pytest.mark.unit
def test_metrics_accumulate_across_gates(mock_client):
    """Two chained gates both append to payload.metrics."""
    gate1 = CustomRegexGate(config={"phrases": "alpha"})
    gate2 = CustomRegexGate(config={"phrases": "beta"})
    pipeline = PipelineManager(
        client=mock_client,
        input_gates=[("gate1", gate1), ("gate2", gate2)],
        output_gates=[],
    )
    gate_modes = {"gate1": "AUDIT", "gate2": "AUDIT"}
    payload = pipeline.run_input_gates("neutral prompt", gate_modes)
    assert len(payload.metrics) == 2


@pytest.mark.unit
def test_output_gates_do_not_run_after_input_block(mock_client):
    """If an input ENFORCE gate blocks, output gates must not run."""
    input_gate = CustomRegexGate(config={"phrases": "block this"})
    output_gate = CustomRegexGate(config={"phrases": "output check"})
    pipeline = PipelineManager(
        client=mock_client,
        input_gates=[("input_g", input_gate)],
        output_gates=[("output_g", output_gate)],
    )
    gate_modes = {"input_g": "ENFORCE", "output_g": "ENFORCE"}
    payload = pipeline.execute("please block this", gate_modes)
    assert payload.is_blocked
    # Only the input gate ran — output gate must not have appended a metric.
    # Both gates share gate_name="custom_regex" (from self.name), so we
    # verify count: exactly one metric means the output gate was skipped.
    assert len(payload.metrics) == 1


# ── Message builder ───────────────────────────────────────────────────────────

@pytest.mark.unit
def test_build_messages_system_prompt(empty_pipeline):
    messages = empty_pipeline._build_messages(
        current_text="hello",
        system_prompt="You are helpful.",
        rag_context="",
        history=[],
    )
    assert messages[0]["role"] == "system"
    assert "You are helpful." in messages[0]["content"]
    assert messages[-1]["role"] == "user"
    assert messages[-1]["content"] == "hello"


@pytest.mark.unit
def test_build_messages_rag_context_appended(empty_pipeline):
    messages = empty_pipeline._build_messages(
        current_text="question",
        system_prompt="Be concise.",
        rag_context="The answer is 42.",
        history=[],
    )
    system_content = messages[0]["content"]
    assert "Be concise." in system_content
    assert "The answer is 42." in system_content


@pytest.mark.unit
def test_build_messages_history_included(empty_pipeline):
    history = [
        {"role": "user", "content": "previous question"},
        {"role": "assistant", "content": "previous answer"},
    ]
    messages = empty_pipeline._build_messages(
        current_text="follow-up",
        system_prompt="",
        rag_context="",
        history=history,
    )
    roles = [m["role"] for m in messages]
    assert roles == ["user", "assistant", "user"]
    assert messages[-1]["content"] == "follow-up"


@pytest.mark.unit
def test_build_messages_uses_current_text_not_original(empty_pipeline):
    """current_text (post-gate) must be the final user message, not the raw input."""
    messages = empty_pipeline._build_messages(
        current_text="[CREDIT_CARD] gave it to me",
        system_prompt="",
        rag_context="",
        history=[{"role": "user", "content": "4111-1111-1111-1111 gave it to me"}],
    )
    # Last user message should use the masked current_text
    assert messages[-1]["content"] == "[CREDIT_CARD] gave it to me"


# ── Fail-open guarantee ───────────────────────────────────────────────────────


@pytest.mark.unit
def test_broken_input_gate_does_not_block_pipeline(mock_client):
    """If a gate's _scan() raises, the pipeline must continue as if it passed."""
    from gates.base_gate import SecurityGate

    class _Exploding(SecurityGate):
        @property
        def name(self) -> str:
            return "exploding"

        def _scan(self, payload: PipelinePayload) -> PipelinePayload:
            raise RuntimeError("model load failed")

    pipeline = PipelineManager(
        client=mock_client,
        input_gates=[("exploding", _Exploding(config={}))],
        output_gates=[],
    )
    payload = pipeline.run_input_gates("hello", gate_modes={"exploding": "ENFORCE"})
    assert payload.is_blocked is False  # fail-open
    assert payload.metrics[0]["verdict"] == "ERROR"


@pytest.mark.unit
def test_broken_output_gate_does_not_block_pipeline(mock_client):
    from gates.base_gate import SecurityGate

    class _Exploding(SecurityGate):
        @property
        def name(self) -> str:
            return "exploding_out"

        def _scan(self, payload: PipelinePayload) -> PipelinePayload:
            raise RuntimeError("scanner crashed")

    pipeline = PipelineManager(
        client=mock_client,
        input_gates=[],
        output_gates=[("exploding_out", _Exploding(config={}))],
    )
    payload = PipelinePayload(
        original_input="hello",
        current_text="hello",
        output_text="The answer is 42.",
    )
    result = pipeline.run_output_gates(payload, gate_modes={"exploding_out": "ENFORCE"})
    assert result.is_blocked is False
    assert result.metrics[0]["verdict"] == "ERROR"


# ── Vault threading (FastScanGate → DeanonymizeGate) ─────────────────────────


@pytest.mark.unit
def test_vault_threads_from_fast_scan_to_deanonymize(mock_client):
    """payload.vault set by FastScanGate must be readable by DeanonymizeGate."""
    from unittest.mock import patch, MagicMock
    from gates.local_scanners import FastScanGate, DeanonymizeGate

    original_text = "My name is Alice"
    masked_text = "My name is [PERSON_1]"
    restored_text = "My name is Alice"

    mock_vault = MagicMock()
    mock_anon = MagicMock()
    mock_anon.scan.return_value = (masked_text, False, 0.9)
    mock_sec = MagicMock()
    mock_sec.scan.return_value = (original_text, True, 0.0)

    mock_deano_scanner = MagicMock()
    mock_deano_scanner.scan.return_value = (restored_text, True, 0.0)

    fast_scan = FastScanGate(config={"scan_pii": True, "scan_secrets": False, "pii_threshold": 0.5})
    deanon = DeanonymizeGate(config={})

    mock_client.generate.return_value.output_text = "Hello [PERSON_1], how are you?"

    pipeline = PipelineManager(
        client=mock_client,
        input_gates=[("fast_scan", fast_scan)],
        output_gates=[("deanonymize", deanon)],
    )

    with patch("llm_guard.input_scanners.Anonymize", return_value=mock_anon), \
         patch("llm_guard.input_scanners.Secrets", return_value=mock_sec), \
         patch("llm_guard.vault.Vault", return_value=mock_vault), \
         patch("llm_guard.output_scanners.Deanonymize", return_value=mock_deano_scanner):

        payload = pipeline.run_input_gates(original_text, {"fast_scan": "AUDIT"})
        # Simulate LLM inference populating output_text
        payload.output_text = "Hello [PERSON_1], how are you?"
        result = pipeline.run_output_gates(payload, {"deanonymize": "ENFORCE"})

    # Vault set by FastScanGate must have been consumed by DeanonymizeGate
    assert result.vault is mock_vault
    assert result.output_text == restored_text


# ── original_input immutability across the full pipeline ─────────────────────


@pytest.mark.unit
def test_original_input_immutable_through_full_pipeline(mock_client):
    """No gate, no inference step, no pipeline method may modify original_input."""
    from unittest.mock import patch, MagicMock
    from gates.local_scanners import FastScanGate

    raw = "My SSN is 123-45-6789"
    mock_vault = MagicMock()
    mock_anon = MagicMock()
    mock_anon.scan.return_value = ("My SSN is [SSN]", False, 0.95)
    mock_sec = MagicMock()
    mock_sec.scan.return_value = (raw, True, 0.0)

    fast_scan = FastScanGate(config={"scan_pii": True, "scan_secrets": False, "pii_threshold": 0.5})
    pipeline = PipelineManager(
        client=mock_client,
        input_gates=[("fast_scan", fast_scan)],
        output_gates=[],
    )

    with patch("llm_guard.input_scanners.Anonymize", return_value=mock_anon), \
         patch("llm_guard.input_scanners.Secrets", return_value=mock_sec), \
         patch("llm_guard.vault.Vault", return_value=mock_vault):
        payload = pipeline.execute(raw, gate_modes={"fast_scan": "AUDIT"})

    assert payload.original_input == raw            # never modified
    assert payload.current_text == "My SSN is [SSN]"  # correctly masked
