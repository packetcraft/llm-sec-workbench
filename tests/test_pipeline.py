"""
tests/test_pipeline.py
──────────────────────
Unit tests for PipelineManager state mutations and execution flow.

These tests will be fully implemented in Phase 2 when core/pipeline.py and
core/payload.py exist. The structure and test cases are defined here now so
the CI suite fails loudly (as expected) and is ready to go green immediately
once the implementations land.

All tests in this file are marked ``unit`` — they must never require a live
Ollama instance or any network access.
"""

from __future__ import annotations

import pytest


# ── Helpers / Fixtures ────────────────────────────────────────────────────────

@pytest.fixture()
def minimal_payload():
    """Return a minimal PipelinePayload-like namespace for testing.

    Replaced with the real PipelinePayload import once Phase 2 lands.
    """
    # TODO (Phase 2): replace with:
    #   from core.payload import PipelinePayload
    #   return PipelinePayload(original_input="hello", current_text="hello")
    from types import SimpleNamespace
    return SimpleNamespace(
        original_input="hello world",
        current_text="hello world",
        is_blocked=False,
        block_reason="",
        metrics=[],
        output_text="",
        prompt_tokens=0,
        completion_tokens=0,
        tokens_per_second=0.0,
        raw_traces={},
    )


@pytest.fixture()
def pipeline_manager():
    """Return an initialised PipelineManager.

    TODO (Phase 2): replace stub with real import.
    """
    pytest.skip("PipelineManager not yet implemented (Phase 2)")


# ── Payload integrity ─────────────────────────────────────────────────────────

@pytest.mark.unit
def test_payload_original_input_never_mutated(minimal_payload):
    """original_input must remain unchanged after any gate modifies current_text."""
    original = minimal_payload.original_input
    minimal_payload.current_text = "[REDACTED]"
    assert minimal_payload.original_input == original


@pytest.mark.unit
def test_payload_is_blocked_defaults_false(minimal_payload):
    assert minimal_payload.is_blocked is False


@pytest.mark.unit
def test_payload_metrics_starts_empty(minimal_payload):
    assert minimal_payload.metrics == []


@pytest.mark.unit
def test_payload_raw_traces_starts_empty(minimal_payload):
    assert minimal_payload.raw_traces == {}


# ── Pipeline execution flow ───────────────────────────────────────────────────

@pytest.mark.unit
def test_off_mode_gate_skips_execution(pipeline_manager):
    """A gate in OFF mode must add zero entries to payload.metrics."""
    # TODO (Phase 2)
    pass


@pytest.mark.unit
def test_audit_mode_does_not_block(pipeline_manager):
    """A gate in AUDIT mode must not halt the pipeline even if is_blocked is set."""
    # TODO (Phase 2)
    pass


@pytest.mark.unit
def test_enforce_mode_halts_on_block(pipeline_manager):
    """A gate in ENFORCE mode must return a refusal payload when is_blocked=True."""
    # TODO (Phase 2)
    pass


@pytest.mark.unit
def test_enforce_mode_continues_when_safe(pipeline_manager):
    """A gate in ENFORCE mode must allow the pipeline to continue when is_blocked=False."""
    # TODO (Phase 2)
    pass


@pytest.mark.unit
def test_blocked_pipeline_skips_inference(pipeline_manager):
    """If any ENFORCE gate blocks, the target LLM must not be called."""
    # TODO (Phase 2)
    pass


@pytest.mark.unit
def test_output_gates_do_not_run_after_input_block(pipeline_manager):
    """Output gates must be skipped when an input gate blocks in ENFORCE mode."""
    # TODO (Phase 2)
    pass


@pytest.mark.unit
def test_metrics_accumulate_across_gates(pipeline_manager):
    """Each gate that runs must append exactly one entry to payload.metrics."""
    # TODO (Phase 2)
    pass
