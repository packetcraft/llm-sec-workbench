"""
tests/conftest.py
─────────────────
Shared pytest fixtures for the LLM Security Workbench test suite.

Fixtures
--------
payload         — minimal input-side PipelinePayload ("Hello world").
output_payload  — payload with output_text set (for output gate tests).
make_payload    — factory fixture for custom payloads.
mock_llm_result — a simple namespace object standing in for OllamaClient.generate().
"""

from __future__ import annotations

import types

import pytest

from core.payload import PipelinePayload


# ── Basic payload fixtures ────────────────────────────────────────────────────


@pytest.fixture
def payload() -> PipelinePayload:
    """Minimal input-side payload. No output_text."""
    return PipelinePayload(
        original_input="Hello world",
        current_text="Hello world",
    )


@pytest.fixture
def output_payload() -> PipelinePayload:
    """Payload with output_text set — used by output gate tests."""
    p = PipelinePayload(
        original_input="What is the capital of France?",
        current_text="What is the capital of France?",
    )
    p.output_text = "The capital of France is Paris."
    return p


@pytest.fixture
def make_payload():
    """Factory for custom payloads.

    Usage::

        def test_something(make_payload):
            p = make_payload("my input", output="my output")
    """
    def _factory(
        input_text: str = "Hello",
        output: str = "",
    ) -> PipelinePayload:
        p = PipelinePayload(
            original_input=input_text,
            current_text=input_text,
        )
        p.output_text = output
        return p

    return _factory


# ── Mock LLM result ───────────────────────────────────────────────────────────


@pytest.fixture
def mock_llm_result():
    """Stand-in for the object returned by OllamaClient.generate()."""
    return types.SimpleNamespace(
        output_text="Mocked LLM response.",
        prompt_tokens=10,
        completion_tokens=5,
        tokens_per_second=42.0,
    )
