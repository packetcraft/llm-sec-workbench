"""
tests/test_canary_token.py
──────────────────────────
Unit tests for CanaryTokenGate.
"""

from __future__ import annotations

import pytest

from core.payload import PipelinePayload
from gates.output.canary_token import CanaryTokenGate


def _metric(payload: PipelinePayload) -> dict:
    """Return the single metrics entry a gate appended."""
    assert len(payload.metrics) == 1
    return payload.metrics[0]


def _make(output_text: str = "") -> PipelinePayload:
    p = PipelinePayload(original_input="prompt", current_text="prompt")
    p.output_text = output_text
    return p


@pytest.mark.unit
class TestCanaryTokenGate:
    """CanaryTokenGate detection logic."""

    def test_name(self):
        gate = CanaryTokenGate(config={})
        assert gate.name == "canary_token"

    def test_skip_when_no_tokens_configured(self):
        gate = CanaryTokenGate(config={"tokens": []})
        payload = _make("leaking SECRET_123")
        gate.scan(payload)
        m = _metric(payload)
        assert m["verdict"] == "SKIP"
        assert payload.is_blocked is False

    def test_pass_when_no_tokens_found(self):
        gate = CanaryTokenGate(config={"tokens": ["SECRET_123", "IP_10.0.0.1"]})
        payload = _make("this is a clean response")
        gate.scan(payload)
        m = _metric(payload)
        assert m["verdict"] == "PASS"
        assert payload.is_blocked is False

    def test_block_when_token_found(self):
        gate = CanaryTokenGate(config={"tokens": ["SECRET_123", "IP_10.0.0.1"]})
        payload = _make("here is the leaked IP_10.0.0.1 token")
        gate.scan(payload)
        m = _metric(payload)
        assert m["verdict"] == "BLOCK"
        assert payload.is_blocked is True
        assert "IP_10.0.0.1" in m["detail"]

    def test_block_when_multiple_tokens_found(self):
        gate = CanaryTokenGate(config={"tokens": ["SECRET_123", "IP_10.0.0.1"]})
        payload = _make("leaking SECRET_123 and IP_10.0.0.1 together")
        gate.scan(payload)
        m = _metric(payload)
        assert m["verdict"] == "BLOCK"
        assert payload.is_blocked is True
        assert "SECRET_123" in m["detail"]
        assert "IP_10.0.0.1" in m["detail"]

    def test_case_sensitive_match(self):
        # Current implementation uses 'in', which is case-sensitive
        gate = CanaryTokenGate(config={"tokens": ["SECRET_123"]})
        payload = _make("leaking secret_123")
        gate.scan(payload)
        m = _metric(payload)
        assert m["verdict"] == "PASS"
        assert payload.is_blocked is False
