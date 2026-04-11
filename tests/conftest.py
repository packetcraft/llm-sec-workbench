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

llm_guard stubs
---------------
llm_guard is an optional ML dependency that may not be installed in all test
environments.  The ``_stub_llm_guard`` session fixture injects lightweight
MagicMock modules into ``sys.modules`` so that:

  1. ``patch("llm_guard.input_scanners.BanTopics", ...)`` and similar targets
     can be resolved by unittest.mock without the library being installed.
  2. Gates that import from llm_guard at the top of ``_scan()`` receive a
     MagicMock object instead of raising ModuleNotFoundError, allowing
     early-return (SKIP) paths to be tested in isolation.

If llm_guard IS installed, the real modules are already in sys.modules and
the stub is skipped, so production tests run against the real library.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest

from core.payload import PipelinePayload


# ── llm_guard optional-dependency stubs ──────────────────────────────────────


@pytest.fixture(autouse=True, scope="session")
def _stub_llm_guard():
    """Inject MagicMock stubs for llm_guard sub-modules when not installed.

    The stubs allow ``patch("llm_guard.output_scanners.Deanonymize", ...)``
    targets to resolve and let gate early-return paths be exercised without
    the full ML stack.  Tests that supply their own ``patch()`` mocks are
    unaffected: ``patch()`` sets the attribute on the stub module before the
    test body runs and restores it afterward.
    """
    if "llm_guard" not in sys.modules:
        # Top-level stub
        stub_root = MagicMock(name="llm_guard")
        sys.modules["llm_guard"] = stub_root

        # Sub-module stubs (must be registered as real sys.modules entries so
        # that ``from llm_guard.X import Y`` works inside gate _scan() methods)
        for sub in ("input_scanners", "output_scanners", "vault"):
            fq = f"llm_guard.{sub}"
            stub = MagicMock(name=fq)
            sys.modules[fq] = stub
            setattr(stub_root, sub, stub)

    yield  # tests run here

    # No cleanup: stubs can stay for the session lifetime.


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
