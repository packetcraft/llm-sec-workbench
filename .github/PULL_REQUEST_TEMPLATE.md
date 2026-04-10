## Summary

<!-- What does this PR do and why? 1-3 bullet points. -->

-
-

## Type of change

- [ ] Bug fix
- [ ] New feature / gate
- [ ] Refactor (no behavior change)
- [ ] Documentation
- [ ] CI / tooling

## Testing

- [ ] `pytest` passes locally with no failures
- [ ] New/changed gates include a unit test in `tests/test_gates.py`
- [ ] Tested manually against Ollama (specify model): ___________

## Gate checklist (if adding/modifying a gate)

- [ ] Inherits from `SecurityGate`
- [ ] `scan()` wraps all logic in `try-except` and never raises
- [ ] Appends `{gate_name, latency_ms, score, verdict}` to `payload.metrics`
- [ ] Stores raw traces in `payload.raw_traces[self.name]`
- [ ] Uses `payload.original_input` for classifiers, `payload.current_text` for inference input

## Security considerations

<!-- Does this PR introduce any new network calls, file I/O, subprocess usage, or user-controlled inputs?
     If yes, describe how they are handled safely. -->

N/A

## Screenshots / recordings (if UI changes)

<!-- Drag and drop a screenshot or screen recording here. -->
