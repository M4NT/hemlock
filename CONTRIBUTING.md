# Contributing to Hemlock

## Adding a new attack

1. Create `attacks/my_attack_name.py`
2. Define a class that inherits from `Attack`
3. Set `name`, `reference`, implement `setup()`, `run()`, `_score()`
4. Add tests in `tests/test_my_attack_name.py`

That's it — the registry picks it up automatically. No changes to `__init__.py`, `cli.py`, or `scorer.py`.

```python
from hemlock.pipeline import RetrievalTrace
from .base import Attack, AttackResult

TRIGGER_QUERY = "..."
SUCCESS_MARKERS = ["..."]

class MyAttack(Attack):
    name = "My Attack"
    reference = "Author et al. (2024) — arxiv:XXXX.XXXXX"

    def setup(self) -> None:
        self.pipeline.reset()
        self.pipeline.ingest_text("legit doc", metadata={"source": "legit"})
        self.pipeline.ingest_text("malicious doc", metadata={"source": "malicious"})

    def run(self) -> AttackResult:
        self.setup()
        trace = self.pipeline.query(TRIGGER_QUERY)
        succeeded = self._score(trace)
        return AttackResult(
            attack_name=self.name,
            reference=self.reference,
            succeeded=succeeded,
            trace=trace,
        )

    def _score(self, trace: RetrievalTrace) -> bool:
        return any(m in trace.response.lower() for m in SUCCESS_MARKERS)
```

## Adding a new defense

Implement one of the ABCs in `defenses/base.py`:

- `IngestDefense.inspect(doc)` → `(doc | None, DefenseReport)` — return `None` to reject
- `RetrievalDefense.filter(chunks)` → `(safe_chunks, reports)`
- `OutputDefense.validate(response)` → `DefenseReport`

Then add it to `defenses/__init__.py`.

## Running tests

```bash
pip install -e ".[dev]"
pytest
```

Tests use `MockLLM` and in-memory ChromaDB — no API keys needed.

## Linting

```bash
ruff check .
ruff check . --fix
```

## Building the wheel

```bash
python -m build
twine check dist/*
```
