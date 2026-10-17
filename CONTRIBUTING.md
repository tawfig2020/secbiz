# Contributing to Aegis

## Setup

```bash
# Core is stdlib-only; install optional dev tooling:
pip install -e ".[dev]"

# Or, without an editable install, the src/ layout is bootstrapped by
# _bootstrap.py (entrypoints) and tests/__init__.py (unittest).
```

## Running tests

```bash
python -m unittest discover -s tests -t .   # full suite
python validate.py                           # deploy gate (tests + regression)
python fuzz_gateway.py --iterations 5000     # fuzz harness
pytest -q                                    # optional (pytest + coverage)
```

## Quality gates

- `ruff check .` — lint.
- `mypy src/aegis` — type check.
- `bandit -r src/aegis` — security lint.
- `lint-imports` — dependency-direction enforcement (import-linter).
- `pytest --cov=aegis --cov-fail-under=85` — coverage gate.

## Architecture rules

1. `aegis/core` imports nothing from the rest of the package.
2. `aegis/capability_bounded` depends only on `core` + `semantic_gateway`.
3. `verticals`/`plugins`/`edge` are the outer shell; they never import
   `dashboard` or each other.
4. Every security control must trace to a threat in `docs/threat-model.md`.
5. New errors use the taxonomy in `aegis/core/errors.py` (never bare strings).

## Commit hygiene

- One logical change per commit.
- Security-relevant changes must add or update a test.
- Schema changes require a migration (`aegis/core/migrations.py`).

See `CHANGELOG.md` for the release history and `docs/adr/` for decisions.
