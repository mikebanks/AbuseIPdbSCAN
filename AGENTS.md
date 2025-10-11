# Repository Guidelines

## Project Structure & Module Organization
- Primary CLI logic lives in `AbuseIPDB.py` at the repo root; the console entrypoint is registered as `abuseipdb-scan`.
- `tests/` hosts the pytest suite; start with `tests/test_cli.py` and the companion README for context.
- `examples/` contains runnable scripts (e.g. `quickstart.sh`) that demonstrate workflows and write to `examples/out/`.
- `reports/` stores sample outputs; reuse these for manual regression comparisons before publishing results.
- Packaging metadata sits in `pyproject.toml`, `MANIFEST.in`, and `abuseipdbscanner.egg-info`; update them together for releases.

## Build, Test, and Development Commands
- `python3 -m pip install -r requirements.txt` – install baseline runtime dependencies.
- `python3 -m pip install -r requirements-dev.txt` – add pytest and tooling used in CI.
- `python3 AbuseIPDB.py --help` – quick smoke test of the CLI and argparse wiring.
- `pytest -q` – execute the fast CLI suite; combine with `-k` to target specific cases.
- `pipenv run python AbuseIPDB.py -v` – mirrors the Pipenv workflow referenced in documentation.

## Coding Style & Naming Conventions
Write Python 3.10+ with 4-space indentation and PEP 8 naming (`snake_case` for functions, `UPPER_SNAKE` for constants such as `DEFAULT_USER_AGENT`). Maintain type hints and docstrings that clarify HTTP retry behaviour, input parsing, and serialization branches. Follow the existing argparse layout: group inputs, outputs, and options in contiguous blocks and keep help strings concise. Avoid introducing third-party dependencies without discussing compatibility and packaging impacts.

## Testing Guidelines
Pytest drives coverage; extend `tests/test_cli.py` or nearby `test_*.py` modules for new behaviours. Match the current pattern of command invocations that assert exit codes, stdout/stderr messaging, and output file creation. Run `pytest -q` locally before opening a PR and add fixtures for any new sample files. When testing authentication paths, mock environment variables rather than reading real secrets.

## Commit & Pull Request Guidelines
History shows conventional prefixes (`fix:`, `docs:`, `test:`); continue that style with short, imperative subjects and optional bullet lists in the body. Keep each PR focused, link related issues, and describe runtime or packaging effects. Attach sample command output or screenshots when behaviour changes, update `README.md` or `examples/` as needed, and confirm CI checks before requesting review.

## Security & Configuration Tips
Never commit `.env` or real API keys; rely on `.env.example` and `python3 AbuseIPDB.py --init` for local setup. Obfuscate IPs in shared artefacts, respect AbuseIPDB rate limits, and keep `--sleep` defaults user-tunable.
