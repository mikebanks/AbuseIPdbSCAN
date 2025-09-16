Changelog

## v2.2 — Hardened CLI, normalized outputs, country scan controls

Release date: 2025-09-16

Features
- Default JSON stdout: When no output flag is provided, results print as pretty JSON to stdout.
- Country scan controls: New `--limit` to cap subnets and `--sleep` to throttle API calls for `--countrycode` scans.
- Category translation: Mapping expanded to cover AbuseIPDB categories 0–23.
- Examples: Added `examples/quickstart.sh` showcasing common invocations.

Stability and Correctness
- Output normalization: All code paths now produce a list of objects; single lookups are wrapped automatically. Writers handle union of keys.
- Private IP/blocks: Skipped with clear stderr notices, avoiding string returns that broke writers.
- Country scan fix: Processes the full NirSoft dataset (no premature return) and returns a flat list of results.
- HTTP robustness: Requests include timeouts, limited retries with exponential backoff, and a default User-Agent.

CLI and UX
- Improved help text and messages; fixed typos and clarified CIDR validation (/24–/32).
- Added `--init` to interactively create a `.env` with `API_KEY`.

Docs & Tooling
- README updated to reflect behavior and new flags; added notes on retries, stdout JSON, and automation tips.
- `.env.example` documents `--init`. `.gitignore` now ignores `examples/out/`.
- Tests: Added pytest-based CLI tests for non-network paths.

Breaking Changes
- Python 3.10+ is now required (enforced at runtime). `-h/--help` and `-v/--version` still work on older interpreters.

Upgrade Notes
- Ensure your environment uses Python 3.10+.
- Set `API_KEY` via environment or `.env` (use `--init` to create one interactively).
- For large country scans, consider `--limit` and `--sleep` to manage rate limits.

