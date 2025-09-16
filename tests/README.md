Tests

Lightweight CLI tests using pytest. These tests avoid network calls and
validate argument handling, version/help output, private IP/block behavior,
and CIDR validation.

Requirements:
- Python 3.10+
- pytest (`python3 -m pip install pytest`), or use `requirements-dev.txt`.

Run from repo root:

```bash
python3 -m pip install -r requirements-dev.txt
pytest -q
```

