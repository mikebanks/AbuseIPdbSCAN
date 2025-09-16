#!/usr/bin/env bash
set -euo pipefail

# Simple walkthrough of common invocations.
# It writes outputs into examples/out/.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCRIPT_DIR%/examples}"
cd "$REPO_ROOT"

mkdir -p examples/out

echo "AbuseIPDB Scanner quickstart"
echo "Version:" $(python3 AbuseIPDB.py -v || true)

if [[ ! -f .env && -z "${API_KEY:-}" ]]; then
  echo "API_KEY not found in environment or .env."
  echo "Run: python3 AbuseIPDB.py --init  # to create .env"
  echo "Or: export API_KEY=your_key_here"
  exit 1
fi

echo
echo "1) Single IP lookup (stdout JSON)"
python3 AbuseIPDB.py -i 8.8.8.8 || true

echo
echo "2) CIDR block lookup (/24) -> JSONL file"
python3 AbuseIPDB.py -b 1.1.1.0/24 -l examples/out/block.jsonl || true
echo "Wrote: examples/out/block.jsonl"

echo
echo "3) Parse a file of IPs with category translation -> JSON file"
python3 AbuseIPDB.py -f example_list.txt -x -j examples/out/file.json || true
echo "Wrote: examples/out/file.json"

echo
echo "4) Country scan (NirSoft) -> JSONL file (may be slow)"
echo "Note: Throttle with --sleep and limit with --limit to avoid rate limits."
python3 AbuseIPDB.py -cc nz --limit 50 --sleep 0.5 -l examples/out/nz.jsonl || true
echo "Wrote: examples/out/nz.jsonl"

echo
echo "Done. Check examples/out for outputs."
