# AbuseIPDB Scanner

Query AbuseIPDB for IPs, CIDR blocks, files of IPs, or full country allocations, and export results as CSV, TSV, JSON, or JSONL. Designed for quick lookups, bulk workflows, and downstream automation/AI ingestion.

## Features

- Single IP and CIDR block lookups (AbuseIPDB v2)
- File parsing for IPv4 lists (deduplicated)
- Country-wide scanning via allocation lists (NirSoft)
- Multiple output formats: CSV, TSV, JSON, JSONL
- Optional category name translation for reports

## Quickstart

```bash
git clone https://github.com/mikebanks/AbuseIPdbSCAN.git
cd AbuseIPdbSCAN
python3 -m pip install -r requirements.txt
```

Configure your AbuseIPDB API key (see Configuration). Then run, for example:

```bash
python3 AbuseIPDB.py -i 1.1.1.1 -j result.json
```

## Requirements

- Python 3.10+ (tested with 3.13)
- Dependencies in `requirements.txt`

Install with pip:

```bash
python3 -m pip install -r requirements.txt
```

Or with Pipenv:

```bash
pipenv install
pipenv run python AbuseIPDB.py -v
```

## Configuration

You need an AbuseIPDB API key. See the official docs: https://docs.abuseipdb.com/

The tool reads `API_KEY` from environment variables or a local `.env` file:

- Option A (environment): `export API_KEY=your_key_here`
- Option B (dotenv file): create a `.env` in the repo root with:

```
API_KEY=your_key_here
```

Tip: On first run, if `API_KEY` isn’t found, the script will prompt you and create `.env` automatically.

## Usage

General form (write results to a file when using a format flag):

```bash
python3 AbuseIPDB.py [INPUT] [OPTIONS]
```

Inputs (choose one):

- `-i, --ip <IP>`: Lookup a single IP address
- `-b, --block <CIDR>`: Lookup a CIDR block (AbuseIPDB accepts /24 or smaller)
- `-f, --file <path>`: Parse a file and lookup all IPv4 addresses found
- `-cc, --countrycode <cc>`: Scan all /24 subnets for a country code (NirSoft list)

Options:

- `-d, --days <int>`: Max age of reports to include (default: 30)
- `-x, --translate`: Translate numeric categories to names when present
- `-v, --version`: Show version and exit

Output formats (provide a filename to write results):

- `-j, --json <file>`: JSON array (recommended for sharing)
- `-l, --jsonl <file>`: JSON Lines, one object per line (recommended for AI/ETL)
- `-c, --csv <file>`: Comma-separated values
- `-t, --tsv <file>`: Tab-separated values

Note: If no output flag is provided, results are printed to stdout as Python structures. Prefer `--json`/`--jsonl` for stable, machine-readable output.

## Examples

Single IP (pretty JSON saved to a file):

```bash
python3 AbuseIPDB.py -i 8.8.8.8 -j out.json
```

CIDR block (/24 or smaller):

```bash
python3 AbuseIPDB.py -b 1.1.1.0/24 -l out.jsonl
```

Parse a file of IPs and translate categories to names:

```bash
python3 AbuseIPDB.py -f example_list.txt -x -j out.json
```

Scan all /24s in a country (heavy; mind rate limits):

```bash
python3 AbuseIPDB.py -cc nz -l nz.jsonl
```

Sample outputs are in `reports/`:

- `reports/example_list.json`
- `reports/example_list.jsonl`
- `reports/example_list.csv`
- `reports/example_list.tsv`

## Output Schema (overview)

Returned objects mirror AbuseIPDB v2 responses with a few conveniences. Typical top-level fields include:

- `ipAddress`, `ipVersion`, `isPublic`, `isWhitelisted`
- `countryCode`, `countryName`, `domain`, `isp`, `usageType`
- `abuseConfidenceScore`, `totalReports`, `numDistinctUsers`, `lastReportedAt`
- `reports`: list of report objects with `categories`, `comment`, `reportedAt`, `reporterCountryCode`, `reporterCountryName`, `reporterId`

When `--translate` is used on IP lookups, `reports[*].categories` will contain category names instead of integers.

Example (truncated):

```json
{
  "ipAddress": "8.8.8.8",
  "abuseConfidenceScore": 0,
  "totalReports": 15,
  "reports": [
    { "categories": [15], "comment": "…", "reportedAt": "2020-04-02T01:32:48+01:00" }
  ]
}
```

## Notes for Automation and AI

- Prefer `--jsonl` for large/batch jobs; it’s line-delimited and stream-friendly.
- Keys are stable and predictable; JSON output uses sorted keys for consistency.
- Use `--translate` to convert numeric categories to readable labels before ingestion.
- For reproducibility, pin `requirements.txt` and record CLI invocations alongside outputs.

## Troubleshooting

- Private IPs: Private addresses/blocks are skipped with a message.
- Large blocks: AbuseIPDB requires /24 or smaller; larger blocks will be rejected.
- HTTP 503: The tool retries on some transient errors when checking blocks; try again later if issues persist.
- Country scans: This uses NirSoft allocation data. Invalid codes return 404; see https://www.nirsoft.net/countryip/ for available codes. Country scans can be slow and may hit rate limits.

## Security and Privacy

- Keep your `API_KEY` secret. Do not commit `.env` files.
- Outputs may contain reporter metadata and comments. Handle and share responsibly.

## Acknowledgements

- AbuseIPDB: https://www.abuseipdb.com/
- NirSoft Country IP Lists: https://www.nirsoft.net/countryip/

## License

No license file is present in this repository. If you plan to use or distribute this project, please open an issue to clarify licensing.
