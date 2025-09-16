#!/usr/bin/python3
import os
import re
import csv
import time
import json
import sys
import netaddr
import argparse
import requests
import ipaddress

from dotenv import load_dotenv
from typing import Optional, Dict, Tuple, List, Any


DEFAULT_USER_AGENT = "AbuseIPDB-Scanner/2.2 (+https://github.com/mikebanks/AbuseIPdbSCAN)"

# Enforce Python version (allow -h/--help and -v/--version without hard fail)
if sys.version_info < (3, 10):
    allow_flags = {'-h', '--help', '-v', '--version'}
    if not any(f in sys.argv for f in allow_flags):
        sys.stderr.write("Python 3.10+ is required to run this tool.\n")
        sys.exit(3)


parser = argparse.ArgumentParser(
    description='Query AbuseIPDB for IPs, CIDR blocks, files of IPs, or country allocations, and export results.'
)
# Inputs
required = parser.add_mutually_exclusive_group()
required.add_argument(
    "-f",
    "--file",
    help="Parses IPv4 addresses from a given file",
    action="store")
required.add_argument(
    "-i",
    "--ip",
    help="Lookup a single IP address",
    action="store")
required.add_argument(
    "-b",
    "--block",
    help="Lookup a CIDR block (/24–/32 supported by AbuseIPDB)",
    action="store")
required.add_argument(
    "-cc",
    "--countrycode",
    help="Select a country code (NirSoft) to check all /24 ranges",
    action="store")

# Outputs
outputs = parser.add_mutually_exclusive_group()
outputs.add_argument(
    "-c", "--csv", help="Outputs items in comma separated values",  action="store")
outputs.add_argument(
    "-j", "--json", help="Outputs items in JSON format (recommended)",  action="store")
outputs.add_argument(
    "-l", "--jsonl", help="Outputs items in JSONL format (recommended)",  action="store")
outputs.add_argument(
    "-t", "--tsv", help="Outputs items in tab separated values", action="store")

# Additional Options
parser.add_argument(
    "-d", "--days", help="Number of days of report history to include (default: 30)", type=int)
parser.add_argument("-x", "--translate",
                    help="Translate numeric categories to labels for IP lookups",  action="store_true")
parser.add_argument(
    "-v", "--version", help="show program version", action="store_true")
parser.add_argument(
    "--init", help="Interactively create a .env with API_KEY", action="store_true")
parser.add_argument(
    "--limit", type=int, help="Max number of /24 subnets to check for --countrycode")
parser.add_argument(
    "--sleep", type=float, default=0.0, help="Seconds to sleep between API calls (useful for country scans)")

args = parser.parse_args()


def get_cat(x):
    # AbuseIPDB category IDs: https://www.abuseipdb.com/categories
    return {
        0: 'BLANK',
        1: 'DNS_Compromise',
        2: 'DNS_Poisoning',
        3: 'Fraud_Orders',
        4: 'DDoS_Attack',
        5: 'FTP_Brute-Force',
        6: 'Ping_of_Death',
        7: 'Phishing',
        8: 'Fraud_VoIP',
        9: 'Open_Proxy',
        10: 'Web_Spam',
        11: 'Email_Spam',
        12: 'Blog_Spam',
        13: 'VPN_IP',
        14: 'Port_Scan',
        15: 'Hacking',
        16: 'SQL_Injection',
        17: 'Spoofing',
        18: 'Brute_Force',
        19: 'Bad_Web_Bot',
        20: 'Exploited_Host',
        21: 'Web_App_Attack',
        22: 'SSH',
        23: 'IoT_Targeted',
    }.get(x, 'UNKNOWN_CATEGORY')


def print_err(msg: str) -> None:
    sys.stderr.write(str(msg).rstrip() + "\n")


def http_get(url: str, headers: Optional[Dict] = None, params: Optional[Dict] = None,
             timeout: int = 15, max_retries: int = 5, backoff: float = 1.5,
             retry_statuses: Tuple[int, ...] = (429, 500, 502, 503, 504)) -> requests.Response:
    """HTTP GET with basic retries and exponential backoff."""
    attempt = 0
    last_exc = None
    while attempt < max_retries:
        attempt += 1
        try:
            send_headers = dict(headers or {})
            send_headers.setdefault('User-Agent', DEFAULT_USER_AGENT)
            r = requests.get(url, headers=send_headers, params=params, timeout=timeout)
            if r.status_code in retry_statuses:
                sleep_for = backoff ** attempt
                print_err(f"HTTP {r.status_code} from {url}. Retry {attempt}/{max_retries} in {sleep_for:.1f}s…")
                time.sleep(sleep_for)
                continue
            return r
        except requests.RequestException as e:
            last_exc = e
            sleep_for = backoff ** attempt
            print_err(f"Request error contacting {url}: {e}. Retry {attempt}/{max_retries} in {sleep_for:.1f}s…")
            time.sleep(sleep_for)
    if last_exc:
        raise last_exc
    raise RuntimeError("Unreachable")


def check_block(ip_block: str, days: int, api_key: str) -> Optional[Dict[str, Any]]:
    net = ipaddress.ip_network(ip_block, False)
    if net.is_private:
        print_err(f"Skipping private block: {ip_block}")
        return None

    headers = {
        'Key': api_key,
        'Accept': 'application/json',
    }

    params = {
        'maxAgeInDays': days,
        'network': f'{ip_block}'
    }

    r = http_get('https://api.abuseipdb.com/api/v2/check-block', headers=headers, params=params)
    try:
        response = r.json()
    except ValueError:
        print_err(f"Non-JSON response for block {ip_block}: HTTP {r.status_code}")
        return None
    if 'errors' in response:
        print_err(f"Error for block {ip_block}: {response['errors'][0].get('detail', 'Unknown error')}")
        return None
    return response.get('data')


def check_ip(ip: str, days: int, api_key: str) -> Optional[Dict[str, Any]]:
    addr = ipaddress.ip_address(ip)
    if addr.is_private:
        print_err(f"Skipping private IP: {ip}")
        return None

    headers = {
        'Key': api_key,
        'Accept': 'application/json',
    }
    params = {
        'maxAgeInDays': days,
        'ipAddress': ip,
        'verbose': ''
    }

    r = http_get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
    try:
        response = r.json()
    except ValueError:
        print_err(f"Non-JSON response for IP {ip}: HTTP {r.status_code}")
        return None
    if 'errors' in response:
        print_err(f"Error for IP {ip}: {response['errors'][0].get('detail', 'Unknown error')}")
        return None

    data = response.get('data')
    if args.translate and data and data.get('totalReports', 0) > 0:
        for report in data.get('reports', []) or []:
            translated = [get_cat(cat) for cat in report.get('categories', [])]
            report['categories'] = translated
    return data


def check_file(file_path: str, days: int, api_key: str) -> List[Dict[str, Any]]:
    logs: List[Dict[str, Any]] = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        ipv4_re = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
        ips = {m.group(0) for m in ipv4_re.finditer(content)}
        for ip in sorted(ips):
            data = check_ip(ip, days, api_key)
            if data:
                logs.append(data)
    return logs


def make_subnet(block: netaddr.IPNetwork) -> List[netaddr.IPNetwork]:
    """Expand ranges to AbuseIPDB-supported CIDRs (/24–/32)."""
    ip = netaddr.IPNetwork(block)
    if ip.prefixlen < 24:
        return list(ip.subnet(24))
    if 24 <= ip.prefixlen <= 32:
        return [ip]
    return []


def search_cc(days: int, api_key: str) -> List[Dict[str, Any]]:
    logs: List[Dict[str, Any]] = []
    cc = (args.countrycode or '').lower()
    url = f"https://www.nirsoft.net/countryip/{cc}.csv"
    try:
        r = http_get(url, headers=None, params=None, timeout=20, max_retries=3)
        if r.status_code == 404:
            print_err(f"{url} not a valid url. See https://www.nirsoft.net/countryip/ for codes.")
            return logs
        ip_blocks = r.text
        cr = csv.reader(ip_blocks.splitlines())
        processed = 0
        max_items = args.limit if args.limit and args.limit > 0 else None
        delay = args.sleep if args.sleep and args.sleep > 0 else 0.0
        for row in cr:
            if not row:
                continue
            startip, endip = row[0], row[1]
            try:
                blocks = netaddr.iprange_to_cidrs(startip, endip)
            except Exception as e:
                print_err(f"Skipping invalid range {startip}-{endip}: {e}")
                continue
            for block in blocks:
                subnets = make_subnet(block)
                for ip_range_24 in subnets:
                    data = check_block(str(ip_range_24), days, api_key)
                    if data:
                        logs.append(data)
                    processed += 1
                    if delay:
                        time.sleep(delay)
                    if max_items is not None and processed >= max_items:
                        return logs
        return logs
    except requests.RequestException as e:
        print_err(f"Error fetching {url}: {e}")
        return logs


def _ensure_list(logs) -> List[Dict[str, Any]]:
    if logs is None:
        return []
    if isinstance(logs, dict):
        return [logs]
    if isinstance(logs, list):
        flat: list[dict] = []
        for item in logs:
            if isinstance(item, list):
                flat.extend([i for i in item if isinstance(i, dict)])
            elif isinstance(item, dict):
                flat.append(item)
        return flat
    return []


def get_report(logs) -> None:
    logs = _ensure_list(logs)
    if not logs:
        print_err("No results.")
        return

    # Build union of keys for consistent CSV/TSV
    keys = sorted({k for d in logs for k in d.keys()})

    if args.csv:
        with open(args.csv, 'w', newline='', encoding='utf-8') as outfile:
            dict_writer = csv.DictWriter(outfile, keys, quoting=csv.QUOTE_ALL, extrasaction='ignore')
            dict_writer.writeheader()
            dict_writer.writerows(logs)
    elif args.tsv:
        with open(args.tsv, 'w', newline='', encoding='utf-8') as outfile:
            dict_writer = csv.DictWriter(outfile, keys, delimiter='\t', extrasaction='ignore')
            dict_writer.writeheader()
            dict_writer.writerows(logs)
    elif args.jsonl:
        with open(args.jsonl, 'w', encoding='utf-8') as outfile:
            for log in logs:
                json.dump(log, outfile, sort_keys=True)
                outfile.write('\n')
    elif args.json:
        with open(args.json, 'w', encoding='utf-8') as outfile:
            json.dump(logs, outfile, indent=2, sort_keys=True)
    else:
        # Default to JSON on stdout for stability
        print(json.dumps(logs, indent=2, sort_keys=True))


def main():
    # Version early-exit
    if args.version:
        print(f"{parser.prog} Version: 2.2.1")
        sys.exit(0)

    # Optional interactive init
    if args.init:
        if os.path.exists('.env'):
            print_err(".env already exists; refusing to overwrite.")
            sys.exit(1)
        key = input('Enter your API Key for AbuseIPDB: ').strip()
        with open('.env', 'w', encoding='utf-8') as outfile:
            outfile.write(f'API_KEY={key}\n')
        print('.env created.')
        sys.exit(0)

    # Load API key
    load_dotenv()
    api_key = os.getenv('API_KEY')
    if not api_key:
        print_err('API_KEY not found. Set environment variable or create a .env file (see README).')
        sys.exit(2)

    days = args.days if args.days else 30

    if args.file:
        get_report(check_file(args.file, days, api_key))
    elif args.ip:
        get_report(check_ip(args.ip, days, api_key))
    elif args.block:
        regex = r'^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)\/(?:2[4-9]|3[0-2])$'
        valid_block = re.match(regex, args.block) is not None
        if valid_block:
            # Wrap single block result in list for reporting
            data = check_block(args.block, days, api_key)
            get_report([data] if data else [])
        else:
            print_err('Not a valid CIDR or not within accepted range. AbuseIPDB only accepts /24 to /32.')
            sys.exit(1)
    elif args.countrycode:
        get_report(search_cc(days, api_key))
    else:
        print_err('Error: one of the following arguments is required: -f/--file, -i/--ip, -b/--block or -cc/--countrycode')
        sys.exit(2)


if __name__ == '__main__':
    main()
