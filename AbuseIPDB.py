#!/usr/bin/python3
import os
import re
import csv
import time
import json
import codecs
import socket
import os.path
import netaddr
import argparse
import requests
import ipaddress
import urllib.request as urllib
import urllib.request as urlRequest
import urllib.parse as urlParse

from dotenv import load_dotenv


# Setup API Key
while os.getenv('API_KEY') is None:
    load_dotenv()
    if os.getenv('API_KEY'):
        api_key = os.getenv('API_KEY')
    else:
        with open('.env', 'w') as outfile:
            setKey = input(
                'Config File Not Found....\nCreating...\nEnter you API Key for AbuseIPDB: ')
            outfile.write(f'API_KEY={setKey}')


parser = argparse.ArgumentParser(
    description='This program utilizes the Abuse IP Database from: AbuseIPDB.com to perform queries about IP addresses and returns the output to standard out.'
)
# Inputs
required = parser.add_mutually_exclusive_group()
required.add_argument(
    "-f",
    "--file",
    help="parses IP Addresses from a single given file",
    action="store")
required.add_argument(
    "-i",
    "--ip",
    help="lookup a single IP address",
    action="store")
required.add_argument(
    "-b",
    "--block",
    help="lookup an IP block",
    action="store")
required.add_argument(
    "-cc",
    "--countrycode",
    help="Select a country code to check IP range",
    action="store")

# Outputs
outputs = parser.add_mutually_exclusive_group()
outputs.add_argument(
    "-c", "--csv", help="outputs items in comma seperated values",  action="store")
outputs.add_argument(
    "-j", "--json", help="outputs items in json format (reccomended)",  action="store")
outputs.add_argument(
    "-l", "--jsonl", help="outputs items in jsonl format (reccomended",  action="store")
outputs.add_argument(
    "-t", "--tsv", help="outputs items in tab seperated values (Default)", action="store")

# Additional Options
parser.add_argument(
    "-d", "--days", help="take in the number of days in history to go back for IP reports. Default: 30 Days", type=int)
parser.add_argument("-x", "--translate",
                    help="By default categories are numbers, with this flag it will convert them to text",  action="store_true")
parser.add_argument(
    "-v", "--version", help="show program version", action="store_true")

args = parser.parse_args()


def get_cat(x):
    return {
        0: 'BLANK',
        3: 'Fraud_Orders',
        4: 'DDoS_Attack',
        5: 'FTP_Brute-Force',
        6: 'Ping of Death',
        7: 'Phishing',
        8: 'Fraud VoIP',
        9: 'Open_Proxy',
        10: 'Web_Spam',
        11: 'Email_Spam',
        12: 'Blog_Spam',
        13: 'VPN IP',
        14: 'Port_Scan',
        15: 'Hacking',
        16: 'SQL Injection',
        17: 'Spoofing',
        18: 'Brute_Force',
        19: 'Bad_Web_Bot',
        20: 'Exploited_Host',
        21: 'Web_App_Attack',
        22: 'SSH',
        23: 'IoT_Targeted',
    }.get(
        x,
        'UNK CAT, ***REPORT TO MAINTAINER***OPEN AN ISSUE ON GITHUB w/ IP***')


def check_block(ip_block, days):
    if ipaddress.ip_network(ip_block, False).is_private is False:
        headers = {
            'Key': api_key,
            'Accept': 'application/json',
        }

        params = {
            'maxAgeInDays': days,
            'network': f'{ip_block}'
        }

        while True:
            r = requests.get(
                'https://api.abuseipdb.com/api/v2/check-block', headers=headers, params=params)
            if r.status_code == 503:
                print(
                    f"Error: abuseIPDB returned a 503 for {ip_block}")
            else:
                break

        response = r.json()
        if 'errors' in response:
            print(f"Error: {response['errors'][0]['detail']}")
            exit(1)
        else:
            logs = []
            logs.append(response['data'])
            return logs

    else:
        return (f"{ip_block} is a private block")


def check_ip(IP, days):
    if ipaddress.ip_address(IP).is_private is False:
        headers = {
            'Key': api_key,
            'Accept': 'application/json',
        }

        params = {
            'maxAgeInDays': days,
            'ipAddress': IP,
            'verbose': ''
        }

        r = requests.get('https://api.abuseipdb.com/api/v2/check',
                         headers=headers, params=params)
        response = r.json()
        if 'errors' in response:
            print(f"Error: {response['errors'][0]['detail']}")
            exit(1)
        else:
            if args.translate:
                if response['data']['totalReports'] > 0:
                    for report in response['data']['reports']:
                        tmp_catergory = []
                        category = report['categories']
                        for cat in category:
                            tmp_catergory.append(get_cat(cat))
                        report['categories'] = tmp_catergory
            return response['data']
    else:
        return (f"{IP} is private. No Resuls")


def check_file(file, days):
    logs = []
    found = []
    with open(file) as f:
        file_item = f.read()
        regex = r'(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))'

        matches = re.finditer(regex, file_item, re.MULTILINE)

        [found.append(match.group())
         for matchNum, match in enumerate(matches, start=1)]
        found = set(found)
        for match in found:
            logs.append(check_ip(match, days))
    return logs


def make_subnet(block):
    # Setting to /24 as AbuseIPDB doesn't support anything larger
    ip = netaddr.IPNetwork(block)
    return list(ip.subnet(24))


def search_cc(days):
    logs = []
    try:
        url = f"https://www.nirsoft.net/countryip/{args.countrycode}.csv"
        req = urlRequest.Request(url)
        x = urlRequest.urlopen(req)
        ip_blocks = x.read().decode('utf-8')
        cr = csv.reader(ip_blocks.splitlines())
        for row in cr:
            if row:
                startip = row[0]
                endip = row[1]
                block = netaddr.iprange_to_cidrs(startip, endip)[0]
                subnets = make_subnet(block)
                for ip_range_24 in subnets:
                    logs.append(check_block(ip_range_24, days))
            return logs

    except urllib.URLError as e:
        if '404' in str(e):
            print(f"{url} not a valid url")
            print(
                "List of countries codes can be found at https://www.nirsoft.net/countryip/")
        else:
            print(f"Error: {e.reason}")

        exit()


def get_report(logs):
    if logs:
        # Output options
        if args.csv:
            try:
                keys = logs[0].keys()
            except KeyError:
                keys = logs.keys()
            
            with open(args.csv, 'w') as outfile:
                dict_writer = csv.DictWriter(
                    outfile, keys, quoting=csv.QUOTE_ALL)
                dict_writer.writeheader()
                dict_writer.writerows(logs)
            pass
        elif args.tsv:
            keys = logs[0].keys()
            with open(args.tsv, 'w') as outfile:
                dict_writer = csv.DictWriter(outfile, keys, delimiter='\t')
                dict_writer.writeheader()
                dict_writer.writerows(logs)
            pass
        elif args.jsonl:
            json_logs = json.dumps(logs)
            with open(args.jsonl, 'w') as outfile:
                for log in logs:
                    json.dump(log, outfile)
                    outfile.write('\n')
            pass
        elif args.json:
            with open(args.json, 'w') as outfile:
                json.dump(logs, outfile, indent=4, sort_keys=True)
            pass
        else:
            print(logs)
            pass
    else:
        pass


def main():
    if args.days:
        days = args.days
    else:
        days = 30

    if args.file:
        get_report(check_file(args.file, days))
    elif args.ip:
        get_report(check_ip(args.ip, days))
    elif args.block:
        regex = '^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([2][4-9]|3[0-2]))?$'
        valid_block = re.findall(regex, args.block)
        if valid_block:
            get_report(check_block(args.block, days))
        else:
            exit(
                "Not valid CIDR or Not within the accepted Block. Note: AbuseIPDB only accepts /24+")
    elif args.countrycode:
        get_report(search_cc(days))
    elif args.version:
        print(f"{parser.prog} Version: 2.1")
    else:
        exit(
            "Error: one of the following arguments are required: -f/--file, -i/--ip, -b/--block or -cc/--countrycode")


if __name__ == '__main__':
    main()
