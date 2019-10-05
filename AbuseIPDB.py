#!/usr/bin/python3
import argparse
import codecs
import csv
import ipaddress
import json
import netaddr
import os.path
import re
import requests
import socket
import time
import urllib.request as urllib
import urllib.request as urlRequest
import urllib.parse as urlParse

api_key = 'YOUR_API_KEY_HERE'

parser = argparse.ArgumentParser(
    description='This program utilizes the Abuse IP Database from: AbuseIPDB.com to perform queries about IP addresses and returns the output to standard out.'
)
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
parser.add_argument(
    "-c", "--csv", help="outputs items in comma seperated values",  action="store")
parser.add_argument(
    "-j", "--json", help="outputs items in json format",  action="store")
parser.add_argument(
    "-l", "--jsonl", help="outputs items in jsonl format",  action="store")
parser.add_argument(
    "-t", "--tsv", help="outputs items in tab seperated values (Default)", action="store")

# Additional Options
parser.add_argument(
    "-d", "--days", help="take in the number of days in history to go back for IP reports. Default: 30 Days", type=int)
parser.add_argument("-x", "--translate",
                    help="By default categories are numbers, with this flag it will convert them to text",  action="store_true")
parser.add_argument(
    "-v", "--version', action='version', version='%(prog)s 2.0")

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
    if ipaddress.ip_network(ip_block).is_private is False:
        headers = {
            'Key': api_key,
            'Accept': 'application/json',
        }

        params = {
            'maxAgeInDays': days,
            'network': '{0}'.format(ip_block)
        }

        while True:
            r = requests.get('https://api.abuseipdb.com/api/v2/check-block',headers=headers, params=params)
            if r.status_code == 503:
                print("Error: abuseIPDB returned a 503 for {0}".format(ip_block))
            else:
                break
            
        response = r.json()
        if 'errors' in response:
            print("Error: {0}".format(response['errors'][0]['detail']))
            exit(1)
        else:
            print("Report IP's in {0} Block: {1}".format(
                ip_block, len(response['data']['reportedAddress'])))
            for reports in response['data']['reportedAddress']:
                if args.countrycode is None or args.countrycode.lower() in reports['countryCode'].lower():
                    check_ip(reports['ipAddress'], days)
    else:
        print("{0} is a private block".format(ip_block))


def check_ip(IP, days):
    logs = []
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

        r = requests.get('https://api.abuseipdb.com/api/v2/check',headers=headers, params=params)
        response = r.json()
        if 'errors' in response:
            print("Error: {0}".format(response['errors'][0]['detail']))
            exit(1)
        else:
            for reports in response['data']['reports']:
                reports['ipAddress'] = response['data']['ipAddress']
                reports['isp'] = response['data']['isp']
                reports['domain'] = response['data']['domain']
                reports['usageType'] = response['data']['usageType']
                reports['countryName'] = response['data']['countryName']
                reports['isWhitelisted'] = response['data']['isWhitelisted']
                reports['abuseConfidenceScore'] = response['data']['abuseConfidenceScore']
                reports['totalReports'] = response['data']['totalReports']
                logs.append(reports)
            get_report(logs)
    else:
        exit("A Private IP will return no result...")

def check_file(file,days):
    logs = []
    file_list = [line.rstrip('\n') for line in open(file)]
    for file_item in file_list:
        if file_item:
            if "/" in file_item:
                subnets = make_subnet_24(file_item)
                for ip_range_24 in subnets:
                    check_block(ip_range_24, days)
            else:
                found = re.findall(
                    r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', file_item)
                list(found)
                for ip in found:
                    check_ip(ip, days)

def make_subnet_24(block):
    # Need to make range /24 as AbuseIPDB doesn't support anything larger
    ip = netaddr.IPNetwork(block)
    return list(ip.subnet(24))


def search_cc(days):
    try:
        url = "https://www.nirsoft.net/countryip/{0}.csv".format(
            args.countrycode)
        req = urlRequest.Request(url)
        x = urlRequest.urlopen(req)
        ip_blocks = x.read().decode('utf-8')
        cr = csv.reader(ip_blocks.splitlines())
        for row in cr:
            if row:
                startip = row[0]
                endip = row[1]
                block = netaddr.iprange_to_cidrs(startip, endip)[0]
                subnets = make_subnet_24(block)
                for ip_range_24 in subnets:
                    if str(ip_range_24) not in open('checked.txt').read():
                        check_block(ip_range_24, days)
                        print(ip_range_24,  file=open('checked.txt', 'a'))
                    else:
                        #print("Already checked {0}".format(ip_range_24))
                        pass
    except urllib.URLError as e:
        if '404' in str(e):
            print("{0} not a valid url".format(url))
            print(
                "List of countries codes can be found at https://www.nirsoft.net/countryip/")
        else:
            print("Error: {0}".format(e.reason))

        exit()


def get_report(logs):
    if logs:
        # Convert category numbers to words
        if args.translate:
            for log in logs:
                tmp_catergory = []
                category = log['categories']
                for cat in category:
                    tmp_catergory.append(get_cat(cat))
                log['categories'] = tmp_catergory

        # Output options
        if args.csv:
            keys = logs[0].keys()
            if not os.path.isfile(args.csv):
                with open(args.csv, 'a') as outfile:
                    dict_writer = csv.DictWriter(outfile, keys,quoting=csv.QUOTE_ALL)
                    dict_writer.writeheader()
                    dict_writer.writerows(logs)
            else:
                with open(args.csv, 'a') as outfile:
                    dict_writer = csv.DictWriter(outfile, keys,quoting=csv.QUOTE_ALL)
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
                json.dump(logs, outfile)
            pass
        else:
            for log in logs:
                print(log)
            pass
    else:
        pass


def main():
    if args.days:
        days = args.days
    else:
        days = 30

    if not os.path.isfile('checked.txt'):
        print(file=open('checked.txt', 'w'))

    if args.file:
        check_file(args.file, days)
    elif args.ip:
        check_ip(args.ip, days)
    elif args.block:
        subnets = make_subnet_24(args.block)
        for ip_range_24 in subnets:
            check_block(ip_range_24, days)
    elif args.countrycode:
        search_cc(days)
    else:
        exit(
            "Error: one of the following arguments are required: -f/--file, -i/--ip, -b/--block or -cc/--countrycode")


if __name__ == '__main__':
    main()
