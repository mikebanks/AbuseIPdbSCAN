#! /bin/python/env
import codecs
import argparse
import re
import sys
import requests
import ipaddress
import socket
import time
from sys import argv

api_key = 'YOUR_API_KEY_HERE'

parser = argparse.ArgumentParser(
    description='This program utilizes the Abuse IP Database from: AbuseIPDB.com to perform queries about IP addresses and returns the output to standard out.'
)
required = parser.add_argument_group('required arguments')
required.add_argument(
    "-f",
    "--file",
    help="parses IP Addresses from a single given file",
    action="store",
    required=True)


parser.add_argument("-t", "--tsv", help="outputs items in tab seperated values (Default)", action="store_true")
parser.add_argument("-c", "--csv", help="outputs items in comma seperated values",  action="store_true")

args = parser.parse_args()

def get_file(infile):
    with codecs.open(infile, "r", encoding='utf-8', errors='ignore') as f:
        return f.read()


def get_cat(x):
    return {
        3: 'Frad_Orders',
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


def get_report(IP):
    request = 'https://www.abuseipdb.com/check/%s/json?key=%s' % (IP, api_key)
    # DEBUG
    # print(request)
    r = requests.get(request)
    # DEBUG
    # print(r.json())
    try:
        data = r.json()
        if data == []:
            print("%s:  No Abuse Reports" % IP)
        else:
            for record in data:
                log = []
                ip_address = ("Alert for %s:" % IP)
                # ip_address = record['ip']
                country = record['country']
                # iso_code = record['isoCode']
                category = record['category']
                created = record['created']
                log.append(ip_address)
                log.append(country)
                # log.append(iso_code)
                log.append(created)
                for cat in category:
                    temp_cat = get_cat(cat)
                    log.append(temp_cat)
                    if args.csv:
                       print(','.join(log))
                    else: 
                        print('\t'.join(log))
                    log.remove(temp_cat)
    except (ValueError, KeyError, TypeError):
        #log = []
        ip_address = ("Alert for %s:" % IP)
        # ip_address = record['ip']
        country = data['country']
        # iso_code = record['isoCode']
        category = data['category']
        created = data['created']
        log.append(ip_address)
        log.append(country)
        # log.append(iso_code)
        log.append(created)
        for cat in category:
            temp_cat = get_cat(cat)
            log.append(temp_cat)
            if args.csv:
                print(','.join(log))
            else: 
                print('\t'.join(log))
            log.remove(temp_cat)


def main():
    if args.file:
        f = get_file(argv[2])
        found = re.findall(
            r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', f)

        list(set(found))

        print("Abuse IP Database REPORT:")
        count = 0
        for ip in found:
            try:
                socket.inet_aton(ip)
            except socket.error:
                continue

            if ipaddress.ip_address(ip).is_private is False:
                if count == 59:
                    time.sleep(60)
                    count = 0
                get_report(ip)
                count += 1


if __name__ == '__main__':
    main()
