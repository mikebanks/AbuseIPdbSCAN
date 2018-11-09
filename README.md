# AbuseIP DB Scanner

This is a python script that will parse IP addresses from files and interact with AbuseIPDB API. It will return the information about the IP into standard out in tab separated values in standard out.

## Requirements (Setup)

- Python3 (2.7 may have errors)
- Requests

``` BASH
pip3 install -r requirements.txt
```

- AbuseIP DB API Key

In order to use the script you will need an API key and place it in the scrip under the "api_key" variable. API key information can be found here: (https://www.abuseipdb.com/api.html)

## Usage

``` BASH
python3 AbuseIPDB.py -f file_to_parse.txt
```

 The options are as follows:

``` BASH
  -f FILE, --file FILE  	parses IP Addresses from a single given file
  -i IP, --ip IP        	Takes a single IP Addresse
  -c CSV, --csv CSV     	outputs items in comma seperated values
  -j JSON, --json JSON  	outputs items in jsonl format
  -l JSONL, --jsonl JSONL	outputs items in jsonl format
  -t TSV, --tsv TSV     	outputs items in tab seperated values (Default)
  -d DAYS, --days DAYS  	take in the number of days in history to go back for IP reports. Default: 30 Days
  -x, --translate       By default categories are numbers, with this flag it will convert them to text
  -v, --version			Displays version information
```

## Troubleshooting

- If you are receiving errors, please look at the Issues queue and see if there is already an issue open.

- If you have a unique issue, please create a new Issue, and include the output of your terminal from the script down until the error.

## Backlog

- Parse for IPs recursively through directories

## Completed (After Launch)

- ~~Create an option to output data in TSV~~
- ~~Create an option to output data in CSV~~
- ~~Create an option to output data in JSON~~
- ~~Create an option to output data to a file~~
