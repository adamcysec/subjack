# subjack

## Synposis

Just like [subjack](https://github.com/haccer/subjack) from [haccer](https://github.com/haccer) but in Python.

## Description

My implementation of subjack written in Python. 

Pass in a subdomain wordlist and subjack.py will work your wordlist in batches of 1,000 domains.

Each subdomain's CNAME record is queried from the DNS. 

If a CNAME record exists for the given subdomain, then the CNAME is checked for registration status from a whois lookup.

> 📘
>
> Subjack.py by default will only output subdomains found to be hijackable.
>
> Use verbose output to save all subdomain data regardless of it's hijackable status. 

Subjack.py uses the concurrent module to make quick work of the wordlist.

## Dependencies
subjack.py requires the following dependencies:
- [argparse](https://pypi.org/project/argparse/)
  - `pip install argparse`
- [dnspython](https://pypi.org/project/dnspython/)
  - `pip install dnspython`
- [python-whois](https://pypi.org/project/python-whois/)
  - `pip install python-whois`

## Installation

1. git clone repository
2. pip install dependencies

## Usage

**Parameter --filepath, -f**
- type : str
- filepath to wordlist
- required : true

**Parameter --outfile, -o**
- type : str
- file name to output

**Parameter --verbose, -v**
- type : bool
- save verbose domain meta data to file

<br/>
<br/>

**Example 1**

`py subjack.py -f "wordlist.txt`

- outputs results.csv

**Example 2**

`py subjack.py -f "wordlist.txt" -v`

- verbose domain data is saved
- outputs results.csv

**Example 3**

`py subjack.py -f "wordlist.txt" -o "results_02.csv" -v`

- verbose domain data is saved
- outputs results_02.csv
