# subjack

## Synposis

Just like [subjack](https://github.com/haccer/subjack) from [haccer](https://github.com/haccer) but in Python.

## Description

My implementation of subjack written in Python. 

Pass in a subdomain wordlist and subjack.py will work your wordlist in batches of 1,000 domains.

Each subdomain's CNAME record is queried from the DNS. 

If a CNAME record exists for the given subdomain, then the CNAME is checked for registration status from a RDAP lookup. RDAP tends to be more accurate than WHOIS.

> 📘 **Note**
>
> **Subjack.py by default will only output subdomains found to be hijackable.**
>
> **Use verbose output to save all subdomain meta data regardless of it's hijackable status.**

Subjack.py uses the concurrent module to make quick work of the wordlist.

## Dependencies
subjack.py requires the following dependencies:
- [argparse](https://pypi.org/project/argparse/)
  - `pip install argparse`
- [dnspython](https://pypi.org/project/dnspython/)
  - `pip install dnspython`
- [whoisit](https://pypi.org/project/whoisit/)
  - `pip install whoisit`

## Installation

1. git clone repository
2. pip install dependencies

## Wordlist

Your wordlist should include a list of subdomains you're checking:

```
assets.cody.su
assets.github.com
b.cody.su
big.example.com
cdn.cody.su
dev.cody.su
dev2.twitter.com
```


[Seclists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS) provides a great starting point for subdomains.

## Usage

**Parameter --wordlist, -w**
- type : str
- file path to wordlist
- required : true

**Parameter --outfile, -o**
- type : str
- file name to output

**Parameter --fingerprints, -f**
- type : str
- file path to fingerprint.json
- default : relative import from project dir

**Parameter --cname, -c**
- type : bool
- save all subdomains with a CNAME record

**Parameter --verbose, -v**
- type : bool
- save verbose domain meta data to file

<br/>
<br/>

**Example 1**

`py subjack.py -w "wordlist.txt`

- outputs results.csv

**Example 2**

`py subjack.py -w "wordlist.txt" -v`

- verbose domain data is saved
- outputs results.csv

**Example 3**

`py subjack.py -w "wordlist.txt" -o "results_02.csv" -v`

- verbose domain data is saved
- outputs results_02.csv

**Example 4**

`py subjack.py -f "wordlist.txt" -o "results_02.csv" -f "C:\Users\<user>\Downloads\fingerprints.json" -v`

- Uses fingerprints.json from another directory
- verbose domain data is saved
- outputs results_02.csv

**Example 5**

`py subjack.py -f "wordlist.txt" -o "results_02.csv" -c`

- All subdomains with a CNAME record is saved regardless of hijackable status
- outputs results_02.csv
