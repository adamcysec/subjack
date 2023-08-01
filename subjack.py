import argparse
import textwrap
import time
import concurrent.futures
import dns.resolver
import whoisit
import csv
import os
import json
import requests

CONNECTIONS = 100
WHOIS_COUNT = 0
HIGHJACK_COUNT = 0
SERVICE_COUNT = 0
SERVICES = []
SERVICES_LIST = []

# connect to RDAP
if not whoisit.is_bootstrapped():
    whoisit.bootstrap() 
BOOTSTRAP_INFO = whoisit.save_bootstrap_data()

def get_args():
    parser = argparse.ArgumentParser(
        description="Find hijackable subdomains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Examples:
        py subjack.py -f "wordlist.txt"
        py subjack.py -f "wordlist.txt" -v
        py subjack.py -f "wordlist.txt" -o "results_02.csv" -v
        ''')
    )

    parser.add_argument('-w', '--wordlist', action='store', type=str, required=True, help="wordlist file path")
    parser.add_argument('-o', '--outfile', action='store', type=str, required=False, default="results.csv", help="file name to output")
    parser.add_argument('-f', '--fingerprints', action='store', type=str, required=False, default="fingerprints.json", help="fingerprints.json file path")
    parser.add_argument('-v', '--verbose', action='store_true', required=False, help="print verbose output")

    args = parser.parse_args() # parse arguments

    args_dict = vars(args)

    return args_dict

def main():
    start_time = time.time()

    args = get_args()
    input_file =  args['wordlist']
    out_file = args['outfile']
    fingerprints_file = args['fingerprints']
    verbose = args['verbose']

    wordlist = read_in_wordlist(input_file)
    fingerprints_dict = read_in_fingerprints(fingerprints_file)
    global SERVICES_LIST
    SERVICES_LIST = fingerprints_dict
    services = [x['service'] for x in fingerprints_dict]
    global SERVICES
    SERVICES = services

    out_rows = []
    word_num_subdomains = 10000 # the number of subdomains to work at one time

    count_batches = 1

    while len(wordlist) > 0:
        first_10000 = wordlist[:word_num_subdomains] # grab subdomains to work
        del wordlist[:word_num_subdomains] # remove urls we worked
        batch_time = time.time()
        
        # start concurrent work
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONNECTIONS) as executor:
            future_to_subdomain = (executor.submit(query_dns, subdomain) for subdomain in first_10000)
            for future in concurrent.futures.as_completed(future_to_subdomain):
                try:
                    data = future.result()
                except Exception as exc:
                    print(str(type(exc)))
                finally:
                    out_rows.append(data)
        if verbose:
            print(f"--- Validated Batch Num {count_batches} Completed in {time.time() - batch_time} seconds ---")
        count_batches += 1

        # save subdomains worked to file
        save_worked_urls(out_rows, out_file, verbose)
        out_rows = []

    # yay we validated all the subdomains!
    print(f"--- Validated subdomains Completed in {time.time() - start_time} seconds ---")
    if verbose:
        print(f"total RDAP whois queries: {WHOIS_COUNT}")
        print(f"total services found: {SERVICE_COUNT}")
        print(f"total hijackable: {HIGHJACK_COUNT}")

def read_in_wordlist(filepath):
    """Reads in subdomain wordllist

    Paramters:
    ----------
    filepath : str
        wordlist file path

    Returns:
    ---------
    wordlist : list
        subdomain wordlist 
    """
    
    wordlist = []
    
    with open(filepath, 'r', encoding='utf-8') as in_file:
        lines = in_file.readlines()
        for line in lines:
            wordlist.append(line.strip())
    
    return wordlist

def read_in_fingerprints(filepath):
    """Reads in fingerprints.json

    Parameters:
    -----------
    filepath : str
        file path to fingerprints.json

    Returns:
    --------
    finger_prints : list
        contains dict of finger prints
    """

    with open(filepath, 'r') as json_file:
        finger_prints =  json.load(json_file)
    
    return finger_prints

def query_dns(subdomain):
    """Determin if a subdomain is hijackable from DNS queries

    Parameters:
    -----------
    subdomain : str
        subdomain name

    Returns:
    --------
    data : dict
        hijackable meta data
    """

    global WHOIS_COUNT
    global HIGHJACK_COUNT
    global SERVICE_COUNT
    global SERVICES_LIST
    global SERVICES

    cname = get_cname(subdomain)
    
    if not cname == "cname not found":
        cname_parts = cname.split(".")
        subdomain_parts = subdomain.split(".")
        
        cname_domain = f"{cname_parts[-2].strip()}"
        domain_name = f"{subdomain_parts[-2].strip()}"
       
        if not cname_domain == domain_name:
            if cname_domain in SERVICES:
                # service found
                SERVICE_COUNT +=1
                finger_print = [x['fingerprint'] for x in SERVICES_LIST if x['service'] == cname_domain][0][0]
                response_text = get_request(f"https://{cname}")
                if finger_print in response_text:
                    # service domain not registered.. possibly hijackable
                    registered = "Service"
                    hijackable = "Yes"
                    HIGHJACK_COUNT += 1
            else:
                # check for hijackable cname domain
                registered = get_whois(cname)
                WHOIS_COUNT +=1
        else:
            # cname's domain matches previous domain
            registered = "Yes"
            hijackable = "No"
    
    else:
        # no cname record.. can't be hijacked then
        registered = "Skipped"
        hijackable = "No"


    if registered == "Yes":
        # cname is registered.. can't be hijacked then
        hijackable = "No"
    
    elif registered == "No":
        # cname is not registered.. hijackable
        hijackable = "Yes"
        HIGHJACK_COUNT += 1
    
    data = {'subdomain': subdomain, 'cname': cname, 'cname_registered': registered, 'hijackable': hijackable}
    
    return data

def get_cname(domain):
    """Perform DNS query for cname record of given domain name

    Parameter:
    ----------
    domain : str
        domain name

    Returns:
    --------
    cname : str
        cname record message
    """
    
    try:
        answer = dns.resolver.resolve(domain, 'CNAME')

        cname_items = answer.rrset.items 
        for item in cname_items:
            cname = str(item)[:-1]
        
    except Exception as e:
        cname = "cname not found"

    return cname

def get_whois(domain):
    """Performs whois lookup for given domain

    Returns Yes or No message.

    Parameters:
    -----------
    domain : str
        domain name
    
    Returns:
    --------
    registered : str
        Yes or No
    """
    
    if not whoisit.is_bootstrapped():
        whoisit.load_bootstrap_data(BOOTSTRAP_INFO)
    
    parts = domain.split('.')
    domain_name = f"{(parts[-2]).strip()}.{(parts[-1]).strip()}"

    try:
        results = whoisit.domain(domain_name)
        registered = "Yes"
    except Exception as e:
        # not registered
        registered = "No"

    return registered

def get_request(url):
    """Returns GET response text

    Parameter:
    ----------
    url : str
        https url

    Returns:
    --------
    text : str
        webpage content
    """

    response = requests.get(url, allow_redirects=True)
    text = response.text

    return text

def save_worked_urls(data, file_name, verbose):
    """Saves validated pypi urls to file

    Keeps track of urls worked to prevent double work 
    if script execution stops in the middle of work.

    Parameters:
    --------
    data : list
        contains a dict of subdomain hijackable meta data
    file_name : str
        file name to output
    verbose : bool
        True : ouput only hijackable subdomains
        False : output all subdomains meta data 
    """
    
    # check verbose settings
    if not verbose:
        out_data = []
        for record in data:
            if record['hijackable'] == "Yes":
                out_data.append(record)
    else:
        out_data = data

    file_exists = os.path.exists(file_name)
    field_names = ['subdomain', 'cname', 'cname_registered', 'hijackable']
    
    if not len(out_data) == 0:
        with open(file_name, 'a', encoding='utf-8', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=field_names)
            
            if not file_exists:
                writer.writeheader()
            
            writer.writerows(out_data)
        
        print(f"Results saved: {file_name}")

if __name__ == "__main__":
    main()