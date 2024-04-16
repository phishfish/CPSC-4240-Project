import sys
import os
import hashlib
import requests
import subprocess

# WARNING: DO NOT PUSH YOUR APIKEY HERE
API_KEY = ''
READ_SIZE = 65536

def get_IP_request(webPage):
    """
    Gets a report for an IP address
    """
    print(f"Retrieving report for IP: {webPage}")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{webPage}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    parse_report(response.json())

def get_request(calc_hash):
    """
    Performs a GET request to the VirusTotal API to retrieve the scan report of the file.
    """
    print(f"Retrieving report for hash: {calc_hash}")
    url = f"https://www.virustotal.com/api/v3/files/{calc_hash}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to retrieve report: HTTP {response.status_code}")
        return None

def get_hash(file):
    """
    Generates a SHA-256 hash of the file by reading in chunks.
    """
    print(f"Calculating SHA-256 for {file}...")
    file_hash = hashlib.sha256()
    with open(file, "rb") as open_file:
        file_bytes = open_file.read(READ_SIZE)
        while len(file_bytes) > 0:
            file_hash.update(file_bytes)
            file_bytes = open_file.read(READ_SIZE)
    return file_hash.hexdigest()

def parse_report(report):
    """
    Parses the report from VirusTotal and prints a user-friendly summary.
    """
    if not report or 'data' not in report or 'attributes' not in report['data']:
        print("No data found in the report.")
        return
    
    attributes = report['data']['attributes']
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    detection_names = attributes.get('last_analysis_results', {})
    country = attributes.get("country")
    if country is None:
        country = "Unknown"
    detected_by = {k: v for k, v in detection_names.items() if v['category'] == 'malicious'}

    print("\nScan Summary:")
    print(f"Malicious detections: {last_analysis_stats.get('malicious', 0)}")
    print(f"Undetected: {last_analysis_stats.get('undetected', 0)}")
    print(f"Harmless detections: {last_analysis_stats.get('harmless', 0)}")
    print(f"Suspicious detections: {last_analysis_stats.get('suspicious', 0)}")
    print(f"Failed scans: {last_analysis_stats.get('type-unsupported', 0) + last_analysis_stats.get('failure', 0)}")
    print(f"Country: " + country)
    print("\nDetected By:")
    for engine, result in detected_by.items():
        print(f"- {engine}: {result['result']}")

def display_mitre_techniques(mitre_data):
    """Parses and displays MITRE ATT&CK data, sorting techniques by the highest severity within their signatures."""
    if not mitre_data or 'data' not in mitre_data:
        print("No MITRE ATT&CK data available.")
        return

    for sandbox, details in mitre_data['data'].items():
        print(f"\nSandbox: {sandbox}")
        for tactic in details.get('tactics', []):
            print(f"\n  Tactic: {tactic['name']} ({tactic['description']})")

            # Process each technique to find the highest severity within its signatures
            for technique in tactic.get('techniques', []):
                highest_severity = "UNKNOWN"  # Default if no signatures exist
                descriptions = []

                for signature in technique.get('signatures', []):
                    descriptions.append((signature['severity'], signature['description']))
                    # Update highest severity based on predefined severity order
                    severity_order = ['LOW', 'MEDIUM', 'HIGH', 'INFO', 'UNKNOWN']  # Customizable order
                    if severity_order.index(signature['severity']) > severity_order.index(highest_severity):
                        highest_severity = signature['severity']

                # Sorting descriptions by severity according to the predefined order
                descriptions.sort(key=lambda x: severity_order.index(x[0]))

                print(f"    Technique: {technique['name']} - {technique['description']}")
                print(f"      Highest Severity: {highest_severity}")
                for severity, desc in descriptions:
                    print(f"        Signature: {desc} (Severity: {severity})")

#Uploading File to VirusTotal
def uploadFile(fileName):
    """
    Uploads a file to VirusTotal
    """
    url = ""
    file_size = (os.stat(fileName).st_size) / (1024 * 1024)
    if file_size > 32:
        url = "https://www.virustotal.com/api/v3/files/upload_url"
    else:
        url = "https://www.virustotal.com/api/v3/files"
    
    with open(fileName, "rb") as file:
        contents = file.read()
    files = {"file": (fileName, contents)}
    headers =  {"accept": "application/json", 'x-apikey': API_KEY}
    while True:
        response = requests.post(url, headers=headers, files=files)
        if response.status_code == 200:
            break
        elif response.status_code == 429:
            print("Rate limit exceeded. Waiting...")
            time.sleep(60)
        elif response.status_code == 401:
            print("Failed to upload file. Did you include an API key?")
            break
        else:
            print(f"Failed to upload file. Error: {response.status_code}")
            break  
    return response

def hunt_persist():
    """
    Hunts for basic persistance mechanisms left behind by an attacker
    """
    try:
        cron_jobs = subprocess.check_output(['crontab', '-l'], stderr=subprocess.STDOUT, text=True)
        print("Scheduled cron jobs: ")
        print(cron_jobs)
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            print("No scheduled cron jobs found")

    user_accounts = subprocess.check_output(['getent', 'passwd'], stderr=subprocess.STDOUT, text=True)
    print("Accounts on machine: ")
    print(user_accounts)

    connections = subprocess.check_output(['ss', '-tulpn'], stderr=subprocess.STDOUT, text=True)
    print("Connections and listening ports:")
    print(connections)

    services = subprocess.check_output(['systemctl', 'list-timers'], stderr=subprocess.STDOUT, text=True)
    print("Services: ")
    print(services)

def get_mitre_attack_data(calc_hash):
    """
    Retrieves the MITRE ATT&CK data for a file based on its hash.
    """
    base_url = "https://www.virustotal.com/api/v3/files/"
    headers = {"x-apikey": API_KEY, "accept": "application/json"}
    mitre_url = f"{base_url}{calc_hash}/behaviour_mitre_trees"
    mitre_response = requests.get(mitre_url, headers=headers)
    if mitre_response.status_code != 200:
        print(f"Failed to retrieve MITRE ATT&CK data: HTTP {mitre_response.status_code}")
        return None
    return mitre_response.json()

#Print Analysis of File
def fileAnalysis(file_ID):
    """
    Sends a file to be analyzed and returns the response
    """
    url = "https://www.virustotal.com/api/v3/analyses/" + file_ID
    headers =  {"accept": "application/json", 'x-apikey': API_KEY}
    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            break
        elif response.status_code == 429:
            print("Rate limit exceeded. Waiting...")
            time.sleep(60)
        else:
            print(f"Failed to get file analysis. Error: {response.status_code}")
            break
    return response

def main():
    # Splits command line arguments
    flags = args = sys.argv[1:]
    outfile = None
    if '-f' in flags:
        index = flags.index('-f')
        outfile = flags[index + 1]
        del flags[index:index + 2]
    
    # Prints info about usage
    if '-h' in flags:
        print("Usage: python3 file-analyzer.py [OPTION] ... FILE")
        print("Analyzer a file for malware using the VirusTotal API")
        print("-----------------------------------------------------------------------------")
        print("-i --IP address          will check a malicious IP address instead of a file")
        print("-f --another file        will print the output to another file")
        print("-v --verbose             output a diagnostic for the file processed")
        print("-p --persistence         hunt for persistence left behind by an attacker")
        print("-t --attack tactics      lists possible indicators a file is malicious")
        sys.exit(1)
    
    # Prints out raw json response
    if '-v' in flags:
        index = flags.index('-v')
        file = flags[index + 1]
        response = uploadFile(file)
        response = response.json()
        file_id = response['data']['id']
        analysis_report = fileAnalysis(file_id)

        if outfile:
            with open(outfile, 'a') as f:
                sys.stdout = f
                print(analysis_report.json())
        else:
            print(analysis_report.json())
    
    # Prints ip info
    if '-i' in flags:
        index = flags.index('-i')
        ip = flags[index + 1]

        if outfile:
            with open(outfile, 'a') as f:
                sys.stdout = f
                get_IP_request(ip)
        else:
            get_IP_request(ip)
    
    # Prints out persistence on machine
    if '-p' in flags:
        if outfile: 
            with open(outfile, 'a') as f:
                sys.stdout = f
                hunt_persist()
        else:
            hunt_persist()
    
    # Prints MITRE ATT&CK tactics
    if '-t' in args:
        t_index = args.index('-t')
        try:
            file_path = args[t_index + 1]
            file_hash = get_hash(file_path)
            mitre_data = get_mitre_attack_data(file_hash)
            if mitre_data:
                if outfile:
                    with open(outfile, 'a') as f:
                        sys.stdout = f
                        display_mitre_techniques(mitre_data)
                else:
                    display_mitre_techniques(mitre_data)
        except IndexError:
            print("Error: No file specified after -t flag.")
    
    # Prints parsed file analysis
    if not flags[0].startswith('-'):
        file = flags[0]
        response = uploadFile(file)
        response = response.json()
        file_id = response['data']['id']
        analysis_report = fileAnalysis(file_id)
        
        if outfile:
            with open(outfile, 'a') as f:
                sys.stdout = f
                parse_report(get_request(get_hash(file)))
        else:
            parse_report(get_request(get_hash(file)))
    
if __name__ == "__main__":
    main()
