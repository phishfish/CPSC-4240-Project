
import os
import hashlib
import requests
import time
import argparse
import sys

# WARNING: DO NOT PUSH YOUR APIKEY HERE
API_KEY = ''
READ_SIZE = 65536

def get_request(calc_hash):
    """
    Performs a GET request to the VirusTotal API to retrieve the scan report of the file.
    """
    """
    Fetches general scan report and MITRE ATT&CK data for a given file hash from VirusTotal.
    """
    # Define the base URL and headers for VirusTotal API
    base_url = "https://www.virustotal.com/api/v3/files/"
    headers = {"x-apikey": API_KEY, "accept": "application/json"}

    # First, fetch the general scan report
    scan_url = f"{base_url}{calc_hash}"
    scan_response = requests.get(scan_url, headers=headers)
    if scan_response.status_code != 200:
        print(f"Failed to retrieve general scan report: HTTP {scan_response.status_code}")
        return None

    # Parse the general scan response
    scan_data = scan_response.json()

    # Then, fetch the MITRE ATT&CK data using the same file ID
    mitre_url = f"{base_url}{calc_hash}/behaviour_mitre_trees"
    mitre_response = requests.get(mitre_url, headers=headers)
    if mitre_response.status_code != 200:
        print(f"Failed to retrieve MITRE ATT&CK data: HTTP {mitre_response.status_code}")
        return scan_data  # Return just the scan data if MITRE data retrieval fails

    # Parse the MITRE ATT&CK response
    mitre_data = mitre_response.json()

    # Return both sets of data
    return scan_data, mitre_data

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


def search_mitre_technique(mitre_data, technique_id):
    """
    Searches for a specified MITRE ATT&CK technique in the provided data.
    """
    if not mitre_data:
        return False
    for sandbox, details in mitre_data.get('data', {}).items():
        for tactic in details.get('tactics', []):
            for technique in tactic.get('techniques', []):
                if technique['id'] == technique_id:
                    return True
    return False


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
    detected_by = {k: v for k, v in detection_names.items() if v['category'] == 'malicious'}

    print("\nScan Summary:")
    print(f"Malicious detections: {last_analysis_stats.get('malicious', 0)}")
    print(f"Undetected: {last_analysis_stats.get('undetected', 0)}")
    print(f"Harmless detections: {last_analysis_stats.get('harmless', 0)}")
    print(f"Suspicious detections: {last_analysis_stats.get('suspicious', 0)}")
    print(f"Failed scans: {last_analysis_stats.get('type-unsupported', 0) + last_analysis_stats.get('failure', 0)}")
    print("\nDetected By:")
    for engine, result in detected_by.items():
        print(f"- {engine}: {result['result']}")

#Uploading File to VirusTotal
def upload_file(file_name):
    url = ""
    file_size = (os.stat(file_name).st_size) / (1024 * 1024)
    if file_size > 32:
        url = "https://www.virustotal.com/api/v3/files/upload_url"
    else:
        url = "https://www.virustotal.com/api/v3/files"
    
    with open(file_name, "rb") as file:
        contents = file.read()
    files = {"file": (file_name, contents)}
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

#Print Analysis of File
def file_analysis(file_ID):
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
    if len(sys.argv) > 1 and sys.argv[1].startswith('-'):
        # Traditional flag handling
        flags = sys.argv[1]
        file = sys.argv[2]
        for x in range(len(flags)):
            if 'h' in flags:
                print("Usage: python3 file-analyzer.py [OPTION] ... FILE")
                print("Analyze a file for malware using the VirusTotal API")
                print("-----------------------------------------------------------------------------")
                print("-i --IP address          will check a malicious IP address instead of a file")
                print("-f --another file        will print the output to another file")
                print("-v --verbose             output a diagnostic for the file processed")
                print("-p --persistence         hunt for persistence left behind by an attacker")
                print("-t --technique TECH_ID   specify MITRE ATT&CK technique ID to search for")
                sys.exit(1)
            elif 'v' in flags:
                response = upload_file(file)
                response_json = response.json()
                file_id = response_json['data']['id']
                analysis_report = file_analysis(file_id)
                print(analysis_report.json())
                scan_data, mitre_data = get_request(get_hash(file))
                parse_report(scan_data)
            elif 't' in flags:  # Assuming technique flag comes with technique ID as the next argument
                technique_id = sys.argv[3]
                scan_data, mitre_data = get_request(get_hash(file))
                if search_mitre_technique(mitre_data, technique_id):
                    print(f"File {file} exhibits behavior related to MITRE ATT&CK technique ID {technique_id}.")
                else:
                    print(f"No evidence of MITRE ATT&CK technique ID {technique_id} found in file {file}.")
    else:
        # argparse handling
        parser = argparse.ArgumentParser(description='Analyze files and check for specific MITRE ATT&CK techniques.')
        parser.add_argument('file', help='File to analyze')
        parser.add_argument('--technique', '-t', help='MITRE ATT&CK technique ID to search for')
        parser.add_argument('--upload', '-u', action='store_true', help='Upload file for scanning')
        parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
        args = parser.parse_args()

        if args.upload:
            response = upload_file(args.file)
            response_json = response.json()
            file_id = response_json['data']['id']
            if args.verbose:
                print("Uploaded file, ID:", file_id)

        file_hash = get_hash(args.file)
        if args.verbose:
            print(f"File hash calculated: {file_hash}")

        scan_data, mitre_data = get_request(file_hash)
        if scan_data and args.verbose:
            print("Scan data retrieved successfully.")

        if args.technique:
            if search_mitre_technique(mitre_data, args.technique):
                print(f"File {args.file} exhibits behavior related to MITRE ATT&CK technique ID {args.technique}.")
            else:
                print(f"No evidence of MITRE ATT&CK technique ID {args.technique} found in file {args.file}.")


    
if __name__ == "__main__":
    main()
