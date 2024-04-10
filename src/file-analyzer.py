import sys
import hashlib
import time
import requests

# WARNING: DO NOT PUSH YOUR APIKEY HERE
API_KEY = '5f4eb36e1c81f098f84ddf2b86fb3bbde18df9ac8580cdda8c02a2061b1c6f8d'
READ_SIZE = 65536

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
def uploadFile(fileName):
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

#Print Analysis of File
def file_analysis(file, file_hash):
    hash_url = "https://www.virustotal.com/api/v3/files/" + file_hash
    url = "https://www.virustotal.com/api/v3/analyses/" + file_ID
    headers =  {"accept": "application/json", 'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)

#Retrieving file report of the hashed file
def retrieve_report(file):

    file_hash = get_hash(file)
    url = "https://www.virustotal.com/api/v3/files/" + file_hash
    headers = {"accept": "application/json", 'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    print(response.text)


# Run program like "python3 file-analyzer.py <file>"
def main():
    #Saving File
    file = sys.argv[1]

    #Uploads the file and returns a response (aka, has this been uploaded already?)
    response = uploadFile(file)
    file_id = response.json().get("data").get("id")

    if response == NOT_FOUND:
        ...

    #Option to Print out a File Analysis or File Report
    #1. File Analysis - prints information on the analysis object (using id from uploadFile)
    #2. File Report - retrieve detailed information about a file
    # print('Enter Options "1" or "2": \n 1. File Analysis \n 2. File Report')
    # answer = input()
    # if answer == "1":
    #     fileAnalysis(file_id)
    # elif answer == "2":
    #     retrieveReport(file)

    #report = get_request(file_hash)
    #print(report)
    
if __name__ == "__main__":
    main()
