import sys
import hashlib
import requests

# WARNING: DO NOT PUSH YOUR APIKEY HERE
API_KEY = 'f809ff8422b573c68a15f8e8f97782942e2fcada0f7d5b3ba2bda99b78de0025'
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

#Print Analysis of File
def fileAnalysis(file, file_hash):
    hash_url = "https://www.virustotal.com/api/v3/files/" + file_hash
    url = "https://www.virustotal.com/api/v3/analyses/" + file_ID
    headers =  {"accept": "application/json", 'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)

#Retrieving file report of the hashed file
def retrieveReport(file):

    file_hash = get_hash(file)
    url = "https://www.virustotal.com/api/v3/files/" + file_hash
    headers = {"accept": "application/json", 'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    print(response.text)

def main():
    if len(sys.argv) > 1 and sys.argv[1].startswith('-'):
        print("Detect malicious behavior in a file or an IP address")
        print("-----------------------------------------------------------------------------")
        print("-i --IP address          will check a malicious IP address instead of a file")
        print("-f --another file        will print the output to another file")
        sys.exit(1)
    else:
        file_path = sys.argv[1]
        try:
#             file_hash = get_hash(file_path)
#             report = get_request(file_hash)
#             parse_report(report)
            file = sys.argv[1]
            response = uploadFile(file)
            response = response.json()
            file_id = response['data']['id']
        except FileNotFoundError:
            print(f"Error: The file '{file_path}' was not found.")
        except Exception as e:
            print(f"An unexpected error occurred: {str(e)}")
    
if __name__ == "__main__":
    main()
