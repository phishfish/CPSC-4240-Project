import sys
import hashlib
import requests

# WARNING: DO NOT PUSH YOUR APIKEY HERE
API_KEY = 'your_api_key_here'
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

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 file-analyzer.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    try:
        file_hash = get_hash(file_path)
        report = get_request(file_hash)
        parse_report(report)
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    main()
