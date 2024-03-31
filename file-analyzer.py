import sys 
import hashlib
import requests

# WARNING: DO NOT PUSH YOUR APIKEY HERE
API_KEY = ''
READ_SIZE = 65536

def get_request(calc_hash):
    ...

def get_hash(file):
    file_hash = hashlib.sha256()
    with open(file, "rb") as open_file:
        file_bytes = open_file.read(READ_SIZE)
        while len(file_bytes) > 0:
            file_hash.update(file_bytes)
            file_bytes = open_file.read(READ_SIZE)
    return file_hash.hexdigest()

#Uploading File to VirusTotal
def uploadFile(fileName):
    url = "https://www.virustotal.com/api/v3/files"
    files = {"file": open(fileName, "rb")}
    headers =  {"accept": "application/json", 'x-apikey': API_KEY}
    response = requests.post(url, headers=headers, files=files)
    if response.headers['content-type'] == 'application/json':
        return response.json()['data']['id']

#Print Analysis of File
def fileAnalysis(file_ID):
    url = "https://www.virustotal.com/api/v3/analyses/" + file_ID
    headers =  {"accept": "application/json", 'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    print(response.text)

#Retrieving file report of the hashed file
def retrieveReport(file):

    file_hash = get_hash(file)
    url = "https://www.virustotal.com/api/v3/files/" + file_hash
    headers = {"accept": "application/json", 'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    print(response.text)


# Run program like "python3 file-analyzer.py <file>"
def main():
    #Saving File
    file = sys.argv[1]

    #Uploads the file and returns the file ID (so it can be used for a file analysis)
    file_id = uploadFile(file)

    #Option to Print out a File Analysis or File Report
    #1. File Analysis - prints information on the analysis object (using id from uploadFile)
    #2. File Report - retrieve detailed information about a file
    print('Enter Options "1" or "2": \n 1. File Analysis \n 2. File Report')
    answer = input()
    if answer == "1":
        fileAnalysis(file_id)
    elif answer == "2":
        retrieveReport(file)

    #report = get_request(file_hash)
    #print(report)

if __name__ == "__main__":
    main()
