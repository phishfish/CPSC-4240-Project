import sys 
import hashlib
import requests

# WARNING: DO NOT PUSH YOUR APIKEY HERE
API_KEY = ''
READ_SIZE = 65536
NOT_FOUND = 404

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
        elip response.status_code == 401:
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
