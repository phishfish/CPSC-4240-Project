import sys
import getopt
import os
import hashlib
import requests
import subprocess

# WARNING: DO NOT PUSH YOUR APIKEY HERE
API_KEY = ''
READ_SIZE = 65536

#Get Report from VirusTotal - IP Address
def get_IP_request(webPage):
    print(f"Retrieving report for IP: {webPage}")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{webPage}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to retrieve report: HTTP {response.status_code}")
        return None
    
#Get Report from VirusTotal - Hashed File
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

#Get Hash Value from File
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

#Parsing of a report
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

    
    scan_summary = f'''
    \nScan Summary:
    Malicious detections: {last_analysis_stats.get('malicious', 0)}
    Undetected: {last_analysis_stats.get('undetected', 0)}
    Harmless detections: {last_analysis_stats.get('harmless', 0)}
    Suspicious detections: {last_analysis_stats.get('suspicious', 0)}
    Failed scans: {last_analysis_stats.get('type-unsupported', 0) + last_analysis_stats.get('failure', 0)}
    Detected By:\n'''
    for engine, result in detected_by.items():
        scan_summary += "- " + engine + ":" + result['result']

    return scan_summary

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
def fileAnalysis(file_ID):
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

#Hunting Persistence
def hunt_persist():
    try:
        cron_jobs = subprocess.check_output(['crontab', '-l'], stderr=subprocess.STDOUT, text=True)
        cron_string = "Scheduled cron jobs: \n"
        cron_string += cron_jobs
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            cron_string = "No scheduled cron jobs found"
            return cron_string

    #Data from Hunting Persistence
    user_accounts = subprocess.check_output(['getent', 'passwd'], stderr=subprocess.STDOUT, text=True)
    connections = subprocess.check_output(['ss', '-tulpn'], stderr=subprocess.STDOUT, text=True)
    services = subprocess.check_output(['systemctl', 'list-timers'], stderr=subprocess.STDOUT, text=True)

    #Persistent Report
    persistent_report = f'''
    Accounts on machine: 
    {user_accounts}\n
    Connections and listening ports:
    {connections}\n
    Services:
    {services}'''

    return cron_string + persistent_report
    
#File Output Redirection
def fileRedirection(report, output_report):
    with open(output_report, 'w') as sys.stdout:
       print(report)

def main():
 
    # list of command line arguments
    argumentList = sys.argv[1:]

    # Options
    '''
    -i: IP Address
    -f: File
    -h: Manpage
    -p: Hunt Persist

    -v: Verbose
    -s: summary

    -o: Output Redirection
    '''

    #Available Flags; if has ':' after the letter, it requires an additional argument after the flag
    options = "i:f:hvspo:"

    try:
        # Parsing argument
        arguments, values = getopt.getopt(argumentList, options)
        #Sorting of flags
        flags=[]
        for input_type in range(len(arguments)):
            if arguments[input_type][0] == '-i' or arguments[input_type][0] == '-f' or arguments[input_type][0] == '-h' or arguments[input_type][0] == '-p':
                flags.append(arguments[input_type])
                break
        for output_type in range(len(arguments)):
            if arguments[output_type][0] == '-v' or arguments[output_type][0] == '-s':
                flags.append(arguments[output_type])
                break
        for pipe_validity in range(len(arguments)):
            if arguments[pipe_validity][0] == '-o':
                flags.append(arguments[pipe_validity])
                break

        #Invalid Number of Arguments
        if len(flags) <= 0 or len(flags) > 5:
            print("Invalid Number of Arguments")
            sys.exit()

        #Flag Types
        input_type_flag = flags[0][0]

        # checking each argument
        #Options for IP-Address
        if input_type_flag == '-i':
            ip_address = flags[0][1]
            ip_address_report = get_IP_request(ip_address)
            if flags[1][0] == '-v':
                if len(flags) == 3:
                    #Ip-address verbose Output Redirection
                    if flags[2][0] == '-o':
                        output_report = flags[2][1]
                        fileRedirection(ip_address_report, output_report)
                #Ip address verbose not Output Redirection
                else:
                    get_IP_request(ip_address)
            elif flags[1][0] == '-s':
                if len(flags) == 3:
                    #Ip address summary Output Redirection
                    if flags[2][0] == '-o':
                        output_report = flags[2][1]
                        fileRedirection(parse_report(ip_address_report), output_report)
                #Ip address summary not Output Redirection
                else:
                    parse_report(get_IP_request(ip_address))
            else:
                print('Invalid Arguments')

        #Option for Files
        elif input_type_flag == '-f':
            file = flags[0][1]
            response = uploadFile(file)
            response = response.json()
            file_id = response['data']['id']
            analysis_report = fileAnalysis(file_id)
            if flags[1][0] == '-v':
                if len(flags) == 3:
                    #File verbose Output Redirection
                    if flags[2][0] == '-o':
                        output_report = flags[2][1]
                        fileRedirection(analysis_report.text, output_report)
                #File verbose not Output Redirection
                else:
                    print(analysis_report.text)
            elif flags[1][0] == '-s':
                if len(flags) == 3:
                    #File summary Output Redirection
                    if flags[2][0] == '-o':
                        output_report = flags[2][1]
                        fileRedirection(parse_report(get_request(get_hash(file))), output_report)
                #File summary not Output Redirection
                else:
                    print(parse_report(get_request(get_hash(file))))
            else:
                print('Invalid Arguments')

        #Option for Hunting Persistence
        elif input_type_flag == '-p':
            analysis_report = hunt_persist()
            #Persistent Hunt Output Redirection
            if len(flags) == 2:
                if flags[1][0] == '-o':
                    output_report = flags[1][1]
                    fileRedirection(analysis_report, output_report)
            #Persistent Hunt no Output Redirection
            else:
                print(analysis_report)

        #Option for Manual Page
        elif input_type_flag == '-h':
            print("\n\nUsage: python3 file-analyzer.py [OPTION] ... FILE")
            print("Analyzer a file for malware using the VirusTotal API")
            print("-----------------------------------------------------------------------------")
            print("-i [IP-Address]              --IP address: will check a malicious IP address instead of a file")
            print("-f [File Name]               --File: will check a malicious file")
            print("-p                           --Persistence: hunt for persistence left behind by an attacker")
            print("-s                           --Summary: summary diagnostic of a file")
            print("-v                           --Verbose: output a diagnostic for the file processed")
            print("-o [Empty File Name]         --Output Redirection: perform output redirection to a stated output file\n\n")
        else:
            print("Invalid Arguments")
    
    except getopt.error as err:
        # output error, and return with an error code
        print (str(err))
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
    
if __name__ == "__main__":
    main()
