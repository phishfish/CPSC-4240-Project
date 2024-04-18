# Command-Line Malware Threat Detector via VirusTotal API
The intended purpose of this Command Line tool is to improve detection rates and enhance user comprehension of security threats, therefore making cybersecurity more accessible and understandable to a broader audience. It was designed to improve security comprehension for Linux systems on analyzed files or IP addresses.


## Objective 

With an emphasis on security comprehension towards a broader audience and expanding antivirus capabilities for Linux systems,  **objectives** include:
* Develop a command-line tool that provides efficient and reliable malware scanning on Linux systems, filling a crucial gap in the Linux security landscape.
* Educate users by augmenting the tool's functionality and discuss the nature and severity of detected threats, thereby enhancing their understanding and response to cybersecurity issues.
* Offer large file size analysis reports to widen the range of acceptable threat detections
* Improve accessibility by creating a user-friendly command-line interface that simplifies the process of scanning files and IP addresses for threats, making advanced cybersecurity tools accessible to a broader audience.
* Provide a Linux security tool that conveys information on detection process and existing Linux malware

## Getting Started

This tool is written in Python and **requires Python (and a few packages)** downloaded on to the system.
```bash
#For Linux Systems
sudo apt-get install python3

#Modules to Download
pip install hashlib

pip install requests
```

Since this tool uses VirusTotal API, you will need to create an account on VirusTotal and use your given API KEY for this tool to work. To create an account on VirusTotal, go to the link: https://www.virustotal.com/gui/join-us. You can **insert your API KEY in the file "file-analyzer.py"**. After finding the section of the code in "file-analyzer.py", input your file key in the "API_KEY = '' area.
```Python
# WARNING: DO NOT PUSH YOUR APIKEY HERE
API_KEY = ''
READ_SIZE = 65536
```

## How To Use
Given this is a command line tool, the optional flags include:
```touch
-h                        Manual Page
-i [IP_address]           IP Address: will analyze a IP Address to determine if it is malicious
(just filename)           File: will analyze a file to determine if it is malicious
-f [Output Filename]      Output Redirection: will print output to another file
-v                        Verbose: output a diagnostic for a file processed
-p                        Persistence: hunt for persistence left behind by an attacker
-t [filename]             Attack Tactics: list possible indicatiors file is malicious based on MITRE ATT&CK framework
-r [filename]             Remediate File: removes file from machine
```
#### Considerations to Keep in Mind when Using the Command Line
* ###### Can only use -v with files
* ###### Using -v with a filename will require the order: -v [filename]
* ###### It does not matter the order of where the -f Output *Filename* is placed within the command line
* ###### Analyzing a File only requires the filename, no flags to indicate a file is being anlayzed
* ###### -h, -p are lone flags that will not have any arguments after the flag
* ###### -r requires a filename after the flag (no other additional flags)
#### *Potential Combinations*
```touch
-h: no other flag combinations
-i [IP_ADDRESS]: -f
(filename): -v (but -v needs to be before filename)
-f [OUTPUT_FILE]: -i, -v, -p, or -t
-p: -f [OUTPUT_FILE]
-t [FILENAME]: -f [OUTPUT_FILE]
-r [FILENAME]: no other flag combinations
```

## Examples of Uses
These examples are assuming you have the files required and a separate file called *text.txt* in the same directory.

1. Analyze Verbose Report of an existing file named *text.txt*
```bash
python file_analyzer.py -v text.txt
```

2. Analyze Summary Report of an existing file named *text.txt*
```bash
python file_analyzer.py text.txt
```

3. Analyze Summary Report of an existing file named *text.txt* but Output Redirect to file named *output.txt*
```bash
python file_analyzer.py text.txt -f output.txt
```

4. Analyze Summary Report of Malicious IP Address
```bash
python file_analyzer.py -i 62.204.41.103
```

5. Analyze Summary Report of Malicious IP Address but Output Redirect to file named *output.txt*
```bash
python file_analyzer.py -i 62.204.41.103 -f output.txt
```

6. Analyze for Persistence Left Behind from Attackers but Output Redirect to file named *output.txt*
```bash
python file_analyzer.py -p -f output.txt
```

7. Analyze for attack tactics of a file (*text.txt*) based on MITRE ATT&CK Framework but Output Redirect to file named *output.txt*
```bash
python file_analyzer.py -t text.txt -f output.txt
```

8. Remove file from Machine named *text.txt*
```bash
python file_analyzer.py -r text.txt 
```




