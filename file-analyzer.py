import sys 
import hashlib
import requests

# WARNING: DO NOT PUSH YOUR APIKEY HERE
API_KEY = ''

def get_request(calc_hash):
    ...

def get_hash(file):
    ...

# Run program like "python3 file-analyzer.py <file>"
def main():
    file = sys.argv[1]
    calc_hash = get_hash(file)
    report = get_request(calc_hash)
    print(report)


if __name__ == "__main__":
    main()
