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

# Run program like "python3 file-analyzer.py <file>"
def main():
    file = sys.argv[1]
    file_hash = get_hash(file)
    report = get_request(file_hash)
    print(report)


if __name__ == "__main__":
    main()
