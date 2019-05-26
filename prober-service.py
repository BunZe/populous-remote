import analyzer
import requests
import sys
import getopt
from scapy import utils


api_URL = "http://localhost:8080/api/data/"
api_token = "INSERT_TOKEN_HERE"
min_signal = -80
deviceId = "0000"
pcap_file_path = "./last.pcap"

numScanned = analyzer.analyze(min_signal, utils.rdpcap(pcap_file_path))
print(numScanned)

# Send out HTTP POST request to core server
data = {"deviceID": "XXX", "numProbed": numScanned}
headers = {"API_TOKEN": api_token, "Content-Type": "application/json"}
try:
    r = requests.post(api_URL, json=data, headers=headers)
except Exception as e:
    print(e)
else:
    print(r.content)



# update device log

