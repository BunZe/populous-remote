import analyzer
from urllib import request, response

api_URL = "https://testsite.com/api/data/"
api_token = "INSERT_TOKEN_HERE"
# device_ID = getDeviceID()

# Every 5 minutes
    # Record traffic for 1 minute

    # Send out HTTP POST request to core server
    data = '{"deviceID": xxx, "numProbed": xxx}'
    headers = {"API_TOKEN": api_token, "Content-Type:": "application/json"}
    request.Request(api_URL, data=data, headers=headers)
    # maybe I'll use the requests Python package...

    # update device log

