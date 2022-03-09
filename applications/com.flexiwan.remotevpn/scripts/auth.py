#! /usr/bin/python3

# OpenVPN will write the username and password to the first two lines of a temporary file.
# The filename will be passed as an argument to this script,
# and the file will be automatically deleted by OpenVPN after the script returns.

import json
import os
import sys

import requests

# get temporary file
user_password_file = sys.argv[1]

# retrive username and password from the temporary file
username = os.popen(f'head -n 1 {user_password_file}').read().strip()
password = os.popen(f'cat {user_password_file} | head -2 | tail -1').read().strip()

# For the verification process, we also send to the server some information about the router
device_info_txt = os.popen('cat /etc/flexiwan/agent/fwagent_info.txt').read()
data = json.loads(device_info_txt)

data['userName'] = username

# the "__VPN_SERVER__" should be replaced with the server base url that we send from flexiManage
# in the installation vpn job parameters
url = "__VPN_SERVER__/api/auth/tokens/verify"

# on local setup there is no real ssl certificate and we need to call the server without verification
verify = False if 'local' in url else True

# send password as authorization header.
# The server checks if this JWT is valid
headers = {'Authorization': f'Bearer {password}'}
response = requests.post(url, json=data, headers=headers, verify=verify)
status = response.status_code

if status is not 200:
  sys.exit(1)
else:
  sys.exit(0)
