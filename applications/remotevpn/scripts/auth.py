#! /usr/bin/python3

import sys
import os
import json
import requests
import hashlib

user_password_file = sys.argv[1]
username = os.popen(f'head -n 1 {user_password_file}').read().strip()
password = os.popen(f'cat {user_password_file} | head -2 | tail -1').read().strip()

device_info_txt = os.popen('cat /etc/flexiwan/agent/fwagent_info.txt').read()
data = json.loads(device_info_txt)
data['userName'] = username

url = "__VPN_SERVER__/api/auth/tokens/verify"

headers = {'Authorization': f'Bearer {password}'}
response = requests.post(url, json=data, headers=headers, verify=False)

status = response.status_code
if status is not 200:
  sys.exit(1)
else:
  sys.exit(0)
