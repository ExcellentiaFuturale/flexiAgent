#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2022  flexiWAN Ltd.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
################################################################################

# OpenVPN will write the username and password to the first two lines of a temporary file.
# The filename will be passed as an argument to this script,
# and the file will be automatically deleted by OpenVPN after the script returns.

import json
import os
import sys
import traceback

import requests

from scripts_logger import Logger
logger = Logger()

# get temporary file
user_password_file = sys.argv[1]

try:
  # retrive username and password from the temporary file
  username = os.popen(f'head -n 1 {user_password_file}').read().strip()
  password = os.popen(f'cat {user_password_file} | head -2 | tail -1').read().strip()

  # For the verification process, we also send to the server some information about the router
  device_info_txt = os.popen('cat /etc/flexiwan/agent/fwagent_info.txt').read()
  data = json.loads(device_info_txt)

  data['userName'] = username

  # the "__VPN_SERVER__" should be replaced with the server base url that we send from flexiManage
  # in the installation vpn job parameters
  url = f"__VPN_SERVER__/api/auth/tokens/verify"

  # on local setup there is no real ssl certificate and we need to call the server without verification
  verify = False if 'local' in url else True

  # send password as authorization header.
  # The server checks if this JWT is valid
  headers = {'Authorization': f'Bearer {password}'}
  response = requests.post(url, json=data, headers=headers, verify=verify)
  status = response.status_code

  if status is not 200:
    logger.info(f'Authentication for user {username} returned status code {status}')
    sys.exit(1)
  else:
    logger.info(f'Authentication for user {username} succeeded')
    sys.exit(0)
except Exception as e:
  logger.error(f"auth: {str(e)}. {str(traceback.extract_stack())}")
  sys.exit(1)
