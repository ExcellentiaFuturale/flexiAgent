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

# This script is called by OpenVpn on client connection
# In order to create a dynamic config file to be applied on the server when the client connects,
# it should write it to the file named by the last argument.

import json
import os
import sys
import traceback
from ipaddress import IPv4Network

from scripts_logger import Logger
logger = Logger()

conf_file = sys.argv[1]

try:
    # get all ospf routes
    output = os.popen('vtysh -c "show ip route ospf json"').read()
    parsed = json.loads(output)

    # push ospf routes to the clients
    for network in parsed:
        ip_network = IPv4Network(network)
        network = ip_network.network_address
        netmask = ip_network.netmask
        os.system(f"sudo echo 'push \"route {network} {netmask}\"' >> {conf_file}")

except Exception as e:
    logger.error(f"client-connect: {str(e)}. {str(traceback.extract_stack())}")
    # returning 1 as exit code will disconnect the client
    sys.exit(1)
