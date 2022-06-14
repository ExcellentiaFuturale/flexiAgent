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
    # get all frr routes
    frr_output = os.popen('vtysh -c "show ip route json"').read()
    parsed = json.loads(frr_output)

    routes = set()

    # push ospf/bgp routes to the clients
    for network in parsed:
        for item in parsed[network]:
            protocol = item.get('protocol')
            if not (protocol == 'ospf' or protocol == 'bgp'):
                continue

            ip_network = IPv4Network(network)
            network = ip_network.network_address
            netmask = ip_network.netmask
            routes.add(f'push \"route {network} {netmask}\"')

    # [root@flexiwan-router /usr/bin]# fwagent show --configuration networks
    # [
    #   "185.55.66.1/24"
    # ]
    agent_networks = os.popen('fwagent show --configuration networks lan').read()
    parsed_networks = json.loads(agent_networks)

    for network in parsed_networks:
        routes.add(f'push \"route {network}\"')

    if len(routes) > 0:
        route_str = '\n'.join(routes)
        os.system(f"sudo echo '{route_str}' >> {conf_file}")

except Exception as e:
    logger.error(f"client-connect: {str(e)}. {str(traceback.extract_stack())}")
    # returning 1 as exit code will disconnect the client
    sys.exit(1)
