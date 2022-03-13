#! /usr/bin/python3

# This script is called by OpenVpn on client connection
# In order to create a dynamic config file to be applied on the server when the client connects,
# it should write it to the file named by the last argument.

import json
import os
import sys
import traceback
from ipaddress import IPv4Network

from scripts_logger import logger

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
    logger(str(e) + "\r\n" + str(traceback.extract_stack()))
    # always return 0 as exit code. otherwise the client will be dropped
    pass
