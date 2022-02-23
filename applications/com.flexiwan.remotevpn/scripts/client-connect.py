#! /usr/bin/python3

# This script is called by OpenVpn on client connection
# In order to create a dynamic config file to be applied on the server when the client connects,
# it should write it to the file named by the last argument.

import sys
import os
import json
from ipaddress import IPv4Network

config_file = sys.argv[1]

try:
    # get all ospf routes
    output = os.popen('vtysh -c "show ip route ospf json"').read()
    parsed = json.loads(output)

    # push ospf routes to the clients
    for network in parsed:
        ip_network = IPv4Network(network)
        os.system(f"sudo echo 'push \"route {ip_network.network_address} {ip_network.netmask}\"' >> {config_file}")

    sys.exit(0)
except:
    # always return 0 as exit code. otherwise the client will be dropped
    sys.exit(0)
