#! /usr/bin/python3

import sys
import os
from netaddr import IPAddress

tap_dev = sys.argv[1]
tap_mtu = sys.argv[2]
link_mtu = sys.argv[3]
ifconfig_local_ip = sys.argv[4]
ifconfig_netmask = sys.argv[5]

mask = IPAddress(ifconfig_netmask).netmask_bits()

vtysh_cmd = f'sudo /usr/bin/vtysh -c "configure" -c "router ospf" -c "network {ifconfig_local_ip}/{mask} area 0.0.0.0"'

output = os.system(vtysh_cmd)

sys.exit(0)
