#! /usr/bin/python3

# This script is called by OpenVpn after TUN/TAP device close

import sys
import os
from netaddr import IPAddress
import json

# get OpenVpn settings
tup_dev = sys.argv[1]
tup_mtu = sys.argv[2]
link_mtu = sys.argv[3]
ifconfig_local_ip = sys.argv[4]
ifconfig_netmask = sys.argv[5]

app_db_path = '__APP_DB_FILE__'

mask = IPAddress(ifconfig_netmask).netmask_bits()

# remove tc filter commands
os.system('sudo tc qdisc delete dev t_vpp_remotevpn ingress')

# remove the openvpn network from ospf
vtysh_cmd = f'sudo /usr/bin/vtysh -c "configure" -c "router ospf" -c "no network {ifconfig_local_ip}/{mask} area 0.0.0.0"'
output = os.system(vtysh_cmd)

# remove vpp tun interface
data = None
with open(app_db_path, 'r') as json_file:
    data = json.load(json_file)
    tun_vpp_if_name = data.get('tun_vpp_if_name')
    if tun_vpp_if_name:
        os.system(f'sudo vppctl delete tap {tun_vpp_if_name}')
        del data['tun_vpp_if_name']

# update
with open(app_db_path, 'w+') as json_file:
    json.dump(data, json_file)

sys.exit(0)
