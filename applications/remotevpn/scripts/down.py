#! /usr/bin/python3

import sys
import os
from netaddr import IPAddress
import json

tup_dev = sys.argv[1]
tup_mtu = sys.argv[2]
link_mtu = sys.argv[3]
ifconfig_local_ip = sys.argv[4]
ifconfig_netmask = sys.argv[5]

app_db_path = '/etc/openvpn/server/fw_db'

try:
    mask = IPAddress(ifconfig_netmask).netmask_bits()

    # remove tc filter commands
    os.system('sudo tc qdisc delete dev t_vpp_remotevpn handle ffff: ingress')
    os.system('sudo tc filter delete dev t_vpp_remotevpn parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev t_remotevpn')

    os.system('sudo tc qdisc delete dev t_remotevpn handle ffff: ingress')
    os.system('sudo tc filter delete dev t_remotevpn parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev t_vpp_remotevpn')

    # remove vpp tun interface
    with open(app_db_path, 'r') as json_file:
        data = json.load(json_file)
        tun_vpp_if_name = data.get('tun_vpp_if_name')
        if tun_vpp_if_name:
            os.system(f'sudo vppctl delete tap {tun_vpp_if_name}')

    # remove network from ospf
    vtysh_cmd = f'sudo /usr/bin/vtysh -c "configure" -c "router ospf" -c "no network {ifconfig_local_ip}/{mask} area 0.0.0.0"'
    output = os.system(vtysh_cmd)
except:
    pass

sys.exit(0)