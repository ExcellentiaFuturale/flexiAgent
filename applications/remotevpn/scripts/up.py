#! /usr/bin/python3

import sys
import os
from netaddr import IPAddress

tap_dev = sys.argv[1]
tap_mtu = sys.argv[2]
link_mtu = sys.argv[3]
ifconfig_local_ip = sys.argv[4]
ifconfig_netmask = sys.argv[5]

try:
    # add network to ospf
    mask = IPAddress(ifconfig_netmask).netmask_bits()
    vtysh_cmd = f'sudo /usr/bin/vtysh -c "configure" -c "router ospf" -c "network {ifconfig_local_ip}/{mask} area 0.0.0.0"'
    output = os.system(vtysh_cmd)

    # configure interface with vpp
    os.system('sudo vppctl create tap host-if-name t_vpp_remotevpn tun')          
    os.system(f'sudo vppctl set interface ip address tun0 {ifconfig_local_ip}/{mask}')
    os.system('sudo vppctl set interface state tun0 up')
    
    os.system('sudo tc qdisc add dev t_vpp_remotevpn handle ffff: ingress')
    os.system('sudo tc filter add dev t_vpp_remotevpn parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev t_remotevpn')

    os.system('sudo tc qdisc add dev t_remotevpn handle ffff: ingress')
    os.system('sudo tc filter add dev t_remotevpn parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev t_vpp_remotevpn')
except: 
    pass

sys.exit(0)
