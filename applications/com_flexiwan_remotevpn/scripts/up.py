#! /usr/bin/python3

# This script is called by OpenVpn after successful TUN / TAP device open

import json
import os
import sys

from netaddr import IPAddress

# get OpenVpn settings
tun_dev = sys.argv[1]
tun_mtu = sys.argv[2]
link_mtu = sys.argv[3]
ifconfig_local_ip = sys.argv[4]
ifconfig_netmask = sys.argv[5]

# We need to save information between the script called when running (up)
# and the script called when the daemon goes down.
# For this purpose we create a file in the library of the application where we store the required information
app_db_path = '__APP_DB_FILE__'

# add the openvpn network to ospf
mask = IPAddress(ifconfig_netmask).netmask_bits()
vtysh_cmd = f'sudo /usr/bin/vtysh -c "configure" -c "router ospf" -c "network {ifconfig_local_ip}/{mask} area 0.0.0.0"'
output = os.system(vtysh_cmd)

# configure the vpp interface
tun_vpp_if_name = os.popen('sudo vppctl create tap host-if-name t_vpp_remotevpn tun').read().strip()

# if 'error' in tun_vpp_if_name:
if not tun_vpp_if_name:
    sys.exit("Cannot create tun device in vpp")

# store the vpp_if_name in application db
data = { 'tun_vpp_if_name': tun_vpp_if_name }
with open(app_db_path, 'w') as f:
    json.dump(data, f)

os.system(f'sudo vppctl set interface ip address {tun_vpp_if_name} {ifconfig_local_ip}/{mask}')
os.system(f'sudo vppctl set interface state {tun_vpp_if_name} up')


# configure mirror ingress traffic from the tun interface created by vpp to the the openvpn tun interface
os.system('sudo tc qdisc add dev t_vpp_remotevpn handle ffff: ingress')
os.system('sudo tc filter add dev t_vpp_remotevpn parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev t_remotevpn')


# configure mirror ingress traffic from vpn tun interace to the tun interface that created by vpp
os.system('sudo tc qdisc add dev t_remotevpn handle ffff: ingress')
# don't mirror traffic that its destination address is the vpn server itself (traffic originated by linux).
os.system(f'sudo tc filter add dev t_remotevpn parent ffff: protocol all priority 1 u32 match ip dst {ifconfig_local_ip}/32 action pass')
os.system('sudo tc filter add dev t_remotevpn parent ffff: protocol all priority 2 u32 match u32 0 0 action mirred egress mirror dev t_vpp_remotevpn')

sys.exit(0)
