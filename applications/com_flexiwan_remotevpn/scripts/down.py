#! /usr/bin/python3

# This script is called by OpenVpn after TUN/TAP device close

import sys

import script_utils

# get OpenVpn settings
tup_dev = sys.argv[1]
tup_mtu = sys.argv[2]
link_mtu = sys.argv[3]
ifconfig_local_ip = sys.argv[4]
ifconfig_netmask = sys.argv[5]

script_utils.remove_tc_commands(vpn_tun_is_up=False)
script_utils.remove_from_ospf(ifconfig_local_ip, ifconfig_netmask)
script_utils.remove_tun_from_vpp()