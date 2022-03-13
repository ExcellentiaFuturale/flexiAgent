#! /usr/bin/python3

# This script is called by OpenVpn after successful TUN / TAP device open

import sys
import traceback

import script_utils
from scripts_logger import logger

# get OpenVpn settings
tun_dev = sys.argv[1]
tun_mtu = sys.argv[2]
link_mtu = sys.argv[3]
ifconfig_local_ip = sys.argv[4]
ifconfig_netmask = sys.argv[5]

ospf = False
vpp_tun = False
tc_commands = False

try:
    ospf = True
    script_utils.add_to_ospf(ifconfig_local_ip, ifconfig_netmask)

    vpp_tun = True
    script_utils.create_tun_in_vpp(ifconfig_local_ip, ifconfig_netmask)

    tc_commands = True
    script_utils.add_tc_commands(ifconfig_local_ip)
except Exception as e:
    if tc_commands:
        script_utils.remove_tc_commands(vpn_tun_is_up=True)

    if vpp_tun:
        script_utils.remove_tun_from_vpp()

    if ospf:
        script_utils.remove_from_ospf(ifconfig_local_ip, ifconfig_netmask)
    logger(f'Failed in running "up" script. err: {str(e)} "\r\n" {str(traceback.extract_stack())}')
    sys.exit(1)
