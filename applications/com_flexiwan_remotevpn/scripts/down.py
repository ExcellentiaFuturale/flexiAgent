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
script_utils.remove_from_bgp(ifconfig_local_ip, ifconfig_netmask)
script_utils.remove_tun_from_vpp()