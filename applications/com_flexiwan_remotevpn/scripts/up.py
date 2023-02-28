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

# This script is called by OpenVpn after successful TUN / TAP device open

import sys
import traceback

import script_utils
from scripts_logger import Logger
from netaddr import IPAddress

logger = Logger()

# get OpenVpn settings
tun_dev = sys.argv[1]
tun_mtu = sys.argv[2]
link_mtu = sys.argv[3]
ifconfig_local_ip = sys.argv[4]
ifconfig_netmask = sys.argv[5]

try:
    mask = IPAddress(ifconfig_netmask).netmask_bits()
    ip = f'{ifconfig_local_ip}/{mask}'

    script_utils.create_tun_in_vpp(ip)
    script_utils.add_tc_commands(ifconfig_local_ip)
except Exception as e:
    logger.error(f'Failed in running "up" script. err: {str(e)}. {str(traceback.extract_stack())}')
    sys.exit(1)
