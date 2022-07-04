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

import psutil
import socket

import fwglobals
import fwutils

from netaddr import IPAddress

def get_ip(mac_address):
    interfaces = psutil.net_if_addrs()
    for if_name, addrs in interfaces.items():
        ip = ''
        netmask = ''
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
                netmask = str(IPAddress(addr.netmask).netmask_bits())
            if addr.family == socket.AF_PACKET:
                mac = addr.address
        if mac == mac_address and ip:
            return (if_name, ip, netmask)
    return ('', '', '')

def dev_id_is_azure(dev_id):
    return fwutils.dev_id_is_of_type(dev_id, 'mlx5_core')
