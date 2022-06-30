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

def is_azure_interface(driver):
    if driver == 'mlx5_core':
        return True

    return False

def get_ip(mac_address):
    interfaces = psutil.net_if_addrs()
    for addrs in interfaces.values():
        ip = ''
        netmask = ''
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
                netmask = addr.netmask
            if addr.family == socket.AF_PACKET:
                mac = addr.address
        if mac == mac_address and ip:
            return (ip, netmask)
