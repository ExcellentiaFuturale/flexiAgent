#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2019  flexiWAN Ltd.
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

import os

import fwutils
import fwglobals

def add_dhcp_config(params):
    """Generate commands to add DHCP configuration.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    cmd_list = []

    dev_id              = params.get('interface')
    range_start         = params.get('range_start')
    range_end           = params.get('range_end')
    dns                 = params.get('dns', [])
    mac_assign          = params.get('mac_assign', [])
    options             = params.get('options', [])
    max_lease_time      = params.get('maxLeaseTime')
    default_lease_time  = params.get('defaultLeaseTime')

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "modify_dhcpd_conf"
    cmd['cmd']['module']    = "fwutils"
    cmd['cmd']['descr']     = "update dhcpd config file"
    cmd['cmd']['params']    = {
        'is_add': 1,
        'dev_id': dev_id,
        'range_start': range_start,
        'range_end': range_end,
        'dns': dns,
        'mac_assign': mac_assign,
        'options': options,
        'max_lease_time': max_lease_time,
        'default_lease_time': default_lease_time
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "modify_dhcpd_conf"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['descr']  = "clean dhcpd config file"
    cmd['revert']['filter'] = 'must'   # When 'remove-XXX' commands are generated out of the 'add-XXX' commands, run this command even if vpp doesn't run
    cmd['revert']['params'] = {
        'is_add': 0,
        'dev_id': dev_id,
        'range_start': range_start,
        'range_end': range_end,
        'dns': dns,
        'mac_assign': mac_assign,
        'options': options,
        'max_lease_time': max_lease_time,
        'default_lease_time': default_lease_time
    }
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "os_system"
    cmd['cmd']['module'] = "fwutils"
    cmd['cmd']['params'] = { 'cmd': 'systemctl restart isc-dhcp-server', 'log_prefix': '_restart_dhcp_server' }
    cmd['cmd']['descr'] = "restart dhcp service"
    cmd['revert'] = {}
    cmd['revert']['func']   = "os_system"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['params'] = { 'cmd': 'systemctl restart isc-dhcp-server', 'log_prefix': '_restart_dhcp_server' }
    cmd['revert']['descr'] = "restart dhcp service"
    cmd_list.append(cmd)

    return cmd_list


def get_request_key(params):
    """Get add-dhcp-config command.

    :param params:        Parameters from flexiManage.

    :returns: add-dhcp-config command.
    """
    key = 'add-dhcp-config %s' % params['interface']
    return key
