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

import copy

import fwglobals
import fwutils
import fw_nat_command_helpers

# add_wan_nat_mapping
# --------------------------------------
# Translates request:
#
#    {
#      "message": "add-wan-nat-mapping",
#      "params": {
#           "dev_id":"0000:00:01.00",
#           "port":"4789"
#      }
#    }
#
# into list of commands:
#
#    1.vpp.cfg
#    ------------------------------------------------------------
#    01. sudo vppctl nat44 out GigabitEthernet1/0/0 output-feature
#    02. sudo vppctl nat44 add interface address GigabitEthernet1/0/0 session-recovery
#    03. fwutils: enable forward of tap-inject to ip4-output features
#    04. sudo vppctl nat44 add identity mapping external GigabitEthernet1/0/0 udp 4789 vrf 0 del
#    05. sudo vppctl nat44 add static mapping udp local 0.0.0.0 4789 external GigabitEthernet1/0/0 4789 vrf 0

def add_wan_nat_mapping(params):
    """
    Generates command to default NAT identity mappings
    on WAN interfaces

    :param dev_id: device identifier of the WAN interface
    :type dev_id: String
    :return: Command params carrying the generated config
    :rtype: list
    """

     # Setup NAT config on WAN interface
    cmd_list = []
    dev_id  = params['dev_id']
    port = params.get('port', fwglobals.VXLAN_PORTS["port"])

    for service_name, service_cfg in fwglobals.WAN_INTERFACE_SERVICES.items():
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "call_vpp_api"
        cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr'] = "Add NAT WAN identity mapping for port %s:%d Protocol: %s" % (
            service_name, port, service_cfg['protocol'])
        cmd['cmd']['params'] = {
                        'api': "nat44_add_del_identity_mapping",
                        'args': {
                            'port':     port,
                            'protocol': fwutils.proto_map[service_cfg['protocol']],
                            'is_add':   1,
                            'substs': [
                                {'add_param': 'sw_if_index',
                                'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': dev_id}
                            ]
                        },
        }

        cmd['revert'] = {}
        cmd['revert']['func']   = "call_vpp_api"
        cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr'] = "Delete NAT WAN identity mapping for port %s:%d Protocol: %s" % (
            service_name, port, service_cfg['protocol'])
        cmd['revert']['params'] = {
                        'api': "nat44_add_del_identity_mapping",
                        'args': {
                            'port': port,
                            'protocol': fwutils.proto_map[service_cfg['protocol']],
                            'is_add': 0,
                            'substs': [
                                {'add_param': 'sw_if_index',
                                'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': dev_id}
                            ]
                        },
        }
        cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add wan nat mapping command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-wan-nat-mapping:%s' % params['dev_id']
