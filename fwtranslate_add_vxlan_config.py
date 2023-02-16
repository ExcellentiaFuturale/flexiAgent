#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2023  flexiWAN Ltd.
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
import fwglobals

# {
#   "entity":"agent"
#   "message":"add-vxlan-config"
#   "params":{
#       "port":"1212"
#   }
# }
def add_vxlan_config(params):
    """Generate commands to add VXLAN configuration.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    cmd_list = []

    port = int(params.get('port', 4789))

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "vpp_add_remove_nat_identity_mapping_from_wan_interfaces"
    cmd['cmd']['module'] = "fwutils"
    cmd['cmd']['params'] = { 'is_add': 1, 'port': port, 'protocol': 'udp' }
    cmd['cmd']['descr']  = f"add NAT identity mapping for {port} UDP port for all WAN interfaces"
    cmd['revert'] = {}
    cmd['revert']['func']   = "vpp_add_remove_nat_identity_mapping_from_wan_interfaces"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['params'] = { 'is_add': 0, 'port': port, 'protocol': 'udp' }
    cmd['revert']['descr']  = f"remove NAT identity mapping for {port} UDP port from all WAN interfaces"
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-vxlan-config key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-vxlan-config request.
    """
    key = 'add-vxlan-config' # only one request.
    return key
