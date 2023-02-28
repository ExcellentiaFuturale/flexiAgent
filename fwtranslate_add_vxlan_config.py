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
    return vxlan_config_translation_command(params)

def modify_vxlan_config(new_params, old_params):
    return vxlan_config_translation_command(new_params, old_params)

def vxlan_config_translation_command(new_params, old_params=None):
    cmd_list = []

    new_port = int(new_params.get('port'))
    old_port = int(old_params.get('port')) if old_params else fwglobals.g.default_vxlan_port

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "exec"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   = f"set {new_port} as the default vxlan port"
    cmd['cmd']['params']  = {
                    'cmd': f"sudo vppctl set vxlan default-port {new_port}"
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "exec"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['params'] = {
                    'cmd': f"sudo vppctl set vxlan default-port {old_port}"
    }
    cmd['revert']['descr']  = f"set {old_port} as the default vxlan port"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "vpp_add_remove_nat_identity_mapping_from_wan_interfaces"
    cmd['cmd']['module'] = "fwutils"
    cmd['cmd']['params'] = { 'is_add': 1, 'port': new_port, 'protocol': 'udp' }
    cmd['cmd']['descr']  = f"add NAT identity mapping for {new_port} UDP port for all WAN interfaces"
    cmd['revert'] = {}
    cmd['revert']['func']   = "vpp_add_remove_nat_identity_mapping_from_wan_interfaces"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['params'] = { 'is_add': 0, 'port': new_port, 'protocol': 'udp' }
    cmd['revert']['descr']  = f"remove NAT identity mapping for {new_port} UDP port from all WAN interfaces"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['object']  = "fwglobals.g.stun_wrapper"
    cmd['cmd']['func']    = "update_vxlan_port"
    cmd['cmd']['params']  = { 'port': new_port }
    cmd['cmd']['descr']   = "update STUN vxlan port"
    cmd['cmd']['filter']  = "must"
    cmd['revert'] = {}
    cmd['revert']['object'] = "fwglobals.g.stun_wrapper"
    cmd['revert']['func']   = "update_vxlan_port"
    cmd['revert']['params'] = { 'port': old_port }
    cmd['revert']['descr']  = f"update STUN vxlan port"
    cmd['revert']['filter'] = "must"
    cmd_list.append(cmd)

    return cmd_list

modify_vxlan_config_supported_params = {
    'port': None
}

def get_request_key(params):
    """Get add-vxlan-config key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-vxlan-config request.
    """
    key = 'add-vxlan-config' # only one request.
    return key
