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

def add_ospf(params):
    """OSPF configuration to frr.

    :param cmd_list:            List of commands.

    :returns: None.
    """
    cmd_list = []

    # routerId
    routerId = params.get('routerId')
    if routerId:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "frr_vtysh_run"
        cmd['cmd']['module'] = "fwutils"
        cmd['cmd']['descr']  =  f"add routerId {routerId} to OSPF"
        cmd['cmd']['params'] = {
                    'commands'   : ["router ospf", f"ospf router-id {routerId}"],
                    'restart_frr': True,
                    'on_error_commands': ["router ospf", f"no ospf router-id {routerId}"],
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "frr_vtysh_run"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['params'] = {
                    'commands'   : ["router ospf", f"no ospf router-id {routerId}"],
                    'restart_frr': True,
        }
        cmd['revert']['descr']   =  f"remove routerId {routerId} from OSPF"
        cmd_list.append(cmd)

    redistribute_bgp = params.get('redistributeBgp')
    if redistribute_bgp:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "frr_vtysh_run"
        cmd['cmd']['module'] = "fwutils"
        cmd['cmd']['descr']  =  "add redistribute bgp to OSPF configuration"
        cmd['cmd']['params'] = {
                    'commands'   : ["router ospf", "redistribute bgp"],
                    'on_error_commands': ["router ospf", "no redistribute bgp"],
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "frr_vtysh_run"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['params'] = {
                    'commands'   : ["router ospf", "no redistribute bgp"],
        }
        cmd['revert']['descr']   =  "remove redistribute bgp to OSPF configuration"
        cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-ospf-config command.

    :param params:        Parameters from flexiManage.

    :returns: add-ospf-config command.
    """
    key = 'add-ospf-config'
    return key
