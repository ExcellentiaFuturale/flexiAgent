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

# {
#     "entity": "agent",
#     "message": "add-frr-route-map",
#     "params": {
#         "name": "default",
#         "description": "default",
#         "action": "permit",
#         "sequence": "100",
#         "accessList": "default"
#     }
# }
def add_frr_route_map(params):
    """Configure FRR Route Map.

    :param params:

    :returns: cmd_list. List of commands.
    """
    cmd_list = []
    vty_commands = []

    name = params.get('name')
    description = params.get('description')
    action = params.get('action')
    sequence = params.get('sequence')
    access_list = params.get('accessList')

    vty_commands.append(f'route-map {name} {action} {sequence}')
    vty_commands.append(f'description {description}')

    if access_list:
        vty_commands.append(f'match ip address {access_list}')

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "frr_vtysh_run"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   =  f"add FRR route map. Name={name}"
    cmd['cmd']['params'] = {
                    'commands': vty_commands,
                    'restart_frr': True,
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "frr_vtysh_run"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['params'] = {
                    'commands': [f'no route-map {name}'],
                    'restart_frr': True,
    }
    cmd['revert']['descr']   =  f"remove FRR route map. Name={name}"
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-frr-route-map command.

    :param params:        Parameters from flexiManage.

    :returns: add-frr-route-map command.
    """
    name = params.get('name')
    key = f'add-frr-route-map-{name}'
    return key
