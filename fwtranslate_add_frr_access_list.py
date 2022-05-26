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
#     "message": "add-frr-access-list",
#     "params": {
#         "name": "default",
#         "description": "default",
#         "rules": [
#             {
#                 "sequence": "100",
#                 "action": "permit",
#                 "network": "any"
#             }
#         ]
#     }
# }
def add_frr_access_list(params):
    """Configure FRR Access list.

    :param params:

    :returns: cmd_list. List of commands.
    """
    cmd_list = []
    vty_commands = []

    name = params.get('name')
    description = params.get('description')

    vty_commands.append(f'access-list {name} remark {description}')

    rules = params.get('rules', [])
    for rule in rules:
        sequence = rule.get('sequence')
        action = rule.get('action')
        network = rule.get('network')

        vty_commands.append(f'access-list {name} seq {sequence} {action} {network}')

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "frr_vtysh_run"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   =  f"add FRR access list. Name={name}"
    cmd['cmd']['params'] = {
                    'commands': vty_commands,
                    'on_error_commands': [f'no access-list {name}'],
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "frr_vtysh_run"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['params'] = {
                    'commands': [f'no access-list {name}'],
    }
    cmd['revert']['descr']   =  f"remove FRR access list. Name={name}"
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-frr-access-list command.

    :param params:        Parameters from flexiManage.

    :returns: add-frr-access-list command.
    """
    name = params.get('name')
    key = f'add-frr-access-list-{name}'
    return key
