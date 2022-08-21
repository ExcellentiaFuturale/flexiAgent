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

# add_routing_filter
# --------------------------------------
# Translates following request into list of commands:
#
# {
#     "entity": "agent",
#     "message": "add-routing-filter",
#     "params": {
#         "name": "filterName",
#         "description": "filterName",
#         "defaultAction": 'deny',
#         "rules": [
#             {
#                 "network": "100.0.0.1/24"
#             }
#         ]
#     }
# }
#
# As generated commands configure the FRR, the FRR terminology is used as follows:
#
#   "defaultAction" -
#       if 'deny' - all routes should be denied except those specified in the "rules".
#       if 'allow' - all routes should be allowed except those specified in the "rules".
#
# FRR has many filtering operations, and basically it is done by "Route Map" and "Access list".
#
# A route map schema in FRR includes few parts but the following are important for us:
#   1. Matching Conditions - filter condition, optional.
#   2. Matching Policy - what to do if "Matching Conditions" is matched, required.
#   example:
#       route-map name permit 5
#           match ip address access-list-name
#
#       The "match ip address access-list-name" is the "Matching Conditions".
#           For each route it will try to match it in the access-list.
#       The "permit" is the "Matching Policy" which means what do to if "Matching Conditions" is matched.
#
# Important things to know when using FRR route maps and access lists:
#   1. Multiple route-map with the same name can be implemented with different order number.
#       The FRR will go over them one be one, starting from the lower order number, and try to find a match.
#       if matched, it will use the "Matching Policy", if not matched, it will try to go the next route-map if exists.
#   2. At the end of route-map process, if not matched, the default is always to deny.
#       The "permit" and "deny" are only used for *matched* routes.
#   3. If no "Matching Conditions" specified (since it's optional) - all routes will be *matched*.
#       If route map uses "permit", all routes will be permitted.
#   4. Matching by access list means that only *permitted* networks in the access-list are matched.
#       Example:
#
#       "
#       access-list access-list-name seq 5 permit 155.55.55.1/24
#       access-list access-list-name seq 10 deny 166.66.66.1/24
#       route-map name permit 5
#           match ip address access-list-name
#       "
#
#       The 155.55.55.1/24 will be permitted because it is permitted by the access list, hence it matched.
#       The 166.66.66.1/24 will be denied because it is denied by the access list, hence it not matched,
#           and go to default which is to deny.
#
#
#       So, when using FRR route maps to achieve the "routing filter" functionally,
#       here is the way (the names and networks are the params of the request example above):
#
#       "defaultAction: 'deny'" - Deny all routes, but allow the specified in the "rules":
#           "
#           access-list filterName seq 5 permit 100.0.0.1/24
#           route-map filterName permit 5
#              match ip address filterName
#           "
#
#           All routes permitted by "filterName" access-list will be matched and *permitted* by route-map
#           All the others will go to default which is "deny"
#
#       "defaultAction: 'allow'" - Allow all routes, but deny the specified in the "rules":
#           "
#           access-list filterName seq 5 permit 100.0.0.1/24
#           route-map filterName deny 5
#              match ip address filterName
#
#           route-map filterName permit 10
#           "
#
#           All routes that permitted by "filterName" access-list will be matched and *denied* by route-map order number 5.
#           All the others will go to next route-map (order number 10) that has no "Matching Conditions", hence all routes are matched,
#           And permitted.
#
def add_routing_filter(params):
    """Configure Routing Filter.

    :param params:

    :returns: cmd_list. List of commands.
    """
    cmd_list = []
    vtysh_commands = []

    name = params.get('name')
    description = params.get('description')
    default_action = params.get('defaultAction', 'deny')
    rules = params.get('rules', [])

    # set access list description
    vtysh_commands.append(f'access-list {name} remark {description}')

    # create acl with name for each rule with "permit"
    rules = params.get('rules', [])
    for rule in rules:
        network = rule.get('network')
        vtysh_commands.append(f'access-list {name} permit {network}')

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "frr_vtysh_run"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   =  f"add FRR access list. Name={name}"
    cmd['cmd']['params'] = {
                    'commands': vtysh_commands,
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


    route_map_vtysh_commands = []
    if default_action == 'deny':  # deny all
        route_map_vtysh_commands += [
            f'route-map {name} permit 5',
            f'  description {description}',
            f'  match ip address {name}',
        ]
    else: # allow all
        route_map_vtysh_commands += [
            f'route-map {name} deny 5',
            f'  description {description}',
            f'  match ip address {name}',

            f'route-map {name} permit 10',
        ]

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "frr_vtysh_run"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   =  f"add FRR route map. Name={name}"
    cmd['cmd']['params'] = {
                    'commands': route_map_vtysh_commands,
                    'on_error_commands': [f'no route-map {name}'],
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "frr_vtysh_run"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['params'] = {
                    'commands': [f'no route-map {name}'],
    }
    cmd['revert']['descr']   =  f"remove FRR route map. Name={name}"
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-routing-filter command.

    :param params:        Parameters from flexiManage.

    :returns: add-routing-filter command.
    """
    name = params.get('name')
    key = f'add-routing-filter-{name}'
    return key
