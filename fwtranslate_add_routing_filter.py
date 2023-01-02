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
#   "entity":"agent",
#   "message":"add-routing-filter",
#   "params":{
#       "name":"filterName",
#       "description":"default routing filter",
#       "rules":[
#           {
#               "route":"0.0.0.0/0",
#               "action":"allow",
#               "nextHop":"",
#               "priority":4
#           },
#           {
#               "route":"5.5.5.5/32",
#               "action":"allow",
#               "nextHop":"",
#               "priority":2
#           },
#           {
#               "route":"8.8.8.8/32",
#               "action":"allow",
#               "nextHop":"2.2.2.2",
#               "priority":1
#           },
#           {
#               "route":"9.9.9.9/32",
#               "action":"allow",
#               "nextHop":"",
#               "priority":3
#           }
#       ]
#   }
# }
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
# So, when using FRR route maps to achieve the "routing filter" functionally,
# here is the way (the names and networks are the params of the request example above):
#
# We force that the "rules" list will have a route for "0.0.0.0/0".
# This route will be use as the "default" for all routes except those that they have representation in the "rules" list.
# If the default route action is "allow", the FRR last route-map will be:
#     route-map filterName permit 5
#       description default routing filter
#
# If the default route action is "deny", the FRR last route-map will be:
#     route-map filterName deny 5
#       description default routing filter
#
# We don't have "match" in this last default route-map, hence, all routes considered as "matched" hance they are permitted or denied.
#
# We analyze the rest of the list and convert it to FRR commands (See explanation in the function below).
#
def add_routing_filter(params):
    """Configure Routing Filter.

    :param params:

    :returns: cmd_list. List of commands.
    """
    cmd_list = []

    name = params.get('name')
    description = params.get('description')

    rules = params.get('rules', [])

    add_vtysh_commands, remove_vtysh_commands = _convert_params_to_frr_configs(name, description, rules)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "frr_vtysh_run"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   =  f"add FRR routing filter. Name={name}"
    cmd['cmd']['params'] = {
                    'commands': add_vtysh_commands
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "frr_vtysh_run"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['params'] = {
                    'commands': remove_vtysh_commands
    }
    cmd['revert']['descr']   =  f"remove FRR routing filter. Name={name}"
    cmd_list.append(cmd)

    return cmd_list

def _get_rule_params(rule):
    route = rule.get('route') # "5.5.5.5/32",
    action = rule.get('action') # "allow",
    nextHop = rule.get('nextHop') # "",
    return (route, action, nextHop)

def _get_route_map_frr_commands(name, description, action, seq, match_acl_name=None, next_hop=None):
    frr_action = 'permit' if action == 'allow' else 'deny'
    commands = [
        f'route-map {name} {frr_action} {seq}',
        f'  description {description}',
    ]

    if match_acl_name:
        commands.append(f'  match ip address {match_acl_name}')

    if next_hop:
        commands.append(f'  set ip next-hop {next_hop}')

    return commands


# The logic to convert rules to route-maps and access-lists is as follows:
#
# First, we sort the "rules" by "priority" field. As written above, multiple route-map with the same name
# can be configured. Route that is "matched" early in the chain
# will not continue to the next steps, but will be permitted/denied according to the policy.
#
# Then, we loop over the rules, one by one and creates groups of routes that have the same set of actions.
# Route has "action" (allow, deny), and "nextHop" (ipv4 address or empty).
# When looping on the routes, we group all routes that their "action" and "nextHop" are the same.
#
# Then, we loop over the groups and we create access-lists and route-maps for each group.
# We do not create route-map for a group that has same set of actions as the default route.
#
def _convert_params_to_frr_configs(name, description, rules):
    '''Convert flexiManage route map params to FRR add and remove commands.

    :param name:         name of route map.
    :param description:  description of the route map
    :param rules:        list of rules.

    :returns: tuple with two lists - add commands and remove commands.
    '''
    add_commands    = []
    remove_commands = []

    groups = {}
    default_rule = None

    rules = sorted(rules, key=lambda x: x['priority'])

    for rule in rules:
        route, action, nextHop = _get_rule_params(rule)

        if route == '0.0.0.0/0': # don't create group for default route, we always add it at the end.
            default_rule = (route, action, nextHop)
            continue

        group_key = f'{action}_{nextHop}' # "action" and "nextHop" are the key to check if routes should be groups.

        if not group_key in groups:
            groups[group_key] = []

        groups[group_key].append(route)

    if not default_rule:
        raise Exception(f'default action for routing filter {name} is missing')

    default_rule_route, default_rule_action, default_rule_nextHop = default_rule

    route_map_seq = 5  # each route-map should have different order number.
    for idx, group_key in enumerate(groups):
        routes = groups[group_key]
        action, nextHop = group_key.split('_')

        if action == default_rule_action and nextHop == default_rule_nextHop:
            continue # no need a dedicated access list and route maps if they are going to be matched by default rule.

        access_list_name = f'rm_{name}_group_{idx}'
        for route in routes:
            add_commands.append(f'access-list {access_list_name} permit {route}')
            remove_commands.append(f'no access-list {access_list_name} permit {route}')

        add_commands += _get_route_map_frr_commands(name, description, action, route_map_seq, access_list_name, nextHop)
        route_map_seq += 5

    # add default rule route map at the end
    add_commands += _get_route_map_frr_commands(name, description, default_rule_action, route_map_seq, None, default_rule_nextHop)
    remove_commands.append(f'no route-map {name}')

    return add_commands, remove_commands

def get_request_key(params):
    """Get add-routing-filter command.

    :param params:        Parameters from flexiManage.

    :returns: add-routing-filter command.
    """
    name = params.get('name')
    key = f'add-routing-filter-{name}'
    return key
