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

import fwglobals
import fwutils

# {
#   "entity": "agent",
#   "message": "add-routing-bgp",
#   "params": {
#       "routerId": "",
#       "localAsn": "35",
#       "redistributeOspf": True,
#       "neighbors": [
#           {
#               "ip": "8.8.8.8",
#               "remoteAsn": "666",
#               "password": "",
#               "inboundFilter": "test-rm",
#               "outboundFilter": "test-rm",
#               "holdInterval": "40",
#               "keepaliveInterval": "40",
#           },
#           {
#               "ip": "9.9.9.9",
#               "remoteAsn": "555",
#               "password": "",
#               "inboundFilter": "",
#               "outboundFilter": "",
#               "holdInterval": "40",
#               "keepaliveInterval": "40",
#           },
#       ]
#       "networks": [
#           {
#               "ipv4": "192.168.70.1/24"
#           }
#       ]
#   ]
# }
def add_routing_bgp(params):
    """Configure BGP in FRR.

    :param params:

    :returns: cmd_list. List of commands.
    """
    cmd_list = []

    # kernel redistribute route-map
    kernel_redistribute_route_map = [
        f"route-map {fwglobals.g.FRR_BGP_ROUTE_MAP} permit 1",
        f"match ip address {fwglobals.g.FRR_BGP_ACL}",
    ]
    # revert kernel redistribute route-map
    kernel_redistribute_route_map_revert = [
        f"no route-map {fwglobals.g.FRR_BGP_ROUTE_MAP} permit 1",
    ]
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "frr_vtysh_run"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   =  "create BGP redistribute kernel route-map"
    cmd['cmd']['params'] = {
                    'commands': kernel_redistribute_route_map,
                    'on_error_commands': kernel_redistribute_route_map_revert,
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "frr_vtysh_run"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['params'] = {
                    'commands': kernel_redistribute_route_map_revert,
    }
    cmd['revert']['descr']   =  "remove BGP redistribute kernel route-map"
    cmd_list.append(cmd)


    local_asn = params.get('localAsn')
    router_id = params.get('routerId')
    redistribute_ospf = params.get('redistributeOspf')

    vty_commands = [
        f'router bgp {local_asn}',

        # used to disable the connection verification process for EBGP peering sessions
        # that are reachable by a single hop but are configured on a loopback interface
        # or otherwise configured with a non-directly connected IP address.
        'bgp disable-ebgp-connected-route-check',

        # This command eliminates the need to apply incoming and outgoing filters for eBGP sessions
        # Without the cancellation of this option, Without the incoming filter,
        # no routes will be accepted. Without the outgoing filter, no routes will be announced.
        'no bgp ebgp-requires-policy',

        f'bgp router-id {router_id}' if router_id else None,
    ]

    # Neighbors
    neighbors = params.get('neighbors', [])
    for neighbor in neighbors:
        vty_commands += _get_neighbor_frr_commands(neighbor)

    vty_commands += [
        'address-family ipv4 unicast',
        f"redistribute kernel route-map {fwglobals.g.FRR_BGP_ROUTE_MAP}",
        'redistribute ospf' if redistribute_ospf else None,
    ]

    # loop again on neighbors. "address-family" (above) must be before that and after the first neighbors commands.
    for neighbor in neighbors:
        vty_commands += _get_neighbor_address_family_frr_commands(neighbor)

    networks = params.get('networks', [])
    for network in networks:
        ip = network.get('ipv4')
        vty_commands += [f'network {ip}']

    vty_commands += ['exit-address-family']

    # During above code lines we put None sometimes. Here we are filtering all None out.
    vty_commands = list(filter(None, vty_commands))

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "frr_vtysh_run"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   =  f"add bgp router ASN={local_asn}"
    cmd['cmd']['params'] = {
                    'commands': vty_commands,
                    'restart_frr': True,
                    'wait_after': 2,
                    'on_error_commands': [f'no router bgp {local_asn}']
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "frr_vtysh_run"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['params'] = {
                    'commands': [f'no router bgp {local_asn}'],
                    'restart_frr': True,
                    'wait_after': 2
    }
    cmd['revert']['descr']   =  f"remove bgp router ASN={local_asn}"
    cmd_list.append(cmd)

    return cmd_list

def _get_neighbor_frr_commands(neighbor):
    ip = neighbor.get('ip')
    remote_asn = neighbor.get('remoteAsn')
    password = neighbor.get('password')
    keepalive_interval = neighbor.get('keepaliveInterval')
    hold_interval = neighbor.get('holdInterval')

    commands = [
        f'neighbor {ip} remote-as {remote_asn}',

        # Allow peering between directly connected eBGP peers using loopback addresses.
        f'neighbor {ip} disable-connected-check',
    ]

    if password:
        commands.append(f'neighbor {ip} password {password}')

    if keepalive_interval and hold_interval:
        commands.append(f'neighbor {ip} timers {keepalive_interval} {hold_interval}')

    return commands

def _get_neighbor_address_family_frr_commands(neighbor):
    ip = neighbor.get('ip')
    inbound_filter = neighbor.get('inboundFilter')
    outbound_filter = neighbor.get('outboundFilter')

    commands = [
        f'neighbor {ip} activate',
    ]

    if inbound_filter:
        commands.append(f'neighbor {ip} route-map {inbound_filter} in')

    if outbound_filter:
        commands.append(f'neighbor {ip} route-map {outbound_filter} out')

    return commands

def _generate_modify_cmd(old_dict, new_dict, generate_remove_cmd_func, generate_add_cmd_func, cmd_list):
    # loop on the old list
    for old in old_dict:
        # if item doesn't exists in new - generate remove frr commands
        if not old in new_dict:
            commands = generate_remove_cmd_func(old_dict[old])
            cmd_list += commands
            continue

        # if item exists in new and they are the same - remove it from new list
        if old_dict[old] == new_dict[old]:
            del new_dict[old]
            continue

    for new in new_dict:
        commands = generate_add_cmd_func(new_dict[new])
        cmd_list += commands

def _modify_networks(cmd_list, new_params, old_params):
    local_asn = new_params.get('localAsn')

    def _remove_cmd_func(network):
        ipv4 = network.get('ipv4')
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "frr_vtysh_run"
        cmd['cmd']['module']  = "fwutils"
        cmd['cmd']['descr']   =  f"remove existing BGP network {ipv4}"
        cmd['cmd']['params'] = {
                        'commands': [f'router bgp {local_asn}', f'address-family ipv4 unicast', f'no network {ipv4}'],
        }
        return [cmd]

    def _add_cmd_func(network):
        ipv4 = network.get('ipv4')
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "frr_vtysh_run"
        cmd['cmd']['module']  = "fwutils"
        cmd['cmd']['descr']   =  f"add/override BGP network {ipv4}"
        cmd['cmd']['params'] = {
                        'commands': [f'router bgp {local_asn}', f'address-family ipv4 unicast', f'network {ipv4}'],
        }
        return [cmd]

    # convert old and new lists to dicts with IP as keys
    old_networks = fwutils.list_to_dict_by_key(old_params.get('networks', []), 'ipv4')
    new_networks = fwutils.list_to_dict_by_key(new_params.get('networks', []), 'ipv4')

    _generate_modify_cmd(old_networks, new_networks, _remove_cmd_func, _add_cmd_func, cmd_list)

def _modify_neighbors(cmd_list, new_params, old_params):
    local_asn = new_params.get('localAsn')

    def _remove_cmd_func(neighbor):
        ip = neighbor.get('ip')
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "frr_vtysh_run"
        cmd['cmd']['module']  = "fwutils"
        cmd['cmd']['descr']   =  f"remove existing BGP neighbor {ip}"
        cmd['cmd']['params'] = {
                        'commands': [f'router bgp {local_asn}', f'no neighbor {ip}'],
        }
        return [cmd]

    def _add_cmd_func(neighbor):
        ip = neighbor.get('ip')
        vtysh_commands = [f'router bgp {local_asn}']
        vtysh_commands += _get_neighbor_frr_commands(neighbor)

        vtysh_commands.append(f'address-family ipv4 unicast')

        vtysh_commands += _get_neighbor_address_family_frr_commands(neighbor)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "frr_vtysh_run"
        cmd['cmd']['module']  = "fwutils"
        cmd['cmd']['descr']   =  f"add/override BGP neighbor {ip}"
        cmd['cmd']['params'] = {
                        'commands': vtysh_commands,
        }
        return [cmd]

    # convert old and new lists to dicts with IP as keys
    old_neighbors = fwutils.list_to_dict_by_key(old_params.get('neighbors', []), 'ip')
    new_neighbors = fwutils.list_to_dict_by_key(new_params.get('neighbors', []), 'ip')

    _generate_modify_cmd(old_neighbors, new_neighbors, _remove_cmd_func, _add_cmd_func, cmd_list)

# {
#     "entity": "agent",
#     "message": "modify-routing-bgp",
#     "params": {
#         "localAsn": "65001",
#         "neighbors": [
#             {
#                 "ip": "8.8.8.8",
#                 "remoteAsn": "6668",
#                 "password": "",
#                 "inboundFilter": "",
#                 "outboundFilter": "",
#                 "holdInterval": "90",
#                 "keepaliveInterval": "30"
#             },
#             {
#                 "ip": "9.9.9.9",
#                 "remoteAsn": "45",
#                 "password": "",
#                 "inboundFilter": "",
#                 "outboundFilter": "",
#                 "holdInterval": "90",
#                 "keepaliveInterval": "30"
#             }
#         ],
#         "networks": [
#             {
#                 "ipv4": "155.155.155.12/32"
#             }
#         ],
#         "redistributeOspf": true
#     }
# }
#
def modify_routing_bgp(new_params, old_params):
    cmd_list = []

    local_asn = new_params.get('localAsn')

    _modify_neighbors(cmd_list, new_params, old_params)
    _modify_networks(cmd_list, new_params, old_params)

    old_redistribute_ospf = old_params.get('redistributeOspf', True)
    new_redistribute_ospf = new_params.get('redistributeOspf', True)

    if old_redistribute_ospf != new_redistribute_ospf:
        redistribute_ospf_cmd = 'redistribute ospf' if new_redistribute_ospf else \
                                'no redistribute ospf'
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "frr_vtysh_run"
        cmd['cmd']['module']  = "fwutils"
        cmd['cmd']['descr']   =  f"change BGP redistribute ospf option to {new_redistribute_ospf}"
        cmd['cmd']['params'] = {
                        'commands': [f'router bgp {local_asn}', f'address-family ipv4 unicast', redistribute_ospf_cmd],
        }
        cmd_list.append(cmd)

    return cmd_list

# The modify_X_supported_params variable represents set of modifiable parameters
# that can be received from flexiManage within the 'modify-X' request.
# If the received 'modify-X' includes parameters that do not present in this set,
# the agent framework will not modify the configuration item, but will recreate
# it from scratch. To do that it replaces 'modify-X' request with pair of 'remove-X'
# and 'add-X' requests, where 'remove-X' request uses parameters stored
# in the agent configuration database, and the 'add-X' request uses modified
# parameters received with the 'modify-X' request and all the rest of parameters
# are taken from the configuration database.
#
modify_routing_bgp_supported_params = {
    'neighbors': None,
    'networks': None,
    'redistributeOspf': None,
}

def get_request_key(params):
    """Get add-routing-bgp command.

    :param params:        Parameters from flexiManage.

    :returns: add-routing-bgp command.
    """
    key = 'add-routing-bgp'
    return key
