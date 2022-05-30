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
# {
#   "entity": "agent",
#   "message": "add-bgp",
#   "params": {
#       "routerId": "",
#       "holdInterval": "40",
#       "keepaliveInterval": "40",
#       "localASN": "35",
#       "neighbors": [
#           {
#               "ip": "8.8.8.8",
#               "remoteASN": "666",
#               "password": "",
#               "inboundFilter": "test-rm",
#               "outboundFilter": "test-rm"
#           },
#           {
#               "ip": "9.9.9.9",
#               "remoteASN": "555",
#               "password": "",
#               "inboundFilter": "",
#               "outboundFilter": ""
#           },
#       ]
#       "networks": [
#           {
#               "ipv4": "192.168.70.1/24"
#           }
#       ]
#   ]
# }
def add_bgp(params):
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


    local_asn = params.get('localASN')
    router_id = params.get('routerId')
    keepalive_interval = params.get('keepaliveInterval')
    hold_interval = params.get('holdInterval')
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
        ip = neighbor.get('ip')
        remote_asn = neighbor.get('remoteASN')
        password = neighbor.get('password')

        vty_commands += [
            f'neighbor {ip} remote-as {remote_asn}',

            # Allow peering between directly connected eBGP peers using loopback addresses.
            f'neighbor {ip} disable-connected-check',

            f'neighbor {ip} password {password}' if password else None,

            f'neighbor {ip} timers {keepalive_interval} {hold_interval}' if keepalive_interval and hold_interval else None,
        ]

    vty_commands += [
        'address-family ipv4 unicast',
        f"redistribute kernel route-map {fwglobals.g.FRR_BGP_ROUTE_MAP}",
        'redistribute ospf' if redistribute_ospf else None,
    ]

    # loop again on neighbors. "address-family" (above) must be before that and after the first neighbors commands.
    for neighbor in neighbors:
        ip = neighbor.get('ip')
        inbound_filter = neighbor.get('inboundFilter')
        outbound_filter = neighbor.get('outboundFilter')

        vty_commands += [
            f'neighbor {ip} activate',
            f'neighbor {ip} route-map {inbound_filter} in' if inbound_filter else None,
            f'neighbor {ip} route-map {outbound_filter} out' if outbound_filter else None,
        ]

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

def get_request_key(params):
    """Get add-bgp command.

    :param params:        Parameters from flexiManage.

    :returns: add-bgp command.
    """
    key = 'add-bgp'
    return key
