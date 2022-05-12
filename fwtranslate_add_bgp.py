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
#       {
#           "ip": "8.8.8.8/31",
#           "remoteASN": "55",
#           "password": "abc"
#           "accessList": "default"
#       },
#       {
#           "ip": "6.6.6.6/32",
#           "remoteASN": "44",
#           "password": "abc"
#           "accessList": ""
#       }
#   ]
# }
def add_bgp(params):
    """Configure BGP in FRR.

    :param params:

    :returns: cmd_list. List of commands.
    """
    cmd_list = []

    # enable bgp process
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "exec"
    cmd['cmd']['module']    = "fwutils"
    cmd['cmd']['params'] = {
                    'cmd':    'if [ -n "$(grep bgpd=no %s)" ]; then sudo sed -i -E "s/bgpd=no/bgpd=yes/" %s; sudo systemctl restart frr; fi' % (fwglobals.g.FRR_DAEMONS_FILE, fwglobals.g.FRR_DAEMONS_FILE),
    }
    cmd['cmd']['descr'] = "start BGP daemon"
    cmd['revert'] = {}
    cmd['revert']['func']   = "exec"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['descr']  = "stop BGP daemon"
    cmd['revert']['params'] = {
                    'cmd':    'if [ -n "$(grep bgpd=yes %s)" ]; then sudo sed -i -E "s/bgpd=yes/bgpd=no/" %s; sudo systemctl restart frr; fi' % (fwglobals.g.FRR_DAEMONS_FILE, fwglobals.g.FRR_DAEMONS_FILE),
    }
    cmd_list.append(cmd)

    local_asn = params.get('localASN')
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
    ]

    # router ID
    router_id = params.get('routerId')
    if router_id:
        vty_commands.append(f'bgp router-id {router_id}')

    keepalive_interval = params.get('keepaliveInterval')
    hold_interval = params.get('holdInterval')

    # Neighbors
    neighbors = params.get('neighbors', [])
    for neighbor in neighbors:
        ip = neighbor.get('ip')
        remote_asn = neighbor.get('remoteASN')
        password = neighbor.get('password')

        vty_commands.append(f'neighbor {ip} remote-as {remote_asn}')

        # Allow peerings between directly connected eBGP peers using loopback addresses.
        vty_commands.append(f'neighbor {ip} disable-connected-check')

        if password:
            vty_commands.append(f'neighbor {ip} password {password}')

        if keepalive_interval and hold_interval:
            vty_commands.append(f'neighbor {ip} timers {keepalive_interval} {hold_interval}')

    vty_commands.append('address-family ipv4 unicast')
    vty_commands.append('redistribute ospf')

    for neighbor in neighbors:
        ip = neighbor.get('ip')
        vty_commands.append(f'neighbor {ip} activate')

        route_map_inbound_filter = neighbor.get('routeMapInboundFilter')
        if route_map_inbound_filter:
            vty_commands.append(f'neighbor {ip} route-map {route_map_inbound_filter} in')

        route_map_outbound_filter = neighbor.get('routeMapOutboundFilter')
        if route_map_outbound_filter:
            vty_commands.append(f'neighbor {ip} route-map {route_map_inbound_filter} out')


    networks = params.get('networks', [])
    for network in networks:
        ip = network.get('ipv4')
        vty_commands.append(f'network {ip}')

    vty_commands.append('exit-address-family')

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "frr_vtysh_run"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   =  f"add bgp router ASN={local_asn}"
    cmd['cmd']['params'] = {
                    'commands': vty_commands,
                    'restart_frr': True,
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "frr_vtysh_run"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['params'] = {
                    'commands': [f'no router bgp {local_asn}'],
                    'restart_frr': True,
    }
    cmd['revert']['descr']   =  f"remove bgp router ASN={local_asn}"
    cmd_list.append(cmd)

    # TODO: complete this section
    # cmd = {}
    # cmd['cmd'] = {}
    # cmd['cmd']['name']   = "python"
    # cmd['cmd']['params'] = {
    #         'module': 'fwutils',
    #         'func':   'frr_create_redistribution_filter',
    #         'args': {
    #             'router': router_bgp_asn,
    #             'acl': fwglobals.g.FRR_BGP_ACL,
    #             'route_map': fwglobals.g.FRR_BGP_ROUTE_MAP,
    #             'route_map_num': '2', # 1 is for OSPF, 2 is for BGP
    #         }
    # }
    # cmd['cmd']['descr']   =  "add bgp redistribution filter"
    # cmd['revert'] = {}
    # cmd['revert']['name']   = "python"
    # cmd['revert']['params'] = {
    #         'module': 'fwutils',
    #         'func':   'frr_create_redistribution_filter',
    #         'args': {
    #             'router': router_bgp_asn,
    #             'acl': fwglobals.g.FRR_BGP_ACL,
    #             'route_map': fwglobals.g.FRR_BGP_ROUTE_MAP,
    #             'route_map_num': '2', # 1 is for OSPF, 2 is for BGP
    #             'revert': True
    #         }
    # }
    # cmd['revert']['descr']   =  "remove bgp redistribution filter"
    # cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-bgp command.

    :param params:        Parameters from flexiManage.

    :returns: add-bgp command.
    """
    key = 'add-bgp'
    return key
