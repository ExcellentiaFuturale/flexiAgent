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
#       },
#       {
#           "ip": "6.6.6.6/32",
#           "remoteASN": "44",
#           "password": "abc"
#       }
#   ]
# }
def add_bgp(params):
    """Change /etc/dhcp/dhcpd.conf config file.

    :param cmd_list:            List of commands.

    :returns: None.
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

    localASN = params.get('localASN')
    router_bgp_asn = 'router bgp %s' % localASN

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "frr_vtysh_run"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   =  f"add bgp router ASN={localASN}"
    cmd['cmd']['params'] = {
                    'commands': [f'router bgp {localASN}'],
                    'restart_frr': True,
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "frr_vtysh_run"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['params'] = {
                    'commands': [f'no router bgp {localASN}'],
                    'restart_frr': True,
    }
    cmd['revert']['descr']   =  f"remove bgp router ASN={localASN}"
    cmd_list.append(cmd)

    vty_commands = [router_bgp_asn]
    restart_frr = False

    routerId = params.get('routerId')
    neighbors = params.get('neighbors', [])
    keepaliveInterval = params.get('keepaliveInterval')
    holdInterval = params.get('holdInterval')
    networks = params.get('networks', [])

    # add remote tunnels IP as neighbors
    # tunnels = fwglobals.g.router_cfg.get_tunnels()
    # for tunnel in tunnels:
    #     # calc remote IP based on local
    #     ip  = IPNetwork(tunnel['loopback-iface']['addr'])     # 10.100.0.4 / 10.100.0.5
    #     ip.value  ^= IPAddress('0.0.0.1').value               # 10.100.0.4 -> 10.100.0.5 / 10.100.0.5 -> 10.100.0.4
    #     neighbors.append({
    #         'ip': str(ip.ip),
    #         'remoteASN': localASN # we create an iBGP session between tunnels interfaces
    #     })

    if routerId:
        vty_commands.append('bgp router-id %s' % routerId)
        restart_frr = True

    neighbors = params.get('neighbors')
    keepaliveInterval = params.get('keepaliveInterval')
    holdInterval = params.get('holdInterval')
    if neighbors:
        for neighbor in neighbors:
            ip = neighbor['ip']
            remoteASN = neighbor['remoteASN']
            vty_commands.append('neighbor %s remote-as %s' % (ip, remoteASN))

            password = neighbor.get('password')
            if password:
                vty_commands.append('neighbor %s password %s' % (ip, password))

            if keepaliveInterval and holdInterval:
                vty_commands.append('neighbor %s timers %s %s' % (ip, keepaliveInterval, holdInterval))

    if vty_commands:
        vty_commands_revert = map(lambda x: 'no %s' % x, list(reversed(vty_commands)))

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "frr_vtysh_run"
        cmd['cmd']['module']  = "fwutils"
        cmd['cmd']['descr']   =  "add BGP configurations"
        cmd['cmd']['params'] = {
                        'commands': list(vty_commands),
                        'restart_frr': True,
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "frr_vtysh_run"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['params'] = {
                        'commands': list(vty_commands_revert),
                        'restart_frr': True,
        }
        cmd['revert']['descr']   =  "remove BGP configurations"
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
    """Get add-dhcp-config command.

    :param params:        Parameters from flexiManage.

    :returns: add-dhcp-config command.
    """
    key = 'add-bgp-config'
    return key
