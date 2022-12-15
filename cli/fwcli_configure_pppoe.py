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
from fwagent import daemon_rpc, daemon_is_alive
from  fwpppoe import FwPppoeInterface, FwPppoeClient

def argparse(configure_subparsers):
    configure_router_parser = configure_subparsers.add_parser('pppoe', help='Configure router')
    configure_router_subparsers = configure_router_parser.add_subparsers(dest='pppoe')

    interfaces_parser = configure_router_subparsers.add_parser('interfaces', help='Configure interfaces')
    router_interfaces_subparsers = interfaces_parser.add_subparsers(dest='interfaces')

    create_interfaces_cli = router_interfaces_subparsers.add_parser('create', help='Create PPPoE interface')
    create_interfaces_cli.add_argument('--if_name', dest='params.if_name', help="Linux interface name", required=False)
    create_interfaces_cli.add_argument('--dev_id', dest='params.dev_id', help="Device id", required=False)
    create_interfaces_cli.add_argument('--user', dest='params.user', help="User login", required=True)
    create_interfaces_cli.add_argument('--password', dest='params.password', help="Password", required=True)
    create_interfaces_cli.add_argument('--mtu', dest='params.mtu', help="MTU", required=True)
    create_interfaces_cli.add_argument('--mru', dest='params.mru', help="MRU", required=True)
    create_interfaces_cli.add_argument('--usepeerdns', dest='params.usepeerdns', help="usepeerdns", required=True)
    create_interfaces_cli.add_argument('--metric', dest='params.metric', help="Metric", required=True)
    create_interfaces_cli.add_argument('--enabled', dest='params.enabled', help="Enabled", required=True)
    create_interfaces_cli.add_argument('--nameserver1', dest='params.nameserver1', help="nameserver", required=False)
    create_interfaces_cli.add_argument('--nameserver2', dest='params.nameserver2', help="nameserver", required=False)

    remove_interfaces_cli = router_interfaces_subparsers.add_parser('delete', help='Remove PPPoE interface')
    remove_interfaces_cli.add_argument('--if_name', dest='params.if_name', help="Linux interface name", required=False)
    remove_interfaces_cli.add_argument('--dev_id', dest='params.dev_id', help="Device id", required=False)

def interfaces_create(if_name, dev_id, user, password, mtu, mru, usepeerdns, metric, enabled, nameserver1='', nameserver2=''):
    if daemon_is_alive():
        daemon_rpc(
            'api',
            api_module='fwcli_configure_pppoe',
            api_name='api_interface_create',
            if_name=if_name, dev_id=dev_id,
            user=user, password=password, mtu=mtu, mru=mru, usepeerdns=usepeerdns, metric=metric,
            enabled=enabled, nameserver1=nameserver1, nameserver2=nameserver2
        )
    else:
        # Daemon does not run, try to use local instance.
        api_interface_create(if_name=if_name, dev_id=dev_id,
            user=user, password=password, mtu=mtu, mru=mru, usepeerdns=usepeerdns, metric=metric,
            enabled=enabled, nameserver1=nameserver1, nameserver2=nameserver2)

def interfaces_delete(if_name, dev_id):
    if daemon_is_alive():
        daemon_rpc(
            'api',
            api_module='fwcli_configure_pppoe',
            api_name='api_interface_delete',
            if_name=if_name, dev_id=dev_id
        )
    else:
        # Daemon does not run, try to use local instance.
        api_interface_delete(if_name=if_name, dev_id=dev_id)

def api_interface_create(if_name, dev_id, user, password, mtu, mru, usepeerdns, metric, enabled, nameserver1, nameserver2):
    nameservers = []
    if nameserver1:
        nameservers.append(nameserver1)
    if nameserver2:
        nameservers.append(nameserver2)

    pppoe_iface = FwPppoeInterface(user, password, int(mtu), int(mru), usepeerdns=='True', int(metric), enabled=='True', nameservers)

    if fwglobals.g.pppoe:
        fwglobals.g.pppoe.add_interface(pppoe_iface, if_name=if_name, dev_id=dev_id)
    else:
        with FwPppoeClient() as pppoe:
            pppoe.add_interface(pppoe_iface, if_name=if_name, dev_id=dev_id)

def api_interface_delete(if_name, dev_id):
    if fwglobals.g.pppoe:
        fwglobals.g.pppoe.remove_interface(if_name=if_name, dev_id=dev_id)
    else:
        with FwPppoeClient() as pppoe:
            pppoe.remove_interface(if_name=if_name, dev_id=dev_id)