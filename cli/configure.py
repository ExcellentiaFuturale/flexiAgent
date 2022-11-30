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
from fwagent import daemon_rpc

def configure(args):
    """Handles 'fwagent configure' command.

    :returns: None.
    """
    args_dict = vars(args) # args is NameSpace and is not iterable

    def _extract_rpc_params(_args):
        out = {}
        for key in _args:
            if key.startswith('params.'):
                out[key.split('.')[-1]] = _args[key]
        return out
    rpc_params = _extract_rpc_params(args_dict)

    if 'interfaces' in args_dict:
        call = f'{args_dict["interfaces"]}_interface'
        out = daemon_rpc('configure', call=call, params=rpc_params)
        if out:
            print(out)

def build(subparsers):
    router_parser = subparsers.add_parser('configure', help='Configure router')
    router_subparsers = router_parser.add_subparsers()

    interfaces_parser = router_subparsers.add_parser('interfaces', help='Configure interfaces')
    router_interfaces_subparsers = interfaces_parser.add_subparsers(dest='interfaces')

    create_interfaces_cli = router_interfaces_subparsers.add_parser('create', help='Create VPP interface')
    create_interfaces_cli.add_argument('--type', dest='params.type', choices=['wan', 'lan'], metavar='INTERFACE_TYPE', help="Indicates if interface will be use to go to the internet", required=True)
    create_interfaces_cli.add_argument('--addr', dest='params.addr', metavar='ADDRESS', help="The IPv4 to configure on the VPP interface", required=True)
    create_interfaces_cli.add_argument('--host_if_name', dest='params.host_if_name', metavar='INTERFACE_TYPE', help="The name of the interface that will be created in Linux side", required=True)

    remove_interfaces_cli = router_interfaces_subparsers.add_parser('delete', help='Remove VPP interface')
    remove_interfaces_cli.add_argument('--type', dest='params.type', choices=['wan', 'lan'], metavar='INTERFACE_TYPE', help="Indicates if interface is used to go to the internet", required=True)
    remove_interfaces_cli.add_argument('--addr', dest='params.addr', metavar='INTERFACE_IP', help="The IPv4 of VPP interface to remove", required=True)
    remove_interfaces_cli.add_argument('--vpp_if_name', dest='params.vpp_if_name', metavar='VPP_INTERFACE_NAME', help="VPP interface name", required=True)
    remove_interfaces_cli.add_argument('--ignore_errors', dest='params.ignore_errors', help="Ignore exceptions during removal", action='store_true')

    return configure