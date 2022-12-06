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
import json

import fwglobals
import fw_os_utils
import fwutils
from fwagent import daemon_rpc

def argparse(configure_subparsers):
    configure_router_parser = configure_subparsers.add_parser('router', help='Configure router')
    configure_router_subparsers = configure_router_parser.add_subparsers(dest='router')

    interfaces_parser = configure_router_subparsers.add_parser('interfaces', help='Configure interfaces')
    router_interfaces_subparsers = interfaces_parser.add_subparsers(dest='interfaces')

    create_interfaces_cli = router_interfaces_subparsers.add_parser('create', help='Create VPP interface')
    create_interfaces_cli.add_argument('--type', dest='params.type', choices=['wan', 'lan'], metavar='INTERFACE_TYPE', help="Indicates if interface will be use to go to the internet", required=True)
    create_interfaces_cli.add_argument('--addr', dest='params.addr', metavar='ADDRESS', help="The IPv4 to configure on the VPP interface", required=True)
    create_interfaces_cli.add_argument('--host_if_name', dest='params.host_if_name', metavar='LINUX_INTERFACE_NAME', help="The name of the interface that will be created in Linux side", required=True)

    remove_interfaces_cli = router_interfaces_subparsers.add_parser('delete', help='Remove VPP interface')
    remove_interfaces_cli.add_argument('--type', dest='params.type', choices=['wan', 'lan'], metavar='INTERFACE_TYPE', help="Indicates if interface is used to go to the internet", required=True)
    remove_interfaces_cli.add_argument('--addr', dest='params.addr', metavar='ADDRESS', help="The IPv4 of VPP interface to remove", required=True)
    remove_interfaces_cli.add_argument('--vpp_if_name', dest='params.vpp_if_name', metavar='VPP_INTERFACE_NAME', help="VPP interface name", required=True)
    remove_interfaces_cli.add_argument('--ignore_errors', dest='params.ignore_errors', help="Ignore exceptions during removal", action='store_true')

    firewall_parser = configure_router_subparsers.add_parser('firewall', help='Configure firewall')
    router_firewall_subparsers = firewall_parser.add_subparsers(dest='firewall')
    router_firewall_subparsers.add_parser('restart', help='Re-apply firewall (Temporary)')

def interfaces_create(type, addr, host_if_name):
    if not fwutils.is_ipv4(addr):
        raise Exception(f'addr {addr} is not valid IPv4 address')

    if len(host_if_name) > 15:
        raise Exception(f'host_if_name {host_if_name} cannot have more then 15 characters')

    ret = daemon_rpc(
        'api',
        api_module='fwcli_configure_router',
        api_name='api_interface_create',
        type=type, addr=addr, host_if_name=host_if_name
    )

def interfaces_delete(vpp_if_name, type, addr, ignore_errors=False):
    if not fwutils.is_ipv4(addr):
        raise Exception(f'addr {addr} is not valid IPv4 address')

    daemon_rpc(
        'api',
        api_module='fwcli_configure_router',
        api_name='api_interface_delete',
        type=type, addr=addr, vpp_if_name=vpp_if_name, ignore_errors=ignore_errors
    )

def firewall_restart():
    daemon_rpc(
        'api',
        api_module='fwcli_configure_router',
        api_name='api_firewall_restart'
    )

def api_interface_create(type, addr, host_if_name, ospf=True, bgp=True):
    if not fw_os_utils.vpp_does_run():
        return

    revert_ospf = False
    revert_bgp = False

    try:
        ret = {}
        if ospf:
            _ret, err_str = fwglobals.g.router_api.frr.run_ospf_add(addr, '0.0.0.0')
            if not _ret:
                raise Exception(f'api_add_interface(): Failed to add {addr} network to ospf. err_str={str(err_str)}')
            revert_ospf = True

        if bgp and fwglobals.g.router_cfg.get_bgp(): # check if BGP exists
            _ret, err_str = fwglobals.g.router_api.frr.run_bgp_add_network(addr)
            if not _ret:
                raise Exception(f'api_add_interface(): Failed to add {addr} network to bgp. err_str={str(err_str)}')
            revert_bgp = True

        tun_vpp_if_name = fwutils.create_tun_in_vpp(addr, host_if_name=host_if_name, recreate_if_exists=True)
        ret['tun_vpp_if_name'] = tun_vpp_if_name

        fwglobals.g.router_api.apply_features_on_interface(True, tun_vpp_if_name, type)

        return ret
    except Exception as e:
        fwglobals.log.error(f'api_interface_create({type}, {addr}, {host_if_name}) failed. {str(e)}')
        if revert_bgp:
            fwglobals.g.router_api.frr.run_bgp_remove_network(addr)

        if revert_ospf:
            fwglobals.g.router_api.frr.run_ospf_remove(addr, '0.0.0.0')

        raise e

def api_interface_delete(vpp_if_name, type, addr, ospf=True, bgp=True, ignore_errors=False):
    if not fw_os_utils.vpp_does_run():
        return

    try:
        if ospf:
            ret, err_str = fwglobals.g.router_api.frr.run_ospf_remove(addr, '0.0.0.0')
            if not ret and not ignore_errors:
                raise Exception(f'api_remove_interface(): Failed to remove {addr} network from ospf. err_str={str(err_str)}')

        if bgp and fwglobals.g.router_cfg.get_bgp():
            ret, err_str = fwglobals.g.router_api.frr.run_bgp_remove_network(addr)
            if not ret and not ignore_errors:
                raise Exception(f'api_remove_interface(): Failed to remove {addr} network from bgp. err_str={str(err_str)}')

        fwglobals.g.router_api.apply_features_on_interface(False, vpp_if_name, type)

        fwutils.delete_tun_tap_from_vpp(vpp_if_name, ignore_errors)
    except Exception as e:
        fwglobals.log.error(f'api_interface_delete({vpp_if_name}, {type}, {addr}) failed. {str(e)}')
        raise e

def api_firewall_restart():
    firewall_policy_params = fwglobals.g.router_cfg.get_firewall_policy()
    if firewall_policy_params:
        fwglobals.log.info(f"api_restart_firewall(): Inject remove and add firewall jobs")
        fwglobals.g.router_api.call({'message': 'remove-firewall-policy', 'params': firewall_policy_params})
        fwglobals.g.router_api.call({'message': 'add-firewall-policy',    'params': firewall_policy_params})
