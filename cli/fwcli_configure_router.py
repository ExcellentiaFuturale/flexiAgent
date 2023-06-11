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
import fw_os_utils
import fwutils
from fwagent import daemon_rpc
from fwcfg_request_handler import FwCfgMultiOpsWithRevert

def argparse(configure_subparsers):
    configure_router_parser = configure_subparsers.add_parser('router', help='Configure router')
    configure_router_subparsers = configure_router_parser.add_subparsers(dest='router')

    interfaces_parser = configure_router_subparsers.add_parser('interfaces', help='Configure interfaces')
    router_interfaces_subparsers = interfaces_parser.add_subparsers(dest='interfaces')

    create_interfaces_cli = router_interfaces_subparsers.add_parser('create', help='Create VPP interface')
    create_interfaces_cli.add_argument('--type', dest='params.type', choices=['wan', 'lan'], metavar='INTERFACE_TYPE', help="Indicates if interface will be use to go to the internet", required=True)
    create_interfaces_cli.add_argument('--addr', dest='params.addr', metavar='ADDRESS', help="The IPv4 to configure on the VPP interface", required=True)
    create_interfaces_cli.add_argument('--host_if_name', dest='params.host_if_name', metavar='LINUX_INTERFACE_NAME', help="The name of the interface that will be created in Linux side", required=True)
    create_interfaces_cli.add_argument('--dev_id', dest='params.dev_id', help="Device id", required=True)
    create_interfaces_cli.add_argument('--no_vppsb', dest='params.no_vppsb', help="If it appears, VPPSB will not create Linux interface for it (but VPP will) - Do it if you know what you are doing", action='store_true')

    remove_interfaces_cli = router_interfaces_subparsers.add_parser('delete', help='Remove VPP interface')
    remove_interfaces_cli.add_argument('--type', dest='params.type', choices=['wan', 'lan'], metavar='INTERFACE_TYPE', help="Indicates if interface is used to go to the internet", required=True)
    remove_interfaces_cli.add_argument('--addr', dest='params.addr', metavar='ADDRESS', help="The IPv4 of VPP interface to remove", required=True)
    remove_interfaces_cli.add_argument('--vpp_if_name', dest='params.vpp_if_name', metavar='VPP_INTERFACE_NAME', help="VPP interface name", required=True)
    remove_interfaces_cli.add_argument('--ignore_errors', dest='params.ignore_errors', help="Ignore exceptions during removal", action='store_true')

def interfaces_create(type, addr, host_if_name, dev_id, no_vppsb=False):
    if not fwutils.is_ipv4(addr):
        raise Exception(f'addr {addr} is not valid IPv4 address')
    if len(host_if_name) > 15:
        raise Exception(f'host_if_name {host_if_name} cannot have more then 15 characters')
    ret = daemon_rpc(
        'api',
        api_module='fwcli_configure_router',
        api_name='api_interface_create',
        type=type, addr=addr, host_if_name=host_if_name, dev_id=dev_id, no_vppsb=no_vppsb
    )
    return ret

def interfaces_delete(vpp_if_name, type, addr, ignore_errors=False):
    if not fwutils.is_ipv4(addr):
        raise Exception(f'addr {addr} is not valid IPv4 address')
    daemon_rpc(
        'api',
        api_module='fwcli_configure_router',
        api_name='api_interface_delete',
        type=type, addr=addr, vpp_if_name=vpp_if_name, ignore_errors=ignore_errors
    )

def api_interface_create(type, addr, host_if_name, dev_id, no_vppsb, ospf=True, bgp=True):
    if not fw_os_utils.vpp_does_run():
        return

    ret = {}
    with FwCfgMultiOpsWithRevert() as handler:
        try:
            # create tun
            tun_vpp_if_name = handler.exec(
                func=fwutils.create_tun_in_vpp,
                params={ 'addr': addr, 'host_if_name': host_if_name, 'recreate_if_exists': True, 'no_vppsb': no_vppsb }
            )
            handler.add_revert_func(
                revert_func=fwutils.delete_tun_tap_from_vpp,
                revert_params={ 'vpp_if_name': tun_vpp_if_name, 'ignore_errors': False }
            )
            ret['tun_vpp_if_name'] = tun_vpp_if_name

            # apply features
            handler.exec(
                func=fwglobals.g.router_api.apply_features_on_interface,
                params={ 'add': True, 'vpp_if_name': tun_vpp_if_name, 'dev_id': dev_id, 'if_type': type },
                revert_func=fwglobals.g.router_api.apply_features_on_interface,
                revert_params={ 'add': False, 'vpp_if_name': tun_vpp_if_name, 'dev_id': dev_id, 'if_type': type },
            )

            if ospf:
                _ret, err_str = handler.exec(
                    func=fwglobals.g.router_api.frr.run_ospf_add,
                    params={ 'address': addr, 'area': '0.0.0.0' },
                    revert_func=fwglobals.g.router_api.frr.run_ospf_remove,
                    revert_params={ 'address': addr, 'area': '0.0.0.0' },
                )
                if not _ret:
                    raise Exception(f'api_interface_create(): Failed to add {addr} network to ospf. err_str={str(err_str)}')

            if bgp and fwglobals.g.router_cfg.get_bgp(): # check if BGP exists
                _ret, err_str = handler.exec(
                    func=fwglobals.g.router_api.frr.run_bgp_add_network,
                    params={ 'address': addr },
                    revert_func=fwglobals.g.router_api.frr.run_bgp_remove_network,
                    revert_params={ 'address': addr },
                )
                if not _ret:
                    raise Exception(f'api_interface_create(): Failed to add {addr} network to bgp. err_str={str(err_str)}')

            return ret
        except Exception as e:
            fwglobals.log.error(f'api_interface_create({type}, {addr}, {host_if_name}) failed. {str(e)}')
            handler.revert(e)

def api_interface_delete(vpp_if_name, type, addr, ospf=True, bgp=True, ignore_errors=False):
    if not fw_os_utils.vpp_does_run():
        return

    try:
        if ospf:
            ret, err_str = fwglobals.g.router_api.frr.run_ospf_remove(addr, '0.0.0.0')
            if not ret:
                err_msg = f'api_interface_delete(): Failed to remove {addr} network from ospf. err_str={str(err_str)}'
                if ignore_errors:
                    fwglobals.log.error(err_msg)
                else:
                    raise Exception(err_msg)

        if bgp and fwglobals.g.router_cfg.get_bgp():
            ret, err_str = fwglobals.g.router_api.frr.run_bgp_remove_network(addr)
            if not ret:
                err_msg = f'api_interface_delete(): Failed to remove {addr} network from bgp. err_str={str(err_str)}'
                if ignore_errors:
                    fwglobals.log.error(err_msg)
                else:
                    raise Exception(err_msg)

        fwglobals.g.router_api.apply_features_on_interface(False, type, vpp_if_name=vpp_if_name)

        fwutils.delete_tun_tap_from_vpp(vpp_if_name, ignore_errors)
    except Exception as e:
        fwglobals.log.error(f'api_interface_delete({vpp_if_name}, {type}, {addr}) failed. {str(e)}')
        raise e
