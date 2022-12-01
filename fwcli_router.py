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


import os
import json
import fwglobals
import fwutils

def api_interfaces_create(type, addr, host_if_name, ospf=True, bgp=True):
    if not fwutils.vpp_does_run():
        return

    revert_ospf = False
    revert_bgp = False

    try:
        response = {}
        if ospf:
            ret, err_str = fwglobals.g.router_api.frr.run_ospf_add(addr, '0.0.0.0')
            if not ret:
                raise Exception(f'api_add_interface(): Failed to add {addr} network to ospf. err_str={str(err_str)}')
            revert_ospf = True

        if bgp and fwglobals.g.router_cfg.get_bgp(): # check if BGP exists
            ret, err_str = fwglobals.g.router_api.frr.run_bgp_add_network(addr)
            if not ret:
                raise Exception(f'api_add_interface(): Failed to add {addr} network to bgp. err_str={str(err_str)}')
            revert_bgp = True

        tun_vpp_if_name = create_tun_in_vpp(addr, host_if_name=host_if_name, recreate_if_exists=True)
        response['tun_vpp_if_name'] = tun_vpp_if_name

        fwglobals.g.router_api.apply_features_on_interface(True, tun_vpp_if_name, type)

        return json.dumps(response, indent=2, sort_keys=True)
    except Exception as e:
        if revert_bgp:
            fwglobals.g.router_api.frr.run_bgp_remove_network(addr)

        if revert_ospf:
            fwglobals.g.router_api.frr.run_ospf_remove(addr, '0.0.0.0')

        raise e

def api_interfaces_delete(vpp_if_name, type, addr, ospf=True, bgp=True, ignore_errors=False):
    if not fwutils.vpp_does_run():
        return

    if ospf:
        ret, err_str = fwglobals.g.router_api.frr.run_ospf_remove(addr, '0.0.0.0')
        if not ret and not ignore_errors:
            raise Exception(f'api_remove_interface(): Failed to remove {addr} network from ospf. err_str={str(err_str)}')

    if bgp:
        ret, err_str = fwglobals.g.router_api.frr.run_bgp_remove_network(addr)
        if not ret and not ignore_errors:
            raise Exception(f'api_remove_interface(): Failed to remove {addr} network from bgp. err_str={str(err_str)}')

    fwglobals.g.router_api.apply_features_on_interface(False, vpp_if_name, type)

    delete_tun_tap_from_vpp(vpp_if_name, ignore_errors)

def delete_tun_tap_from_vpp(vpp_if_name, ignore_errors):
    fwutils.vpp_cli_execute([f'delete tap {vpp_if_name}'], raise_exception_on_error=(not ignore_errors))

def create_tun_in_vpp(addr, host_if_name, recreate_if_exists=False):
    # ensure that tun is not exists in case of down-script failed
    tun_exists = os.popen(f'sudo vppctl show tun | grep -B 1 "{host_if_name}"').read().strip()
    if tun_exists:
        if not recreate_if_exists:
            raise Exception(f'The tun "{host_if_name}" already exists in VPP. tun_exists={str(tun_exists)}')

        # root@flexiwan-zn1:/home/shneorp# sudo vppctl show tun | grep -B 1 "t_vpp_remotevpn"
        # Interface: tun0 (ifindex 7)
        #   name "t_vpp_remotevpn"
        tun_name = tun_exists.splitlines()[0].split(' ')[1]
        os.system(f'sudo vppctl delete tap {tun_name}')

    # configure the vpp interface
    tun_vpp_if_name = os.popen(f'sudo vppctl create tap host-if-name {host_if_name} tun').read().strip()
    if not tun_vpp_if_name:
        raise Exception('Cannot create tun device in vpp')

    fwglobals.log.info(f'create_tun_in_vpp(): TUN created in vpp. vpp_if_name={tun_vpp_if_name}')

    vpp_cmds = [
        f'set interface ip address {tun_vpp_if_name} {addr}',
        f'set interface state {tun_vpp_if_name} up'
    ]

    fwutils.vpp_cli_execute(vpp_cmds)

    return tun_vpp_if_name

def api_firewall_restart():
    firewall_policy_params = fwglobals.g.router_cfg.get_firewall_policy()
    if firewall_policy_params:
        fwglobals.log.info(f"api_restart_firewall(): Inject remove and add firewall jobs")
        fwglobals.g.router_api.call({'message': 'remove-firewall-policy', 'params': firewall_policy_params})
        fwglobals.g.router_api.call({'message': 'add-firewall-policy',    'params': firewall_policy_params})
        fwglobals.log.info(f"api_restart_firewall(): finished")
