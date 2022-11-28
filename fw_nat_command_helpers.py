"""
Helper functions to convert NAT configurations into VPP NAT commands
"""

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2021  flexiWAN Ltd.
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

import copy
import fwutils
import fwglobals

# Services enabled for access on WAN interface
WAN_INTERFACE_SERVICES = {
  "VXLAN Tunnel":
    {
        "port": 4789,
        "protocol": "udp"
    },
}

def get_nat_forwarding_config(enable):
    """
    Generates commands to enable/disable nat44 forwarding configuration

    :param enable: Carries value indicating it it need to be enabled
    :type enable: Boolean
    :return: Command params carrying the generated config
    :rtype: dict
    """

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']  = "call_vpp_api"
    cmd['cmd']['descr'] = "Set NAT forwarding"
    cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['params'] = {
                    'api': "nat44_forwarding_enable_disable",
                    'args': {'enable': enable}
    }
    return cmd

def get_nat_wan_setup_config(dev_id):
    """
    Generates command to enable NAT and required default identity mappings
    on WAN interfaces

    :param dev_id: device identifier of the WAN interface
    :type dev_id: String
    :return: Command params carrying the generated config
    :rtype: list
    """
    cmd_list = []

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "call_vpp_api"
    cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr'] = "Enable NAT output feature on interface %s " % (
        dev_id)
    cmd['cmd']['params'] = {
                    'api': "nat44_interface_add_del_output_feature",
                    'args': {
                        'is_add': 1,
                        'substs': [
                            {'add_param': 'sw_if_index',
                            'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': dev_id}
                        ]
                    }
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "call_vpp_api"
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['descr'] = "Disable NAT output feature on interface %s " % (
        dev_id)
    cmd['revert']['params'] = {
                    'api': "nat44_interface_add_del_output_feature",
                    'args': {
                        'is_add': 0,
                        'substs': [
                            {'add_param': 'sw_if_index',
                            'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': dev_id}
                        ]
                    }
    }
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "call_vpp_api"
    cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr'] = "enable NAT for interface address %s" % dev_id
    cmd['cmd']['params'] = {
                    'api': "nat44_add_del_interface_addr",
                    'args': {
                        'is_add': 1,
                        'is_session_recovery': 1, #session recovery is enabled (adds resiliency on address flap)
                        'substs': [
                            {'add_param': 'sw_if_index',
                             'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': dev_id}
                        ],
                    }
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "call_vpp_api"
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['descr'] = "disable NAT for interface %s" % dev_id
    cmd['revert']['params'] = {
                    'api': "nat44_add_del_interface_addr",
                    'args': {
                        'is_add': 0,
                        'substs': [
                            {'add_param': 'sw_if_index',
                             'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': dev_id}
                        ],
                    }
    }
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "vpp_wan_tap_inject_configure"
    cmd['cmd']['module'] = "fwutils"
    cmd['cmd']['descr'] = "enable forward of tap-inject to ip4-output features %s" % dev_id
    cmd['cmd']['params'] = {
                    'dev_id': dev_id,
                    'remove': False,
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "vpp_wan_tap_inject_configure"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['descr'] = "disable forward of tap-inject to ip4-output features %s" % dev_id
    cmd['revert']['params'] = {
                        'dev_id': dev_id,
                        'remove': True,
    }
    cmd_list.append(cmd)

    for service_name, service_cfg in WAN_INTERFACE_SERVICES.items():
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "call_vpp_api"
        cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr'] = "Add NAT WAN identity mapping for port %s:%d Protocol: %s" % (
            service_name, service_cfg['port'], service_cfg['protocol'])
        cmd['cmd']['params'] = {
                        'api': "nat44_add_del_identity_mapping",
                        'args': {
                            'port':     service_cfg['port'],
                            'protocol': fwutils.proto_map[service_cfg['protocol']],
                            'is_add':   1,
                            'substs': [
                                {'add_param': 'sw_if_index',
                                'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': dev_id}
                            ]
                        },
        }

        cmd['revert'] = {}
        cmd['revert']['func']   = "call_vpp_api"
        cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr'] = "Delete NAT WAN identity mapping for port %s:%d Protocol: %s" % (
            service_name, service_cfg['port'], service_cfg['protocol'])
        cmd['revert']['params'] = {
                        'api': "nat44_add_del_identity_mapping",
                        'args': {
                            'port': service_cfg['port'],
                            'protocol': fwutils.proto_map[service_cfg['protocol']],
                            'is_add': 0,
                            'substs': [
                                {'add_param': 'sw_if_index',
                                'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': dev_id}
                            ]
                        },
        }
        cmd_list.append(cmd)

    return cmd_list


def get_nat_1to1_config(sw_if_index, internal_ip):
    """
    Generates command for 1:1 NAT configuration

    :param sw_if_index: device identifier of the WAN interface
    :type sw_if_index: String
    :param internal_ip: Internal IP to which WAN IP need to be mapped
    :type internal_ip: String
    :return: Command params carrying the generated config
    :rtype: list
    """
    cmd_list = []
    cmd = {}
    ip_bytes, _ = fwutils.ip_str_to_bytes(internal_ip)

    add_params = {
        'is_add': 1,
        'external_sw_if_index': sw_if_index,
        'local_ip_address': ip_bytes,
        'flags': 12 #[IS_OUT2IN_ONLY(0x4) | IS_ADDR_ONLY (0x8)]
    }

    revert_params = copy.deepcopy(add_params)
    revert_params['is_add'] = 0

    cmd['cmd'] = {}
    cmd['cmd']['func']   = "call_vpp_api"
    cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr'] = "Add NAT 1:1 rule"
    cmd['cmd']['params'] = {
                    'api':  "nat44_add_del_static_mapping",
                    'args': add_params
    }

    cmd['revert'] = {}
    cmd['revert']['func']   = "call_vpp_api"
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['descr'] = "Delete NAT 1:1 rule"
    cmd['revert']['params'] = {
                    'api':  "nat44_add_del_static_mapping",
                    'args': revert_params
    }

    cmd_list.append(cmd)

    return cmd_list


def get_nat_port_forward_config(sw_if_index, protocols, ports, internal_ip,
                                internal_port_start):
    """
    Generates command for NAT Port forwarding configuration

    :param sw_if_index: device identifier of the WAN interface
    :type sw_if_index: String
    :param protocols: protocols for which the port forward is applied
    :type protocols: list
    :param ports: ports for which forwarding is applied
    :type ports: list
    :param internal_ip: Internal IP to which WAN IP need to be mapped
    :type internal_ip: String
    :param internal_port_start: Internal port start to be used
    :type internal_port_start: integer
    :raises Exception: If protocol value is unsupported
    :return: Command params carrying the generated config
    :rtype: list
    """
    cmd_list = []
    ip_bytes, _ = fwutils.ip_str_to_bytes(internal_ip)
    port_from, port_to = fwutils.ports_str_to_range(ports)
    port_iter = 0

    for port in range(port_from, (port_to + 1)):

        if not protocols:
            protocols = ['tcp', 'udp']
        for proto in protocols:

            if (fwutils.proto_map[proto] != fwutils.proto_map['tcp'] and
                    fwutils.proto_map[proto] != fwutils.proto_map['udp']):
                raise Exception(
                    'Invalid input : NAT Protocol input is wrong %s' % (proto))

            cmd = {}
            add_params = {
                'is_add': 1,
                'external_sw_if_index': sw_if_index,
                'local_ip_address': ip_bytes,
                'protocol': fwutils.proto_map[proto],
                'external_port': port,
                'local_port': internal_port_start + port_iter
            }
            revert_params = copy.deepcopy(add_params)
            revert_params['is_add'] = 0

            cmd['cmd'] = {}
            cmd['cmd']['func']   = "call_vpp_api"
            cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
            cmd['cmd']['descr'] = "Add NAT Port Forward rule"
            cmd['cmd']['params'] = {
                            'api': "nat44_add_del_static_mapping",
                            'args': add_params
            }

            cmd['revert'] = {}
            cmd['revert']['func']   = "call_vpp_api"
            cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
            cmd['revert']['descr'] = "Delete NAT Port Forward rule"
            cmd['revert']['params'] = {
                            'api': "nat44_add_del_static_mapping",
                            'args': revert_params
            }

            cmd_list.append(cmd)
        port_iter += 1

    return cmd_list


def get_nat_identity_config(sw_if_index, protocols, ports):
    """
    Generates command for NAT identity mapping configuration

    :param sw_if_index: device identifier of the WAN interface
    :type sw_if_index: String
    :param protocols: protocols for which the port forward is applied
    :type protocols: list
    :param ports: ports for which forwarding is applied
    :type ports: list
    :return: Command params carrying the generated config
    :rtype: list
    """
    cmd_list = []

    cmd = {}

    cmd['cmd'] = {}
    cmd['cmd']['func']   = "run_nat_identity_config"
    cmd['cmd']['module'] = "fw_nat_command_helpers"
    cmd['cmd']['descr'] = "Add NAT identity mapping rule"
    cmd['cmd']['params'] = {
        'is_add': 1,
        'sw_if_index': sw_if_index,
        'protocols': protocols,
        'ports': ports
    }

    cmd['revert'] = {}
    cmd['revert']['func']   = "run_nat_identity_config"
    cmd['revert']['module'] = "fw_nat_command_helpers"
    cmd['revert']['descr'] = "Delete NAT identity mapping rule"
    cmd['revert']['params'] = {
        'is_add': 0,
        'sw_if_index': sw_if_index,
        'protocols': protocols,
        'ports': ports
    }

    cmd_list.append(cmd)

    return cmd_list

def run_nat_identity_config(is_add, sw_if_index, protocols, ports):
    """
    Executes command for NAT identity mapping configuration

    :param sw_if_index: device identifier of the WAN interface
    :type sw_if_index: String
    :param protocols: protocols for which the port forward is applied
    :type protocols: list
    :param ports: ports for which forwarding is applied
    :type ports: list
    :raises Exception: If protocol value is unsupported
    """
    port_from, port_to = fwutils.ports_str_to_range(ports)

    for port in range(port_from, (port_to + 1)):

        if not protocols:
            protocols = ['tcp', 'udp']
        for proto in protocols:

            if (fwutils.proto_map[proto] != fwutils.proto_map['tcp'] and
                    fwutils.proto_map[proto] != fwutils.proto_map['udp']):
                raise Exception(
                    'Invalid input : NAT Protocol input is wrong %s' % (proto))

            fwglobals.g.router_api.vpp_api.vpp.call('nat44_add_del_identity_mapping',
                is_add=is_add, sw_if_index=sw_if_index, protocol=fwutils.proto_map[proto], port=port)
