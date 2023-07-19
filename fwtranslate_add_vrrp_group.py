#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2023  flexiWAN Ltd.
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

# {
#   "entity": "agent",
#   "message": "add-vrrp-group",
#   "params": {
#     "virtualRouterId": 30,
#     "virtualIp": "172.16.1.100",
#     "preemption": true,
#     "acceptMode": false,
#     "priority": 100,
#     "trackInterfaces": [],
#     "devId": "pci:0000:00:0a.00"
#   }
# }
#
# preemption -
#   Controls whether a higher priority Backup router preempts a lower priority Master.
#   In other words, When router with high priority become backup due to link status failure,
#   and then the problem fixed - the router will become Master back.
#   In VRRP Protocol, it is enabled by default
#
# acceptMode -
#   Controls whether a virtual router in Master state will accept packets addressed to the virtual IP address
#   In VRRP Protocol, it is disabled by default
#
# trackInterfaces -
#   Router can go to backup state if the interface it self is not accessible,
#   or if *other* interfaces are not accessible. The specified "other" interfaces are the tracked interface.

import fwutils
import ipaddress

def add_vrrp_group(params):
    """Generate commands to add a VRRP.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    cmd_list = []

    dev_id = params.get('devId')
    virtual_router_id = params.get('virtualRouterId')
    virtual_router_ip = params.get('virtualIp')
    priority = params.get('priority')
    interval = params.get('interval', 100)
    preemption = params.get('preemption', True)
    accept_mode = params.get('acceptMode', False)

    cache_key = 'vrrp_sw_if_index'

    preemption_flag  = 0x1 if preemption else 0  # see VRRP_API_VR_PREEMPT = 1 in vrrp_api.json
    accept_mode_flag = 0x2 if accept_mode else 0 # see VRRP_API_VR_ACCEPT = 2 in vrrp_api.json

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "call_vpp_api"
    cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['params']    = {
        'api':  "vrrp_vr_add_del",
        'args': {
            'is_add': 1,
            'vr_id': virtual_router_id,
            'priority': priority,
            'flags': (preemption_flag|accept_mode_flag),
            'addrs': [ipaddress.ip_address(virtual_router_ip)],
            'n_addrs': 1,
            'interval': interval,
            'substs': [{
                'add_param': 'sw_if_index',
                'val_by_func': 'fwtranslate_add_vrrp_group.vpp_vrrp_dev_id_to_sw_if_index',
                'arg': {
                    'dev_id':  dev_id,
                    'cmd_cache_key': cache_key,
                    'cmd_cache': fwglobals.g.router_api.cmd_cache
                },
            }]
        }
    }
    cmd['cmd']['descr']         = f"create vrrp vr (virtual_router_id={virtual_router_id})"
    cmd['revert'] = {}
    cmd['revert']['func']      = "call_vpp_api"
    cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['params'] = {
        'api':  "vrrp_vr_add_del",
        'args': {
            'is_add': 0,
            'vr_id': virtual_router_id,
            'priority': priority,
            'flags': (preemption_flag|accept_mode_flag),
            'addrs': [ipaddress.ip_address(virtual_router_ip)],
            'n_addrs': 1,
            'interval': interval,
            'substs': [{ 'add_param': 'sw_if_index', 'val_by_key': cache_key }]
        }
    }
    cmd['revert']['descr']      = f"delete vrrp vr (virtual_router_id={virtual_router_id})"
    cmd_list.append(cmd)

    is_switch = fwutils.is_bridged_interface(dev_id)
    if is_switch:
        # In VRRP the BVI interface has a virtual IP.
        # As DHCP clients on LAN run ARP resolution for the virtual IP,
        # the interface that owns this IP should have VRRP virtual MAC address,
        # so VPP could answer ARP requests. So, assign virtual MAC address on BVI interface.
        #
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "call_vpp_api"
        cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['params']    = {
            'api':  "sw_interface_set_mac_address",
            'args': {
                'substs': [
                    { 'add_param': 'sw_if_index', 'val_by_key': cache_key },
                    {
                        'add_param': 'mac_address',
                        'val_by_func': 'fwtranslate_add_vrrp_group.build_vrrp_virtual_mac_address',
                        'arg': virtual_router_id
                    }
                ]
            }
        }
        cmd['cmd']['descr']         = f"set VRRP mac address on the bvi interface (virtual_router_id={virtual_router_id})"
        cmd['revert'] = {}
        cmd['revert']['func']      = "call_vpp_api"
        cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['params']    = {
            'api':  "sw_interface_set_mac_address",
            'args': {
                'substs': [
                    { 'add_param': 'sw_if_index', 'val_by_key': cache_key },
                    { 'add_param': 'mac_address', 'val_by_func': 'build_loopback_mac_address', 'arg_by_key': cache_key }
                ]
            }
        }
        cmd['revert']['descr']      = f"remove VRRP mac address on the bvi interface (virtual_router_id={virtual_router_id})"
        cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "call_vpp_api"
    cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['params'] = {
                    'api':  "vrrp_vr_start_stop",
                    'args': {
                        'is_start': 1,
                        'vr_id': virtual_router_id,
                        'substs': [{'add_param': 'sw_if_index', 'val_by_key': cache_key}],
                    }
    }
    cmd['cmd']['descr']         = "start vrrp vr (virtual_router_id=%s)" % (virtual_router_id)
    cmd['revert'] = {}
    cmd['revert']['func']   = 'call_vpp_api'
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['params'] = {
                    'api':  "vrrp_vr_start_stop",
                    'args': {
                        'is_start': 0,
                        'vr_id': virtual_router_id,
                        'substs': [{'add_param': 'sw_if_index', 'val_by_key': cache_key}]
                    }
    }
    cmd['revert']['descr']      = "stop vrrp vr (virtual_router_id=%s)" % (virtual_router_id)
    cmd_list.append(cmd)

    track_interfaces = params.get('trackInterfaces', [])
    if track_interfaces:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "vpp_vrrp_add_del_track_interfaces"
        cmd['cmd']['module']    = "fwutils"
        cmd['cmd']['descr']     = "add track interfaces to vrrp vr (virtual_router_id=%s)" % (virtual_router_id)
        cmd['cmd']['params']    = {
            'is_add': 1,
            'track_interfaces': track_interfaces,
            'vr_id': virtual_router_id,
            'track_ifc_priority': (priority - 1), # vpp allows priority less than VRID priority
            'mandatory_only': True,
            'substs': [{'add_param': 'sw_if_index', 'val_by_key': cache_key}]
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "vpp_vrrp_add_del_track_interfaces"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['descr']  = "delete track interfaces from vrrp vr (virtual_router_id=%s)" % (virtual_router_id)
        cmd['revert']['params'] = {
            'is_add': 0,
            'track_interfaces': track_interfaces,
            'vr_id': virtual_router_id,
            'track_ifc_priority': (priority - 1), # vpp allows priority less than VRID priority
            'mandatory_only': True,
            'substs': [{'add_param': 'sw_if_index', 'val_by_key': cache_key}]
            }
        cmd_list.append(cmd)

    return cmd_list

def vpp_vrrp_dev_id_to_sw_if_index(dev_id, cmd_cache_key, cmd_cache):
    ''' Resolve sw_if_index for the VRRP.

    If the selected vrrp interface is bridged, we need to setup the VRRP on the BVI interface.
    Otherwise, we set it on the selected interface itself.
    '''
    sw_if_index = fwutils.dev_id_to_bvi_sw_if_index(dev_id)
    if not sw_if_index:
        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)
    cmd_cache[cmd_cache_key] = sw_if_index
    return sw_if_index

def build_vrrp_virtual_mac_address(vr_id):
    mac = "00:00:5e:00:01%0.2x" % vr_id
    mac = mac[:-2] + ':' + mac[-2:]
    return fwutils.mac_str_to_bytes(mac)

def get_request_key(params):
    """Get add-vrrp-group key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-lte request.
    """
    key = 'add-vrrp-group-%s' % params['virtualRouterId']
    return key
