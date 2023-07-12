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

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "vpp_vrrp_add_del_vr"
    cmd['cmd']['module']    = "fwutils"
    cmd['cmd']['params']    = {
        'is_add': 1,
        'dev_id': dev_id,
        'virtual_router_id': virtual_router_id,
        'virtual_router_ip': virtual_router_ip,
        'priority': priority,
        'interval': interval,
        'preemption': preemption,
        'accept_mode': accept_mode
    }
    cmd['cmd']['descr']         = "create vrrp vr (virtual_router_id=%s)" % (virtual_router_id)
    cmd['cmd']['cache_ret_val'] = ('sw_if_index', cache_key)
    cmd['revert'] = {}
    cmd['revert']['func']      = "vpp_vrrp_add_del_vr"
    cmd['revert']['module']    = "fwutils"
    cmd['revert']['params'] = {
        'is_add': 0,
        'dev_id': dev_id,
        'virtual_router_id': virtual_router_id,
        'virtual_router_ip': virtual_router_ip,
        'priority': priority,
        'interval': interval,
        'preemption': preemption,
        'accept_mode': accept_mode
    }
    cmd['revert']['descr']      = "delete vrrp vr (virtual_router_id=%s)" % (virtual_router_id)
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

def get_request_key(params):
    """Get add-switch key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-lte request.
    """
    key = 'add-vrrp-group-%s' % params['virtualRouterId']
    return key
