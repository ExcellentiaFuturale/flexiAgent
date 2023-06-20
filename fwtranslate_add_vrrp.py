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
#   "message": "add-vrrp",
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

def add_vrrp(params):
    """Generate commands to add a VRRP.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    cmd_list = []

    virtual_router_id = params.get('virtualRouterId')
    priority = params.get('priority')

    cache_key = 'vrrp_sw_if_index'

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "vrrp_add_del_vr"
    cmd['cmd']['module']    = "fwutils"
    cmd['cmd']['params']    = {
        'params': params,
        'is_add': 1,
    }
    cmd['cmd']['descr']         = "create vrrp vr (virtual_router_id=%s)" % (virtual_router_id)
    cmd['cmd']['cache_ret_val'] = ('sw_if_index', cache_key)
    cmd['revert'] = {}
    cmd['revert']['func']      = "vrrp_add_del_vr"
    cmd['revert']['module']    = "fwutils"
    cmd['revert']['params'] = {
        'params': params,
        'is_add': 0,
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
        cmd['cmd']['func']      = "vrrp_add_del_track_interfaces"
        cmd['cmd']['module']    = "fwutils"
        cmd['cmd']['descr']     = "add track interfaces to vrrp vr (virtual_router_id=%s)" % (virtual_router_id)
        cmd['cmd']['params']    = {
            'is_add': 1,
            'track_interfaces': track_interfaces,
            'vr_id': virtual_router_id,
            'track_ifc_priority': (priority - 1), # vpp allows priority less than VRID priority
            'substs': [{'add_param': 'sw_if_index', 'val_by_key': cache_key}]
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "vrrp_add_del_track_interfaces"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['descr']  = "delete track interfaces from vrrp vr (virtual_router_id=%s)" % (virtual_router_id)
        cmd['revert']['params'] = {
            'is_add': 0,
            'track_interfaces': track_interfaces,
            'vr_id': virtual_router_id,
            'track_ifc_priority': (priority - 1), # vpp allows priority less than VRID priority
            'substs': [{'add_param': 'sw_if_index', 'val_by_key': cache_key}]
            }
        cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-switch key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-lte request.
    """
    key = 'add-vrrp-%s' % params['virtualRouterId']
    return key
