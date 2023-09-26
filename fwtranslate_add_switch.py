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

def add_switch(params):
    """Generate commands to add a VPP l2 bridge with bvi interface.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    cmd_list = []

    addr = params['addr']

    bridge_ret_attr = 'bridge_id'
    bridge_cache_key = 'bridge_id_0'
    loopback_ret_attr = 'sw_if_index'
    loopback_cache_key = 'loop_bridge_%s' % addr

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "allocate_bridge_id"
    cmd['cmd']['module']    = "fwutils"
    cmd['cmd']['descr']     = "get bridge id for address %s" % addr
    cmd['cmd']['cache_ret_val'] = (bridge_ret_attr, bridge_cache_key)
    cmd['cmd']['params']    = { 'object_id': addr, 'type': 'switch_bridges' }
    cmd['revert'] = {}
    cmd['revert']['func']   = "release_bridge_id"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['descr']  = "remove bridge id for address %s" % addr
    cmd['revert']['params'] = { 'object_id': addr, 'type': 'switch_bridges' }
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "call_vpp_api"
    cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['params']    = {
                    'api': "bridge_domain_add_del",
                    'args': {
                        'is_add':   1,
                        'learn':    1,
                        'forward':  1,
                        'uu_flood': 1,
                        'flood':    1,
                        'arp_term': 0,
                        'substs': [ { 'add_param':'bd_id', 'val_by_key':bridge_cache_key} ]
                    },
    }
    cmd['cmd']['descr']     = "create bridge for %s" % addr
    cmd['revert'] = {}
    cmd['revert']['func']   = "call_vpp_api"
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['params'] = {
                    'api':    "bridge_domain_add_del",
                    'args':   {
                        'is_add': 0,
                        'substs': [ { 'add_param':'bd_id', 'val_by_key':bridge_cache_key} ]
                    },
    }
    cmd['revert']['descr']  = "delete bridge for %s" % addr
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']          = "call_vpp_api"
    cmd['cmd']['object']        = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['params']        = {
                    'api':  "create_loopback_instance",
                    'args': {
                        'is_specified': 1,
                        'substs': [ { 'add_param':'user_instance', 'val_by_key':bridge_cache_key} ]
                    },
    }
    cmd['cmd']['cache_ret_val'] = (loopback_ret_attr, loopback_cache_key)
    cmd['cmd']['descr']         = "create loopback interface for bridge %s" % addr
    cmd['revert'] = {}
    cmd['revert']['func']       = "call_vpp_api"
    cmd['revert']['object']     = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['params']     = {
                    'api':  "delete_loopback",
                    'args': {
                        'substs': [ { 'add_param':'sw_if_index', 'val_by_key':loopback_cache_key} ]
                    },
    }
    cmd['revert']['descr']      = "delete loopback interface for bridge %s" % addr
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "call_vpp_api"
    cmd['cmd']['object']  = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr']   = "add loop interface to bridge %s" % addr
    cmd['cmd']['params']  = {
                    'api':    "sw_interface_set_l2_bridge",
                    'args': {
                        'enable':    1,
                        'port_type': 1, # port_type 1 stands for BVI (see test\vpp_l2.py)
                        'substs': [
                            { 'add_param':'rx_sw_if_index', 'val_by_key':loopback_cache_key},
                            { 'add_param':'bd_id', 'val_by_key':bridge_cache_key}
                        ]
                    },
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "call_vpp_api"
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['descr']  = "remove loop interface from bridge %s" % addr
    cmd['revert']['params'] = {
                    'api':    "sw_interface_set_l2_bridge",
                    'args':   {
                        'enable':0,
                        'substs': [
                                    { 'add_param':'rx_sw_if_index', 'val_by_key':loopback_cache_key},
                                    { 'add_param':'bd_id', 'val_by_key':bridge_cache_key}
                        ]
                    },
    }
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "_update_cache_sw_if_index"
    cmd['cmd']['object']  = "fwglobals.g.router_api"
    cmd['cmd']['descr']   = "add BVI sw_if_index to router_api cache"
    cmd['cmd']['params']  = {
                    'type':   'switch',
                    'add':    True,
                    'substs': [ { 'add_param':'sw_if_index', 'val_by_key':loopback_cache_key} ]
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "_update_cache_sw_if_index"
    cmd['revert']['object'] = "fwglobals.g.router_api"
    cmd['revert']['descr']  = "remove BVI sw_if_index from router_api cache"
    cmd['revert']['params'] = {
                    'type':   'switch',
                    'add':    False,
                    'substs': [ { 'add_param':'sw_if_index', 'val_by_key':loopback_cache_key} ]
    }
    cmd_list.append(cmd)

    # Enable classification on BVI interface
    fwglobals.g.qos.get_classification_setup_commands(loopback_cache_key, None, cmd_list)

    return cmd_list

def get_request_key(params):
    """Get add-switch key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-lte request.
    """
    key = 'add-switch-%s' % params['addr']
    return key
