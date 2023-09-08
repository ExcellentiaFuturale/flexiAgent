"""
Translates LAN NAT policy request to a set of commands
"""

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

import copy
import fwutils
import fwglobals
import fw_acl_command_helpers
from fwcfg_request_handler import FwCfgMultiOpsWithRevert


LAN_NAT_LOOPBACK_CACHE_KEY = 'lan_nat_loopback'
LAN_NAT_LOOPBACK_ADDR = '169.254.0.1/32'
LAN_NAT_INTERFACES = {}


def get_nat_loopback_interface_setup_commands(cmd_list):

   # Add loopback interface to be used in LAN-NAT feature
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['descr']  = "Create NAT loopback interface"
    cmd['cmd']['func']   = "call_vpp_api"
    cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['params'] = {
        'api':  "create_loopback_instance",
        'args': {'flexiwan_flags': (1) } #no VPPSB
    }
    cmd['cmd']['cache_ret_val'] = ('sw_if_index', LAN_NAT_LOOPBACK_CACHE_KEY)

    cmd['revert'] = {}
    cmd['revert']['descr']  = "Delete NAT loopback interface"
    cmd['revert']['func']   = 'call_vpp_api'
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['params'] = {
        'api':  "delete_loopback",
        'args': {
            'substs': [ { 'add_param':'sw_if_index', 'val_by_key': LAN_NAT_LOOPBACK_CACHE_KEY} ]
        },
    }
    cmd_list.append(cmd)

    # Make the loopback work as L3 interface - Assign a link local address
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "call_vpp_api"
    cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr']     = "set %s to loopback interface" % LAN_NAT_LOOPBACK_ADDR
    cmd['cmd']['params']    = {
        'api':    "sw_interface_add_del_address",
        'args':   {
            'is_add': 1,
            'prefix': LAN_NAT_LOOPBACK_ADDR,
            'substs': [
                {
                'add_param':'sw_if_index',
                'val_by_key':LAN_NAT_LOOPBACK_CACHE_KEY
                }
            ]
        },
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "call_vpp_api"
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['descr']  = "unset %s from loopback interface" % LAN_NAT_LOOPBACK_ADDR
    cmd['revert']['params'] = {
        'api':    "sw_interface_add_del_address",
        'args':   {
            'is_add': 0,
            'prefix': LAN_NAT_LOOPBACK_ADDR,
            'substs': [
                {
                    'add_param':'sw_if_index',
                    'val_by_key':LAN_NAT_LOOPBACK_CACHE_KEY
                }
            ]
        },
    }
    cmd_list.append(cmd)

    # Set the loopback interface state as UP
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "call_vpp_api"
    cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr']     = "UP loopback interface %s" % LAN_NAT_LOOPBACK_ADDR
    cmd['cmd']['params']    = {
        'api':    "sw_interface_set_flags",
        'args': {
            'flags':  1, # VppEnum.vl_api_if_status_flags_t.IF_STATUS_API_FLAG_ADMIN_UP
            'substs': [
                {
                'add_param':'sw_if_index',
                'val_by_key':LAN_NAT_LOOPBACK_CACHE_KEY
                }
            ]
        },
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "call_vpp_api"
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['descr']  = "DOWN loopback interface %s" % LAN_NAT_LOOPBACK_ADDR
    cmd['revert']['params'] = {
        'api':  "sw_interface_set_flags",
        'args': {
            'flags':  0,
            'substs': [
                {
                'add_param':'sw_if_index',
                'val_by_key':LAN_NAT_LOOPBACK_CACHE_KEY
                }
            ]
        },
    }
    cmd_list.append(cmd)


def get_lan_nat_match_acl_setup_commands (rules, nat_actions, src_nat_prefixes,
                                          nat_interfaces, cmd_list):
    for rule in rules:
        src_match_prefix = '%s/%s' % (rule['source']['match'], rule['source']['prefix'])
        dst_match_prefix = None
        src_nat_prefix = '%s/%s' % (rule['source']['apply'], rule['source']['prefix'])
        dst_nat_prefix = None

        # In IN direction - Action is to apply NAT
        in_nat_action = {}
        in_nat_action['nat_src'] = {}
        in_nat_action['nat_src']['address'], _ = fwutils.ip_str_to_bytes(rule['source']['apply'])
        in_nat_action['nat_src']['len'] = rule['source']['prefix']

        # In OUT (Return path) direction - Action is to de-NAT i.e. Apply the actual source
        out_nat_action = {}
        out_nat_action['nat_dst'] = {}
        out_nat_action['nat_dst']['address'], _ = fwutils.ip_str_to_bytes(rule['source']['match'])
        out_nat_action['nat_dst']['len'] = rule['source']['prefix']

        if rule.get('destination'):
            # Check if 1:1 DNAT is also configured
            dst_match_prefix = '%s/%s' % (rule['destination']['match'],
                                          rule['destination']['prefix'])
            dst_nat_prefix = '%s/%s' % (rule['destination']['apply'],
                                        rule['destination']['prefix'])
            in_nat_action['nat_dst'] = {}
            in_nat_action['nat_dst']['address'], _ =\
                fwutils.ip_str_to_bytes(rule['destination']['apply'])
            in_nat_action['nat_dst']['len'] = rule['destination']['prefix']

            out_nat_action['nat_src'] = {}
            out_nat_action['nat_src']['address'], _ =\
                fwutils.ip_str_to_bytes(rule['destination']['match'])
            out_nat_action['nat_src']['len'] = rule['destination']['prefix']

        in_action_id = len(nat_actions)
        nat_actions.append(in_nat_action)
        out_action_id = len(nat_actions)
        nat_actions.append(out_nat_action)

        in_acl_id = 'fw-lan-nat-in-%d' % in_action_id
        out_acl_id = 'fw-lan-nat-out-%d' % out_action_id

        in_acl_src = { 'ipPort': {'ip': src_match_prefix } }
        in_acl_dst = { 'ipProtoPort': { 'ip': dst_match_prefix } } if dst_match_prefix else None
        cmd = fw_acl_command_helpers.add_acl_rule(in_acl_id, in_acl_src, in_acl_dst,
                                                  in_action_id, 0, 0, 1, 0)
        cmd_list.append (cmd)

        out_acl_dst = { 'ipProtoPort': { 'ip': src_nat_prefix } }
        out_acl_src = { 'ipPort': { 'ip': dst_nat_prefix } } if dst_nat_prefix else None
        cmd = fw_acl_command_helpers.add_acl_rule (out_acl_id, out_acl_src, out_acl_dst,
                                                   out_action_id, 0, 0, 1, 0)
        cmd_list.append (cmd)

        # Maintain the ACL ids in the per interface context - Later to be used in attachment
        if nat_interfaces.get(rule['interface']) is None:
            nat_interfaces[rule['interface']] = { 'in': [], 'out': [] }
        nat_interfaces[rule['interface']]['in'].append(in_acl_id)
        nat_interfaces[rule['interface']]['out'].append(out_acl_id)
        bvi_sw_if_index = fwutils.dev_id_to_bvi_sw_if_index (rule['interface'])
        if bvi_sw_if_index:
            if nat_interfaces.get('bvi') is None:
                nat_interfaces['bvi'] = {}
            if nat_interfaces['bvi'].get(bvi_sw_if_index) is None:
                nat_interfaces['bvi'][bvi_sw_if_index] = set()
            nat_interfaces['bvi'][bvi_sw_if_index].add(rule['interface'])
            nat_interfaces[rule['interface']]['bvi'] = bvi_sw_if_index

        src_nat_prefixes.add(src_nat_prefix)


def get_lan_nat_route_setup_commands (src_nat_prefixes, cmd_list):

    for src_nat_prefix in src_nat_prefixes:

        ip4_prefix, prefix_len = fwutils.ip_str_to_bytes(src_nat_prefix)
        route_args = {
            'prefix'      : {
                'address' : {
                    'af'      : 0, #IP4,
                    'un'      : {
                        'ip4' :  ip4_prefix
                    }
                },
                'len'     : prefix_len
            },
            'n_paths'     : 1,
            'paths'       : [
                {
                    'type'        : 9, #FIB_API_PATH_TYPE_INTERFACE_RX
                    'proto'       : 0, #FIB_API_PATH_NH_PROTO_IP4
                    'label_stack' : [0] * 16, #Fixed number used in the API definition
                    'substs': [{
                        'add_param' : 'sw_if_index',
                        'val_by_key': LAN_NAT_LOOPBACK_CACHE_KEY
                    }],
                }
            ]
        }
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "call_vpp_api"
        cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']     = "Add NAT IP route on NAT Loopback interface"
        cmd['cmd']['params']    =   {
            'api'   : 'ip_route_add_del',
            'args'  : {
                'is_add': True,
                'route' : route_args
            }
        }
        cmd['revert'] = {}
        cmd['revert']['func']      = "call_vpp_api"
        cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr']     = "Delete NAT IP route on NAT Loopback interface"
        cmd['revert']['params']    =   {
            'api'   : 'ip_route_add_del',
            'args'  : {
                'is_add': False,
                'route' : copy.deepcopy(route_args)
            }
        }
        cmd_list.append(cmd)


def get_lan_nat_1to1_action_setup_commands (nat_actions, cmd_list):

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "call_vpp_api"
    cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr']     = "Configure 1:1 NAT Actions"
    cmd['cmd']['params']    =   {
        'api'   : 'nat44_1to1_add_del_acl_actions',
        'args'  : {
            'is_add'  : True,
            'count'   : len (nat_actions),
            'actions' : nat_actions
        }
    }
    cmd['revert'] = {}
    cmd['revert']['func']      = "call_vpp_api"
    cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['descr']     = "Clear 1:1 NAT Actions"
    cmd['revert']['params']    =   {
        'api'   : 'nat44_1to1_add_del_acl_actions',
        'args'  : {
            'is_add': False,
            'count'   : 0
        }
    }
    cmd_list.append(cmd)


def get_lan_nat_frr_setup_commands (src_nat_prefixes, cmd_list):

    frr_cmd_list = []
    rev_frr_cmd_list = []

    for src_nat_prefix in src_nat_prefixes:
        acl_cmd = "access-list %s permit %s" % (fwglobals.g.FRR_LAN_NAT_ROUTE_ACL , src_nat_prefix)
        revert_acl_cmd = "no " + acl_cmd
        route_cmd = "ip route %s Null0" % src_nat_prefix
        revert_route_cmd = "no ip route %s Null0" % src_nat_prefix
        frr_cmd_list.extend([acl_cmd, route_cmd])
        rev_frr_cmd_list.extend([revert_acl_cmd, revert_route_cmd])

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['descr']  =  "Add LAN SNAT address %s to route and Permit-ACLs" % src_nat_prefix
    cmd['cmd']['func']   = "frr_vtysh_run"
    cmd['cmd']['module'] = "fwutils"
    cmd['cmd']['params'] = {
        'commands': frr_cmd_list
    }

    cmd['revert'] = {}
    cmd['revert']['descr']  =  "Delete LAN SNAT address %s to route and Permit-ACLs" %src_nat_prefix
    cmd['revert']['func']   = "frr_vtysh_run"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['params'] = {
                'commands': rev_frr_cmd_list
    }
    cmd_list.append(cmd)


def lan_nat_attach_acls(is_add, dev_id):

    interface_params = LAN_NAT_INTERFACES[dev_id]
    acls = fwutils.map_keys_to_acl_ids(interface_params['in'], fwglobals.g.router_api.cmd_cache)
    if interface_params.get('bvi') is None:
        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)
    else:
        sw_if_index = interface_params['bvi']
    if is_add:
        fwglobals.g.router_api.vpp_api.vpp.call('nat44_1to1_attach_detach_match_acls',
            is_add = is_add, total_acl_count=len(acls),
            input_acl_count = len(acls), sw_if_index = sw_if_index, acls = acls)
    else:
        fwglobals.g.router_api.vpp_api.vpp.call('nat44_1to1_attach_detach_match_acls',
            is_add = is_add, total_acl_count=0,
            input_acl_count = 0, sw_if_index = sw_if_index)


def lan_nat_enable_interface(is_add, dev_id):
    interface_params = LAN_NAT_INTERFACES[dev_id]
    if interface_params.get('bvi') is None:
        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)
    else:
        sw_if_index = interface_params['bvi']
    fwglobals.g.router_api.vpp_api.vpp.call('nat44_interface_add_del_feature',
        is_add = is_add, flags=0x20, #NAT_IS_INSIDE = 0x20
        sw_if_index = sw_if_index)


def lan_nat_loopback_attach_acls(is_add, acls):
    sw_if_index = fwglobals.g.router_api.cmd_cache[LAN_NAT_LOOPBACK_CACHE_KEY]
    acls = fwutils.map_keys_to_acl_ids(acls, fwglobals.g.router_api.cmd_cache)
    if is_add:
        fwglobals.g.router_api.vpp_api.vpp.call('nat44_1to1_attach_detach_match_acls',
            is_add = is_add, total_acl_count=len(acls),
            input_acl_count = len(acls), sw_if_index = sw_if_index, acls = acls)
    else:
        fwglobals.g.router_api.vpp_api.vpp.call('nat44_1to1_attach_detach_match_acls',
            is_add = is_add, total_acl_count=0,
            input_acl_count = 0, sw_if_index = sw_if_index)


def lan_nat_loopback_enable_interface(is_add):
    sw_if_index = fwglobals.g.router_api.cmd_cache[LAN_NAT_LOOPBACK_CACHE_KEY]
    fwglobals.g.router_api.vpp_api.vpp.call('nat44_interface_add_del_feature',
        is_add = is_add, flags=0x10, #NAT_IS_OUTSIDE = 0x10
        sw_if_index = sw_if_index)


def setup_lan_nat_interfaces():

    lan_nat_out_acls = []
    with FwCfgMultiOpsWithRevert() as handler:
        try:
            for dev_id, value in LAN_NAT_INTERFACES.items():
                lan_nat_out_acls.extend(value['out'])
                handler.exec(
                    func=lan_nat_attach_acls,
                    params={ 'is_add': True, 'dev_id':  dev_id},
                    revert_func=lan_nat_attach_acls,
                    revert_params={ 'is_add': False, 'dev_id': dev_id }
                )

                handler.exec(
                    func=lan_nat_enable_interface,
                    params={ 'is_add': True, 'dev_id':  dev_id},
                    revert_func=lan_nat_enable_interface,
                    revert_params={ 'is_add': False, 'dev_id': dev_id }
                )

            handler.exec(
                func=lan_nat_loopback_attach_acls,
                params={ 'is_add': True, 'acls':  lan_nat_out_acls},
                revert_func=lan_nat_loopback_attach_acls,
                revert_params={ 'is_add': True, 'acls':  lan_nat_out_acls},
            )

            handler.exec(
                func=lan_nat_loopback_enable_interface,
                params={ 'is_add': True },
                revert_func=lan_nat_loopback_enable_interface,
                revert_params={ 'is_add': False }
            )

        except Exception as e:
            fwglobals.log.error("setup_lan_nat_interfaces: Failed: %s" % str(e))
            handler.revert(e)


def clear_lan_nat_interfaces():
    try:
        for dev_id,_ in LAN_NAT_INTERFACES.items():
            lan_nat_attach_acls(False, dev_id)
            lan_nat_enable_interface(False, dev_id)
        lan_nat_loopback_attach_acls(False, None)
        lan_nat_loopback_enable_interface(False)
    except Exception as e:
        fwglobals.log.error("clear_lan_nat_interfaces: Failed: %s" % str(e))


def get_lan_nat_interface_setup_commands (cmd_list):
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "setup_lan_nat_interfaces"
    cmd['cmd']['module']  = "fwtranslate_add_lan_nat_policy"
    cmd['cmd']['descr']     = "Setup LAN NAT on interface"
    cmd['revert'] = {}
    cmd['revert']['func']    = "clear_lan_nat_interfaces"
    cmd['revert']['module']  = "fwtranslate_add_lan_nat_policy"
    cmd['revert']['descr']     = "Clear LAN NAT on interface"
    cmd_list.append(cmd)


def setup_lan_nat_states(reset=False):
    if reset:
        global LAN_NAT_INTERFACES
        LAN_NAT_INTERFACES = {}
    #else: Currently, No init context to setup


def get_lan_nat_init_command(cmd_list):

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['descr']  = "Init LAN NAT States"
    cmd['cmd']['func']   = "setup_lan_nat_states"
    cmd['cmd']['module'] = "fwtranslate_add_lan_nat_policy"

    cmd['revert'] = {}
    cmd['revert']['descr']  = "Init LAN NAT States"
    cmd['revert']['func']   = "setup_lan_nat_states"
    cmd['revert']['module'] = "fwtranslate_add_lan_nat_policy"
    cmd['revert']['params'] = { 'reset': True }
    cmd_list.append(cmd)


def add_lan_nat_policy(params):
    """
    Processes the LAN NAT rules and generates corresponding commands

    :param params: json/dict carrying the firewall message
    :return: Array of commands and each command is a dict
    """
    cmd_list = []
    nat_actions = []
    src_nat_prefixes = set()

    get_lan_nat_init_command(cmd_list)

    get_nat_loopback_interface_setup_commands (cmd_list)

    get_lan_nat_match_acl_setup_commands (params['nat44-1to1'], nat_actions,
                                          src_nat_prefixes,  LAN_NAT_INTERFACES, cmd_list)

    get_lan_nat_route_setup_commands (src_nat_prefixes, cmd_list)

    get_lan_nat_1to1_action_setup_commands (nat_actions, cmd_list)

    get_lan_nat_frr_setup_commands (src_nat_prefixes, cmd_list)

    #get_lan_nat_interface_setup_commands (LAN_NAT_INTERFACES, cmd_list)
    get_lan_nat_interface_setup_commands (cmd_list)

    return cmd_list


def get_request_key(_params):
    """
    Mandatory function in all translate modules to return the message type handled

    :param params: Unused
    :return: String identifier representing the message
    """
    return 'add-lan-nat-policy'

'''
def get_nat_acls_attach_detach_command (dev_id, sw_if_index_by_key, acl_id_list, in_acl_count):
    if dev_id:
        sw_if_index_param = {
            'add_param'  : 'sw_if_index',
            'val_by_func': 'dev_id_to_vpp_sw_if_index',
            'arg'        : dev_id
        }
    else:
        sw_if_index_param = {
            'add_param' : 'sw_if_index',
            'val_by_key': sw_if_index_by_key
        }

    cmd_substs = [sw_if_index_param]
    revert_substs = [sw_if_index_param]
    acls_param =  {
        'add_param'  : 'acls',
        'val_by_func': 'map_keys_to_acl_ids',
        'arg': {
            'keys'     : copy.deepcopy(acl_id_list),
            'cmd_cache': fwglobals.g.router_api.cmd_cache
        }
    }
    cmd_substs.append(acls_param)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "call_vpp_api"
    cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr']     = "Attach NAT policy ACLs on interface: %s" % dev_id
    cmd['cmd']['params']    =   {
        'api'   : 'nat44_1to1_attach_detach_match_acls',
        'args'  : {
            'is_add' : 1,
            'total_acl_count'  : len(acl_id_list),
            'input_acl_count'  : in_acl_count,
            'substs': cmd_substs
        }
    }
    cmd['revert'] = {}
    cmd['revert']['func']      = "call_vpp_api"
    cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['descr']     = "Clear NAT policy ACLs on interface: %s" % dev_id
    cmd['revert']['params']    =   {
        'api'   : 'nat44_1to1_attach_detach_match_acls',
        'args'  : {
            'is_add' : 0,
            'total_acl_count'  : 0,
            'input_acl_count'  : 0,
            'substs': revert_substs
        }
    }
    return cmd


def get_interface_nat_setup_command(dev_id, sw_if_index_by_key, flags):

    if dev_id:
        substs = [ {
            'add_param'  : 'sw_if_index',
            'val_by_func': 'dev_id_to_vpp_sw_if_index',
            'arg'        : dev_id
        } ]
    else:
        substs = [ {
            'add_param' : 'sw_if_index',
            'val_by_key': sw_if_index_by_key
        } ]

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "call_vpp_api"
    cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr']     = "Enable NAT on interface: %s" % dev_id
    cmd['cmd']['params']    =   {
        'api'   : 'nat44_interface_add_del_feature',
        'args'  : {
            'is_add'  : True,
            'flags'   : flags,
            'substs': substs
        }
    }
    cmd['revert'] = {}
    cmd['revert']['func']      = "call_vpp_api"
    cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['descr']     = "Enable NAT on interface: %s" % dev_id
    cmd['revert']['params']    =   {
        'api'   : 'nat44_interface_add_del_feature',
        'args'  : {
            'is_add': False,
            'flags'   : flags,
            'substs': copy.deepcopy(substs)
        }
    }
    return cmd

def get_lan_nat_interface_setup_commands (nat_interfaces, cmd_list):

    lan_nat_out_acls = []
    for dev_id, value in nat_interfaces.items():
        lan_nat_out_acls.extend(value['out'])
        #NAT_IS_INSIDE = 0x20
        cmd = get_interface_nat_setup_command (dev_id, None, 0x20)
        cmd_list.append(cmd)

        cmd = get_nat_acls_attach_detach_command (dev_id, None, value['in'], len (value['in']))
        cmd_list.append(cmd)

    # Enable NAT on NAT specific loopback interface
    # NAT_IS_OUTSIDE = 0x10
    cmd = get_interface_nat_setup_command (None, LAN_NAT_LOOPBACK_CACHE_KEY, 0x10)
    cmd_list.append(cmd)

    cmd = get_nat_acls_attach_detach_command (None, LAN_NAT_LOOPBACK_CACHE_KEY, lan_nat_out_acls, 0)
    cmd_list.append(cmd)
'''
