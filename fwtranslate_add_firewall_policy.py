"""
Translates firewall request to a set of commands
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
import enum

import fwglobals
import fwutils
import fw_acl_command_helpers
import fw_nat_command_helpers
import fwfirewall

class InboundNatType(enum.Enum):
    """
    Enum to represent different Inbound NAT types
    """
    NAT_1TO1 = 1
    PORT_FORWARD = 2
    IDENTITY_MAPPING = 3

DEFAULT_ALLOW_ID = 'fw_default_allow_id'

def get_firewall_map_acl_keys_command():
    """
    Generate command to map ACL keys to ACL index
    """
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "map_acl_keys_to_index"
    cmd['cmd']['object'] = "fwglobals.g.firewall"
    cmd['cmd']['descr']  = "Map Firewall ACL keys to actual ACL Index"
    return cmd

def get_setup_firewall_interface_command():
    """
    Generate command to make ACL attachments to the interfaces
    """
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "setup_interface_acls"
    cmd['cmd']['object'] = "fwglobals.g.firewall"
    cmd['cmd']['descr']  = "Process attachments on dynamic interfaces"

    cmd['revert'] = {}
    cmd['revert']['func']   = "clear_interface_acls"
    cmd['revert']['object'] = "fwglobals.g.firewall"
    cmd['revert']['descr']  = "Process attachments on dynamic interfaces"
    return cmd

def get_setup_global_identity_nat_command():
    """
    Generate command to setup global Identity NAT rules on the interfaces
    """
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "process_wan_global_identity_nat"
    cmd['cmd']['object'] = "fwglobals.g.firewall"
    cmd['cmd']['descr']  = "Setup global Identity NAT rules"
    cmd['cmd']['params'] = { 'is_add' : True }

    cmd['revert'] = {}
    cmd['revert']['func']   = "process_wan_global_identity_nat"
    cmd['revert']['object'] = "fwglobals.g.firewall"
    cmd['revert']['descr']  = "Remove global Identity NAT rules"
    cmd['revert']['params'] = { 'is_add' : False }
    return cmd

def add_firewall_policy(params):
    """
    Processes the firewall rules and generates corresponding commands
    Types of firewall rules
        1. Outbound rules - Attached on LAN interfaces
        2. Inbound rules - Attach on WAN ingress and create NAT mappings
        for 1:1 NAT, Port forward and Edge Access

    :param params: json/dict carrying the firewall message
    :return: Array of commands and each command is a dict
    """

    def convert_dest_to_acl_rule_params(destination):

        dest_rule_params = {}
        rule_array = []

        ports = destination.get('ports')
        protocols = destination.get('protocols')
        if ports:
            if not protocols:
                protocols = ['tcp', 'udp']
            for proto in protocols:
                rule_array.append({
                    'ports': ports,
                    'protocol': proto
                })
        dest_rule_params['ipProtoPort'] = rule_array
        return dest_rule_params


    def process_inbound_rules(inbound_rules):

        cmd_list = []
        intf_attachments = {}
        global_ingress_ids = []

        for rule_name, rules in inbound_rules.items():
            if rule_name == "nat1to1":
                rule_type = InboundNatType.NAT_1TO1
            elif rule_name == "portForward":
                rule_type = InboundNatType.PORT_FORWARD
            elif rule_name == "edgeAccess":
                rule_type = InboundNatType.IDENTITY_MAPPING
            else:
                raise Exception("Invalid Inbound NAT type %d" % rule_name)

            for rule_index, rule in enumerate(rules['rules']):

                ingress_id = None
                classification = rule.get('classification')
                action = rule.get('action')
                destination = classification.get('destination')
                source = classification.get('source')
                interface = destination.get('interface')
                dev_ids = [interface] if interface else []

                if source:
                    ingress_id = 'fw_wan_ingress__type_%s_rule_%d' % (
                        rule_type, rule_index)
                    dest_rule_params = convert_dest_to_acl_rule_params(destination)
                    cmd_list.append(fw_acl_command_helpers.add_acl_rule(
                        ingress_id, source, dest_rule_params, True, True, True))

                if dev_ids:
                    for dev_id in dev_ids:
                        if rule_type == InboundNatType.IDENTITY_MAPPING:
                            cmd_list.extend(fw_nat_command_helpers.get_nat_identity_config(
                                dev_id, destination.get('protocols'), destination['ports']))

                        elif rule_type == InboundNatType.NAT_1TO1:
                            cmd_list.extend(fw_nat_command_helpers.get_nat_1to1_config(
                                dev_id, action['internalIP']))

                        elif rule_type == InboundNatType.PORT_FORWARD:
                            cmd_list.extend(fw_nat_command_helpers.get_nat_port_forward_config(
                                dev_id, destination.get('protocols'), destination['ports'],
                                action['internalIP'], action['internalPortStart']))

                        if ingress_id:
                            if intf_attachments.get(dev_id) is None:
                                    intf_attachments[dev_id] = {}
                                    intf_attachments[dev_id]['ingress'] =\
                                        copy.deepcopy(global_ingress_ids)
                            intf_attachments[dev_id]['ingress'].append(ingress_id)
                else:
                    if rule_type == InboundNatType.IDENTITY_MAPPING:
                        fwglobals.g.firewall.add_wan_global_identity_nat\
                            (destination.get('protocols'), destination['ports'])
                    # Global rule
                    if ingress_id:
                        for dev_id in intf_attachments.keys():
                            intf_attachments[dev_id]['ingress'].append(ingress_id)
                        global_ingress_ids.append(ingress_id)

        for dev_id, value in intf_attachments.items():
            # Add last default ACL as allow ALL
            value['ingress'].append(DEFAULT_ALLOW_ID)
            fwglobals.g.firewall.set_interface_acls (dev_id, value['ingress'], None,
                                                     fwutils.dev_id_to_vpp_sw_if_index(dev_id))

        if global_ingress_ids:
            global_ingress_ids.append(DEFAULT_ALLOW_ID)
            fwglobals.g.firewall.set_wan_global_acls (global_ingress_ids, None)
        return cmd_list


    def process_outbound_rules(outbound_rules):

        cmd_list = []
        intf_attachments = {}
        global_ingress_ids = []
        global_egress_ids = []

        for rule_index, rule in enumerate(outbound_rules['rules']):

            classification = rule.get('classification')
            if classification:
                destination = classification.get('destination')
                source = classification.get('source')
            else:
                destination = None
                source = None

            action = rule['action']
            permit = action['permit']
            # interfaces ['Array of LAN device ids] received from flexiManage
            dev_ids = action.get('interfaces', [])
            ingress_id = 'fw_lan_ingress_rule_%d' % rule_index

            cmd1 = fw_acl_command_helpers.add_acl_rule(ingress_id, source, destination,
                    permit, True, False)
            if cmd1:
                egress_id = 'fw_lan_egress_rule_%d' % rule_index
                cmd2 = fw_acl_command_helpers.add_acl_rule(egress_id, source, destination,
                        permit, False, False)

            if cmd1 and cmd2:
                cmd_list.append(cmd1)
                cmd_list.append(cmd2)
            else:
                fwglobals.log.warning('Outbound firewall: Match conditions ' +
                    'do not exist for rule index: %d' % rule_index)
                continue

            if dev_ids:
                for dev_id in dev_ids:
                    if intf_attachments.get(dev_id) is None:
                        intf_attachments[dev_id] = {}
                        intf_attachments[dev_id]['ingress'] = copy.deepcopy(global_ingress_ids)
                        intf_attachments[dev_id]['egress'] = copy.deepcopy(global_egress_ids)
                intf_attachments[dev_id]['ingress'].append(ingress_id)
                intf_attachments[dev_id]['egress'].append(egress_id)
            else:
                # Global rule
                for dev_id in intf_attachments.keys():
                    intf_attachments[dev_id]['ingress'].append(ingress_id)
                    intf_attachments[dev_id]['egress'].append(egress_id)
                global_ingress_ids.append(ingress_id)
                global_egress_ids.append(egress_id)

        for dev_id in list(intf_attachments):
            # Add last default ACL as allow ALL
            intf_attachments[dev_id]['ingress'].append(DEFAULT_ALLOW_ID)
            intf_attachments[dev_id]['egress'].append(DEFAULT_ALLOW_ID)
            if not dev_id.startswith('app_'):
                fwglobals.g.firewall.set_interface_acls\
                    (dev_id, intf_attachments[dev_id]['ingress'],
                     intf_attachments[dev_id]['egress'], fwutils.dev_id_to_vpp_sw_if_index(dev_id))
            else:
                sw_if_index_list, app_id_list = fwfirewall.get_app_sw_if_index_list(dev_id)
                for idx, sw_if_index in enumerate(sw_if_index_list):
                    app_dev_id = fwfirewall.get_firewall_interface_key_for_app\
                        (app_id_list[idx], sw_if_index)
                    intf_attachments[app_dev_id] = {}
                    intf_attachments[app_dev_id]['ingress'] =\
                        copy.deepcopy(intf_attachments[dev_id]['ingress'])
                    intf_attachments[app_dev_id]['egress'] =\
                        copy.deepcopy(intf_attachments[dev_id]['egress'])
                    fwglobals.g.firewall.set_interface_acls\
                        (app_dev_id, intf_attachments[dev_id]['ingress'],
                        intf_attachments[dev_id]['egress'], sw_if_index)

        if global_ingress_ids:
            global_ingress_ids.append(DEFAULT_ALLOW_ID)
        if global_egress_ids:
            global_egress_ids.append(DEFAULT_ALLOW_ID)
        fwglobals.g.firewall.set_lan_global_acls (global_ingress_ids, global_egress_ids)

        return cmd_list

    # Reset Firewall contexts
    fwglobals.g.firewall.reset()

    cmd_list = []
    # Add default Allow all ACLs
    # Traffic with no static/identity mapping shall get dropped by NAT lookup failure
    cmd_list.append(fw_acl_command_helpers.add_acl_rule(DEFAULT_ALLOW_ID,
                                                        None, None, True, True, False))

    outbound_rules = params.get('outbound')
    if outbound_rules:
        cmd_list.extend(process_outbound_rules(outbound_rules))

    inbound_rules = params.get('inbound')
    if inbound_rules:
        cmd_list.extend(process_inbound_rules(inbound_rules))

    #Command to transform acl keys to acl index using the command cache
    cmd_list.append(get_firewall_map_acl_keys_command())

    #Setup command to be executed for making ACL attachments
    cmd_list.append(get_setup_firewall_interface_command())

    #Setup command to be executed for making global Identity NAT rules
    cmd_list.append(get_setup_global_identity_nat_command())
    return cmd_list


def get_request_key(_params):
    """
    Mandatory function in all translate modules to return the message type handled

    :param params: Unused
    :return: String identifier representing the message
    """
    return 'add-firewall-policy'
