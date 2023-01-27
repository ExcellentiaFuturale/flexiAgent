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

class InboundNatType(enum.Enum):
    """
    Enum to represent different Inbound NAT types
    """
    NAT_1TO1 = 1
    PORT_FORWARD = 2
    IDENTITY_MAPPING = 3

DEFAULT_ALLOW_ID = 'fw_default_allow_id'


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
                dev_id_params = destination.get('interface', [])
                if source:
                    ingress_id = 'fw_wan_ingress__type_%s_rule_%d' % (
                        rule_type, rule_index)
                    dest_rule_params = convert_dest_to_acl_rule_params(destination)
                    cmd_list.append(fw_acl_command_helpers.add_acl_rule(
                        ingress_id, source, dest_rule_params, True, 0, 0, True, True))

                if rule_type != InboundNatType.NAT_1TO1 and ingress_id and dev_id_params:
                    cmd_list.append(fw_acl_command_helpers.add_interface_attachment(ingress_id, None, dev_id_params))

                if rule_type == InboundNatType.IDENTITY_MAPPING:
                    cmd_list.extend(fw_nat_command_helpers.translate_get_nat_identity_config(
                        dev_id_params, destination.get('protocols'), destination['ports']))

                for dev_id in dev_id_params:
                    if rule_type == InboundNatType.NAT_1TO1:
                        cmd_list.extend(fw_nat_command_helpers.get_nat_1to1_config(
                            dev_id, action['internalIP']))
                    elif rule_type == InboundNatType.PORT_FORWARD:
                        cmd_list.extend(fw_nat_command_helpers.get_nat_port_forward_config(
                            dev_id, destination.get('protocols'), destination['ports'],
                            action['internalIP'], action['internalPortStart']))

                if rules['rules'] and dev_id_params:
                    cmd_list.append(fw_acl_command_helpers.add_interface_attachment(DEFAULT_ALLOW_ID, None, dev_id_params))

        return cmd_list


    def process_outbound_rules(outbound_rules):

        cmd_list = []

        # Clean ACL cache
        fwglobals.g.acl_cache.clear()

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
            dev_id_params = action.get('interfaces')
            ingress_id = 'fw_lan_ingress_rule_%d' % rule_index

            cmd1 = fw_acl_command_helpers.add_acl_rule(ingress_id, source, destination,
                    permit, 0, 0, True, False)
            if cmd1:
                egress_id = 'fw_lan_egress_rule_%d' % rule_index
                cmd2 = fw_acl_command_helpers.add_acl_rule(egress_id, source, destination,
                        permit, 0, 0, False, False)

            if cmd1 and cmd2:
                cmd_list.append(cmd1)
                cmd_list.append(cmd2)
            else:
                fwglobals.log.warning('Outbound firewall: Match conditions ' +
                    'do not exist for rule index: %d' % rule_index)
                continue

            if not dev_id_params:
                cmd_list.append(fw_acl_command_helpers.cache_acl_rule('ingress', ingress_id))
                cmd_list.append(fw_acl_command_helpers.cache_acl_rule('egress', egress_id))

            cmd_list.append(fw_acl_command_helpers.add_interface_attachment(ingress_id, egress_id, dev_id_params))

        if outbound_rules['rules']:
            cmd_list.append(fw_acl_command_helpers.cache_acl_rule('ingress', DEFAULT_ALLOW_ID))
            cmd_list.append(fw_acl_command_helpers.cache_acl_rule('egress', DEFAULT_ALLOW_ID))
            cmd_list.append(fw_acl_command_helpers.add_interface_attachment(DEFAULT_ALLOW_ID, DEFAULT_ALLOW_ID, []))

        return cmd_list

    cmd_list = []
    # Add default Allow all ACLs
    # Traffic with no static/identity mapping shall get dropped by NAT lookup failure
    cmd_list.append(fw_acl_command_helpers.add_acl_rule(DEFAULT_ALLOW_ID,
                                                        None, None, True, 0, 0, True, False))

    outbound_rules = copy.deepcopy(params.get('outbound'))
    if outbound_rules:
        cmd_list.extend(process_outbound_rules(outbound_rules))

    inbound_rules = copy.deepcopy(params.get('inbound'))
    if inbound_rules:
        cmd_list.extend(process_inbound_rules(inbound_rules))

    return cmd_list


def get_request_key(_params):
    """
    Mandatory function in all translate modules to return the message type handled

    :param params: Unused
    :return: String identifier representing the message
    """
    return 'add-firewall-policy'
