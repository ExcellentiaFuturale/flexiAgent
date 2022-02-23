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

        intf_attachments = {}
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
                if source:
                    ingress_id = 'fw_wan_ingress__type_%s_rule_%d' % (
                        rule_type, rule_index)
                    dest_rule_params = convert_dest_to_acl_rule_params(destination)
                    cmd_list.append(fw_acl_command_helpers.add_acl_rule(
                        ingress_id, source, dest_rule_params, True, True, True))

                if rule_type == InboundNatType.IDENTITY_MAPPING:
                    interface = destination.get('interface')
                    dev_id_params = [interface] if interface is not None else []
                    if not dev_id_params:
                        interfaces = fwglobals.g.router_cfg.get_interfaces(type='wan')
                        for intf in interfaces:
                            dev_id_params.append(intf['dev_id'])
                else:
                    dev_id_params = [destination['interface']]

                for dev_id in dev_id_params:
                    if intf_attachments.get(dev_id) is None:
                        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)
                        if sw_if_index is None:
                            fwglobals.log.error('Firewall policy - WAN dev_id not found: ' + dev_id)
                            raise Exception('Firewall policy - inbound : dev_id not resolved')
                        intf_attachments[dev_id] = {}
                        intf_attachments[dev_id]['sw_if_index'] = sw_if_index
                        intf_attachments[dev_id]['ingress'] = []
                    if rule_type != InboundNatType.NAT_1TO1 and ingress_id:
                        intf_attachments[dev_id]['ingress'].append(ingress_id)

                    sw_if_index = intf_attachments[dev_id]['sw_if_index']
                    if rule_type == InboundNatType.NAT_1TO1:
                        cmd_list.extend(fw_nat_command_helpers.get_nat_1to1_config(
                            sw_if_index, action['internalIP']))
                    elif rule_type == InboundNatType.PORT_FORWARD:
                        cmd_list.extend(fw_nat_command_helpers.get_nat_port_forward_config(
                            sw_if_index, destination.get('protocols'), destination['ports'],
                            action['internalIP'], action['internalPortStart']))
                    elif rule_type == InboundNatType.IDENTITY_MAPPING:
                        cmd_list.extend(fw_nat_command_helpers.get_nat_identity_config(
                            sw_if_index, destination.get('protocols'), destination['ports']))

        # Generate Per Interface ACL commands
        for dev_id, value in intf_attachments.items():
            if value['ingress']:
                # Add last default ACL as allow ALL
                value['ingress'].append(DEFAULT_ALLOW_ID)
                fwglobals.log.info('Firewall policy - WAN dev_id: ' +
                                dev_id + ' ' + str(value['ingress']))
                cmd_list.append(fw_acl_command_helpers.add_interface_attachment(
                    intf_attachments[dev_id]['sw_if_index'], value['ingress'], None))

        return cmd_list


    def process_outbound_rules(outbound_rules):

        intf_attachments = {}
        cmd_list = []

        # get LAN interfaces for each application
        # the result is a dictionary when the keys are application identifiers, and the values are arrays of vpp interface names
        # e.g. { 'com.flexiwan.vpn': ['tun0'] }
        app_lans = fwutils.call_applications_hook('get_lan_vpp_interface_names')

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

            # interfaces ['Array of LAN device ids]
            dev_id_params = action.get('interfaces', [])
            if not dev_id_params:
                interfaces = fwglobals.g.router_cfg.get_interfaces(type='lan')
                for intf in interfaces:
                    dev_id_params.append(intf['dev_id'])

                # for applications interfaces we are using
                # the prefix 'app_' and the identifier name as the key.
                # if interfaces are specified by flexiManage, it is sent this way as well
                for app_identifier in app_lans:
                    dev_id_params.append(f'app_{app_identifier}')

            for dev_id in dev_id_params:
                if intf_attachments.get(dev_id) is None:
                    intf_attachments[dev_id] = {}
                    intf_attachments[dev_id]['ingress'] = []
                    intf_attachments[dev_id]['egress'] = []
                intf_attachments[dev_id]['ingress'].append(ingress_id)
                intf_attachments[dev_id]['egress'].append(egress_id)

        for dev_id, value in intf_attachments.items():
            # Add last default ACL as allow ALL
            value['ingress'].append(DEFAULT_ALLOW_ID)
            value['egress'].append(DEFAULT_ALLOW_ID)

            # handle application interfaces
            if dev_id.startswith('app_'):
                app_identifier = dev_id.split('_')[-1]
                if not app_identifier in app_lans:
                    continue

                for vpp_if_name in app_lans[app_identifier]:
                    sw_if_index = fwutils.vpp_if_name_to_vpp_sw_if_index(vpp_if_name)
                    if not sw_if_index:
                        continue

                    cmd_list.append(fw_acl_command_helpers.add_interface_attachment(
                        sw_if_index, value['ingress'], value['egress']))

                continue

            sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)
            if sw_if_index is None:
                fwglobals.log.error('Firewall policy - LAN dev_id not found: ' + dev_id +
                                    ' ' + str(value['ingress']) + ' ' + str(value['egress']))
                raise Exception('Firewall policy - outbound : dev_id not resolved')

            cmd_list.append(fw_acl_command_helpers.add_interface_attachment(
                sw_if_index, value['ingress'], value['egress']))

        return cmd_list

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

    return cmd_list


def get_request_key(_params):
    """
    Mandatory function in all translate modules to return the message type handled

    :param params: Unused
    :return: String identifier representing the message
    """
    return 'add-firewall-policy'
