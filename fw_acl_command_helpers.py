"""
Helper functions to convert classifications and actions into VPP ACL commands
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
import ctypes

import fwglobals
import fwutils


def add_acl_rule(acl_id, source, destination, permit, is_ingress,
                 add_last_deny_ace, acl_user_attr=None):
    """ Function that encapsulates call to generation of ACL command and its params

    :param id: String identifier representing the ACL
    :param source: json/dict message representing the source
    :param destination: json/dict message representing the destination
    :param action: json/dict message representing the action
    :param is_ingress: Boolean representing is ingress or not
    :param add_last_deny_ace: Flag to indicate if a last deny rule to be auto added
    :param acl_user_attr: User attributes to be attached to this rule
    :return: Dict representing the command. None can be returned if the given
             traffic tags based match does not have a valid match in the app/traffic ID DB
    """

    def convert_match_to_acl_param(rule):

        ip_with_prefix = rule.get('ip')
        if not ip_with_prefix:
            ip_with_prefix = "0.0.0.0/0"

        ports = rule.get('ports')
        if ports:
            port_from, port_to = fwutils.ports_str_to_range(ports)
        else:
            port_from = 0
            port_to = 0xffff
        protocols = rule.get('protocols')
        if protocols is None:
            protocol_single = rule.get('protocol')
            if protocol_single:
                protocols = [protocol_single]
        protocols_map = []
        if protocols:
            for protocol in protocols:
                protocols_map.append(fwutils.proto_map[protocol])
        elif ports:
            protocols_map.append(fwutils.proto_map['tcp'])
            protocols_map.append(fwutils.proto_map['udp'])

        return ip_with_prefix, port_from, port_to, protocols_map if protocols_map else None


    def build_vpp_acl_params(source_match, dest_match, permit,  is_ingress, acl_user_attr):

        rules = []
        src_ip_with_prefix, src_port_from, src_port_to, src_proto =\
            convert_match_to_acl_param(source_match)
        dst_ip_with_prefix, dest_port_from, dest_port_to, dst_proto =\
            convert_match_to_acl_param(dest_match)
        if dst_proto is None:
            dst_proto = [0]

        # Protocol is not expected to be present in a valid source match
        # Check and log source and destination protocol mismatch
        if src_proto:
            src_proto.sort()
            dst_proto.sort()
            if src_proto != dst_proto:
                fwglobals.log.warning('Mismatch between src (%s) and dest (%s) protocol fields'
                                      % (src_proto, dst_proto))

        for proto in dst_proto:
            if proto == fwutils.proto_map['icmp']:
                sport_from = dport_from = 0
                sport_to = dport_to = 0xffff
            else:
                sport_from = src_port_from
                sport_to = src_port_to
                dport_from = dest_port_from
                dport_to = dest_port_to

            if is_ingress:
                rules.append({'is_permit': int(permit is True),
                              'is_ipv6': 0,
                              'src_prefix': src_ip_with_prefix,
                              'dst_prefix': dst_ip_with_prefix,
                              'proto': proto,
                              'srcport_or_icmptype_first': sport_from,
                              'srcport_or_icmptype_last': sport_to,
                              'dstport_or_icmpcode_first': dport_from,
                              'dstport_or_icmpcode_last': dport_to,
                              'acl_user_attr': acl_user_attr})
            else:
                rules.append({'is_permit': int(permit is True),
                              'is_ipv6': 0,
                              'src_prefix': dst_ip_with_prefix,
                              'dst_prefix': src_ip_with_prefix,
                              'proto': proto,
                              'srcport_or_icmptype_first': dport_from,
                              'srcport_or_icmptype_last': dport_to,
                              'dstport_or_icmpcode_first': sport_from,
                              'dstport_or_icmpcode_last': sport_to,
                              'acl_user_attr': acl_user_attr})
        return rules


    def is_match_unique(match1, match2):

        if match1 and match2:
            ip_with_prefix1, port_from1, port_to1, _ =\
                convert_match_to_acl_param(match1)
            ip_with_prefix2, port_from2, port_to2, _ =\
                convert_match_to_acl_param(match2)
            if ((ip_with_prefix1 == ip_with_prefix2) and (port_from1 == port_from2) and
                    (port_to1 == port_to2)):
                return 0
        return 1


    def generate_acl_params(source, destination, permit, is_ingress, acl_user_attr):

        acl_rules = []
        dest_matches = []
        source_matches = []
        any_match = {}
        tags_based = False

        if destination:
            traffic_id = destination.get('trafficId')
            if traffic_id is None:
                traffic_tags = destination.get('trafficTags')
                if traffic_tags is None:
                    custom_rule = destination.get('ipProtoPort')
                    if isinstance(custom_rule, list):
                        dest_matches.extend(custom_rule)
                    else:
                        dest_matches.append(custom_rule)
                else:
                    category = traffic_tags.get('category')
                    service_class = traffic_tags.get('serviceClass')
                    importance = traffic_tags.get('importance')
                    dest_matches = fwglobals.g.traffic_identifications.get_traffic_rules(
                        None, category, service_class, importance)
                    tags_based = True
            else:
                dest_matches = fwglobals.g.traffic_identifications.get_traffic_rules(
                    traffic_id, None, None, None)
        else:
            dest_matches.append(any_match)

        if source:
            traffic_id = source.get('trafficId')
            if traffic_id is None:
                custom_rule = source.get('ipPort')
                source_matches.append(custom_rule)
            else:
                source_matches = fwglobals.g.traffic_identifications.get_traffic_rules(
                    traffic_id, None, None, None)
        else:
            source_matches.append(any_match)

        for dest_match in dest_matches:
            source_match_prev = None
            for source_match in source_matches:
                if is_match_unique(source_match, source_match_prev):
                    rules = build_vpp_acl_params(
                        source_match, dest_match, permit, is_ingress, acl_user_attr)
                    acl_rules.extend(rules)
                    source_match_prev = source_match

        return acl_rules, tags_based


    def generate_acl_rule(acl_id, acl_rules):

        cmd = {}
        add_params = {
            'acl_index': ctypes.c_uint(-1).value,
            'count': len(acl_rules),
            'r': acl_rules,
            'tag': ''
        }

        cmd['cmd'] = {}
        cmd['cmd']['func']  = "call_vpp_api"
        cmd['cmd']['descr'] = "Add Firewall ACL"
        cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['params'] = {
                                'api': "acl_add_replace",
                                'args': add_params
                               }
        cmd['cmd']['cache_ret_val'] = ('acl_index', acl_id)

        cmd['revert'] = {}
        cmd['revert']['func']  = "call_vpp_api"
        cmd['revert']['descr'] = "Remove Firewall ACL"
        cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['params'] = {
                'api':  "acl_del",
                'args': {
                    'substs': [ { 'add_param': 'acl_index', 'val_by_key': acl_id } ]
                }
        }
        return cmd

    cmd = {}

    acl_rules, tags_based = generate_acl_params\
                            (source, destination, permit, is_ingress, acl_user_attr)

    if not acl_rules:
        fwglobals.log.warning('Generated ACL rule is empty. ' +
            'Check if traffic tags has a valid match.' +
            'Source: %s Destination: %s' % (source, destination))
        if tags_based:
            # It may not be fatal if traffic tags based classification does not exist
            # Allow the caller to make the decision
            return None
        else:
            raise Exception ('Generated ACL rule is empty')
    else:
        # Allow list ACL use case - At end of allow list, add the deny
        # Append acl definition with a deny entry - Block all other sources
        if add_last_deny_ace:
            last_acl, __  = generate_acl_params\
                            (None, destination, False, is_ingress, acl_user_attr)
            if last_acl:
                acl_rules.extend(last_acl)
            else:
                raise Exception ('Generated default last Deny ACL rule is empty')
        cmd = generate_acl_rule(acl_id, acl_rules)
    return cmd


def build_acl_user_attributes (user_value, service_class=0, importance=0):
    """
    Build user attributes structure that can be attached to ACL rule.
    The attributes can be used to encode additional user values to be associated with this rule.

    :param user_value: User value to be attached to the rule
    :type user_value: Integer
    :param service_class: Service class attribute to be attached to the rule, defaults to 0
    :type service_class: int, optional
    :param importance: Importance attribute to be attached to the rule, defaults to 0
    :type importance: int, optional
    :return: user attribute structure that can be passed to the VPP add acl API
    :rtype: dict
    """
    if user_value:
        acl_user_attr = {
            'user_value': user_value
        }
    else:
        acl_user_attr = {
            'attributes': {
                'service_class': service_class,
                'importance': importance
            }
        }
    return acl_user_attr
