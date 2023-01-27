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


def add_acl_rule(acl_id, source, destination, permit, service_class, importance,
                 is_ingress, add_last_deny_ace):
    """ Function that encapsulates call to generation of ACL command and its params

    :param id: String identifier representing the ACL
    :param source: json/dict message repersenting the source
    :param destination: json/dict message repersenting the destination
    :param action: json/dict message repersenting the action
    :param is_ingress: Boolean representing is ingress or not
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


    def build_vpp_acl_params(source_match, dest_match, permit, service_class, importance, is_ingress):

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
                              'service_class': service_class,
                              'importance': importance})
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
                              'service_class': service_class,
                              'importance': importance})
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


    def generate_acl_params(source, destination, permit,
                            rule_service_class, rule_importance, is_ingress):

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
                        source_match, dest_match, permit,
                        rule_service_class, rule_importance, is_ingress)
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
                            (source, destination, permit, service_class, importance, is_ingress)
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
                            (None, destination, False, service_class, importance, is_ingress)
            if last_acl:
                acl_rules.extend(last_acl)
            else:
                raise Exception ('Generated default last Deny ACL rule is empty')
        cmd = generate_acl_rule(acl_id, acl_rules)
    return cmd


def add_interface_attachment(ingress_id, egress_id, dev_id_params):
    """ Prepares command dict required to attach array of ingress and egress
    ACL identifiers to an interface

    :param ingress_id: Ingress ACL identifier
    :param egress_id: Egress ACL identifier
    :param dev_id_params: List of interfaces
    :return: Dict representing the command
    """
    cmd = {}

    add_params = {
                'is_add': True,
                'dev_id_params': dev_id_params,
                'substs': [{'add_param':            'ingress_acl_ids',
                            'val_by_func':          'map_keys_to_acl_ids',
                            'arg':                  {'keys': [ingress_id]},
                            'func_uses_cmd_cache':  True},
                           {'add_param':            'egress_acl_ids',
                            'val_by_func':          'map_keys_to_acl_ids',
                            'arg':                  {'keys': [egress_id]},
                            'func_uses_cmd_cache':  True}]
    }

    revert_params = copy.deepcopy(add_params)
    revert_params['is_add'] = False

    cmd['cmd'] = {}
    cmd['cmd']['func']   = "add_acl_rules_interfaces"
    cmd['cmd']['module'] = "fw_acl_command_helpers"
    cmd['cmd']['descr'] = "Attach ACLs to interface"
    cmd['cmd']['params'] = add_params
    cmd['revert'] = {}
    cmd['revert']['func']   = "add_acl_rules_interfaces"
    cmd['revert']['module'] = "fw_acl_command_helpers"
    cmd['revert']['descr'] = "Detach ACLs from interface"
    cmd['revert']['params'] = revert_params

    return cmd

class FwAclCache():
    """ Cache of ACL rules used by Firewall feature.
    """
    def __init__(self):
        self.ingress_rules = []
        self.egress_rules = []

    def add(self, direction, acl_id):
        if direction == 'ingress':
            self.ingress_rules.append(acl_id)
        elif direction == 'egress':
            self.egress_rules.append(acl_id)

    def remove(self, direction, acl_id):
        if direction == 'ingress':
            self.ingress_rules = [tup for tup in self.ingress_rules if tup == acl_id]
        elif direction == 'egress':
            self.egress_rules = [tup for tup in self.egress_rules if tup == acl_id]

    def get(self, direction):
        if direction == 'ingress':
            return self.ingress_rules
        elif direction == 'egress':
            return self.egress_rules

    def clear(self):
        self.ingress_rules.clear()
        self.egress_rules.clear()

def translate_cache_acl_rule(direction, acl_id):
    """ Translate cache ACL rule

    :param direction: Inbound/outbound
    :param acl_id: ACL identifier
    """
    cmd = {}

    cmd['cmd'] = {}
    cmd['cmd']['func']   = "update_firewall_cache"
    cmd['cmd']['module'] = "fw_acl_command_helpers"
    cmd['cmd']['descr']  = "Add Firewall ACL into cache"
    cmd['cmd']['params'] = {
            'is_add': True,
            'direction': direction,
            'substs': [ { 'add_param': 'acl_index', 'val_by_key': acl_id } ]
    }

    cmd['revert'] = {}
    cmd['revert']['func']   = "update_firewall_cache"
    cmd['revert']['module'] = "fw_acl_command_helpers"
    cmd['revert']['descr']  = "Remove Firewall ACL from cache"
    cmd['revert']['params'] = {
            'is_add': False,
            'direction': direction,
            'substs': [ { 'add_param': 'acl_index', 'val_by_key': acl_id } ]
    }

    return cmd

def update_firewall_cache(is_add, direction, acl_index):
    """Update cache of firewall rules

    :param is_add: Indicate if to add or remove.
    :param direction: ingress or egress.
    :param acl_index: ACL identifier

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    if is_add:
        fwglobals.g.acl_cache.add(direction, acl_index)
    else:
        fwglobals.g.acl_cache.remove(direction, acl_index)

    return (True, None)

def vpp_add_acl_rules(is_add, sw_if_index, ingress_acl_ids, egress_acl_ids):
    """
    Add/remove ACL rules on the interface

    :param is_add: add or remove
    :param sw_if_index: device identifier of the interface
    :param ingress_acl_ids: ingress acl ids
    :param egress_acl_ids: egress acl ids
    """
    acls = []
    ingress_count = 0
    count = 0

    if is_add:
        if ingress_acl_ids:
            acls.extend(ingress_acl_ids)
            ingress_count = len(ingress_acl_ids)
        if egress_acl_ids:
            acls.extend(egress_acl_ids)
        count = len(acls)

    fwglobals.g.router_api.vpp_api.vpp.call('acl_interface_set_acl_list',
        count=count, sw_if_index=sw_if_index, n_input=ingress_count, acls=acls)

def add_acl_rules_interfaces(is_add, dev_id_params, ingress_acl_ids, egress_acl_ids):
    """
    Add/remove ACL rules on the list of interfaces

    :param is_add: add or remove
    :param dev_id_params: list of interfaces
    :param ingress_acl_ids: ingress acl ids
    :param egress_acl_ids: egress acl ids
    """
    updated_dev_id_params = []
    if dev_id_params:
        # Get LAN interfaces managed by installed applications.
        # The function below returns dictionary, where keys are application identifiers,
        # and values are lists of vpp interface names, e.g.
        #      { 'com.flexiwan.vpn': ['tun0'] }
        app_lans = fwglobals.g.applications_api.get_interfaces(type="lan", vpp_interfaces=True, linux_interfaces=False)

        # flexiManage doesn't know about application interfaces,
        # So it sends only 'app_{identifier}' as the dev_id.
        # Hence, we need to manipulate  the dev_id to be app_{identifier}_{vpp_if_name},
        # as it expected by the following code.
        for dev_id_param in dev_id_params:
            # if dev id is a dpdk interface - keep it as is.
            if not dev_id_param.startswith('app_'):
                updated_dev_id_params.append(dev_id_param)
                continue

            # if we don't have vpp interfaces for this app - continue.
            app_identifier = dev_id_param.split('_')[-1]
            if not app_identifier in app_lans:
                continue

            # add the application vpp interface names to the list
            for vpp_if_name in app_lans[app_identifier]:
                updated_dev_id_params.append(f'app_{app_identifier}_{vpp_if_name}')

    else: # if not dev_id_params
        interfaces = fwglobals.g.router_cfg.get_interfaces(type='lan')
        for intf in interfaces:
            updated_dev_id_params.append(intf['dev_id'])
        ingress_acl_ids = fwglobals.g.acl_cache.get('ingress')
        egress_acl_ids = fwglobals.g.acl_cache.get('egress')

    for dev_id in updated_dev_id_params:
        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)
        vpp_add_acl_rules(is_add, sw_if_index, ingress_acl_ids, egress_acl_ids)
