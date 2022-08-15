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

import os
import re
import ctypes
import copy
from fw_traffic_identification import TRAFFIC_IMPORTANCE_VALUES, TRAFFIC_SERVICE_CLASS_VALUES

import fwglobals
import fwutils
import fw_acl_command_helpers



# add-application
# --------------------------------------
# Translates request:
# {
#   "entity":  "agent",
#   "message": "add-application",
#   "params": [{
#            "app":"google-dns",
#            "id":1,
#            "category":"network",
#            "serviceClass":"dns",
#            "priority":3,
#            "rules":[{
#              "ip":"8.8.8.8/32",
#              "ports":"53"
#              },
#              {
#              "ip":"8.8.4.4/32",
#              "ports":"53"}]
#            }]
# }
def _add_traffic_identification(params, cmd_list):

    cmd = {}

    cmd['cmd'] = {}
    cmd['cmd']['func']   = "add_traffic_identification"
    cmd['cmd']['object'] = "fwglobals.g.traffic_identifications"
    cmd['cmd']['descr'] = "Add Traffic Identification %s" % (params['id'])
    cmd['cmd']['params'] = { 'traffic': params }

    cmd['revert'] = {}
    cmd['revert']['func']   = "add_traffic_identification"
    cmd['revert']['object'] = "fwglobals.g.traffic_identifications"
    cmd['revert']['descr'] = "Delete Traffic Identification %s" % (params['id'])
    cmd['revert']['params'] = { 'traffic': params }
    cmd_list.append(cmd)


def _add_traffic_identification_acl(traffic, acl_key_list, cmd_list):
    """
    Generate commands to match Application / Traffic Identification as ACLs
    The match definition ACLs are programmed with the configured service-class and
    importance attributes

    :param traffic: Parameters (IP/Port/Protocol) defining the application / traffic identification
    :type traffic: dict
    :param acl_key_list: An array to store the key of the generated ACL
    :type acl_key_list: Array
    :param cmd_list: Array to store the generated configuration commands
    :type cmd_list: Array
    """
    service_class = TRAFFIC_SERVICE_CLASS_VALUES.get(traffic.get('serviceClass', 'default'))
    importance = TRAFFIC_IMPORTANCE_VALUES.get(traffic.get('importance', 'low'))
    traffic_id = traffic.get("id")
    destination = {}
    destination['ipProtoPort'] = traffic['rules']
    rule_id1 = 'fw_app_rule_%s' % (traffic_id)
    cmd1 = fw_acl_command_helpers.add_acl_rule\
               (rule_id1, None, destination, True, service_class, importance, False, False)
    if cmd1:
        rule_id2 = 'fw_app_rule_%s_reverse' % (traffic_id)
        cmd2 = fw_acl_command_helpers.add_acl_rule\
                    (rule_id2, None, destination, True, service_class, importance, True, False)
    if cmd1 and cmd2:
        cmd_list.append(cmd1)
        cmd_list.append(cmd2)
        acl_key_list.append(rule_id1)
        acl_key_list.append(rule_id2)
    else:
        fwglobals.log.error('Application ACLs : ACL generate failed - Index %s' % (traffic_id))


def _attach_classification_acls(acl_ids, cmd_list):
    """
    Generate commands to attach Traffic/Application Identification ACLs to the
    LAN and WAN interfaces of the device

    :param acl_ids: Array of ACL keys that shall be used to lookup actual ACL index
    :type acl_ids: Array
    :param cmd_list: Array to store the generated configuration commands
    :type cmd_list: Array
    """
    interfaces = fwglobals.g.router_cfg.get_interfaces()
    for interface in interfaces:
        interface_type = interface['type'].lower()
        dev_id = interface['dev_id']
        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)
        if interface_type == 'lan' or interface_type == 'wan':
            add_params = {
                'sw_if_index': sw_if_index,
                'count': len(acl_ids),
                'substs': [
                    {
                        'add_param':            'acls',
                        'val_by_func':          'map_keys_to_acl_ids',
                        'arg':                  {'keys': copy.deepcopy(acl_ids)},
                        'func_uses_cmd_cache':  True
                    }
                ]
            }
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['func']  = "call_vpp_api"
            cmd['cmd']['descr'] = "Attach classification ACLs to interface: %s" % dev_id
            cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
            cmd['cmd']['params'] = {
                'api':  "classifier_acls_set_interface_acl_list",
                'args': add_params,
            }
            cmd['revert'] = {}
            cmd['revert']['func']  = "call_vpp_api"
            cmd['revert']['descr'] = "Detach classification ACLs to interface: %s" % dev_id
            cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
            cmd['revert']['params'] = {
                'api': "classifier_acls_set_interface_acl_list",
                'args': {
                    'sw_if_index': sw_if_index,
                    'count': 0,
                    'acls': []
                }
            }
            cmd_list.append(cmd)


def add_application(params):
    """Generate App commands.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    cmd_list = []
    acl_key_list = []

    for app in params['applications']:
        _add_traffic_identification(app, cmd_list)
        _add_traffic_identification_acl(app, acl_key_list, cmd_list)
    _attach_classification_acls(acl_key_list, cmd_list)

    return cmd_list

def get_request_key(params):
    """Return app key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-application'
