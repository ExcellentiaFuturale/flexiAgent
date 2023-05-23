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

from fw_traffic_identification import TRAFFIC_IMPORTANCE_VALUES, TRAFFIC_SERVICE_CLASS_VALUES
from fw_traffic_identification import APP_CLASSIFICATION_ACLS_LIST_ID
import fwglobals
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
    """
    Add traffic/application identification to the internal sqldict context

    :param params: add-application message from carrying the traffic/app match definitions
    :type params: dict
    :param cmd_list: Command array to be updated with corresponding commands
    :type cmd_list: Array
    """
    cmd = {}

    cmd['cmd'] = {}
    cmd['cmd']['func']   = "add_traffic_identification"
    cmd['cmd']['object'] = "fwglobals.g.traffic_identifications"
    cmd['cmd']['descr'] = "Add Traffic Identification %s" % (params['id'])
    cmd['cmd']['params'] = { 'traffic': params }

    cmd['revert'] = {}
    cmd['revert']['func']   = "remove_traffic_identification"
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


def _get_classification_setup_command(app_acl_ids, cmd_list):
    """
    Generate commands to attach classification ACLs to the given interface

    :param app_acl_ids: It can either be an integer representing the ACL index or a key
    to be used to lookup the actual acl_index from the command cache
    :type app_acl_ids: Array
    :param cmd_list: Array of generated configuration commands
    :type cmd_list: Array
    """
    add_param_acl_ids = False if isinstance(app_acl_ids[0], int) else True

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']  = "call_vpp_api"
    cmd['cmd']['descr'] = "Setup classification ACLs"
    cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['params'] = {
        'api':  "classifier_acls_set_acls",
        'args': {
            'count' : len(app_acl_ids),
            'acl_list_id': APP_CLASSIFICATION_ACLS_LIST_ID,
        }
    }
    args = cmd['cmd']['params']['args']
    if add_param_acl_ids:
        args['substs'] = [{
            'add_param':            'acls',
            'val_by_func':          'map_keys_to_acl_ids',
            'arg':                  {'keys': app_acl_ids},
            'func_uses_cmd_cache':  True
        }]
    else:
        args['acls'] = app_acl_ids

    cmd['revert'] = {}
    cmd['revert']['func']  = "call_vpp_api"
    cmd['revert']['descr'] = "Clear classification ACLs"
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['params'] = {
        'api': "classifier_acls_set_acls",
        'args': {
            'count': 0,
            'acl_list_id': APP_CLASSIFICATION_ACLS_LIST_ID,
            'acls': [],
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
    _get_classification_setup_command(acl_key_list, cmd_list)
    return cmd_list


def get_request_key(params):
    """Return app key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-application'
