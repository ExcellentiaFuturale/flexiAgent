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

import fwglobals
import fwtranslate_revert
import fwutils

import netaddr

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

def add_application(params):
    """Generate App commands.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    cmd_list = []

    for app in params['applications']:
        _add_traffic_identification(app, cmd_list)

    return cmd_list

def get_request_key(params):
    """Return app key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-application'
