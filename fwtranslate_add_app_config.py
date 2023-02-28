#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2022  flexiWAN Ltd.
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

# add-app-config
# --------------------------------------
# Translates request:
# {
#     "entity": "agent",
#     "message": "add-app-config",
#     "params": {
#         "name": "Remote Worker VPN",
#         "identifier": "com.flexiwan.remotevpn",
#         "applicationParams": {
#             "port": "1194",
#             "caCrt": "....",
#             "serverKey": "...",
#         }
#     }
# }
def add_app_config(params):
    cmd_list = []

    identifier = params.get('identifier')

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "configure"
    cmd['cmd']['object']  = "fwglobals.g.applications_api"
    cmd['cmd']['descr']   = f"configure {identifier} application"
    cmd['cmd']['params']  = { 'params': params }
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-app-config key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-lte request.
    """
    key = 'add-app-config-%s' % params['identifier']
    return key
