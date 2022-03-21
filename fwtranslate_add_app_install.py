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

# add-app-install
# --------------------------------------
# Translates request:
# {
#     "entity": "agent",
#     "message": "add-app-install",
#     "params": {
#         "name": "Remote Worker VPN",
#         "identifier": "com.flexiwan.remotevpn",
#         "applicationParams": {}
#     }
# },
def add_app_install(params):
    """Generate commands to install an application.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    cmd_list = []

    identifier = params.get('identifier')

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "install"
    cmd['cmd']['object']  = "fwglobals.g.applications_api"
    cmd['cmd']['descr']   = f"install {identifier} application"
    cmd['cmd']['params']  = { 'params': params }
    cmd['revert'] = {}
    cmd['revert']['func']   = "uninstall"
    cmd['revert']['object'] = "fwglobals.g.applications_api"
    cmd['revert']['descr']  = f"uninstall {identifier} application"
    cmd['revert']['params'] = { 'params': params }
    cmd_list.append(cmd)

    return cmd_list


def get_request_key(params):
    """Get add-lte key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-lte request.
    """
    key = 'add-app-install-%s' % params['identifier']
    return key
