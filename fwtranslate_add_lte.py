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

def add_lte(params):
    """Generate commands to add DHCP configuration.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    cmd_list = []

    dev_id = params['dev_id']

    metric = params.get('metric')
    apn = params.get('apn')
    user = params.get('user')
    password = params.get('password')
    auth = params.get('auth')
    pin = params.get('pin')

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "call"
    cmd['cmd']['object'] = "fwglobals.g.lte"
    cmd['cmd']['params'] = {
        'dev_id': dev_id,
        'func': 'connect',
        'apn': apn,
        'user': user,
        'password': password,
        'auth': auth,
        'pin': pin,
    }
    cmd['cmd']['descr'] = "Connect LTE to the cellular provider"
    cmd['revert'] = {}
    cmd['revert']['func']   = "call"
    cmd['revert']['object'] = "fwglobals.g.lte"
    cmd['revert']['params'] = { 'dev_id': dev_id, 'func': 'disconnect' }
    cmd['revert']['descr'] = "Disconnect LTE from the cellular provider"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}

    cmd['cmd']['func']   = "call"
    cmd['cmd']['object'] = "fwglobals.g.lte"
    cmd['cmd']['params'] = { 'dev_id': dev_id, 'func': 'configure_interface', 'metric': metric }
    cmd['cmd']['descr'] = "Configure LTE IP and gateway on linux interface if vpp is not run"
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-lte key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-lte request.
    """
    key = 'add-lte-%s' % params['dev_id']
    return key
