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

def add_ospf(params):
    """OSPF configuration to frr.

    :param cmd_list:            List of commands.

    :returns: None.
    """
    cmd_list = []

    # routerId
    routerId = params.get('routerId')
    if routerId:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']   = "python"
        cmd['cmd']['descr']   =  "add routerId %s to OSPF" % routerId
        cmd['cmd']['params'] = {
                'module': 'fwutils',
                'func': 'frr_vtysh_run',
                'args': {
                    'flags'              : '-c "configure" -c "router ospf" -c "ospf router-id %s"' % routerId,
                    'restart_frr_service': True,
                }
        }
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['params'] = {
                'module': 'fwutils',
                'func': 'frr_vtysh_run',
                'args': {
                    'flags'              : '-c "configure" -c "router ospf" -c "no ospf router-id %s"' % routerId,
                    'restart_frr_service': True,
                }
        }
        cmd['revert']['descr']   =  "remove routerId %s from OSPF" % routerId
        cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-ospf-config command.

    :param params:        Parameters from flexiManage.

    :returns: add-ospf-config command.
    """
    key = 'add-ospf-config'
    return key
