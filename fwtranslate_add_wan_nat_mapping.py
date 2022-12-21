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

import copy

import fwglobals
import fwutils
import fw_nat_command_helpers

# add_wan_nat_mapping
# --------------------------------------
# Translates request:
#
#    {
#      "message": "add-wan-nat-mapping",
#      "params": {
#           "dev_id":"0000:00:01.00",
#           "port":"4789"
#      }
#    }
#
# into list of commands:
#
#    1.vpp.cfg
#    ------------------------------------------------------------
#    01. sudo vppctl nat44 out GigabitEthernet1/0/0 output-feature
#    02. sudo vppctl nat44 add interface address GigabitEthernet8/0/0 session-recovery
#    03. fwutils: enable forward of tap-inject to ip4-output features
#    04. sudo vppctl nat44 add static mapping udp local 0.0.0.0 4789 external GigabitEthernet1/0/0 4789 vrf 0

def add_wan_nat_mapping(params):
    """Generate commands to configure interface nat mapping in VPP

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    dev_id  = params['dev_id']
    port = params.get('port', fwglobals.VXLAN_PORTS["port"])

    # Setup NAT config on WAN interface
    if 'type' not in params or params['type'].lower() == 'wan':
        cmd_list.extend(fw_nat_command_helpers.get_nat_wan_setup_config(dev_id))

    return cmd_list

def get_request_key(params):
    """Get add wan nat mapping command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-wan-nat-mapping:%s' % params['dev_id']
