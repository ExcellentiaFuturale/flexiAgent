"""
Entry API to process QoS Traffic Map message
"""
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

import fwglobals

def add_qos_traffic_map(params):
    """
    API that is called on receiving QoS Traffic Map

    :param params: QoS Traffic Map parameters
    :type params: dict
    :return: Command array with the commands
    :rtype: Array
    """
    return fwglobals.g.qos.get_traffic_map_update_commands(params)


def get_request_key(_params):
    """
    Mandatory function in all translate modules to return the message type handled

    :param _params: Unused
    :type _params: dict
    :return: Identifier representing the message
    :rtype: String
    """
    return 'add-qos-traffic-map'
