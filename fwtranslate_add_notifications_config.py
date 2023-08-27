#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2023  flexiWAN Ltd.
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

# add device notifications config
# --------------------------------------
# Translates request:
# {
#     "entity": "agent",
#     "message": "add-notifications-config",
#     "params": {
#         "rules": {
#           Temperature: {
#              warningThreshold: null,
#              criticalThreshold: null,
#              thresholdUnit: 'C°',
#              severity: 'critical',
#              immediateEmail: false,
#              resolvedAlert: true,
#              sendWebHook: false,
#              type: device
#           },
#           Hard drive usage: {
#              warningThreshold: 85,
#              criticalThreshold: 95,
#              thresholdUnit: '%',
#              severity: null,
#              immediateEmail: false,
#              resolvedAlert: true,,
#              sendWebHook: false,
#              type: device
#           },..........
#           }
#     }
# }

def add_notifications_config(params=None):
    return []

def get_request_key(*params):
    """Get add notifications config command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-notifications-config'
