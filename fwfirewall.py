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

import fwglobals
import fwutils
from fwobject import FwObject

class FwFirewall(FwObject):
    """Firewall class representation.
    """
    def __init__(self):
        self.rules = {}
        self.rules['ingress'] = []
        self.rules['egress']  = []

    def add(self, direction, acl_id):
        self.rules[direction].append(acl_id)

    def remove(self, direction, acl_id):
        self.rules[direction] = [tup for tup in self.rules[direction] if tup == acl_id]

    def get(self, direction):
        return self.rules[direction]

    def clear(self, direction):
        self.rules[direction].clear()
