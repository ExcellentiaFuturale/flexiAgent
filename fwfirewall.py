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

from fwobject import FwObject

from sqlitedict import SqliteDict

class FwFirewallAcls():
    def __init__(self):
        self.ingress = None
        self.egress = None

    def add(self, direction, value):
        if direction == "ingress":
            self.ingress = value
        if direction == "egress":
            self.egress = value

    def remove(self, direction):
        if direction == "ingress":
            self.ingress = None
        if direction == "egress":
            self.egress = None

    def get(self, direction):
        if direction == "ingress":
            return self.ingress
        if direction == "egress":
            return self.egress

class FwFirewallAclCache(FwObject):
    """Firewall class representation.
    """
    def __init__(self, db_file):
        FwObject.__init__(self)
        self.db_filename = db_file
        self.devices = SqliteDict(db_file, 'devices',autocommit=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.finalize()

    def finalize(self):
        self.devices.close()

    def add(self, dev_id, direction, acl_ids):
        devices = self.devices

        if not dev_id in devices:
            devices[dev_id] = FwFirewallAcls()

        devices[dev_id].add(direction, acl_ids)

        self.devices = devices

    def remove(self, dev_id, direction, acl_ids):
        devices = self.devices

        if not dev_id in devices:
           return

        devices[dev_id].remove(direction)

        self.devices = devices

    def get(self, dev_id, direction):
        if dev_id not in self.devices:
            if 'global' in self.devices:
                dev_id = 'global'
            else:
                return []

        return self.devices[dev_id].get(direction)

    def clear(self):
        self.devices = {}
