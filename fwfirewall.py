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

class FwFirewallAclCache(FwObject):
    """Firewall class representation.
    """
    def __init__(self, db):
        FwObject.__init__(self)
        self.db      = db
        self.devices = db.get('firewall')
        if not self.devices:
            db['firewall'] = {}
            self.devices = db['firewall']

    def _commit(self):
        '''"self.db" is reference to sqlitedict. A such, it does not support in-memory modifications,
        so it should be replaced completely. Hence the "_commit()" function that should be called
        on every modification.
        '''
        self.db['firewall'] = self.devices

    def add(self, dev_id, direction, acl_ids):
        if not dev_id in self.devices:
            self.devices[dev_id] = {}
        self.devices[dev_id][direction] = acl_ids
        self._commit()

    def remove(self, dev_id, direction, acl_ids):
        if not dev_id in self.devices:
           return
        del self.devices[dev_id][direction]
        self._commit()

    def get(self, dev_id, direction):
        if dev_id not in self.devices:
            return []
        return self.devices[dev_id][direction]

    def clear(self):
        self.devices = {}
        self._commit()
