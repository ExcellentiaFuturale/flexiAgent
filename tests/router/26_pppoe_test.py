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

import os
import sys
import time

import fwglobals
from  fwpppoe import FwPppoeClient, FwPppoeInterface

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)

def test(fixture_globals):
    fwglobals.initialize()
    client = FwPppoeClient(fwglobals.g.PPPOE_DB_FILE, fwglobals.g.PPPOE_CONFIG_PATH, fwglobals.g.PPPOE_CONFIG_PROVIDER_FILE)
    client.clean()
    if_name = 'enp0s9'
    dev_id = 'pci:0000:00:09.00'

    pppoe_iface = FwPppoeInterface('denis-2', 'password', 1412, 1412, False, 20, False)
    client.remove_interface(if_name=if_name, dev_id=dev_id)
    client.add_interface(pppoe_iface, if_name=if_name, dev_id=dev_id)

    fwglobals.log.debug("PPPoE: %s" % str(client.get_interface(if_name=if_name, dev_id=dev_id)))

    time.sleep(10)
    client.scan()
    fwglobals.log.debug("PPPoE: %s" % str(client.get_interface(if_name=if_name, dev_id=dev_id)))

    pppoe_iface = client.get_interface(if_name=if_name, dev_id=dev_id)
    pppoe_iface.is_enabled = True
    client.add_interface(pppoe_iface, if_name=if_name, dev_id=dev_id)

    time.sleep(10)
    client.scan()
    fwglobals.log.debug("PPPoE: %s" % str(client.get_interface(if_name=if_name, dev_id=dev_id)))

    client.remove_interface(if_name=if_name, dev_id=dev_id)

if __name__ == '__main__':
    test()
