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

# This script run pre uninstall tasks

import os
import sys

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)

import fwutils
import fwapplications_api

FW_EXIT_CODE_OK      = 0

def uninstall_device_applications():
    print("Uninstalling device applications")
    fwapplications_api.call_applications_hook('uninstall')

if __name__ == '__main__':
    try:
        uninstall_device_applications()
    except Exception as e:
        print("Pre remove error: %s" % (str(e)))
    sys.exit(FW_EXIT_CODE_OK)
