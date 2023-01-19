################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2023 flexiWAN Ltd.
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

# On downgrade from 6.X to previous major version, this migration script removes
# the dpdk config of VPP startup conf. This is required as 6.X uses dpdk as part
# of LTE/PPPoE functionality. The dpdk tuntap-vdev entries added by 6.X shall
# not be compatible with previous version code.

import os
import sys

common_tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , 'common')
sys.path.append(common_tools)

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)

import fwutils

VPP_CONFIG_FILE = '/etc/vpp/startup.conf'

def migrate(prev_version=None, new_version=None, upgrade=True):
    print("Migrating : processing 00017_190123_remove_dpdk_section on downgrade from 6.X")
    try:
        prev_version = prev_version.split('-')[0].split('.')
        new_version  = new_version.split('-')[0].split('.')
        new_major_version = int(new_version[0])
        prev_major_version = int(prev_version[0])

        if upgrade == 'downgrade' and prev_major_version == 6 and new_major_version < 6:
            fwutils.vpp_startup_conf_remove_dpdk_config(VPP_CONFIG_FILE)
            print("* Migrating : removed dpdk config")
    except Exception as e:
        print("Migration error: %s : %s" % (__file__, str(e)))


if __name__ == "__main__":
    migrate()
