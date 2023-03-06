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

# On upgrade this migration script updates the VPN server scripts.

import os
import sys
import shutil

common_tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , 'common')
sys.path.append(common_tools)

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)

import fwglobals
import fwutils
from fwapplications_cfg import FwApplicationsCfg

def _migrate_vpn_script():
    application_db_path = "/etc/flexiwan/agent/.applications.sqlite"
    if os.path.exists(application_db_path):
        with FwApplicationsCfg(application_db_path) as application_cfg:
            apps = application_cfg.get_applications()

            for app in apps:
                identifier = app.get('identifier')
                if not identifier == 'com.flexiwan.remotevpn':
                    continue

                path = '/usr/share/flexiwan/agent/applications/com_flexiwan_remotevpn/scripts'
                shutil.copyfile('{}/script_utils.py'.format(path), '/etc/openvpn/server/script_utils.py')
                os.system('killall openvpn') # it will be start again by our application watchdog

def migrate(prev_version=None, new_version=None, upgrade=True):
    # upgrade from any version before 6:
    if upgrade == 'upgrade' and fwutils.version_less_than(prev_version, '6.2.0'):
        try:
            print("* Migrating OpenVPN scripts for 6.2.X ...")
            _migrate_vpn_script()

        except Exception as e:
            print("Migration error: %s : %s" % (__file__, str(e)))

if __name__ == "__main__":
    migrate()
