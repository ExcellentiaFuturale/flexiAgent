################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2022 flexiWAN Ltd.
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

common_tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , 'common')
sys.path.append(common_tools)

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)

import pathlib
import shutil

import fwglobals
from fwapplications_cfg import FwApplicationsCfg
from fwrouter_api import fwrouter_translators
from fwrouter_cfg import FwRouterCfg

def _migrate_vpn_scripts():
    application_db_path = "/etc/flexiwan/agent/.applications.sqlite"
    if os.path.exists(application_db_path):
        with FwApplicationsCfg(application_db_path) as application_cfg:
            apps = application_cfg.get_applications()

            for app in apps:
                identifier = app.get('identifier')
                if not identifier == 'com.flexiwan.remotevpn':
                    continue

                path = '/usr/share/flexiwan/agent/applications/com_flexiwan_remotevpn/scripts'
                shutil.copyfile('{}/up.py'.format(path), '/etc/openvpn/server/up-script.py')
                shutil.copyfile('{}/down.py'.format(path), '/etc/openvpn/server/down-script.py')
                shutil.copyfile('{}/client-connect.py'.format(path), '/etc/openvpn/server/client-connect.py')
                shutil.copyfile('{}/scripts_logger.py'.format(path), '/etc/openvpn/server/scripts_logger.py')
                shutil.copyfile('{}/script_utils.py'.format(path), '/etc/openvpn/server/script_utils.py')

                os.system('killall openvpn') # it will be start again by our application watchdog

def _migrate_routing_field(upgrade=True):
    requests_db_path = "/etc/flexiwan/agent/.requests.sqlite"
    if os.path.exists(requests_db_path):
        with FwRouterCfg("/etc/flexiwan/agent/.requests.sqlite") as router_cfg:
            router_cfg.set_translators(fwrouter_translators)
            interfaces = router_cfg.get_interfaces()
            for interface in interfaces:
                changed = False

                # upgrade
                if upgrade and isinstance(interface['routing'], str):
                    interface['routing'] = [interface['routing']] # convert string to array
                    changed = True

                # downgrade
                if not upgrade and isinstance(interface['routing'], list):
                    interface_type = interface.get('type')

                    if interface_type == 'WAN':
                        interface['routing'] = 'NONE'
                        changed = True

                    elif interface_type == 'LAN':
                        if 'OSPF' in interface['routing']:
                            interface['routing'] = 'OSPF'
                        else: # means that user has only 'BGP'.
                            if len(interface['routing']) > 0:
                                interface['routing'] = interface['routing'][0]
                            else:
                                interface['routing'] = 'NONE'
                        changed = True

                if changed:
                    new_request = {
                        'message':   'add-interface',
                        'params':    interface
                    }
                    router_cfg.update(new_request, [], False)

def migrate(prev_version=None, new_version=None, upgrade=True):
    prev_version = prev_version.split('-')[0].split('.')
    new_version  = new_version.split('-')[0].split('.')

    prev_major_version = int(prev_version[0])
    prev_minor_version = int(prev_version[1])

    new_major_version  = int(new_version[0])
    new_minor_version  = int(new_version[1])

    # upgrade from lower (or equal) then 5.2
    if upgrade == 'upgrade' and prev_major_version < 5 or (prev_major_version == 5 and prev_minor_version <= 2):
        try:
            print("* Migrating vpn server scripts ...")
            _migrate_vpn_scripts()

            print("* Migrating routing field from string to list ...")
            _migrate_routing_field()

        except Exception as e:
            print("Migration error: %s : %s" % (__file__, str(e)))

    # downgrade to lower (or equal) then 5.2
    if upgrade == 'downgrade' and new_major_version < 5 or (new_major_version == 5 and new_minor_version <= 2):
        try:
            print("* Migrating routing field from list to string ...")
            _migrate_routing_field(upgrade=False)

            # no need to migrate the vpn scripts on downgrade, the new scripts support both versions
        except Exception as e:
            print("Migration error: %s : %s" % (__file__, str(e)))

if __name__ == "__main__":
    migrate()
