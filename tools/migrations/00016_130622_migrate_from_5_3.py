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


from fwrouter_api import fwrouter_translators
from fwrouter_cfg import FwRouterCfg
import fwutils

def _migrate_remove_bgp_tunnel_neighbors(upgrade=True):
    requests_db_path = "/etc/flexiwan/agent/.requests.sqlite"
    if os.path.exists(requests_db_path):
        with FwRouterCfg(requests_db_path) as router_cfg:
            router_cfg.set_translators(fwrouter_translators)

            bgp = router_cfg.get_bgp()
            if not bgp:
                return

            tunnels = router_cfg.get_tunnels()
            tunnel_remote_loopback_ips = list(map(lambda tunnel: fwutils.build_tunnel_remote_loopback_ip(tunnel['loopback-iface']['addr']), tunnels))

            updated_neighbors = []

            neighbors = bgp.get('neighbors', [])
            for neighbor in neighbors:
                ip = neighbor.get('ip')
                if ip in tunnel_remote_loopback_ips:
                    continue # don't add the tunnel remote loopback to the final neighbors list

                updated_neighbors.append(neighbor)

            bgp['neighbors'] = updated_neighbors

            new_request = {
                'message':   'add-routing-bgp',
                'params':    bgp
            }
            router_cfg.update(new_request, [], False)

def migrate(prev_version=None, new_version=None, upgrade=True):
    prev_version = prev_version.split('-')[0].split('.')
    new_version  = new_version.split('-')[0].split('.')

    prev_major_version = int(prev_version[0])
    prev_minor_version = int(prev_version[1])

    # upgrade from 5.3 (the version where BGP feature was introduced in)
    if upgrade == 'upgrade' and prev_major_version == 5 and prev_minor_version == 3:
        try:
            print("* Migrating Tunnel BGP neighbors ...")
            _migrate_remove_bgp_tunnel_neighbors()

        except Exception as e:
            print("Migration error: %s : %s" % (__file__, str(e)))

if __name__ == "__main__":
    migrate()
