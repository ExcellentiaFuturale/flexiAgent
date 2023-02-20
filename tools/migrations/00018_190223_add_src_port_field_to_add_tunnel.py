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

# On the 6.2 version, we added the "srcPort" field to add-tunnel requests.
#
# After the upgrade/downgrade, the agent starts the router, and then, flexiManage sends a "sync" request.
# If the sync contains params which not exist in the device DB, the agent triggers remove and add.
#
# To prevent unnecessary reconstruct of tunnels:
# On upgrade, The agent starts the router with the default field - "4789" before the sync,
# so there is no need to reconstruct again if the "srcPort" in "sync" is "4789".
# Hence we added the "4789" as "srcPort".
#
# On downgrade, the agent starts the router and uses the default in vpp - "4789".
# so no need to reconstruct again. Hence we removed the "srcPort" field.

import os
import sys

common_tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , 'common')
sys.path.append(common_tools)

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)

import fwutils
from fwrouter_api import fwrouter_translators
from fwrouter_cfg import FwRouterCfg

requests_db_path = "/etc/flexiwan/agent/.requests.sqlite"

def migrate(prev_version=None, new_version=None, upgrade=True):
    print("Migrating : processing 00018_190223_add_src_port_field_to_add_tunnel on upgrade from 6.1")
    try:
        if not os.path.exists(requests_db_path):
            return
        with FwRouterCfg(requests_db_path) as router_cfg:
            router_cfg.set_translators(fwrouter_translators)
            tunnels = router_cfg.get_tunnels()

            if not tunnels:
                return

            is_add    = upgrade == 'upgrade'   and fwutils.version_less_than(prev_version, '6.2.0')
            is_remove = upgrade == 'downgrade' and fwutils.version_less_than(new_version, '6.2.0')

            if not is_add and not is_remove:
                return

            for tunnel in tunnels:
                if is_add:
                    tunnel['srcPort'] = '4789'
                elif is_remove and 'srcPort' in tunnel:
                    del tunnel['srcPort']

                new_tunnel_request = {
                    'message':   'add-tunnel',
                    'params':    tunnel
                }
                router_cfg.update(new_tunnel_request, [], False)

            print(f"* Migrating : {'Adding' if is_add else 'Removing'} srcPort field of tunnel requests")

    except Exception as e:
        print("Migration error: %s : %s" % (__file__, str(e)))


if __name__ == "__main__":
    migrate()
