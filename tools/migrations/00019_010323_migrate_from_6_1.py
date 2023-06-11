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
from fwrouter_api import fwrouter_translators
from fwrouter_cfg import FwRouterCfg

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

requests_db_path = "/etc/flexiwan/agent/.requests.sqlite"
def migrate_routing_filters(upgrade):
    if not os.path.exists(requests_db_path):
        return
    with FwRouterCfg(requests_db_path) as router_cfg:
        router_cfg.set_translators(fwrouter_translators)
        routing_filters = router_cfg.get_routing_filters()
        if not routing_filters:
            return

        for routing_filter in routing_filters:
            if upgrade:
                default_action = routing_filter.get('defaultAction')
                if not default_action:
                    continue
                opposite_action = 'allow' if default_action == 'deny' else 'deny'

                final_rules = []
                rules = routing_filter.get('rules', [])
                for idx, rule in enumerate(rules):
                    network = rule.get('network')
                    final_rules.append({ 'route': network, 'action': opposite_action, 'priority': idx + 1, 'nextHop': ''})

                # append default route at the end, as flexiManage sends it this way
                final_rules.append({ 'route': '0.0.0.0/0', 'action': default_action, 'priority': 0, 'nextHop': '' })

                new_routing_filter_request = {
                    'message':   'add-routing-filter',
                    'params':    {
                        'name': routing_filter['name'],
                        'description': routing_filter['description'],
                        'rules': final_rules
                    }
                }
                router_cfg.update(new_routing_filter_request, [], False)
            else:
                default_action = None
                allowed_rules = []
                denied_rules = []

                rules = routing_filter.get('rules', [])
                for rule in rules:
                    network = rule.get('route')
                    action = rule.get('action')

                    if network == '0.0.0.0/0':
                        default_action = action
                        continue # don't push it to final rules

                    if action == 'allow':
                        allowed_rules.append({'network': network })
                        continue

                    if action == 'deny':
                        denied_rules.append({'network': network })
                        continue

                if not default_action:
                    continue # not valid routing filter

                final_rules = []
                if default_action == 'allow':
                    final_rules.extend(denied_rules)
                elif default_action == 'deny':
                    final_rules.extend(allowed_rules)

                new_routing_filter_request = {
                    'message':   'add-routing-filter',
                    'params':    {
                        'name': routing_filter['name'],
                        'description': routing_filter['description'],
                        'defaultAction': default_action,
                        'rules': final_rules
                    }
                }
                router_cfg.update(new_routing_filter_request, [], False)

def migrate_bgp_community(upgrade):
    if not os.path.exists(requests_db_path):
        return
    with FwRouterCfg(requests_db_path) as router_cfg:
        router_cfg.set_translators(fwrouter_translators)
        bgp = router_cfg.get_bgp()
        if not bgp:
            return

        updated_neighbors = []
        neighbors = bgp.get('neighbors', [])
        for neighbor in neighbors:
            if upgrade:
                neighbor['sendCommunity'] = 'all'
            elif 'sendCommunity' in neighbor:
                del neighbor['sendCommunity']

            updated_neighbors.append(neighbor)

        bgp['neighbors'] = updated_neighbors

        new_request = {
            'message':   'add-routing-bgp',
            'params':    bgp
        }
        router_cfg.update(new_request, [], False)

def migrate(prev_version=None, new_version=None, upgrade=True):
    # upgrade from any version before 6:
    try:
        if upgrade == 'upgrade' and fwutils.version_less_than(prev_version, '6.2.0'):
            print("* Migrating OpenVPN scripts for 6.2.X ...")
            _migrate_vpn_script()

            print("* Migrating Routing filters ...")
            migrate_routing_filters(upgrade=True)

            print("* Migrating BGP neighbors - adding community...")
            migrate_bgp_community(upgrade=True)

        if upgrade == 'downgrade' and fwutils.version_less_than(new_version, '6.2.0'):
                print("* Downgrading Routing filters ...")
                migrate_routing_filters(upgrade=False)

                print("* Downgrading BGP neighbors - removing community...")
                migrate_bgp_community(upgrade=False)

    except Exception as e:
        print("Migration error: %s : %s" % (__file__, str(e)))

if __name__ == "__main__":
    migrate()
