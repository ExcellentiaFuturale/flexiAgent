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

import json
import re
import traceback
import copy

from fwcfg_database import FwCfgDatabase

import fwglobals
import fwrouter_api
import fwutils


class FwRouterCfg(FwCfgDatabase):
    """This is requests DB class representation.

    :param db_file: SQLite DB file name.
    """

    def update(self, request, cmd_list=None, executed=False):
        # The `start-router` does not conform `add-X`, `remove-X`, `modify-X` format
        # handled by the superclass update(), so we handle it here.
        # All the rest are handled by FwCfgDatabase.update().
        #

        req     = request['message']
        req_key = None
        try:
            if re.match('start-router', req):
                params  = request.get('params')
                req_key = self._get_request_key(request)
                self[req_key] = { 'request' : req , 'params' : params , 'cmd_list' : cmd_list , 'executed' : executed }
            else:
                FwCfgDatabase.update(self, request, cmd_list, executed)
        except KeyError:
            pass
        except Exception as e:
            self.log.error("update(%s) failed: %s, %s" % \
                        (req_key, str(e), str(traceback.format_exc())))
            raise Exception('failed to update request database')

    def dump(self, types=None, escape=None, full=False, keys=False):
        """Dumps router configuration into list of requests
        """
        if not types:
            types = [
                'start-router',
                'add-routing-filter',
                'add-routing-bgp',           # BGP should come after frr routing filter, as it might use them!
                'add-interface',
                'add-vxlan-config',
                'add-switch',
                'add-tunnel',
                'add-route',		 # routes should come after tunnels, as they might use them
                'add-dhcp-config',
                'add-application',
                'add-multilink-policy',
                'add-firewall-policy',
                'add-lan-nat-policy',
                'add-ospf',
                'add-qos-traffic-map',
                'add-qos-policy',
                'add-vrrp-group',
            ]

        return FwCfgDatabase.dump(self, types, escape, full, keys)

    def dumps(self, types=None, escape=None, full=False):
        """Dumps router configuration into printable string.

        :param types:  list of types of configuration requests to be dumped, e.g. [ 'add-interface' , 'add-tunnel' ]
        :param escape: list of types of configuration requests that should be escaped while dumping
        :param full:   return requests together with translated commands.
        """
        sections = {                # Use stairway to ensure section order in
                                    # output string created by json.dumps()
                                    #
            'start-router':         "======= START COMMAND =======",
            'add-interface':        "======== INTERFACES ========",
            'add-switch':           "======== SWITCHES ========",
            'add-route':            "========= ROUTES =========",
            'add-tunnel':           "========== TUNNELS ==========",
            'add-dhcp-config':      "=========== DHCP CONFIG ===========",
            'add-application':      "============ APPLICATIONS ============",
            'add-multilink-policy': "============= POLICIES =============",
            'add-firewall-policy':  "============= FIREWALL POLICY =============",
            'add-lan-nat-policy':   "============= LAN NAT POLICY =============",
            'add-ospf':             "============= OSPF =============",
            'add-vxlan-config':     "============= VXLAN CONFIG =============",
            'add-routing-bgp':      "============= ROUTING BGP =============",
            'add-routing-filter':   "============= ROUTING FILTERS =============",
            'add-qos-traffic-map':  "============= QOS TRAFFIC MAP =============",
            'add-qos-policy':       "============= QOS POLICY =============",
            'add-vrrp-group':       "============= VRRP =============",
        }

        cfg = self.dump(types=types, escape=escape, full=full, keys=True)
        return FwCfgDatabase.dumps(self, cfg, sections, full)

    def get_interfaces(self, type=None, dev_id=None, ip=None, device_type=None):
        interfaces = self.get_requests('add-interface')
        if not type and not dev_id and not ip and not device_type:
            return interfaces
        result = []
        for params in interfaces:
            if type and not re.match(type, params['type'], re.IGNORECASE):
                continue
            elif dev_id and dev_id != params['dev_id']:
                continue
            elif ip and not re.match(ip, params['addr']):
                continue
            elif device_type and device_type != params.get('deviceType'):
                continue
            result.append(params)
        return result

    def get_routes(self, addr=None, via=None, dev_id=None):
        routes = self.get_requests('add-route')
        if not addr and not via and not dev_id:
            return routes
        result = []
        for params in routes:
            if addr and params['addr'] != addr:
                continue
            elif via and params['via'] != via:
                continue
            elif dev_id and 'dev_id' in params and params['dev_id'] != dev_id:
                continue
            result.append(params)
        return result

    def get_routing_filters(self):
        return self.get_requests('add-routing-filter')

    def get_tunnels(self, routing=None):
        tunnels = self.get_requests('add-tunnel')
        if routing:
            result = []
            for tunnel in tunnels:
                if routing == tunnel.get('loopback-iface', {}).get('routing'):
                    result.append(tunnel)
            tunnels = result
        return tunnels

    def get_bgp(self):
        bgp_req = self.get_requests('add-routing-bgp')
        # add-routing-bgp is a single request and can't be more than that.
        # Therefore, convert it from a list to an object or None
        if not bgp_req:
            return None
        return bgp_req[0]

    def get_vrrp_groups(self, dev_id=None):
        vrrp_groups = self.get_requests('add-vrrp-group')
        if not dev_id:
            return vrrp_groups
        result = []
        for params in vrrp_groups:
            if params['devId'] == dev_id:
                result.append(params)
        return result

    def get_vxlan_config(self):
        vxlan_config = self.get_requests('add-vxlan-config')
        # add-vxlan-config is a single request and can't be more than that.
        # Therefore, convert it from a list to an object or None
        if not vxlan_config:
            return None
        return vxlan_config[0]

    def get_tunnel(self, tunnel_id):
        key = 'add-tunnel:%d' % (tunnel_id)
        return self.get_params(key)

    def get_multilink_policy(self):
        return self.get_params('add-multilink-policy')

    def get_applications(self):
        return self.get_params('add-application')

    def get_firewall_policy(self):
        if 'add-firewall-policy' in self:
            return self['add-firewall-policy']['params']
        return None

    def get_qos_traffic_map(self):
        if 'add-qos-traffic-map' in self:
            return self['add-qos-traffic-map']['params']
        return None

    def get_qos_policy(self):
        if 'add-qos-policy' in self:
            return self['add-qos-policy']['params']
        return None

    def get_lan_nat_policy(self):
        if 'add-lan-nat-policy' in self:
            return self['add-lan-nat-policy']['params']
        return None

    def get_sync_list(self, requests):
        """Intersects requests provided within 'requests' argument against
        the requests stored in the local database and generates output list that
        can be used for synchronization of router configuration. This output list
        is called sync-list. It includes sequence of 'remove-X', 'modify-X' and
        'add-X' requests that should be applied to device in order to configure
        it with the configuration, reflected in the input list 'requests'.

        :param requests: list of requests that reflects the desired configuration.
                         The requests are in formant of flexiManage<->flexiEdge
                         message: { 'message': 'add-X', 'params': {...}}.

        :returns: synchronization list - list of 'remove-X', 'modify-X' and
                         'add-X' requests that takes device to the desired
                         configuration if applied to the device.
        """

        # Firstly we hack a little bit the input list as follows:
        # build dictionary out of this list where values are list elements
        # (requests) and keys are request keys that local database would use
        # to store these requests. Accidentally these are exactly same keys
        # dumped by fwglobals.g.router_cfg.dump() used below ;)
        #
        input_requests = {}
        for request in copy.deepcopy(requests): # Use deepcopy as we might modify input_requests[key] below
            key = self._get_request_key(request)
            input_requests.update({key:request})

        # Now dump local configuration in order of 'remove-X' list.
        # We will go over dumped requests and filter out requests that present
        # in the input list and that have same parameters. They correspond to
        # configuration items that should be not touched by synchronization.
        # The dumped requests that present in the input list but have different
        # parameters stand for modifications.
        #
        dumped_requests = fwglobals.g.router_cfg.dump(keys=True)
        output_requests = []

        for dumped_request in dumped_requests:
            dumped_key = dumped_request['key']
            if dumped_key in input_requests:
                # The configuration item presents in the input list.
                #
                dumped_params = dumped_request.get('params')
                input_params  = input_requests[dumped_key].get('params')
                if fwutils.compare_request_params(dumped_params, input_params):
                    # The configuration item has exactly same parameters.
                    # It does not require sync, so remove it from input list.
                    #
                    del input_requests[dumped_key]
                else:
                    # The configuration item should be modified.
                    # Rename requests in input list with 'modify-X'.
                    #
                    request = input_requests[dumped_key]
                    request['message'] = request['message'].replace('add-', 'modify-')
            else:
                # The configuration item does not present in the input list.
                # So it stands for item to be removed. Add correspondent request
                # to the output list.
                # Ignore 'start-router', 'stop-router', etc as they are not
                # an configuration items.
                #
                if not re.search('(start|stop)-router', dumped_request['message']):
                    dumped_request['message'] = dumped_request['message'].replace('add-', 'remove-')
                    output_requests.append(dumped_request)


        # At this point the input list includes 'add-X' requests that stand
        # for new or for modified configuration items.
        # Just go and add them to the output list 'as-is'.
        #
        output_requests += list(input_requests.values())

        return output_requests
