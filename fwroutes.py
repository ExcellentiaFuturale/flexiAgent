################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2021  flexiWAN Ltd.
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

import enum
import socket
import fwglobals
import fwpppoe
import fwthread
import fwtunnel_stats
import fwutils
import subprocess

from fwobject import FwObject
from pyroute2 import IPRoute
from pyroute2.netlink import exceptions as netlink_exceptions

routes_protocol_map = {
    -1: '',
    0: 'unspec',
    1: 'redirect',
    2: 'kernel',
    3: 'boot',
    4: 'static',
    8: 'gated',
    9: 'ra',
    10: 'mrt',
    11: 'zebra',
    12: 'bird',
    13: 'dnrouted',
    14: 'xorp',
    15: 'ntk',
    16: 'dhcp',
    18: 'keepalived',
    42: 'babel',
    186: 'bgp',
    187: 'isis',
    188: 'ospf',
    189: 'rip',
    192: 'eigrp',
}

routes_protocol_id_map = { y:x for x, y in routes_protocol_map.items() }

class FwRouteKey(str):
    """Route key"""
    def __new__(cls, metric, addr, via):
        obj = f'{addr} {via} {str(metric)}'
        return obj

class FwRouteNextHop:
    """Class used as a route nexthop."""
    def __init__(self, via, dev):
        self.dev        = dev
        self.via        = via

class FwRoute:
    """Class used as a route data."""
    def __init__(self, prefix, via, dev, proto, metric):
        self.key        = FwRouteKey(metric, prefix, via)
        self.prefix     = prefix
        self.via        = via
        self.dev        = dev
        self.proto      = proto
        self.metric     = metric
        self.dev_id     = fwutils.get_interface_dev_id(dev)
        self.probes     = {}        # Ping results per server
        self.ok         = True      # If True there is connectivity to internet

    def __str__(self):
        route = '%s via %s dev %s(%s)' % (self.prefix, self.via, self.dev, self.dev_id)
        if self.proto:
            route += (' proto ' + str(self.proto))
        if self.metric:
            route += (' metric ' + str(self.metric))
        return route

class FwRoutes(FwObject):
    """Manages all route related activity, e.g. watchdog on sync of static
    routes in router configuration to the actual routes in kernel, or monitor
    of default route change, which might require some actions.
    """
    def __init__(self):
        FwObject.__init__(self)
        self.thread_routes = None
        self.default_route = fwutils.get_default_route()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.finalize()

    def initialize(self):
        """Starts the FwRoutes activity - runs the main loop thread.
        """
        self.thread_routes = fwthread.FwRouterThread(target=self.route_thread_func, name="Routes", log=self.log)
        self.thread_routes.start()

    def finalize(self):
        """Stops the FwRoutes activity - stops the main loop thread.
        """
        if self.thread_routes:
            self.thread_routes.join()
            self.thread_routes = None

    def route_thread_func(self, ticks):
        # Firstly sync static routes from router configuration DB to Linux
        # in order to restore routes that disappeared for some reason,
        # for example due to 'netplan apply' that overrod cfg routes.
        # We do that only if router was started already.
        #
        if fwglobals.g.router_api and fwglobals.g.router_api.state_is_started():
            if ticks % 5 == 0:  # Check routes every ~5 seconds
                self._check_reinstall_static_routes()

        # Check if the default route was modified.
        # If it was, reconnect the agent to avoid WebSocket timeout.
        #
        if fwglobals.g.fwagent:
            default_route = fwutils.get_default_route()
            if self.default_route[2] != default_route[2]:
                self.log.debug(f"reconnect as default route was changed: '{self.default_route}' -> '{default_route}'")
                self.default_route = default_route
                fwglobals.g.fwagent.reconnect()


    def _check_reinstall_static_routes(self):
        routes_db = fwglobals.g.router_cfg.get_routes()
        routes_linux = FwLinuxRoutes(proto='static')
        tunnel_addresses = fwtunnel_stats.get_tunnel_info()

        for route in routes_db:
            addr = route['addr']
            via = route['via']
            metric = str(route.get('metric', '0'))
            dev_id = route.get('dev_id')
            exist_in_linux = routes_linux.exist(addr, metric, via)

            if tunnel_addresses.get(via) == 'down':
                if exist_in_linux:
                    success, err_str = add_remove_route(addr, via, metric, True, dev_id, 'static')
                    if success:
                        fwglobals.log.debug(f"remove static route through the broken tunnel: {str(route)}")
                    else:
                        fwglobals.log.error(f"failed to remove static route ({str(route)}): {err_str}")
                continue

            if not exist_in_linux:
                success, err_str = add_remove_route(addr, via, metric, False, dev_id, 'static')
                if success:
                    fwglobals.log.debug(f"restore static route: {str(route)}")
                else:
                    fwglobals.log.error(f"failed to restore static route ({str(route)}): {err_str}")


class FwLinuxRoutes(dict):
    """The object that represents routing rules found in OS.
    """
    def __init__(self, prefix=None, preference=None, via=None, proto=None):
        self._linux_get_routes(prefix, preference, via, proto)

    def __getitem__(self, item):
        return self[item]

    def _linux_get_routes(self, prefix=None, preference=None, via=None, proto=None):
        if not proto:
            proto_id = None
        else:
            proto_id = routes_protocol_id_map.get(proto, -1)

        with IPRoute() as ipr:
            try:
                if prefix == '0.0.0.0/0':
                    routes = ipr.get_default_routes(family=socket.AF_INET)
                else:
                    # if we set filter by prefix ipr.get_routes() returns corrupted routes info (incorrect protocol type, priority, etc.)
                    # so we pass only proto instead and filter results by other params like prefix, metric, etc.
                    # routes = ipr.get_routes(dst=prefix, family=socket.AF_INET, proto=proto_id) - returns wrong data
                    routes = ipr.get_routes(family=socket.AF_INET, proto=proto_id)
            except netlink_exceptions.NetlinkError:
                routes = []     # If no matching route exists in kernel, NetlinkError is raised

            for route in routes:
                nexthops = []
                dst = None # Default routes have no RTA_DST
                metric = 0
                gw = None
                rt_table = 0

                rt_proto = routes_protocol_map[route.get('proto', -1)]

                for attr in route['attrs']:
                    if attr[0] == 'RTA_PRIORITY':
                        metric = int(attr[1])
                    if attr[0] == 'RTA_OIF':
                        try:
                            dev = ipr.get_links(attr[1])[0].get_attr('IFLA_IFNAME')
                        except NetlinkError as e:
                            continue
                    if attr[0] == 'RTA_DST':
                        dst = attr[1]
                    if attr[0] == 'RTA_GATEWAY':
                        gw = attr[1]
                    if attr[0] == 'RTA_MULTIPATH':
                        for elem in attr[1]:
                            try:
                                dev = ipr.get_links(elem['oif'])[0].get_attr('IFLA_IFNAME')
                            except NetlinkError as e:
                                continue
                            for attr2 in elem['attrs']:
                                if attr2[0] == 'RTA_GATEWAY':
                                    nexthops.append(FwRouteNextHop(attr2[1],dev))
                    if attr[0] == 'RTA_TABLE':
                        rt_table = int(attr[1])

                if rt_table >= 255:  # ignore bizare routes which are not in main/local tables
                    continue        # See RT_TABLE_X in /usr/include/linux/rtnetlink.h

                if not dst: # Default routes have no RTA_DST
                    dst = "0.0.0.0"
                addr = "%s/%u" % (dst, route['dst_len'])

                if gw:
                    nexthops.append(FwRouteNextHop(gw,dev))

                # check if non None since metric can be 0
                if preference is not None and metric != int(preference):
                    continue

                if prefix and addr != prefix:
                    continue

                if not nexthops:
                    nexthops.append(FwRouteNextHop(None,dev))

                for nexthop in nexthops:
                    if via and via != nexthop.via:
                        continue
                    self[FwRouteKey(metric, addr, nexthop.via)] = FwRoute(addr, nexthop.via, nexthop.dev, rt_proto, metric)

    def exist(self, addr, metric, via):
        metric = int(metric) if metric else 0
        key = FwRouteKey(metric, addr, via)
        if key in self:
            return True

        # Check if this route exist but with metric changed by WAN_MONITOR
        #
        metric = metric + fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK
        key = FwRouteKey(metric, addr, via)
        if key in self:
            return True

        return False

def add_remove_route(addr, via, metric, remove, dev_id=None, proto='static', dev=None, netplan_apply=True, onLink=False):
    """Add/Remove route.

    :param addr:            Destination network.
    :param via:             Gateway address.
    :param metric:          Metric.
    :param remove:          True to remove route.
    :param dev_id:          Bus address of device to be used for outgoing packets.
    :param proto:           Route protocol.
    :param dev:             Name of device in Linux to be used for the route.
                            This parameter has higher priority than the 'dev_id'.
    :param netplan_apply:   If False, the 'netplan apply' command will be not run at the end of this function.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    metric = int(metric) if metric else 0

    if dev_id and not dev:
        dev = fwutils.dev_id_to_linux_if_name(dev_id)
        if not dev:
            return (False, f"add_remove_route: interface was not found for dev_id {str(dev_id)}")

    if addr == 'default':
        return (True, None)

    pppoe = fwpppoe.is_pppoe_interface(dev_id=dev_id)
    if not pppoe:  # PPPoE interfaces can use any peer in the world as a GW, so escape sanity checks for it
        if not onLink and not fwutils.linux_check_gateway_exist(via):
            return (True, None)
        if not remove:
            tunnel_addresses = fwtunnel_stats.get_tunnel_info()
            if via in tunnel_addresses and tunnel_addresses[via] != 'up':
                return (True, None)

    routes_linux = FwLinuxRoutes(prefix=addr, preference=metric, proto=proto)
    exist_in_linux = routes_linux.exist(addr, metric, via)

    if remove and not exist_in_linux:
        # TODO: implement remove onlink routes
        return (True, None)

    if not remove and exist_in_linux:
        return (True, None)

    next_hops = ''
    if routes_linux:
        for route in routes_linux.values():
            if remove and via == route.via:
                continue
            next_hops += ' nexthop via ' + route.via

    metric = ' metric %s' % metric if metric else ' metric 0'
    op     = 'replace'

    if remove:
        if not next_hops:
            op = 'del'
        cmd = "sudo ip route %s %s%s proto %s %s" % (op, addr, metric, proto, next_hops)
    else:
        if via in next_hops:
            return (False, "via in next_hop")
        if not dev:
            cmd = "sudo ip route %s %s%s proto %s nexthop via %s %s" % (op, addr, metric, proto, via, next_hops)
        else:
            cmd = "sudo ip route %s %s%s proto %s nexthop via %s dev %s %s %s" % (op, addr, metric, proto, via, dev, next_hops, 'onlink' if onLink else '')

    try:
        fwglobals.log.debug(cmd)
        output = subprocess.check_output(cmd, shell=True).decode()
    except Exception as e:
        if op == 'del':
            fwglobals.log.debug("'%s' failed: %s, ignore this error" % (cmd, str(e)))
            return (True, None)
        return (False, str(e))

    # We need to re-apply Netplan configuration here to install default route that
    # could be removed in the flow before.
    # This will happen if static default route installed by user is exactly the same like
    # default route generated based on interface configuration inside Netplan file.
    if remove and netplan_apply:
        fwutils.netplan_apply("add_remove_route")

    return (True, None)

def remove_route(route):
    """Removes route in format of FwRoute object from Linux.

    :param route: the FwRoute object that represents route to be removed from Linux.

    :returns: <error string> on failure, None on success.
    """
    try:
        with pyroute2.IPRoute() as ipr:
            fwglobals.log.debug(f"remove_route: {route.prefix}, metric={route.metric}")
            ipr.route("del", dst=route.prefix, priority=route.metric)
        return None
    except Exception as e:
        fwglobals.log.debug(f"failed to remove_route({route.prefix} metric={route.metric}): {str(e)}, ignore this error")
        return str(e)

def add_remove_static_routes(via, is_add):
    routes_db = fwglobals.g.router_cfg.get_routes()

    for route in routes_db:
        if route['via'] != via:
            continue

        addr = route['addr']
        metric = str(route.get('metric', '0'))
        dev_id = route.get('dev_id')
        via = route['via']

        success, err_str = add_remove_route(addr, via, metric, not is_add, dev_id, 'static')
        if not success:
            fwglobals.log.error(f"failed to add/remove static route ({str(route)}): {err_str}")


def update_route_metric(route, new_metric, netplan_apply=False):
    """Updates metric of the specific route in Linux.

    :param route:           The FwRoute object that reflects route rule in kernel
    :param new_metric:      The new metric to be set for the route.
    :param netplan_apply:   If True the 'netplan apply' command will be run after
                            the update. Take a caution: netplan apply might cancel
                            the metric update by restoring original configuration!

    :returns: True on success, False on failure.
    """
    success, err_str = add_remove_route(route.prefix, route.via, route.metric, True, dev_id=route.dev_id, dev=route.dev, proto=route.proto, netplan_apply=netplan_apply)
    if not success:
        fwglobals.log.error(f"update_route_metric({str(route)}): failed to remove route: {err_str}")
        return False
    success, err_str = add_remove_route(route.prefix, route.via, new_metric, False, dev_id=route.dev_id, dev=route.dev, proto=route.proto, netplan_apply=netplan_apply)
    if not success:
        fwglobals.log.error(f"update_route_metric({str(route)}): failed to add route with new metric: {err_str}")
        return False
    return True
