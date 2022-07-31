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

import enum
import json
import os
import re
import subprocess
import threading
import time
import traceback

from netaddr import IPAddress, IPNetwork

import fw_vpp_coredump_utils
import fwglobals
import fwlte
import fwnetplan
import fwpppoe
import fwrouter_cfg
import fwroutes
import fwthread
import fwtunnel_stats
import fwutils
import fwwifi
from fwcfg_request_handler import FwCfgRequestHandler
from fwfrr import FwFrr
from fwikev2 import FwIKEv2
from fwmultilink import FwMultilink
from fwpolicies import FwPolicies
from vpp_api import VPP_API

fwrouter_translators = {
    'start-router':             {'module': __import__('fwtranslate_start_router'),    'api':'start_router'},
    'stop-router':              {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'add-interface':            {'module': __import__('fwtranslate_add_interface'),   'api':'add_interface'},
    'remove-interface':         {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'modify-interface':         {'module': __import__('fwtranslate_add_interface'),   'api':None,                'ignored_params': 'modify_interface_ignored_params'},
    'add-route':                {'module': __import__('fwtranslate_add_route'),       'api':'add_route'},
    'remove-route':             {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'add-tunnel':               {'module': __import__('fwtranslate_add_tunnel'),      'api':'add_tunnel'},
    'remove-tunnel':            {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'modify-tunnel':            {'module': __import__('fwtranslate_add_tunnel'),      'api':'modify_tunnel',     'supported_params':'modify_tunnel_supported_params'},
    'add-dhcp-config':          {'module': __import__('fwtranslate_add_dhcp_config'), 'api':'add_dhcp_config'},
    'remove-dhcp-config':       {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'add-application':          {'module': __import__('fwtranslate_add_application'), 'api':'add_application'},
    'remove-application':       {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'add-multilink-policy':     {'module': __import__('fwtranslate_add_multilink_policy'), 'api':'add_multilink_policy'},
    'remove-multilink-policy':  {'module': __import__('fwtranslate_revert'),          'api':'revert'},
    'add-switch':               {'module': __import__('fwtranslate_add_switch'),      'api':'add_switch'},
    'remove-switch':            {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'add-firewall-policy':      {'module': __import__('fwtranslate_add_firewall_policy'), 'api':'add_firewall_policy'},
    'remove-firewall-policy':   {'module': __import__('fwtranslate_revert'),          'api':'revert'},
    'add-ospf':                 {'module': __import__('fwtranslate_add_ospf'),        'api':'add_ospf'},
    'remove-ospf':              {'module': __import__('fwtranslate_revert'),          'api':'revert'},
    'add-routing-bgp':          {'module': __import__('fwtranslate_add_routing_bgp'),  'api':'add_routing_bgp'},
    'remove-routing-bgp':       {'module': __import__('fwtranslate_revert'),          'api':'revert'},
    'modify-routing-bgp':       {'module': __import__('fwtranslate_add_routing_bgp'),  'api':'modify_routing_bgp',     'supported_params':'modify_routing_bgp_supported_params'},
    'add-routing-filter':       {'module': __import__('fwtranslate_add_routing_filter'), 'api':'add_routing_filter'},
    'remove-routing-filter':    {'module': __import__('fwtranslate_revert'),           'api':'revert'},
}

class FwRouterState(enum.Enum):
    STARTING  = 1
    STARTED   = 2
    STOPPING  = 3
    STOPPED   = 4
    FAILED    = 666

class FWROUTER_API(FwCfgRequestHandler):
    """This is Router API class representation.
    The Router API class provides control over vpp.
    That includes:
    - start and stop vpp functionality
    - wrappers for vpp configuration APIs
    - collecting statistics about vpp activity
    - monitoring vpp and restart it on exceptions
    - restoring vpp configuration on vpp restart or on device reboot

    :param cfg: instance of the FwRouterCfg object that hold router configuration items,
                like interfaces, tunnels, routes, etc.
    :param pending_cfg_file:  name of file that stores pending configuration items.
                Pending items are configuration items, that were requested by user,
                and that can't be configured at the moment. E.g., tunnel that uses
                WAN interface without IP.
    :param multilink_db_file: name of file that stores persistent multilink data
    """
    def __init__(self, cfg, pending_cfg_file, multilink_db_file, frr_db_file):
        """Constructor method
        """
        self.vpp_api         = VPP_API()
        self.multilink       = FwMultilink(multilink_db_file)
        self.frr             = FwFrr(frr_db_file)
        self.router_state    = FwRouterState.STOPPED
        self.thread_watchdog     = None
        self.thread_tunnel_stats = None
        self.thread_monitor_interfaces = None
        self.vpp_coredump_in_progress = False
        self.monitor_interfaces  = {}  # Interfaces that are monitored for IP changes

        pending_cfg_db = fwrouter_cfg.FwRouterCfg(pending_cfg_file)
        FwCfgRequestHandler.__init__(self, fwrouter_translators, cfg, pending_cfg_db, self._on_revert_failed)

        fwutils.reset_router_api_db() # Initialize cache that persists device reboot / daemon restart


    def finalize(self):
        """Destructor method
        """
        self._stop_threads()  # IMPORTANT! Do that before rest of finalizations!
        self.vpp_api.finalize()

    def vpp_watchdog_thread_func(self, ticks):
        """Watchdog thread function.
        Its function is to monitor if VPP process is alive.
        Otherwise it will start VPP and restore configuration from DB.
        """
        if not self.state_is_started():
            return
        if not fwutils.vpp_does_run():      # This 'if' prevents debug print by restore_vpp_if_needed() every second
            self.log.debug("watchdog: initiate restore")

            self.state_change(FwRouterState.STOPPED)    # Reset state ASAP, so:
                                                        # 1. Monitoring Threads will suspend activity
                                                        # 2. Configuration will be applied correctly by _restore_vpp()

            self.vpp_api.disconnect_from_vpp()          # Reset connection to vpp to force connection renewal
            fwutils.stop_vpp()                          # Release interfaces to Linux

            fwutils.reset_traffic_control()             # Release LTE operations.
            fwutils.remove_linux_bridges()              # Release bridges for wifi.
            fwwifi.stop_hostapd()                      # Stop access point service

            self._restore_vpp()                         # Rerun VPP and apply configuration

            self.log.debug("watchdog: restore finished")
            # Process if any VPP coredump
            self.vpp_coredump_in_progress = fw_vpp_coredump_utils.vpp_coredump_process()
        elif self.vpp_coredump_in_progress:
            self.vpp_coredump_in_progress = fw_vpp_coredump_utils.vpp_coredump_process()

    def tunnel_stats_thread_func(self, ticks):
        """Tunnel statistics thread function.
        Its function is to monitor tunnel state and RTT.
        It is implemented by pinging the other end of the tunnel.
        """
        if self.state_is_started():
            fwtunnel_stats.tunnel_stats_test()

    def monitor_interfaces_thread_func(self, ticks):
        """Monitors VPP interfaces for various dynamic data like DHCP IP addresses,
        link status (carrier-on/no-carrier) and other and adjust system with
        the change. See more details in the specific _sync_X() function.
        """
        if not self.state_is_started():
            return

        if ticks % 3 != 0:  # Check interfaces every ~3 seconds
            return

        try:
            self._sync_link_status()
        except Exception as e:
            self.thread_monitor_interfaces.log_error(
                f"_sync_link_status: {str(e)} ({traceback.format_exc()})")
        try:
            old = self.monitor_interfaces
            new = self._get_monitor_interfaces(cached=False)
            self._sync_addresses(old, new)
        except Exception as e:
            self.thread_monitor_interfaces.log_error(
                f"_sync_interfaces: {str(e)} ({traceback.format_exc()})")


    def _sync_link_status(self):
        '''Monitors link status (CARRIER-UP / NO-CARRIER or CABLE PLUGGED / CABLE UNPLUGGED)
        of the VPP physical interfaces and updates the correspondent tap inject
        interfaces in Linux using the "echo 0/1 > /sys/class/net/vppX/carrier" command,
            We need this logic, as Linux vppX interfaces are not physical interfaces,
        so it is not possible to set the NO-CARRIER link status flag for them.
        As a result, the Linux might continue to use unplugged interface, thus loosing traffic.
        Note, VPP does detects the NO-CARRIER and removes interface from FIB:

            root@vbox-test-171 ~ # ip r
            default via 10.72.100.1 dev vpp2 proto dhcp src 10.72.100.172 metric 50
            default via 192.168.1.1 dev vpp0 proto dhcp src 192.168.1.171 metric 100
            10.10.10.0/24 dev vpp1 proto kernel scope link src 10.10.10.10

            0@0.0.0.0/0
            unicast-ip4-chain
            [@0]: dpo-load-balance: [proto:ip4 index:1 buckets:1 uRPF:16 to:[0:0]]
                [0] [@5]: ipv4 via 192.168.1.1 GigabitEthernet0/3/0: mtu:1500 next:3 00b8c2
            8a6baa08002730db130800

            GigabitEthernet0/9/0               3     up   GigabitEthernet0/9/0
            Link speed: 1 Gbps
            Ethernet address 08:00:27:eb:00:63
            Intel 82540EM (e1000)
                no-carrier full duplex mtu 9206
        '''
        interfaces = fwglobals.g.router_cfg.get_interfaces()
        for interface in interfaces:
            tap_name    = fwutils.dev_id_to_tap(interface['dev_id'])
            if fwpppoe.is_pppoe_interface(dev_id=interface['dev_id']):
                status_vpp  = fwutils.get_interface_link_state(tap_name, interface['dev_id'])
            elif fwlte.is_lte_interface_by_dev_id(dev_id=interface['dev_id']):
                connected = fwlte.mbim_is_connected(interface['dev_id'])
                status_vpp = 'up' if connected else 'down'
            else:
                sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(interface['dev_id'], verbose=False)
                status_vpp  = fwutils.vpp_get_interface_status(sw_if_index)['link']
            (ok, status_linux) = fwutils.exec(f"cat /sys/class/net/{tap_name}/carrier")
            if status_vpp == 'down' and ok and status_linux and int(status_linux)==1:
                self.log.debug(f"detected NO-CARRIER for {tap_name}")
                fwutils.os_system(f"echo 0 > /sys/class/net/{tap_name}/carrier")
            elif status_vpp == 'up' and ok and status_linux and int(status_linux)==0:
                self.log.debug(f"detected CARRIER UP for {tap_name}")
                fwutils.os_system(f"echo 1 > /sys/class/net/{tap_name}/carrier")

    def _sync_addresses(self, old_interfaces, new_interfaces):
        """Monitors VPP interfaces for IP/GW change and updates system as follows:

        - on IP/GW change on WAN interface:
            1. update multi-link policy DIA links with proper GW, so the link
               reachability could be detected properly
            2. update ARP entry for the LTE GW to be black hole

        - on IP/GW change on LAN interface:
            1. update FRR with new local network

        :param old_interfaces: the last interface snap
        :param new_interfaces: the current interface snap
        """
        for dev_id, new in new_interfaces.items():
            old = old_interfaces.get(dev_id)
            if not old:
                continue   # escape newly added interface, take care of it on next sync

            if old['gw'] != new['gw']:
                if new['type'] == 'wan':
                    # Update FWABF link with new GW, it is used for multilink policies
                    #
                    link = self.multilink.get_link(dev_id)
                    if link:
                        self.multilink.vpp_update_labels(
                            remove=False, labels=link.labels, next_hop=new['gw'], dev_id=dev_id)

                    # Update ARP entry of LTE interface
                    try:
                        if new['deviceType'] == 'lte':
                            fwlte.set_arp_entry(is_add=False, dev_id=dev_id, gw=old['gw'])
                            fwlte.set_arp_entry(is_add=True,  dev_id=dev_id, gw=new['gw'])
                    except:
                        pass

            if old['addr'] != new['addr']:
                if new['type'] == 'lan' and 'OSPF' in new['routing']:
                    self.frr.ospf_network_update(dev_id, new['addr'])

    def _get_monitor_interfaces(self, cached=True):
        '''Retrieves interfaces from the configuration database, fetches their
        current IP, GW and other data from Linux and returns this information
        back to the caller in form of dictionary by dev-id.

        :param cached: if True, the cached data is returned, otherwise the cache
                       is rebuilt and the result is returned.

        :return: dictionary <dev-id> -> <interface name, IP/mask, GW, LAN/WAN, DPDK/LTE/WIFI, etc>
        '''
        if not cached:
            self._clear_monitor_interfaces()
        if not self.monitor_interfaces:
            for interface in fwglobals.g.router_cfg.get_interfaces():
                dev_id  = interface['dev_id']
                if_name = fwutils.dev_id_to_tap(dev_id)
                cached_interface = {}
                cached_interface['if_name'] = if_name
                cached_interface['addr']        = fwutils.get_interface_address(if_name, log=False)
                cached_interface['gw']          = fwutils.get_interface_gateway(if_name)[0]
                cached_interface['dhcp']        = interface.get('dhcp', 'no').lower()           # yes/no
                cached_interface['type']        = interface.get('type', 'wan').lower()          # LAN/WAN
                cached_interface['deviceType']  = interface.get('deviceType', 'dpdk').lower()   # DPDK/WIFI/LTE
                cached_interface['routing']     = interface.get('routing', [])                  # ["OSPF","BGP"]
                self.monitor_interfaces[dev_id] = cached_interface
        return self.monitor_interfaces

    def _clear_monitor_interfaces(self):
        self.monitor_interfaces = {}

    def restore_vpp_if_needed(self):
        """Restore VPP.
        If vpp doesn't run because of crash or device reboot,
        and it was started by management, start vpp and restore it's configuration.
        We do that by simulating 'start-router' request.
        Restore router state always to support multiple instances of Fwagent.

        :returns: `False` if no restore was performed, `True` otherwise.
        """

        # Restore failure state if recorded on disk:
        if os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
            self.state_change(FwRouterState.FAILED, 'recorded failure was restored')
            self.log.excep("router is in failed state, try to start it from flexiManage \
                or use 'fwagent reset [--soft]' to recover")

        # If vpp runs already, or if management didn't request to start it, return.
        vpp_runs = fwutils.vpp_does_run()
        vpp_should_be_started = self.cfg_db.exists({'message': 'start-router'})
        if vpp_runs or not vpp_should_be_started:
            self.log.debug("restore_vpp_if_needed: no need to restore(vpp_runs=%s, vpp_should_be_started=%s)" %
                (str(vpp_runs), str(vpp_should_be_started)))
            if vpp_runs:
                self.state_change(FwRouterState.STARTED)
            if self.state_is_started():
                self.log.debug("restore_vpp_if_needed: vpp_pid=%s" % str(fwutils.vpp_pid()))
                self._start_threads()
                # We use here read_from_disk because we can't fill the netplan cache from scratch when vpp is running.
                # We use the original interface names in this cache,
                # but they don't exist when they are under dpdk control and replaced by vppsb interfaces.
                # Hence, we fill the cache with the backup in the disk
                fwnetplan.load_netplan_filenames(read_from_disk=vpp_runs)
            else:
                fwnetplan.restore_linux_netplan_files()
            return False

        self._restore_vpp()
        return True

    def _restore_vpp(self):
        self.log.info("===restore vpp: started===")
        try:
            with FwFrr(fwglobals.g.FRR_DB_FILE) as db_frr:
                db_frr.clean()
            with FwMultilink(fwglobals.g.MULTILINK_DB_FILE) as db_multilink:
                db_multilink.clean()
            with FwPolicies(fwglobals.g.POLICY_REC_DB_FILE) as db_policies:
                db_policies.clean()
            fwglobals.g.cache.dev_id_to_vpp_tap_name.clear()

            # Reboot might cause change of lte modem wan address,
            # so it will not match the netplan file that was before reboot.
            # That might cause contamination of vpp fib with wrong routes
            # during start-router execution. To avoid that we restore original
            # Linux netplan files to remove any lte related information.
            #
            fwnetplan.restore_linux_netplan_files()

            # Reset cache of interfaces for address monitoring.
            # This is needed, when VPP is restored by watchdog on VPP crash.
            # In that case the cache becomes to be stale.
            #
            self._clear_monitor_interfaces()

            fwglobals.g.handle_request({'message': 'start-router'})
        except Exception as e:
            self.log.excep("restore_vpp_if_needed: %s" % str(e))
            self.state_change(FwRouterState.FAILED, "failed to restore vpp configuration")
        self.log.info("====restore vpp: finished===")

    def start_router(self):
        """Execute start router command.
        """
        self.log.info("start_router")
        if self.router_state == FwRouterState.STOPPED or self.router_state == FwRouterState.STOPPING:
            fwglobals.g.handle_request({'message': 'start-router'})
        self.log.info("start_router: started")

    def stop_router(self):
        """Execute stop router command.
        """
        self.log.info("stop_router")
        if self.router_state == FwRouterState.STARTED or self.router_state == FwRouterState.STARTING:
            fwglobals.g.handle_request({'message':'stop-router'})
        self.log.info("stop_router: stopped")

    def state_change(self, new_state, reason=''):
        log_reason = '' if not reason else ' (%s)' % reason
        self.log.debug("%s -> %s%s" % (str(self.router_state), str(new_state), log_reason))
        if self.router_state == new_state:
            return
        old_state = self.router_state
        self.router_state = new_state

        # On failure record the failure reason into file and kill vpp.
        # The file is used to persist reboot and to update flexiManage of
        # the router state.
        # On un-failure delete the file.
        #
        if new_state == FwRouterState.FAILED:
            if not os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
                with open(fwglobals.g.ROUTER_STATE_FILE, 'w') as f:
                    if fwutils.valid_message_string(reason):
                        fwutils.file_write_and_flush(f, reason + '\n')
                    else:
                        self.log.excep("Not valid router failure reason string: '%s'" % reason)
            fwutils.stop_vpp()
        elif old_state == FwRouterState.FAILED:
            if os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
                os.remove(fwglobals.g.ROUTER_STATE_FILE)

    def state_is_started(self):
        return (self.router_state == FwRouterState.STARTED)

    def state_is_stopped(self):
        return (self.router_state == FwRouterState.STOPPED)

    def state_is_starting_stopping(self):
        return (self.router_state == FwRouterState.STARTING or \
                self.router_state == FwRouterState.STOPPING)

    def call(self, request, dont_revert_on_failure=False):
        """Executes router configuration request: 'add-X','remove-X' or 'modify-X'.

        :param request: The request received from flexiManage.

        :returns: dictionary with status code and optional error message.
        """
        prev_logger = self.set_request_logger(request)   # Use request specific logger (this is to offload heavy 'add-application' logging)
        try:

            # First of all strip out requests that have no impact on configuration,
            # like 'remove-X' for not existing configuration items and 'add-X' for
            # existing configuration items.
            #
            new_request = self._strip_noop_request(request)
            if not new_request:
                self.log.debug("call: ignore no-op request: %s" % json.dumps(request))
                self.set_logger(prev_logger)  # Restore logger if was changed
                return { 'ok': 1, 'message':'request has no impact' }
            request = new_request

            # Now find out if:
            # 1. VPP should be restarted as a result of request execution.
            #    It should be restarted on addition/removal interfaces in order
            #    to capture new interface /release old interface back to Linux.
            # 2. Agent should reconnect proactively to flexiManage.
            #    It should reconnect on add-/remove-/modify-interface, as they might
            #    impact on connection under the connection legs. So it might take
            #    a time for connection to detect the change, to report error and to
            #    reconnect again by the agent infinite connection loop with random
            #    sleep between retrials.
            # 3. Gateway of WAN interfaces are going to be modified.
            #    In this case we have to ping the GW-s after modification.
            #    See explanations on that workaround later in this function.
            #
            (restart_router, reconnect_agent, gateways, restart_dhcp_service) = self._analyze_request(request)

            # Some requests require preprocessing.
            # For example before handling 'add-application' the currently configured
            # applications should be removed. The simplest way to do that is just
            # to simulate 'remove-application' receiving. Hence need in preprocessing.
            # The preprocessing adds the simulated 'remove-application' request to the
            # the real received 'add-application' forming thus new aggregation request.
            #
            request = self._preprocess_request(request)

            # Stop vpp if it should be restarted.
            #
            if restart_router:
                fwglobals.g.router_api._call_simple({'message':'stop-router'})

            # Finally handle the request
            #

            reply = FwCfgRequestHandler.call(self, request, dont_revert_on_failure)

            # Start vpp if it should be restarted
            #
            if restart_router:
                fwglobals.g.router_api._call_simple({'message':'start-router'})

            # Restart DHCP service if needed
            #
            if restart_dhcp_service:
                if not restart_router: # on router restart DHCP service is restarted as well
                    cmd = 'systemctl restart isc-dhcp-server'
                    fwutils.os_system(cmd, 'call')

            # Reconnect agent if needed
            #
            if reconnect_agent:
                fwglobals.g.fwagent.reconnect()


            ########################################################################
            # Workaround for following problem:
            # Today 'modify-interface' request is replaced by pair of correspondent
            # 'remove-interface' and 'add-interface' requests. if 'modify-interface'
            # request changes IP or GW of WAN interface, the correspondent
            # 'remove-interface' removes GW from the Linux neighbor table, but the
            # consequent 'add-interface' does not add it back.
            # As a result the VPP FIB is stuck with DROP rule for that interface,
            # and traffic on that interface is dropped.
            # The workaround below enforces Linux to update the neighbor table with
            # the latest GW-s. That causes VPPSB to propagate the ARP information
            # into VPP FIB.
            # Note we do this even if 'modify-interface' failed, as before failure
            # it might succeed to remove few interfaces from Linux.
            ########################################################################
            if gateways:
                # Delay 5 seconds to make sure Linux interfaces were initialized
                time.sleep(5)
                for gw in gateways:
                    try:
                        cmd = 'ping -c 3 %s' % gw
                        output = subprocess.check_output(cmd, shell=True).decode()
                        self.log.debug("call: %s: %s" % (cmd, output))
                    except Exception as e:
                        self.log.debug("call: %s: %s" % (cmd, str(e)))

        except Exception as e:
            self.set_logger(prev_logger)  # Restore logger if was changed
            raise e

        self.set_logger(prev_logger)  # Restore logger if was changed
        return reply

    def _call_simple(self, request, execute=False, filter=None):
        """Execute single request.

        :param request: The request received from flexiManage.

        :returns: dictionary with status code and optional error message.
        """
        try:
            req = request['message']

            router_was_started = fwutils.vpp_does_run()

            # The 'add-application' and 'add-multilink-policy' requests should
            # be translated and executed only if VPP runs, as the translations
            # depends on VPP API-s output. Therefore if VPP does not run,
            # just save the requests in database and return.
            #
            if router_was_started == False and \
                (req == 'add-application' or
                req == 'add-multilink-policy' or
                req == 'add-firewall-policy'):
                self.cfg_db.update(request)
                return {'ok':1}

            # Take care of pending requests.
            # Pending requests are requests that were received from flexiManage,
            # but can't be configured in VPP/Linux right now due to some issue,
            # like absence of IP/GW on interface.
            # As pending request can't be configured at the moment, just save it
            # into the dedicated database and return. No further processing is
            # needed. It is flexiManage responsibility to recreate pending tunnels,
            # routes, etc. The flexiManage detects no-IP/chenaged-IP condition,
            # using the "reconfig" feature and removes or reconstructs pending
            # configuration items.
            #   The 'remove-X' for pending requests just deletes request from
            # the pending request database.
            #
            if self.pending_cfg_db.exists(request):
                # Clean request from pending database before further processing.
                #
                self.pending_cfg_db.remove(request)
                if re.match('remove-',  req):
                    return {'ok':1}     # No further processing is needed for 'remove-X'.
            if router_was_started and self.state_is_starting_stopping(): # For now enable pending requests on start-router only
                if re.match('add-',  req) and self._is_pending_request(request):
                    self.pending_cfg_db.update(request)
                    self.cfg_db.remove(request)
                    return {'ok':1}

            if router_was_started or req == 'start-router':
                execute = True
            elif re.match('remove-',  req):
                filter = 'must'
                execute = True

            FwCfgRequestHandler._call_simple(self, request, execute, filter)

        except Exception as e:
            err_str = "FWROUTER_API::_call_simple: %s" % str(traceback.format_exc())
            self.log.error(err_str)
            if req == 'start-router':
                self.state_change(FwRouterState.FAILED, 'failed to start router')
            raise e

        return {'ok':1}


    def _is_pending_request(self, request):
        """Check if the request can not be configured in VPP/Linux right now.
        Following are cases where the request is considered to be pending:
        1. 'add-tunnel'
            a. If WAN interface used by the tunnel has no IP/GW, e.g. if DHCP
               interface got no response from DHCP server.
               We need the GW in multi-WAN setups in order to bind tunnel traffic
               to the proper WAN interface, and not to rely on default route.
        2. 'add-route'
            a. If route is via WAN interface specified by dev-id, and the device
               has no IP/GW, e.g. if DHCP interface got no response from DHCP server.
            b. If route is via pending tunnel (specified by loopback IP)
            c. If route is via interface specified by IP, and there is no
               successfully configured interface with IP in same network mask.
               That might happen for either WAN or LAN interfaces that has no IP.

        :param request: the request to be checked.

        :returns: True if request can't be fulfilled right now, becoming thus
                  to be pending request. False otherwise.
        """
        if request['message'] != "add-tunnel" and \
           request['message'] != "add-route":
            return False

        monitor_interfaces = self._get_monitor_interfaces()

        if request['message'] == "add-tunnel":
            interface = monitor_interfaces.get(request['params']['dev_id'])
            if not interface or not interface['addr']:
                self.log.debug(f"pending request detected: {str(request)}")
                self.pending_dev_ids.add(request['params']['dev_id'])
                return True
            return False

        if request['message'] == "add-route":
            # If 'add-route' includes 'dev_id' - we are good - use it, otherwise
            # use 'via' and search interfaces and tunnel loopbacks that match it.
            #
            # {
            #     "entity": "agent",
            #     "message": "add-route",
            #     "params": {
            #         "addr": "11.11.11.11/32",
            #         "via": "192.168.1.1",
            #         "redistributeViaOSPF": false,
            #         "dev_id": "pci:0000:00:03.00"
            #     }
            # }
            #
            if 'dev_id' in request['params']:
                # Check assigned interfaces
                #
                interface =  monitor_interfaces.get(request['params']['dev_id'])
                if interface:
                    if not interface['addr']:
                        self.log.debug(f"pending request detected by dev-id: {str(request)}")
                        self.pending_dev_ids.add(request['params']['dev_id'])
                        return True
                    return False
                # Check unassigned interfaces
                #
                if_name = fwutils.get_interface_name(request['params']['via'], by_subnet=True)
                if if_name:
                    return False
                return True
            else:
                # Firstly search for interfaces that match VIA
                #
                for interface in monitor_interfaces.values():
                    if interface['addr'] and \
                       fwutils.is_ip_in_subnet(request['params']['via'], interface['addr']):
                        return False
                # No suiting interface was found, search tunnels that match VIA
                #
                for tunnel in fwglobals.g.router_cfg.get_tunnels():
                    # Try regular tunnel firstly
                    #
                    network = tunnel.get('loopback-iface', {}).get('addr')
                    if not network:
                        network = tunnel.get('peer', {}).get('addr')  # Try peer tunnel
                    if network and fwutils.is_ip_in_subnet(request['params']['via'], network):
                        return False

                # Search for unassigned interfaces that match VIA
                #
                if_name = fwutils.get_interface_name(request['params']['via'], by_subnet=True)
                if if_name:
                    return False

                self.log.debug(f"pending request detected: {str(request)}")
                return True

        return False


    def _on_revert_failed(self, reason):
        self.state_change(FwRouterState.FAILED, "revert failed: %s" % reason)

    def _analyze_request(self, request):
        """Analyzes received request either simple or aggregated in order to
        deduce if some special actions, like router restart, are needed as a
        result or request handling. The collected information is returned back
        to caller in form of booleans. See more details in description of return
        value.

        :param request: The request received from flexiManage.

        :returns: tuple of flags as follows:
            restart_router - VPP should be restarted as 'add-interface' or
                        'remove-interface' was detected in request.
                        These operations require vpp restart as vpp should
                        capture or should release interfaces back to Linux.
            reconnect_agent - Agent should reconnect proactively to flexiManage
                        as add-/remove-/modify-interface was detected in request.
                        These operations might cause connection failure on TCP
                        timeout, which might take up to few minutes to detect!
                        As well the connection retrials are performed with some
                        interval. To short no connectivity periods we close and
                        retries the connection proactively.
            gateways - List of gateways to be pinged after request handling
                        in order to solve following problem:
                        today 'modify-interface' request is replaced by pair of
                        correspondent 'remove-interface' and 'add-interface'
                        requests. The 'remove-interface' removes GW from the
                        Linux neighbor table, but the consequent 'add-interface'
                        request does not add it back. As a result the VPP FIB is
                        stuck with DROP rule for that interface, and traffic
                        which is outgoing on that interface is dropped.
                        So we ping the gateways to enforces Linux to update the
                        neighbor table. That causes VPPSB to propagate the ARP
                        information into VPP FIB.
            restart_dhcp_service - DHCP service should be restarted if modify-interface
                        was received. This is because modify-interface is implemented
                        today by pair of 'remove-interface' and 'add-interface'
                        requests which removes interface from VPP/Linux (see usage of
                        "vppctl delete tap") and recreates it back.
                        That causes DHCP service to stop monitoring of the recreated interface.
                        Therefor we have to restart it on modify-interface completion.
        """

        def _should_reconnect_agent_on_modify_interface(old_params, new_params):
            if new_params.get('addr') and new_params.get('addr') != old_params.get('addr'):
                return True
            if new_params.get('gateway') != old_params.get('gateway'):
                return True
            if new_params.get('metric') != old_params.get('metric'):
                return True
            return False


        (restart_router, reconnect_agent, gateways, restart_dhcp_service) = \
        (False,          False,           [],       False)

        if re.match('(add|remove)-interface', request['message']):
            if self.state_is_started():
                restart_router  = True
                reconnect_agent = True
            return (restart_router, reconnect_agent, gateways, restart_dhcp_service)
        elif re.match('(start|stop)-router', request['message']):
            reconnect_agent = True
            return (restart_router, reconnect_agent, gateways, restart_dhcp_service)
        elif request['message'] != 'aggregated':
            return (restart_router, reconnect_agent, gateways, restart_dhcp_service)
        else:   # aggregated request
            add_remove_requests = {}
            modify_requests = {}
            for _request in request['params']['requests']:
                if re.match('(start|stop)-router', _request['message']):
                    reconnect_agent = True
                elif re.match('(add|remove)-interface', _request['message']):
                    dev_id = _request['params']['dev_id']
                    if not dev_id in add_remove_requests:
                        add_remove_requests[dev_id] = _request
                    else:
                        # This add/remove complements pair created for modify-X

                        # Fetch gateway from the add-interface
                        #
                        gw = add_remove_requests[dev_id]['params'].get('gateway')
                        if not gw:
                            gw = _request['params'].get('gateway')
                        if gw:
                            gateways.append(gw)

                        # If the interface to be modified is used by the WebSocket
                        # connection, we have to reconnect the agent.
                        # We use following heuristic to determine, if the interface
                        # is used for the WebSocket connection: we assume that
                        # there is no static route for the flexiManage address,
                        # so the connection uses the default route.
                        # Hence, if the default route with the lowest metric
                        # uses the interface, we should reconnect.
                        if not reconnect_agent:
                            (_, _, default_route_dev_id, _) = fwutils.get_default_route()
                            if dev_id == default_route_dev_id:
                                reconnect_agent = True

                        # If the interface to be modified might become the interface
                        # for default route due to IP/metric/GW modification,
                        # we have to reconnect agent too.
                        #
                        if not reconnect_agent:
                            if (_request['message'] == 'add-interface'):
                                new_params = _request['params']
                                old_params = add_remove_requests[dev_id]['params']
                            else:
                                old_params = _request['params']
                                new_params = add_remove_requests[dev_id]['params']
                            if _should_reconnect_agent_on_modify_interface(old_params, new_params):
                                reconnect_agent = True

                        # Move the request to the set of modify-interface-s
                        #
                        del add_remove_requests[dev_id]
                        modify_requests[dev_id] = _request

            if add_remove_requests and self.state_is_started():
                restart_router = True
                reconnect_agent = True
            if modify_requests and self.state_is_started():
                restart_dhcp_service = True
            return (restart_router, reconnect_agent, gateways, restart_dhcp_service)

    def _preprocess_request(self, request):
        """Some requests require preprocessing. For example before handling
        'add-application' the currently configured applications should be removed.
        The simplest way to do that is just to simulate 'remove-application'
        receiving: before the 'add-application' is processed we have
        to process the simulated 'remove-application' request.
        To do that we just create the new aggregated request and put the simulated
        'remove-application' request and the original 'add-application' request
        into it.
            Note the main benefit of this approach is automatic revert of
        the simulated requests if the original request fails.

        :param request: The original request received from flexiManage

        :returns: request - The new aggregated request and it's parameters.
                        Note the parameters are list of requests that might be
                        a mix of simulated requests and original requests.
                        This mix should include one original request and one or
                        more simulated requests.
        """
        req     = request['message']
        params  = request.get('params')
        changes = {}

        # For aggregated request go over all remove-X requests and replace their
        # parameters with current configuration for X stored in database.
        # The remove-* request might have partial set of parameters only.
        # For example, 'remove-interface' has 'dev_id' parameter only and
        # has no IP, LAN/WAN type, etc.
        # That makes it impossible to revert these partial remove-X requests
        # on aggregated message rollback that might happen due to failure in
        # in one of the subsequent  requests in the aggregation list.
        #
        if req == 'aggregated':
            for _request in params['requests']:
                if re.match('remove-', _request['message']):
                    _request['params'] = self.cfg_db.get_request_params(_request)

        ########################################################################
        # The code below preprocesses 'add-application' and 'add-multilink-policy'
        # requests. This preprocessing just adds 'remove-application' and
        # 'remove-multilink-policy' requests to clean vpp before original
        # request. This should happen only if vpp was started and
        # initial configuration was applied to it during start. If that is not
        # the case, there is nothing to remove yet, so removal will fail.
        ########################################################################
        if self.state_is_stopped():
            if changes.get('insert'):
                self.log.debug("_preprocess_request: Simple request was \
                        replaced with %s" % json.dumps(request))
            return request

        multilink_policy_params = self.cfg_db.get_multilink_policy()
        firewall_policy_params = self.cfg_db.get_firewall_policy()

        # 'add-application' preprocessing:
        # 1. The currently configured applications should be removed firstly.
        #    We do that by adding simulated 'remove-application' request in
        #    front of the original 'add-application' request.
        # 2. The multilink policy should be re-installed: if exists, the policy
        #    should be removed before application removal/adding and should be
        #    added again after it.
        #
        application_params = self.cfg_db.get_applications()
        if application_params:
            if req == 'add-application':
                pre_requests = [ { 'message': 'remove-application', 'params' : application_params } ]
                process_requests = [ { 'message': 'add-application', 'params' : params } ]
                if multilink_policy_params:
                    pre_requests.insert(0, { 'message': 'remove-multilink-policy', 'params' : multilink_policy_params })
                    process_requests.append({ 'message': 'add-multilink-policy', 'params' : multilink_policy_params })
                if firewall_policy_params:
                    pre_requests.insert(0, { 'message': 'remove-firewall-policy', 'params' : firewall_policy_params })
                    process_requests.append({ 'message': 'add-firewall-policy', 'params' : firewall_policy_params })

                updated_requests = pre_requests + process_requests
                params = { 'requests' : updated_requests }
                request = {'message': 'aggregated', 'params': params}
                self.log.debug("_preprocess_request: Application request \
                        was replaced with %s" % json.dumps(request))
                return request

        # 'add-multilink-policy' preprocessing:
        # 1. The currently configured policy should be removed firstly.
        #    We do that by adding simulated 'remove-multilink-policy' request in
        #    front of the original 'add-multilink-policy' request.
        #
        if multilink_policy_params:
            if req == 'add-multilink-policy':
                updated_requests = [
                    { 'message': 'remove-multilink-policy', 'params' : multilink_policy_params },
                    { 'message': 'add-multilink-policy',    'params' : params }
                ]
                request = {'message': 'aggregated', 'params': { 'requests' : updated_requests }}
                self.log.debug("_preprocess_request: Multilink \
                        request was replaced with %s" % json.dumps(request))
                return request

        # Setup remove-firewall-policy before executing add-firewall-policy
        if firewall_policy_params:
            if req == 'add-firewall-policy':
                updated_requests = [
                    { 'message': 'remove-firewall-policy', 'params' : firewall_policy_params },
                    { 'message': 'add-firewall-policy',    'params' : params }
                ]
                request = {'message': 'aggregated', 'params': { 'requests' : updated_requests }}
                self.log.debug("_preprocess_request: Firewall request \
                        was replaced with %s" % json.dumps(request))
                return request

        # 'add/remove-application' preprocessing:
        # 1. The multilink policy should be re-installed: if exists, the policy
        #    should be removed before application removal/adding and should be
        #    added again after it.
        #
        if multilink_policy_params or firewall_policy_params:
            if re.match('(add|remove)-(application)', req):
                if multilink_policy_params and firewall_policy_params:
                    pre_add_requests = [
                        { 'message': 'remove-multilink-policy', 'params' : multilink_policy_params },
                        { 'message': 'remove-firewall-policy', 'params' : firewall_policy_params },
                    ]
                    post_add_requests = [
                        { 'message': 'add-multilink-policy', 'params' : multilink_policy_params },
                        { 'message': 'add-firewall-policy', 'params' : firewall_policy_params },
                    ]
                elif multilink_policy_params:
                    pre_add_requests = [
                        { 'message': 'remove-multilink-policy', 'params' : multilink_policy_params }
                    ]
                    post_add_requests = [
                        { 'message': 'add-multilink-policy', 'params' : multilink_policy_params }
                    ]
                else:
                    pre_add_requests = [
                        { 'message': 'remove-firewall-policy', 'params' : firewall_policy_params }
                    ]
                    post_add_requests = [
                        { 'message': 'add-firewall-policy', 'params' : firewall_policy_params },
                    ]
                params['requests'] = pre_add_requests
                params['requests'].append({ 'message': req, 'params' : params })
                params['requests'].extend(post_add_requests)
                request = {'message': 'aggregated', 'params': params}
                self.log.debug("_preprocess_request: Aggregated request \
                        with application config was replaced with %s" % json.dumps(request))
                return request

        ########################################################################
        # The code below preprocesses 'add-routing-bgp' request.
        # This preprocessing adds pair of 'remove-tunnel' and 'add-tunnel'
        # requests to make sure a tunnel with bgp routing protocol is configured
        # in frr after add-routing-bgp requests is applied.
        ########################################################################
        bgp_tunnels_params = self.cfg_db.get_tunnels(routing='bgp')
        for bgp_tunnel_params in bgp_tunnels_params:
            add_tunnel_req = { 'message': 'remove-tunnel', 'params' : bgp_tunnel_params }
            remove_tunnel_req = { 'message': 'add-tunnel', 'params' : bgp_tunnel_params }

            if req == 'aggregated':
                is_changed = False
                for _request in params['requests']:
                    if _request['message'] == 'add-routing-bgp':
                        params['requests'].append(add_tunnel_req)
                        params['requests'].append(remove_tunnel_req)
                        is_changed = True
                # don't print debug log for each tunnel to support large scale of tunnels.
                if is_changed:
                    self.log.debug("_preprocess_request: Tunnel requests was added to  \
                            the aggregated with BGP request %s" % json.dumps(request))
                    # don't 'return' here. We need to take care of the aggregated requests order
                    # Which is done next in the function

            if req == 'add-routing-bgp':
                updated_requests = [
                    { 'message': 'remove-tunnel', 'params' : bgp_tunnel_params },
                    request,
                    { 'message': 'add-tunnel', 'params' : bgp_tunnel_params }
                ]
                request = {'message': 'aggregated', 'params': { 'requests' : updated_requests }}
                self.log.debug("_preprocess_request: BGP request \
                        was replaced with aggregated %s" % json.dumps(request))
                return request


        # No preprocessing is needed for rest of simple requests, return.
        if req != 'aggregated':
            return request

        ########################################################################
        # Handle 'aggregated' request.
        # Perform same preprocessing for aggregated requests, either
        # original or created above.
        ########################################################################

        # Go over all requests and rearrange them, as order of requests is
        # important for proper configuration of VPP!
        # The list should start with the 'remove-X' requests in following order:
        #   [ 'add-firewall-policy', 'add-multilink-policy', 'add-application',
        #     'add-dhcp-config', 'add-route', 'add-tunnel', 'add-interface' ]
        # Than the 'add-X' requests should follow in opposite order:
        #   [ 'add-interface', 'add-tunnel', 'add-route', 'add-dhcp-config',
        #     'add-application', 'add-multilink-policy', 'add-firewall-policy' ]
        #
        add_order = [
            'add-ospf', 'add-routing-filter', 'add-routing-bgp', 'add-switch',
            'add-interface', 'add-tunnel', 'add-route', 'add-dhcp-config',
            'add-application', 'add-multilink-policy', 'add-firewall-policy',
        ]
        remove_order = [ re.sub('add-','remove-', name) for name in add_order ]
        remove_order.reverse()
        requests     = []
        for req_name in remove_order:
            for _request in params['requests']:
                if re.match(req_name, _request['message']):
                    requests.append(_request)
        for req_name in add_order:
            for _request in params['requests']:
                if re.match(req_name, _request['message']):
                    requests.append(_request)

        start_router_request = None
        stop_router_request = None
        # append modify-x after all remove-x and add-x
        for _request in params['requests']:
            if _request['message'] == 'start-router':
                start_router_request = _request
                continue
            elif _request['message'] == 'stop-router':
                stop_router_request = _request
                continue
            if re.match('modify-', _request['message']):
                requests.append(_request)

        # append start-router at the end
        if start_router_request:
            requests.append(start_router_request)

        # insert stop-router as the first request
        if stop_router_request:
            requests.insert(0, stop_router_request)

        if requests != params['requests']:
            params['requests'] = requests
        requests = params['requests']


        # We do few passes on requests to find insertion points if needed.
        # It is based on the first appearance of the preprocessor requests.
        #
        indexes = {
            'remove-switch'           : -1,
            'add-switch'              : -1,
            'remove-interface'        : -1,
            'add-interface'           : -1,
            'remove-application'      : -1,
            'add-application'         : -1,
            'remove-multilink-policy' : -1,
            'add-multilink-policy'    : -1,
            'remove-firewall-policy'  : -1,
            'add-firewall-policy'     : -1
        }

        reinstall_multilink_policy = True
        reinstall_firewall_policy = True

        for (idx , _request) in enumerate(requests):
            for req_name in indexes:
                if req_name == _request['message']:
                    if indexes[req_name] == -1:
                        indexes[req_name] = idx
                    if req_name == 'remove-multilink-policy':
                        reinstall_multilink_policy = False
                    if req_name == 'remove-firewall-policy':
                        reinstall_firewall_policy = False
                    break

        def _insert_request(requests, idx, req_name, params):
            requests.insert(idx, { 'message': req_name, 'params': params })
            # Update indexes
            indexes[req_name] = idx
            for name in indexes:
                if name != req_name and indexes[name] >= idx:
                    indexes[name] += 1
            changes['insert'] = True

        # Now preprocess 'add-application': insert 'remove-application' if:
        # - there are applications to be removed
        # - the 'add-application' was found in requests
        #
        if application_params and indexes['add-application'] > -1:
            if indexes['remove-application'] == -1:
                # If list has no 'remove-application' at all just add it before 'add-applications'.
                idx = indexes['add-application']
                _insert_request(requests, idx, 'remove-application', application_params)
            elif indexes['remove-application'] > indexes['add-application']:
                # If list has 'remove-application' after the 'add-applications',
                # it is not supported yet ;) Implement on demand
                raise Exception("_preprocess_request: 'remove-application' was found after 'add-application': NOT SUPPORTED")

        # Now preprocess 'add-multilink-policy': insert 'remove-multilink-policy' if:
        # - there are policies to be removed
        # - there are interfaces to be removed or to be added
        # - the 'add-multilink-policy' was found in requests
        #
        def add_corresponding_remove_policy_message(requests, indexes, request_name, params):
            if request_name == 'multilink':
                add_request_name = 'add-multilink-policy'
                remove_request_name = 'remove-multilink-policy'
            elif request_name == 'firewall':
                add_request_name = 'add-firewall-policy'
                remove_request_name = 'remove-firewall-policy'
            if params and indexes[add_request_name] > -1:
                if indexes[remove_request_name] == -1:
                    # If list has no 'remove-X-policy' at all just add it before 'add-X-policy'.
                    idx = indexes[add_request_name]
                    _insert_request(requests, idx, remove_request_name, params)
                    changes['insert'] = True
                elif indexes[remove_request_name] > indexes[add_request_name]:
                    # If list has 'remove-X-policy' after the 'add-X-policy',
                    # it is not supported yet ;) Implement on demand
                    raise Exception("_preprocess_request: 'remove-X-policy' was found after \
                            'add-X-policy': NOT SUPPORTED")
                self.log.debug("_add_corresponding_remove_policy_message: %s" % request_name)

        add_corresponding_remove_policy_message(requests, indexes, 'multilink',
                multilink_policy_params)

        add_corresponding_remove_policy_message(requests, indexes, 'firewall',
                firewall_policy_params)

        # Now preprocess 'add/remove-application' and 'add/remove-interface':
        # reinstall multilink policy if:
        # - any of 'add/remove-application', 'add/remove-interface' appears in request
        # - the original request does not have 'remove-multilink-policy'
        #
        if multilink_policy_params or firewall_policy_params:
            # Firstly find the right place to insert the 'remove-multilink-policy' - idx.
            # It should be the first appearance of one of the preprocessing requests.
            # As well find the right place to insert the 'add-multilink-policy' - idx_last.
            # It should be the last appearance of one of the preprocessing requests.
            #
            idx = 10000
            idx_last = -1
            for req_name in indexes:
                if indexes[req_name] > -1:
                    if indexes[req_name] < idx:
                        idx = indexes[req_name]
                    if indexes[req_name] > idx_last:
                        idx_last = indexes[req_name]
            if idx == 10000:
                # No requests to preprocess were found, return
                return request


            def update_policy_message_positions(requests, request_name, params,
                    indexes, max_idx, reinstall_needed):
                insert_count = 0
                if request_name == 'multilink':
                    add_request_name = 'add-multilink-policy'
                    remove_request_name = 'remove-multilink-policy'
                elif request_name == 'firewall':
                    add_request_name = 'add-firewall-policy'
                    remove_request_name = 'remove-firewall-policy'

                if indexes[remove_request_name] > idx:
                    # Move 'remove-X-policy' to the min position:
                    # insert it as the min position and delete the original 'remove-X-policy'.
                    idx_policy = indexes[remove_request_name]
                    _insert_request(requests, idx, remove_request_name, params)
                    del requests[idx_policy + 1]
                if indexes[add_request_name] > -1 and indexes[add_request_name] < max_idx:
                    # We exploit the fact that only one 'add-X-policy' is possible
                    # Move 'add-multilink-policy' to the idx_last+1 position to be after all other 'add-X':
                    # insert it at the idx_last position and delete the original 'add-multilink-policy'.
                    idx_policy = indexes[add_request_name]
                    _insert_request(requests, max_idx + 1, add_request_name, params)
                    del requests[idx_policy]
                if indexes[remove_request_name] == -1:
                    _insert_request(requests, idx, remove_request_name, params)
                    insert_count += 1
                    max_idx += 1
                if indexes[add_request_name] == -1 and reinstall_needed:
                    _insert_request(requests, max_idx + 1, add_request_name, params)
                    insert_count += 1
                return insert_count

            # Now add policy reinstallation if needed.
            if multilink_policy_params:
                idx_last +=update_policy_message_positions(requests, 'multilink',
                        multilink_policy_params, indexes, idx_last, reinstall_multilink_policy)

            if firewall_policy_params:
                update_policy_message_positions(requests, 'firewall', firewall_policy_params,
                        indexes, idx_last, reinstall_firewall_policy)

        if changes.get('insert'):
            self.log.debug("_preprocess_request: request was replaced with %s" % json.dumps(request))
        return request

    def _start_threads(self):
        """Start all threads.
        """
        if self.thread_watchdog is None or self.thread_watchdog.is_alive() == False:
            self.vpp_coredump_in_progress = True
            self.thread_watchdog = fwthread.FwRouterThread(self.vpp_watchdog_thread_func, 'VPP Watchdog', self.log)
            self.thread_watchdog.start()
        if self.thread_tunnel_stats is None or self.thread_tunnel_stats.is_alive() == False:
            fwtunnel_stats.fill_tunnel_stats_dict()
            self.thread_tunnel_stats = fwthread.FwRouterThread(self.tunnel_stats_thread_func, 'Tunnel Stats', self.log)
            self.thread_tunnel_stats.start()
        if self.thread_monitor_interfaces is None or self.thread_monitor_interfaces.is_alive() == False:
            self.thread_monitor_interfaces = fwthread.FwRouterThread(self.monitor_interfaces_thread_func, 'Interface Monitor', self.log)
            self.thread_monitor_interfaces.start()

    def _stop_threads(self):
        """Stop all threads.
        """
        if self.thread_watchdog:
            self.thread_watchdog.stop()
            self.thread_watchdog = None

        if self.thread_tunnel_stats:
            self.thread_tunnel_stats.stop()
            self.thread_tunnel_stats = None

        if self.thread_monitor_interfaces:
            self.thread_monitor_interfaces.stop()
            self.thread_monitor_interfaces = None

    def _on_start_router_before(self):
        """Handles pre start VPP activities.
        :returns: None.
        """
        self.state_change(FwRouterState.STARTING)

        # Clean VPP API trace from previous invocation (if exists)
        #
        os.system('sudo rm -rf /tmp/*%s' % fwglobals.g.VPP_TRACE_FILE_EXT)

        fwutils.frr_clean_files()

        fwutils.reset_router_api_db(enforce=True)

        fwnetplan.load_netplan_filenames()

        fwglobals.g.pppoe.stop(remove_tun=True)

        self.multilink.db['links'] = {}

        self.pending_dev_ids = set()


    def _sync_after_start(self):
        """Resets signature once interface got IP during router starting.
        :returns: None.
        """
        do_sync = False
        for dev_id in self.pending_dev_ids:
            if_name = fwutils.dev_id_to_tap(dev_id)
            addr = fwutils.get_interface_address(if_name, log=False)
            if addr:
                fwglobals.log.debug(f'Pending interface {dev_id} got ip {addr}')
                do_sync = True
                break

        if do_sync:
            fwutils.reset_device_config_signature("pending_interfaces_got_ip", log=False)

    def _on_start_router_after(self):
        """Handles post start VPP activities.
        :returns: None.
        """
        self.state_change(FwRouterState.STARTED)
        self._start_threads()
        fwutils.clear_linux_interfaces_cache()
        err = fwutils.frr_flush_config_into_file()
        if err:
            # We don't want to fail router start due to failure to save frr configuration file,
            # so we just log the error and return. Hopefully frr will not crash,
            # so the configuration file will be not needed.
            fwglobals.log.error(f"_on_start_router_after: failed to flush frr configuration into file: {str(err)}")

        if fwglobals.g.is_gcp_vm:
            # When we shutting down the interfaces on Linux before assigning them to VPP
            # the GCP agent is stopped. Hence, we need to restart it again.
            fwutils.restart_gcp_agent()

        fwglobals.g.pppoe.start()

        self._sync_after_start()

        # Build cache of interfaces for address monitoring.
        # Note if address was changed before we reach this point,
        # the `_sync_after_start()` above should handle the change.
        # It forces the flexiManage to send `sync-device` to us.
        #
        self._get_monitor_interfaces(cached=False)

        self.log.info("router was started: vpp_pid=%s" % str(fwutils.vpp_pid()))

        fwglobals.g.applications_api.call_hook('on_router_is_started')

    def _on_stop_router_before(self):
        """Handles pre-VPP stop activities.
        :returns: None.
        """
        self.state_change(FwRouterState.STOPPING)
        with FwIKEv2() as ike:
            ike.clean()
        self._stop_threads()
        fwglobals.g.pppoe.stop(remove_tun=True)
        fwglobals.g.cache.dev_id_to_vpp_tap_name.clear()
        self.log.info("router is being stopped: vpp_pid=%s" % str(fwutils.vpp_pid()))

        fwglobals.g.applications_api.call_hook('on_router_is_stopping')

    def _on_stop_router_after(self):
        """Handles post-VPP stop activities.
        :returns: None.
        """
        self.router_stopping = False
        fwutils.reset_traffic_control()
        fwutils.remove_linux_bridges()
        fwwifi.stop_hostapd()

        if fwglobals.g.is_gcp_vm: # Take care of Google Cloud Platform VM
            fwutils.restart_gcp_agent()

        # keep LTE connectivity on linux interface
        fwglobals.g.system_api.restore_configuration(types=['add-lte'])

        self.state_change(FwRouterState.STOPPED)
        fwglobals.g.cache.dev_id_to_vpp_tap_name.clear()
        fwglobals.g.cache.dev_id_to_vpp_if_name.clear()
        fwutils.clear_linux_interfaces_cache()
        self._clear_monitor_interfaces()

        with FwFrr(fwglobals.g.FRR_DB_FILE) as db_frr:
            db_frr.clean()
        with FwMultilink(fwglobals.g.MULTILINK_DB_FILE) as db_multilink:
            db_multilink.clean()
        with FwPolicies(fwglobals.g.POLICY_REC_DB_FILE) as db_policies:
            db_policies.clean()

        fwglobals.g.applications_api.call_hook('on_router_is_stopped')
        fwglobals.g.pppoe.start()

    def _on_add_interface_after(self, type, sw_if_index):
        """add-interface postprocessing

        :param type:        "wan"/"lan"
        :param sw_if_index: vpp sw_if_index of the interface
        """
        self._update_cache_sw_if_index(sw_if_index, type, True)

    def _on_remove_interface_before(self, type, sw_if_index):
        """remove-interface preprocessing

        :param type:        "wan"/"lan"
        :param sw_if_index: vpp sw_if_index of the interface
        """
        self._update_cache_sw_if_index(sw_if_index, type, False)

    def _on_add_tunnel_after(self, sw_if_index, params):
        """add-tunnel postprocessing

        :param sw_if_index: VPP sw_if_index of the tunnel interface
        :param params:      Parameters from Fleximanage.
        """
        vpp_if_name = fwutils.tunnel_to_vpp_if_name(params)
        fwutils.tunnel_change_postprocess(False, vpp_if_name)

    def _on_remove_tunnel_before(self, sw_if_index, params):
        """remove-tunnel preprocessing

        :param sw_if_index: VPP sw_if_index of the tunnel interface
        :param params:      Parameters from Fleximanage.
        """
        vpp_if_name = fwutils.tunnel_to_vpp_if_name(params)
        fwutils.tunnel_change_postprocess(True, vpp_if_name)

        if 'peer' in params:
            via = str(IPNetwork(params['peer']['addr']).ip)
        else:
            via = fwutils.build_tunnel_remote_loopback_ip(params['loopback-iface']['addr'])

        fwroutes.add_remove_static_routes(via, False)

    def _update_cache_sw_if_index(self, sw_if_index, type, add, params=None):
        """Updates persistent caches that store mapping of sw_if_index into
        name of vpp interface and via versa, and other caches.

        :param sw_if_index: vpp sw_if_index of the vpp software interface
        :param type:        "wan"/"lan"/"tunnel" - type of interface
        :param add:         True to add to cache, False to remove from cache
        :param params:      the 'params' section of 'add-interface'/'add-tunnel' request
        """
        router_api_db  = fwglobals.g.db['router_api']  # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
        cache_by_index = router_api_db['sw_if_index_to_vpp_if_name']
        cache_by_name  = router_api_db['vpp_if_name_to_sw_if_index'][type]
        cache_tap_by_vpp_if_name = router_api_db['vpp_if_name_to_tap_if_name']
        cache_tap_by_sw_if_index = router_api_db['sw_if_index_to_tap_if_name']
        if add:
            if type == 'tunnel':  # For tunnels use shortcut  - exploit vpp internals ;)
                vpp_if_name = fwutils.tunnel_to_vpp_if_name(params)
            elif type == 'peer-tunnel':
                vpp_if_name = fwutils.peer_tunnel_to_vpp_if_name(params)
            else:
                vpp_if_name = fwutils.vpp_sw_if_index_to_name(sw_if_index)
            cache_by_name[vpp_if_name]  = sw_if_index
            cache_by_index[sw_if_index] = vpp_if_name
            if type != 'peer-tunnel':  # ipipX tunnels are not exposed to Linux
                tap = fwutils.vpp_if_name_to_tap(vpp_if_name)
                if tap:
                    cache_tap_by_vpp_if_name[vpp_if_name] = tap
                    cache_tap_by_sw_if_index[sw_if_index] = tap
        else:
            vpp_if_name = cache_by_index[sw_if_index]
            del cache_by_name[vpp_if_name]
            del cache_by_index[sw_if_index]
            if vpp_if_name in cache_tap_by_vpp_if_name:
                del cache_tap_by_vpp_if_name[vpp_if_name]
            if sw_if_index in cache_tap_by_sw_if_index:
                del cache_tap_by_sw_if_index[sw_if_index]
        fwglobals.g.db['router_api'] = router_api_db

    def _on_apply_router_config(self):
        """Apply router configuration on successful VPP start.
        """
        # Before applying configuration move pending requests to the main request
        # database, hopefully their configuration will succeed this time.
        # Reset cache of interfaces, so it will be rebuilt during configuration
        # based on the current interface states.
        #
        for msg in self.pending_cfg_db.dump():
            self.cfg_db.update(msg)
        self.pending_cfg_db.clean()
        self.pending_interfaces = {}

        # Now fetch configuration items from database and configure them one by one.
        #
        types = [
            'add-ospf',
            'add-routing-filter',
            'add-routing-bgp',             # BGP should come after routing filter, as it might use them!
            'add-switch',
            'add-interface',
            'add-tunnel',
            'add-application',
            'add-multilink-policy',
            'add-firewall-policy',
            'add-route',            # Routes should come after tunnels and after BGP, as they might use them!
            'add-dhcp-config'
        ]
        messages = self.cfg_db.dump(types=types)
        for msg in messages:
            reply = fwglobals.g.router_api._call_simple(msg)
            if reply.get('ok', 1) == 0:  # Break and return error on failure of any request
                return reply

    def sync(self, incoming_requests, full_sync=False):
        self.pending_cfg_db.clean()
        FwCfgRequestHandler.sync(self, incoming_requests, full_sync=full_sync)

    def sync_full(self, incoming_requests):
        if len(incoming_requests) == 0:
            self.log.info("sync_full: incoming_requests is empty, no need to full sync")
            return True

        self.log.debug("sync_full: start router full sync")

        restart_router = False
        if self.state_is_started():
            self.log.debug("sync_full: : restart_router=True")
            restart_router = True
            fwglobals.g.handle_request({'message':'stop-router'})

        self.pending_cfg_db.clean()
        fwutils.reset_router_cfg()
        FwCfgRequestHandler.sync_full(self, incoming_requests)

        if restart_router:
            fwglobals.g.handle_request({'message': 'start-router'})

        self.log.debug("sync_full: router full sync succeeded")
