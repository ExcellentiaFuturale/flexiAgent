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

import fw_acl_command_helpers
import fw_nat_command_helpers
import fw_vpp_coredump_utils
import fwglobals
import fwlte
import fwnetplan
import fw_os_utils
import fwpppoe
import fwrouter_cfg
import fwroutes
import fwthread
import fwtunnel_stats
import fwutils
import fwwifi
import fwqos
from fwcfg_request_handler import FwCfgRequestHandler
from fwfrr import FwFrr
from fwikev2 import FwIKEv2
from fwmultilink import FwMultilink
from fwpolicies import FwPolicies
from vpp_api import VPP_API
from tools.common.fw_vpp_startupconf import FwStartupConf
from fwcfg_request_handler import FwCfgMultiOpsWithRevert

fwrouter_translators = {
    'start-router':             {'module': __import__('fwtranslate_start_router'),    'api':'start_router'},
    'stop-router':              {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'add-interface':            {'module': __import__('fwtranslate_add_interface'),   'api':'add_interface'},
    'remove-interface':         {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'modify-interface':         {'module': __import__('fwtranslate_add_interface'),   'api':'modify_interface',
                                    'ignored_params'  : 'modify_interface_ignored_params',
                                    'supported_params': 'modify_interface_supported_params'
                                },
    'add-route':                {'module': __import__('fwtranslate_add_route'),       'api':'add_route'},
    'remove-route':             {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'add-tunnel':               {'module': __import__('fwtranslate_add_tunnel'),      'api':'add_tunnel'},
    'remove-tunnel':            {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'modify-tunnel':            {'module': __import__('fwtranslate_add_tunnel'),      'api':'modify_tunnel',
                                    'supported_params':'modify_tunnel_supported_params'
                                },
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
    'add-qos-traffic-map':      {'module': __import__('fwtranslate_add_qos_traffic_map'), 'api':'add_qos_traffic_map'},
    'remove-qos-traffic-map':   {'module': __import__('fwtranslate_revert'),          'api':'revert'},
    'add-qos-policy':           {'module': __import__('fwtranslate_add_qos_policy'),  'api':'add_qos_policy'},
    'remove-qos-policy':        {'module': __import__('fwtranslate_revert'),          'api':'revert'},
    'add-vxlan-config':         {'module': __import__('fwtranslate_add_vxlan_config'), 'api':'add_vxlan_config'},
    'remove-vxlan-config':      {'module': __import__('fwtranslate_revert'),           'api':'revert'},
    'modify-vxlan-config':      {'module': __import__('fwtranslate_add_vxlan_config'), 'api':'modify_vxlan_config',
                                    'supported_params': 'modify_vxlan_config_supported_params'
                                },

    'add-vrrp-group':           {'module': __import__('fwtranslate_add_vrrp_group'), 'api':'add_vrrp_group'},
    'remove-vrrp-group':        {'module': __import__('fwtranslate_revert'),   'api':'revert'},
    'add-lan-nat-policy':       {'module': __import__('fwtranslate_add_lan_nat_policy'), 'api':'add_lan_nat_policy'},
    'remove-lan-nat-policy':    {'module': __import__('fwtranslate_revert'),   'api':'revert'},
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
        FwCfgRequestHandler.__init__(self, fwrouter_translators, cfg, pending_cfg_db)

        fwutils.reset_router_api_db() # Initialize cache that persists device reboot / daemon restart


    def finalize(self):
        """Destructor method
        """
        self._stop_threads()  # IMPORTANT! Do that before rest of finalizations!
        self.vpp_api.finalize()
        super().finalize()

    def vpp_watchdog_thread_func(self, ticks):
        """Watchdog thread function.
        Its function is to monitor if VPP process is alive.
        Otherwise it will start VPP and restore configuration from DB.
        """
        if not self.state_is_started():
            return
        if not fw_os_utils.vpp_does_run():      # This 'if' prevents debug print by router_api.initialize() every second
            self.log.debug("watchdog: initiate restore")

            fwutils.fwdump(filename="vpp_watchdog")

            self.state_change(FwRouterState.STOPPED)    # Reset state ASAP, so:
                                                        # 1. Monitoring Threads will suspend activity
                                                        # 2. Configuration will be applied correctly by _restore_vpp()

            self.vpp_api.disconnect_from_vpp()          # Reset connection to vpp to force connection renewal
            fwutils.stop_vpp()                          # Release interfaces to Linux

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


    def _get_vrrp_optional_tracked_interfaces(self):
        '''This function builds helper mappings between dev-id of the VRRP tracked interfaces
           and VRRP Virtual Router ID-s. As well it fetches dev-ids of the interfaces actually
           tracked by VPP.
        '''
        router_ids_by_dev_id = {} # -> { dev_id: [5] }
        vrrp_group_by_router_id  = {} # -> { 5: vrrp_group  }
        tracked_dev_ids = [] # -> [dev_id, dev_id]

        vrrp_groups = fwglobals.g.router_cfg.get_vrrp_groups()
        for vrrp_group in vrrp_groups:
            router_id = vrrp_group.get('virtualRouterId')

            if not router_id in vrrp_group_by_router_id:
                vrrp_group_by_router_id[router_id] = vrrp_group

            for track_interface in vrrp_group.get('trackInterfaces', []):
                is_optional = not track_interface.get('isMandatory', True)
                if not is_optional:
                    continue

                track_ifc_dev_id = track_interface.get('devId')
                if not track_ifc_dev_id in router_ids_by_dev_id:
                    router_ids_by_dev_id[track_ifc_dev_id] = []
                router_ids_by_dev_id[track_ifc_dev_id].append(router_id)

        vpp_vrrp_groups = fwglobals.g.router_api.vpp_api.vpp.call('vrrp_vr_track_if_dump', dump_all=1)
        for vpp_vrrp_group in vpp_vrrp_groups:
            for tracked_interface in vpp_vrrp_group.ifs:
                dev_id = fwutils.vpp_sw_if_index_to_dev_id(tracked_interface.sw_if_index)
                tracked_dev_ids.append(dev_id)

        return router_ids_by_dev_id, vrrp_group_by_router_id, tracked_dev_ids

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
        restart_dhcpd = False

        interfaces = fwglobals.g.router_cfg.get_interfaces()

        vrrp_router_ids_by_tracked_dev_id, \
        vrrp_group_by_router_id, \
        vpp_vrrp_tracked_dev_ids \
            = self._get_vrrp_optional_tracked_interfaces()

        vrrp_tracked_dev_ids_by_router_id = {id: {} for id in vrrp_group_by_router_id}

        for interface in interfaces:
            dev_id = interface['dev_id']
            if (fwutils.is_vlan_interface(dev_id=dev_id) or
               fwpppoe.is_pppoe_interface(dev_id=dev_id)):
                continue
            tap_name = fwutils.dev_id_to_tap(dev_id)
            if fwlte.is_lte_interface_by_dev_id(dev_id):
                connected = fwglobals.g.modems.get(dev_id).is_connected()
                status_vpp = 'up' if connected else 'down'
            else:
                status_vpp = fwutils.vpp_get_interface_status(dev_id=dev_id).get('link')
            status_linux = fwutils.get_interface_linux_carrier_value(tap_name)
            if status_vpp == 'down' and status_linux == '1':
                self.log.debug(f"detected NO-CARRIER for {tap_name}")
                fwutils.os_system(f"echo 0 > /sys/class/net/{tap_name}/carrier")
            elif status_vpp == 'up' and status_linux == '0':
                self.log.debug(f"detected CARRIER UP for {tap_name}")
                fwutils.os_system(f"echo 1 > /sys/class/net/{tap_name}/carrier")
                if dev_id in fwglobals.g.db.get('router_api',{}).get('dhcpd',{}).get('interfaces',{}):
                    restart_dhcpd = True

                # When we use sys/class/net/carrier, the VPP fails to handle the VRRP status correctly,
                # causing it to stay in the "Interface down" state even after the carrier is restored.
                # To fix this, we need to restart VRRP.
                dev_id_vrrp_groups = self.cfg_db.get_vrrp_groups(dev_id=dev_id)
                for dev_id_vrrp_group_params in dev_id_vrrp_groups:
                    virtual_router_id = dev_id_vrrp_group_params['virtualRouterId']
                    self.log.debug(f"restarting VRRP ID {virtual_router_id}. dev_id={dev_id}. tap_name={tap_name}")
                    fwutils.vpp_vrrp_restart(vr_id=virtual_router_id, dev_id=dev_id)

            virtual_router_ids = vrrp_router_ids_by_tracked_dev_id.get(dev_id, [])
            if status_vpp == 'down':
                for virtual_router_id in virtual_router_ids:
                    vrrp_tracked_dev_ids_by_router_id[virtual_router_id].update({dev_id: False})
            elif status_vpp == 'up':
                for virtual_router_id in virtual_router_ids:
                    vrrp_tracked_dev_ids_by_router_id[virtual_router_id].update({dev_id: True})

        if restart_dhcpd:
            time.sleep(1)  # give a second to Linux to reconfigure interface
            cmd = 'systemctl restart isc-dhcp-server'
            fwutils.os_system(cmd, '_sync_link_status')

        self._check_and_update_vrrp_tracked_interfaces(
            vrrp_tracked_dev_ids_by_router_id,
            vrrp_group_by_router_id,
            vpp_vrrp_tracked_dev_ids
        )

    def _check_and_update_vrrp_tracked_interfaces(self, dev_ids_by_router_id, vrrp_group_by_router_id, vpp_tracked_dev_ids):
        '''
        We have two types of VRRP tracked interfaces - Mandatory and Optional.
        Mandatory means that the router should go to the Backup state if this interface fails. Regardless of other interfaces.
        Optional means that the router should go to the Backup state only if *all* optional interfaces fail.

        VPP doesn't support this functionality and terminology of Mandatory and optional.
        We introduced it to simplify the configuration for our users.
        The Mandatory interfaces, we add in "fwtranslate_add_vrrp".
        For optional, we added the logic below.
        1. We monitor the link status of the optional interfaces.
        2. If *all* of them fail and they don't exist in VPP, we add them to VPP.
        3. If one of them is OK and they exist in VPP, we remove them from VPP.
        '''
        for router_id in dev_ids_by_router_id:
            # "dev_ids_by_router_id[router_id]" is a dict looks as follows:
            # {
            #   5: {
            #       [dev_id_1]: False,
            #       [dev_id_2]: True,
            #   }
            # }
            # Each interface's link status can be True, False indicates if link is up or down.
            #
            # First, check if all optional links are down to figure out what should be configured in vpp.
            is_all_optional_links_down = False if True in dev_ids_by_router_id[router_id].values() else True

            # once we know what should be configured in vpp, go and check if vpp is synced
            is_vpp_synced = True
            if is_all_optional_links_down:
                # If all down, all of them should be in vpp
                for dev_id in dev_ids_by_router_id[router_id]:
                    if dev_id not in vpp_tracked_dev_ids:
                        is_vpp_synced = False
                        break
            else:
                # If not all down, none of them should be in vpp
                for dev_id in dev_ids_by_router_id[router_id]:
                    if dev_id in vpp_tracked_dev_ids:
                        is_vpp_synced = False
                        break
            if is_vpp_synced:
                return

            self.log.debug(f"Going to change optional VRRP tracked interfaces")
            # if all down, we adding all interfaces, mandatory and optionals,
            # if not all down, we adding only mandatory interfaces
            mandatory_only = 0 if is_all_optional_links_down else 1
            vrrp_group = vrrp_group_by_router_id[router_id]
            sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(vrrp_group['devId'])

            fwutils.vpp_vrrp_add_del_track_interfaces(
                is_add=0,
                track_interfaces=vrrp_group['trackInterfaces'],
                vr_id=router_id,
                track_ifc_priority=(vrrp_group['priority'] - 1), # vpp allows priority less than VRID priority
                mandatory_only=0,
                sw_if_index=sw_if_index
            )

            fwutils.vpp_vrrp_add_del_track_interfaces(
                is_add=1,
                track_interfaces=vrrp_group['trackInterfaces'],
                vr_id=router_id,
                track_ifc_priority=(vrrp_group['priority'] - 1), # vpp allows priority less than VRID priority
                mandatory_only=mandatory_only, # if even one optional is ok, add only mandatory,
                sw_if_index=sw_if_index
            )

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

                    # Update interface cache with new GW
                    #
                    fwutils.update_linux_interfaces(dev_id, new['gw'])

                    # Update FWABF link with new GW, it is used for multilink policies
                    #
                    link = self.multilink.get_link(dev_id)
                    if link:
                        self.multilink.vpp_update_labels(
                            remove=False, labels=link.labels, next_hop=new['gw'], dev_id=dev_id)

                    # Update ARP entry of LTE interface
                    try:
                        if new['deviceType'] == 'lte':
                            fwglobals.g.modems.get(dev_id).set_arp_entry(is_add=False, gw=old['gw'])
                            fwglobals.g.modems.get(dev_id).set_arp_entry(is_add=True, gw=new['gw'])
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

    def initialize(self):
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

        # If vpp runs already, or if management didn't request to start it, return.
        vpp_runs = fw_os_utils.vpp_does_run()
        vpp_should_be_started = self.cfg_db.exists({'message': 'start-router'})
        if vpp_runs or not vpp_should_be_started:
            self.log.debug("initialize: no need to restore(vpp_runs=%s, vpp_should_be_started=%s)" %
                (str(vpp_runs), str(vpp_should_be_started)))
            if vpp_runs:
                self.state_change(FwRouterState.STARTED)
            if self.state_is_started():
                self.log.debug("initialize: vpp_pid=%s" % str(fw_os_utils.vpp_pid()))
                self._start_threads()
                # We use here read_from_disk because we can't fill the netplan cache from scratch when vpp is running.
                # We use the original interface names in this cache,
                # but they don't exist when they are under dpdk control and replaced by vppsb interfaces.
                # Hence, we fill the cache with the backup in the disk
                fwnetplan.load_netplan_filenames(read_from_disk=vpp_runs)
            else:
                fwnetplan.restore_linux_netplan_files()
                fwutils.get_linux_interfaces(cached=False) # Refill global interface cache once netplan was restored
            super().initialize()
            return False

        self._restore_vpp()
        fwutils.get_linux_interfaces(cached=False) # Refill global interface cache once VPP is on air
        super().initialize()
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
            fwpppoe.pppoe_reset()

            fwglobals.g.handle_request({'message': 'start-router'})
        except Exception as e:
            self.log.excep("initialize: %s" % str(e))
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
        self.set_request_logger(request)   # Use request specific logger (this is to offload heavy 'add-application' logging)
        try:

            # First of all strip out requests that have no impact on configuration,
            # like 'remove-X' for not existing configuration items and 'add-X' for
            # existing configuration items.
            #
            new_request = self._strip_noop_request(request)
            if not new_request:
                self.log.debug("call: ignore no-op request: %s" % json.dumps(request))
                return { 'ok': 1, 'message':'request has no impact' }
            request = new_request

            # Now find out if:
            # 1. VPP should be restarted as a result of request execution.
            #    It should be restarted on addition/removal interfaces in order
            #    to capture new interface /release old interface back to Linux.
            # 2. Agent should reconnect proactively to flexiManage.
            #    It should reconnect on QoS policy change.
            # 3. Gateway of WAN interfaces are going to be modified.
            #    In this case we have to ping the GW-s after modification.
            #    See explanations on that workaround later in this function.
            #
            (restart_router, gateways, restart_dhcp_service, reconnect_agent) = self._analyze_request(request)

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

            if reconnect_agent:
                fwglobals.g.fwagent.reconnect()

            if restart_dhcp_service:
                if not restart_router: # on router restart DHCP service is restarted as well
                    cmd = 'systemctl restart isc-dhcp-server'
                    fwutils.os_system(cmd, 'call')

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

        finally:
            self.unset_request_logger()
        return reply

    def _call_simple(self, request, execute=False, filter=None):
        """Execute single request.

        :param request: The request received from flexiManage.

        :returns: dictionary with status code and optional error message.
        """
        try:
            req = request['message']

            vpp_does_run = fw_os_utils.vpp_does_run()

            # The 'add-application' and 'add-multilink-policy' requests should
            # be translated and executed only if VPP runs, as the translations
            # depends on VPP API-s output. Therefore if VPP does not run,
            # just save the requests in database and return.
            #
            if vpp_does_run == False and \
                (req == 'add-application' or
                req == 'add-multilink-policy' or
                req == 'add-firewall-policy' or
                req == 'add-lan-nat-policy' or
                req == 'add-qos-traffic-map' or
                (req == 'add-qos-policy' or req == 'remove-qos-policy')):
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
            if vpp_does_run and self.state_is_starting_stopping(): # For now enable pending requests on start-router only
                if re.match('add-',  req) and self._is_pending_request(request):
                    self.pending_cfg_db.update(request)
                    self.cfg_db.remove(request)
                    return {'ok':1}

            if vpp_does_run or req == 'start-router':
                execute = True
            elif re.match('remove-',  req):
                filter = 'must'
                execute = True
            elif '-vxlan-config' in req:
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

        def _should_restart_on_qos_policy(request):
            hqos_enabled, total_cpu_workers = fwglobals.g.qos.get_hqos_worker_state()
            if (self.state_is_started() is False) or (total_cpu_workers < 2):
                # VPP not started or device not capable - No restart required
                return False

            if (request['message'] == 'add-qos-policy'):
                if fwglobals.g.qos.restart_check_on_qos_interfaces_update(request['params']):
                    # QoS interfaces have changed in the new request - Restart required
                    return True
            elif (request['message'] == 'remove-qos-policy'):
                if hqos_enabled is True:
                    return True
            return False

        restart_router, gateways, restart_dhcp_service, reconnect_agent = \
        False,          [],       False,                False

        def _return_val():
            return (restart_router, gateways, restart_dhcp_service, reconnect_agent)

        if re.match('(add|remove)-interface', request['message']):
            if self.state_is_started():
                if not fwutils.is_vlan_interface(dev_id=request['params']['dev_id']):
                    restart_router  = True
            return _return_val()
        elif re.match('(add|remove)-qos-policy', request['message']):
            if (_should_restart_on_qos_policy(request)):
                restart_router  = True
            return _return_val()
        elif re.match('(add|remove)-dhcp-config', request['message']):
            restart_dhcp_service  = True
            return _return_val()
        elif request['message'] != 'aggregated':
            return _return_val()
        else:   # aggregated request
            add_remove_requests = {}
            modify_requests = {}
            only_vlans = True
            for _request in request['params']['requests']:
                if re.match('(add|remove)-qos-policy', _request['message']):
                    if (_should_restart_on_qos_policy(_request)):
                        restart_router  = True
                elif re.match('(add|remove)-dhcp-config', _request['message']):
                    restart_dhcp_service  = True
                elif re.match('(add|remove)-interface', _request['message']):
                    dev_id = _request['params']['dev_id']
                    # Track vlans. If only vlans in add/remove requests do not restart router
                    if not fwutils.is_vlan_interface(dev_id=dev_id):
                        only_vlans = False
                    # check if requests list contains remove-interface and add-interface for the same dev_id.
                    # If found, it means that these two requests were created for modify-interface
                    if not dev_id in add_remove_requests:
                        add_remove_requests[dev_id] = _request
                    else:
                        # This add/remove complements pair created for modify-interface

                        # Fetch gateway from the add-interface
                        #
                        gw = add_remove_requests[dev_id]['params'].get('gateway')
                        if not gw:
                            gw = _request['params'].get('gateway')
                        if gw:
                            gateways.append(gw)

                        # Move the request to the set of modify-interface-s
                        #
                        del add_remove_requests[dev_id]
                        modify_requests[dev_id] = _request

            if add_remove_requests and self.state_is_started():
                if not only_vlans:
                    restart_router = True
            if modify_requests and self.state_is_started():
                restart_dhcp_service = True

                # If 'modify-interface' for default route was received, the NAT session for the WebSocket connection
                # might be removed from VPP during execution of the simulated 'remove-interface'.
                # As a result, the connection packets will be dropped by VPP and connection will be stuck.
                # To recover out of this situation, we just reconnect agent once the request was handled.
                #
                default_route = fwroutes.get_default_route()
                for dev_id in modify_requests.keys():
                    if dev_id == default_route.dev_id:
                        reconnect_agent = True
                        break
            return _return_val()

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
                    params = self.cfg_db.get_request_params(_request)
                    if params == None:
                        # If params were not found in main database, there is a chance
                        # that request was moved into pending database. Try it.
                        params = self.pending_cfg_db.get_request_params(_request)
                    _request['params'] = params

        if self.state_is_stopped():
            if req == 'aggregated':  # take a care of order of parent & sub-interfaces
                self._preprocess_reorder(request)
            return request

        if req != 'aggregated':
            request = self._preprocess_simple_request(request)
            #
            # Preprocessing might turn simple request to be aggregated.
            # In this case more processing is needed. Hence the 'if' below.
            #
            if request['message'] != 'aggregated':
                return request

        request = self._preprocess_aggregated_request(request)
        return request

    def _preprocess_simple_request(self, request):
        '''Enhancement of the _preprocess_request() for simple requests.

        :param request: The original request received from flexiManage
        :returns: The new aggregated request and it's parameters.
                        Note the parameters are list of requests that might be
                        a mix of simulated requests and original requests.
                        This mix should include one original request and one or
                        more simulated requests.
                        If no preprocessing was needed, the original request is
                        returned.
        '''

        def _single_message_add_corresponding_remove (add_request, current_params, new_params):
            remove_request = add_request.replace('add-', 'remove-')
            updated_requests = [
                { 'message': remove_request, 'params' : current_params },
                { 'message': add_request,    'params' : new_params }
            ]
            request = {'message': 'aggregated', 'params': { 'requests' : updated_requests }}
            self.log.debug("_preprocess_simple_request: %s request \
                    was replaced with %s" % (add_request, json.dumps(request)))
            return request


        req     = request['message']
        params  = request.get('params')

        application_params      = self.cfg_db.get_applications()
        multilink_policy_params = self.cfg_db.get_multilink_policy()
        firewall_policy_params  = self.cfg_db.get_firewall_policy()
        qos_policy_params       = self.cfg_db.get_qos_policy()
        qos_traffic_map_params  = self.cfg_db.get_qos_traffic_map()
        lan_nat_policy          = self.cfg_db.get_lan_nat_policy()

        # 'add-application'/'remove-application' preprocessing:
        # 1. The multilink/firewall/etc policy should be re-installed:
        #    if exists, the policy should be removed before application removal & adding
        #    and it should be added again after it.
        # 2. For 'add-application', the currently configured applications if exist,
        #    should be removed firstly. We do that by adding simulated
        #    'remove-application' request in front of the original 'add-application' request.
        #
        if req == 'add-application' or req == 'remove-application':
            pre_requests, post_requests  = [], []
            if req == 'add-application' and application_params:
                pre_requests  = [ { 'message': 'remove-application', 'params' : application_params } ]
            if multilink_policy_params:
                pre_requests.insert(0, { 'message': 'remove-multilink-policy', 'params' : multilink_policy_params })
                post_requests.append({ 'message': 'add-multilink-policy', 'params' : multilink_policy_params })
            if firewall_policy_params:
                pre_requests.insert(0, { 'message': 'remove-firewall-policy', 'params' : firewall_policy_params })
                post_requests.append({ 'message': 'add-firewall-policy', 'params' : firewall_policy_params })

            if pre_requests == [] and post_requests == []:
                return request
            new_params  = { 'requests' : pre_requests + [request] + post_requests }
            new_request = {'message': 'aggregated', 'params': new_params}
            self.log.debug("_preprocess_simple_request: request was replaced with %s" % json.dumps(new_request))
            return new_request

        # 'add-X-policy' preprocessing:
        # 1. The currently configured policy should be removed firstly.
        #    We do that by adding simulated 'remove-X-policy' request in
        #    front of the original 'add-X-policy' request.
        #
        if multilink_policy_params and req == 'add-multilink-policy':
            return _single_message_add_corresponding_remove(req, multilink_policy_params, params)
        if firewall_policy_params and req == 'add-firewall-policy':
            return _single_message_add_corresponding_remove(req, firewall_policy_params, params)
        if qos_policy_params and req == 'add-qos-policy':
            return _single_message_add_corresponding_remove(req, qos_policy_params, params)
        if qos_traffic_map_params and req == 'add-qos-traffic-map':
            return _single_message_add_corresponding_remove(req, qos_traffic_map_params, params)
        if lan_nat_policy and req == 'add-lan-nat-policy':
            return _single_message_add_corresponding_remove(req, lan_nat_policy, params)

        return request

    def _preprocess_aggregated_request(self, request):
        '''Enhancement of the _preprocess_request() for aggregated requests.
        In addition to the logic implemented in _preprocess_request() and
        in _preprocess_simple_request(), this function reorders requests inside
        of aggregation to ensure proper configuration of VPP.

        :param request: The original request received from flexiManage,
                        or the aggregated request output-ed by the _preprocess_simple_request().
        :returns: request - The new aggregated request and it's parameters.
                        Note the parameters are list of requests that might be
                        a mix of simulated requests and original requests.
                        This mix should include one original request and one or
                        more simulated requests.
                        If no preprocessing was needed, the original request is
                        returned.
        '''
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        # !!!!!!! Order of function calls in this function is important !!!!!!!
        # !!!!!!! Every function might modify request, thus changing    !!!!!!!
        # !!!!!!! input for next function! And, as a result impacting   !!!!!!!
        # !!!!!!! on output of the next function!                       !!!!!!!
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

        changed = self._preprocess_reinstall_policies_if_needed(request)

        changed |= self._preprocess_insert_simulated_requests(request)

        changed |= self._preprocess_reorder(request)

        if changed:
            self.log.debug("_preprocess_aggregated_request: request was replaced with %s" % json.dumps(request))
        return request

    def _preprocess_reorder(self, request):
        '''Implements part of the _preprocess_aggregated_request() logic.
        It rearranges requests in the aggregation to be in following order:
        the first should be 'stop-router' (if exist in the aggregation),
        then the 'remove-X' requests, after that the 'add-X'-s,
        then the 'modify-X'-s and at the end the 'start-router'.
            Moreover, the order of 'add-X' requests is important too, as there
        might be dependencies between configured items. For example,
        'add-interface'-s should be executed before the 'add-tunnel'-s
        as the latest uses the formers, the 'add-route'-s should come after
        the 'add-tunnel'-s as route rules might use tunnels, etc.
        Order of the 'remove-X' requests is important as well, and it should be
        opposite to this of the 'add-X' requests.

        :param request: The aggregated request.
        :returns: 'True' if aggregation was modified by this function, 'False' o/w.
        '''
        add_order = [
            'add-ospf', 'add-routing-filter', 'add-routing-bgp', 'add-switch',
            'add-interface', 'add-vrrp-group', 'add-vxlan-config', 'add-tunnel', 'add-route', 'add-dhcp-config',
            'add-application', 'add-multilink-policy', 'add-firewall-policy', 'add-lan-nat-policy',
            'add-qos-traffic-map', 'add-qos-policy'
        ]
        remove_order = [ re.sub('add-','remove-', name) for name in add_order ]
        remove_order.reverse()

        old_requests = request['params']['requests']
        new_requests = []

        # First of all ensure that all received 'add/remove-X' are listed
        # in the dependency tables.
        #
        for _request in old_requests:
            req_name = _request['message']
            if re.match('add-', req_name) and not (req_name in add_order):
                raise Exception(f'{req_name}: dependencies are not defined')
            elif re.match('remove-', req_name) and not (req_name in remove_order):
                raise Exception(f'{req_name}: dependencies are not defined')

        # Reorder 'remove-X'-s to be before 'add-X'-s, while ensuring order
        # between 'remove-X'-s and order between 'add-X'-s.
        #
        for req_name in remove_order:
            for _request in old_requests:
                if re.match(req_name, _request['message']):
                    new_requests.append(_request)
        for req_name in add_order:
            for _request in old_requests:
                if re.match(req_name, _request['message']):
                    new_requests.append(_request)

        # Reorder 'add-interface'-s and 'remove-interface'-s requests
        # to ensure that the sub-interfaces are added after the parent
        # interface was added and are removed before the parent interface
        # is removed. This is needed for VLAN interfaces.
        #
        new_requests = preprocess_reorder_sub_interfaces(new_requests)

        # Add 'start-router', 'stop-router' and 'modify-X'-s to the list of 'remove-X'-s
        # and 'add-X'-s: put 'stop-router' at the beginning of list, 'modify-X'-s
        # after the 'remove-X'-s & 'add-X'-s and the 'start-router' at the end.
        #
        start_router_request = None
        for _request in old_requests:
            if re.match('modify-', _request['message']):
                new_requests.append(_request)
            elif _request['message'] == 'stop-router':
                new_requests.insert(0, _request)
            elif _request['message'] == 'start-router':
                start_router_request = _request
        if start_router_request:
            new_requests.append(start_router_request)

        request['params']['requests'] = new_requests
        return (old_requests != new_requests)

    def _preprocess_reinstall_policies_if_needed(self, request):
        '''Implements part of the _preprocess_aggregated_request() logic.
        It adds 'remove-X-policy' and 'add-X-policy' requests to aggregation,
        if the aggregation has either 'add/remove-application' or 'add/remove-interface'
        requests. The policy will be removed before application/interface change
        and will be installed after it again.

        :param request: The aggregated request.
        :returns: 'True' if aggregation was modified by this function, 'False' o/w.
        '''
        modified = False
        requests = request['params']['requests']

        # If aggregation has 'remove-X-policy' request, there is no need to
        # reinstall the policy, it will be removed anyway. Find out
        # the 'remove-X-policy' requests.
        #
        policies = {
            'multilink': {
                'add_policy_found' :    False,
                'remove_policy_found' : False,
                'params': self.cfg_db.get_multilink_policy()
                },
            'firewall': {
                'add_policy_found' :    False,
                'remove_policy_found' : False,
                'params': self.cfg_db.get_firewall_policy()
                },
            'lan-nat': {
                'add_policy_found' :    False,
                'remove_policy_found' : False,
                'params': self.cfg_db.get_lan_nat_policy()
                },
        }

        # Find out if policies should be reinstalled.
        #
        reinstall = False
        for _request in requests:
            req_name = _request['message']
            if re.match('(add|remove)-(switch|application)', req_name):
                reinstall = True
            elif req_name == 'add-multilink-policy':
                policies['multilink']['add_policy_found'] = True
            elif req_name == 'remove-multilink-policy':
                policies['multilink']['remove_policy_found'] = True
            elif req_name == 'add-firewall-policy':
                policies['firewall']['add_policy_found'] = True
            elif req_name == 'remove-firewall-policy':
                policies['firewall']['remove_policy_found'] = True
            elif req_name == 'add-lan-nat-policy':
                policies['lan-nat']['add_policy_found'] = True
            elif req_name == 'remove-lan-nat-policy':
                policies['lan-nat']['remove_policy_found'] = True

        if not reinstall:
            return False   # False -> request was not modified

        # Go and add reinstall requests for policies, that are installed
        # (policy['params'] is True) and that are not going to be removed anyway
        # by this aggregation (policy['remove_policy_found'] is False)
        #
        for p_name, policy in policies.items():
            if policy['params'] and policy['remove_policy_found'] == False:
                requests.insert(0, { 'message': f'remove-{p_name}-policy', 'params': policy['params'] })
                if policy['add_policy_found'] == False:   # the original request may have add-XXX-policy, so ne need to simulate it
                    requests.append({ 'message': f'add-{p_name}-policy',   'params': policy['params'] })
                modified = True
        return modified

    def _preprocess_insert_simulated_requests(self, request):
        '''Implements part of the _preprocess_aggregated_request() logic.
        It inserts new requests into aggregation, thus simulating receiving
        requests from flexiManage. This is needed for 'add-X' requests that have
        neither complementing 'remove-X' nor 'modify-X' requests.
        That kind of 'add-X' requests just replaces completely the previously
        configured item.
        An examples of such requests are 'add-application', 'add-multilink-policy', etc.
            To implement the described logic we insert new correspondent 'remove-X'
        request into list of aggregated requests at any point before the corresponding
        'add-X' request.

        :param request: The aggregated request.
        :returns: 'True' if aggregation was modified by this function, 'False' o/w.
        '''
        modified = False
        requests = request['params']['requests']

        # Pass over requests and detect presence of special requests.
        # On the way collect some more info for further pre-processing.
        #
        special_requests = {
            'add-application': {
                'found':                False,
                'remove_request_found': False,
                'params':               self.cfg_db.get_applications()
            },
            'add-multilink-policy': {
                'found':                False,
                'remove_request_found': False,
                'params':               self.cfg_db.get_multilink_policy()
            },
            'add-firewall-policy': {
                'found':                False,
                'remove_request_found': False,
                'params':               self.cfg_db.get_firewall_policy()
            },
            'add-qos-traffic-map': {
                'found':                False,
                'remove_request_found': False,
                'params':               self.cfg_db.get_qos_traffic_map()
            },
            'add-qos-policy': {
                'found':                False,
                'remove_request_found': False,
                'params':               self.cfg_db.get_qos_policy()
            },
            'add-lan-nat-policy': {
                'found':                False,
                'remove_request_found': False,
                'params':               self.cfg_db.get_lan_nat_policy()
            },
        }
        for _request in requests:
            req_name = _request['message']
            if req_name in special_requests:
                special_requests[req_name]['found'] = True
            elif re.match('remove-', req_name):
                add_req_name = req_name.replace("remove-", "add-", 1)
                if add_req_name in special_requests:
                    special_requests[add_req_name]['remove_request_found'] = True

        # Preprocess special requests: insert 'remove-X' if:
        # - the 'add-X' was found in requests
        # - the 'remove-X' was not found in requests
        # - there are configuration to be removed
        #
        for add_req_name, r_info in special_requests.items():
            if r_info['found'] and not r_info['remove_request_found'] and r_info['params']:
                remove_req_name = add_req_name.replace("add-", "remove-", 1)
                requests.insert(0, { 'message': remove_req_name, 'params': r_info['params'] })
                modified = True
        return modified

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

        fwglobals.g.pppoe.stop(reset_tun_if_params=True)

        self.multilink.db['links'] = {}

        self.pending_dev_ids = set()

        # Reset FlexiWAN QoS contexts on VPP start
        fwglobals.g.qos.reset()

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
            fwutils.reset_device_config_signature("pending_interfaces_got_ip")

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

        fwglobals.g.pppoe.start()

        self._sync_after_start()

        # Build cache of interfaces for address monitoring.
        # Note if address was changed before we reach this point,
        # the `_sync_after_start()` above should handle the change.
        # It forces the flexiManage to send `sync-device` to us.
        #
        self._get_monitor_interfaces(cached=False)

        self.log.info("router was started: vpp_pid=%s" % str(fw_os_utils.vpp_pid()))

        fwglobals.g.applications_api.call_hook('on_router_is_started')

    def _on_stop_router_before(self):
        """Handles pre-VPP stop activities.
        :returns: None.
        """
        self.state_change(FwRouterState.STOPPING)
        with FwIKEv2() as ike:
            ike.clean()
        self._stop_threads()
        fwglobals.g.pppoe.stop(reset_tun_if_params=True)
        fwglobals.g.cache.dev_id_to_vpp_tap_name.clear()
        self.log.info("router is being stopped: vpp_pid=%s" % str(fw_os_utils.vpp_pid()))

        fwglobals.g.applications_api.call_hook('on_router_is_stopping')

    def _on_stop_router_after(self):
        """Handles post-VPP stop activities.
        :returns: None.
        """
        self.router_stopping = False

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

        fwglobals.g.fwagent.reconnect()

    def _on_add_interface_after(self, type, sw_if_index, params):
        """add-interface postprocessing

        :param type:        "wan"/"lan"
        :param sw_if_index: vpp sw_if_index of the interface
        """
        self._update_cache_sw_if_index(sw_if_index, type, add=True, params=params)
        self.apply_features_on_interface(True, type, vpp_if_name=None, sw_if_index=sw_if_index)

    def apply_features_on_interface(self, add, if_type, vpp_if_name=None, sw_if_index=None, dev_id=None):
        if not vpp_if_name and not sw_if_index:
            err_msg = 'vpp_if_name and sw_if_index were not provided'
            self.log.error(f"apply_features_on_interface({add, if_type}): failed. {err_msg}")
            raise Exception(err_msg)

        if not vpp_if_name:
            vpp_if_name = fwutils.vpp_sw_if_index_to_name(sw_if_index)
        if not sw_if_index:
            sw_if_index = fwutils.vpp_if_name_to_sw_if_index(vpp_if_name)

        if not dev_id:
            dev_id = fwutils.vpp_if_name_to_dev_id(vpp_if_name)

        with FwCfgMultiOpsWithRevert() as handler:
            try:
                # apply firewall
                if if_type == 'lan':
                    ingress_acls = fwglobals.g.firewall_acl_cache.get(dev_id, 'ingress')
                    if not ingress_acls:
                        ingress_acls = fwglobals.g.firewall_acl_cache.get('global_lan', 'ingress')

                    egress_acls = fwglobals.g.firewall_acl_cache.get(dev_id, 'egress')
                    if not egress_acls:
                        egress_acls = fwglobals.g.firewall_acl_cache.get('global_lan', 'egress')

                    handler.exec(
                        func=fw_acl_command_helpers.vpp_add_acl_rules,
                        params={ 'is_add': add, 'sw_if_index': sw_if_index, 'ingress_acl_ids': ingress_acls, 'egress_acl_ids': egress_acls },
                        revert_func=fw_acl_command_helpers.vpp_add_acl_rules if add else None,
                        revert_params={ 'is_add': (not add), 'sw_if_index': sw_if_index, 'ingress_acl_ids': ingress_acls, 'egress_acl_ids': egress_acls } if add else None,
                    )

                if if_type == 'wan':
                    ingress_acls = fwglobals.g.firewall_acl_cache.get(dev_id, 'ingress')
                    if not ingress_acls:
                        ingress_acls = fwglobals.g.firewall_acl_cache.get('global_wan', 'ingress')

                    handler.exec(
                        func=fw_acl_command_helpers.vpp_add_acl_rules,
                        params={ 'is_add': add, 'sw_if_index': sw_if_index, 'ingress_acl_ids': ingress_acls, 'egress_acl_ids': [] },
                        revert_func=fw_acl_command_helpers.vpp_add_acl_rules if add else None,
                        revert_params={ 'is_add': (not add), 'sw_if_index': sw_if_index, 'ingress_acl_ids': ingress_acls, 'egress_acl_ids': [] } if add else None,
                    )

                    handler.exec(
                        func=fw_nat_command_helpers.add_nat_rules_interfaces,
                        params={ 'is_add': add, 'sw_if_index': sw_if_index },
                        revert_func=fw_nat_command_helpers.add_nat_rules_interfaces,
                        revert_params={ 'is_add': (not add), 'sw_if_index': sw_if_index },
                    )

                # apply qos classification on application interfaces
                if dev_id.startswith('app_'):
                    # Needed only for application interfaces as it is Not added via add-interface message
                    hqos_enabled, _ = fwglobals.g.qos.get_hqos_worker_state()
                    if hqos_enabled:
                        handler.exec(
                            func=fwqos.update_interface_qos_classification,
                            params={ 'vpp_if_name': vpp_if_name, 'add': add },
                            revert_func=fwqos.update_interface_qos_classification if add else None, # no need revert of revert
                            revert_params={ 'vpp_if_name': vpp_if_name, 'add': (not add) } if add else None, # no need revert of revert
                        )

                # apply multilink
                handler.exec(
                    func=fwglobals.g.policies.vpp_attach_detach_policies,
                    params={ 'attach': add, 'vpp_if_name': vpp_if_name, 'if_type': if_type },
                    revert_func=fwglobals.g.policies.vpp_attach_detach_policies if add else None, # no need revert of revert
                    revert_params={ 'attach': (not add), 'vpp_if_name': vpp_if_name, 'if_type': if_type } if add else None, # no need revert of revert
                )
            except Exception as e:
                self.log.error(f"apply_features_on_interface({add, if_type, vpp_if_name, sw_if_index}): failed. {str(e)}")
                handler.revert(e)

    def _on_remove_interface_before(self, type, sw_if_index, params):
        """remove-interface preprocessing

        :param type:        "wan"/"lan"
        :param sw_if_index: vpp sw_if_index of the interface
        """
        self.apply_features_on_interface(False, type, vpp_if_name=None, sw_if_index=sw_if_index)
        self._update_cache_sw_if_index(sw_if_index, type, add=False, params=params)

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
        cache_by_dev_id = router_api_db['dev_id_to_sw_if_index']
        cache_tap_by_vpp_if_name = router_api_db['vpp_if_name_to_tap_if_name']
        cache_tap_by_sw_if_index = router_api_db['sw_if_index_to_tap_if_name']

        dev_id = params.get('dev_id') if params else None
        if dev_id and (type == 'wan' or type == 'lan'):
            if add:
                cache_by_dev_id[dev_id] = sw_if_index
            else:
                del cache_by_dev_id[dev_id]

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
            'add-vxlan-config',            # After interfaces, before tunnels
            'add-tunnel',
            'add-application',
            'add-multilink-policy',
            'add-firewall-policy',
            'add-lan-nat-policy',
            'add-qos-traffic-map',
            'add-qos-policy',
            'add-route',            # Routes should come after tunnels and after BGP, as they might use them!
            'add-dhcp-config',
            'add-vrrp-group',
        ]
        last_msg = None
        start_dhcp_server = False
        messages = self.cfg_db.dump(types=types)
        for idx, msg in enumerate(messages):

            # reconnect as soon as interfaces are initialized
            #
            if last_msg == 'add-interface' and msg['message'] != 'add-interface':
                fwglobals.g.fwagent.reconnect()
            last_msg = msg['message']

            # We start DHCP Server here and not on 'add-dhcp-config' execution
            # to ensure that it is started only once for all 'add-dhcp-config'-s.
            # Otherwise, we might hit the 'too many restarts in second' systemd limit.
            #
            if msg['message'] == 'add-dhcp-config':
                start_dhcp_server = True

            reply = fwglobals.g.router_api._call_simple(msg)
            if reply.get('ok', 1) == 0:  # Break and return error on failure of any request
                return reply

            # reconnect if we have no more requests after the last 'add-interface',
            # as in this case the reconnect() above will be not called.
            #
            if msg['message'] == 'add-interface' and idx == len(messages)-1:
                fwglobals.g.fwagent.reconnect()

        if start_dhcp_server:
            fwutils.os_system('systemctl start isc-dhcp-server', '_on_apply_router_config')

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

def preprocess_reorder_sub_interfaces(requests):
    '''Implements part of the _preprocess_aggregated_request() logic.
    It rearranges 'add-interface'-s and 'remove-interface'-s requests
    in the aggregation to ensure that the sub-interfaces are added after
    the parent interface was added and are removed before the parent interface
    is removed. This is needed for VLAN interfaces.

    :param requests: The list of 'remove-X' and 'add-X' requests.
    :returns: reordered list of requests.
    '''
    # Firstly we build helper hash of indexes of parent and sub-interfaces
    # by 'dev_id'. Than we just swap the last sub-interface 'remove-interface'
    # in the list with the parent 'remove-interface', so the parent interface
    # will be removed at last. And we swap the first sub-interface
    # 'add-interface' in the list with the parent 'add-interface', so the parent
    # interface will be added after before any of it's sub-interfaces.
    #
    add_remove_interface_indexes = { 'add-interface': {}, 'remove-interface': {}}
    for index, _request in enumerate(requests):

        req_name, req_params = _request['message'], _request['params']
        if req_name == "add-interface":
            indexes = add_remove_interface_indexes['add-interface']
        elif req_name == "remove-interface":
            indexes = add_remove_interface_indexes['remove-interface']
        else:
            continue

        parent_dev_id, vlan_id = fwutils.dev_id_parse_vlan(req_params['dev_id'])
        if not parent_dev_id in indexes:
            indexes[parent_dev_id] = {}
        dev_indexes = indexes[parent_dev_id]

        # Store index of 'add-interface'/remove-interface' of parent interface.
        #
        if not vlan_id:
            dev_indexes.update({ 'parent_index': index })
            continue

        # Store index of 'add-interface'/'remove-interface' of VLAN sub-interface.
        # For 'add-interface' we store the smallest index (the first one),
        # so 'add-interface' of the parent interface will be swapped with
        # the first corresponding sub-interface. For 'remove-interface' we
        # store the largest index (the latest), so 'remove-interface'
        # of the parent interface will be swapped with the last corresponding
        # sub-interface.
        #
        if req_name == "remove-interface":
            dev_indexes.update({ 'sub_index': index })
        elif dev_indexes.get('sub_index') == None:  # and req_name == "add-interface"
            dev_indexes.update({ 'sub_index': index })

    # Now go over hash keys and modify the aggregation if needed.
    #
    for dev_indexes in add_remove_interface_indexes['add-interface'].values():
        sub_index    = dev_indexes.get('sub_index', -1)
        parent_index = dev_indexes.get('parent_index', -1)
        if parent_index > -1 and sub_index > -1 and parent_index > sub_index:
            requests[parent_index], requests[sub_index] = requests[sub_index], requests[parent_index]

    for dev_indexes in add_remove_interface_indexes['remove-interface'].values():
        sub_index    = dev_indexes.get('sub_index', -1)
        parent_index = dev_indexes.get('parent_index', -1)
        if parent_index > -1 and sub_index > -1 and parent_index < sub_index:
            requests[parent_index], requests[sub_index] = requests[sub_index], requests[parent_index]

    return requests
