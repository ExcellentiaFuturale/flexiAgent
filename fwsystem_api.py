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

import time
import threading
import traceback
import subprocess
import fwglobals
import fwthread
import fwutils
import fwnetplan
import os
from fwcfg_request_handler import FwCfgRequestHandler
import fwlte_utils
import fw_os_utils
import fwwifi

fwsystem_translators = {
    'add-lte':               {'module': __import__('fwtranslate_add_lte'),    'api':'add_lte'},
    'remove-lte':            {'module': __import__('fwtranslate_revert'),    'api':'revert'},
}

class FWSYSTEM_API(FwCfgRequestHandler):
    """This is System API class representation.
        These APIs are used to handle system configuration requests regardless of the vpp state.
        e.g to enable lte connection even if the vpp is not running.
        They are invoked by the flexiManage over secure WebSocket
        connection using JSON requests.
        For list of available APIs see the 'fwsystem_translators' variable.
    """
    def __init__(self, cfg):
        """Constructor method
        """
        FwCfgRequestHandler.__init__(self, fwsystem_translators, cfg, fwglobals.g.system_cfg)
        self.lte_reconnect_interval  = fwutils.DYNAMIC_INTERVAL(value=10, max_value_on_failure=120)
        self.wifi_reconnect_interval = fwutils.DYNAMIC_INTERVAL(value=10, max_value_on_failure=600)
        self.thread_lte_wifi_watchdog = None

    def initialize(self):
        if self.thread_lte_wifi_watchdog is None:
            self.thread_lte_wifi_watchdog = fwthread.FwRouterThread(target=self.lte_wifi_watchdog_thread_func, name='LTE/WiFi Watchdog', log=self.log)
            self.thread_lte_wifi_watchdog.start()

    def finalize(self):
        if self.thread_lte_wifi_watchdog:
            self.thread_lte_wifi_watchdog.join()
            self.thread_lte_wifi_watchdog = None

    def wifi_watchdog(self, ticks):
        if not ticks % self.wifi_reconnect_interval.current == 0:
            return

        if not fwglobals.g.router_api.state_is_started():
            return

        wifi_interfaces = fwglobals.g.router_cfg.get_interfaces(device_type='wifi')
        if not wifi_interfaces:
            return

        if fw_os_utils.pid_of('hostapd'):
            return

        # at this point, router is running but hostapd process does not run
        self.log.debug("wifi watchdog: hostapd detected as stopped. starting it")
        _, err_str = fwwifi.start_hostapd(remove_files_on_error=False, ensure_hostapd_enabled=True)

        if err_str:
            self.log.debug(f"wifi watchdog: failed to start hostapd ({err_str}). Will try later again")
            self.wifi_reconnect_interval.update(failure=True)
            return

        self.log.debug("wifi watchdog: hostapd started")
        self.wifi_reconnect_interval.update(failure=False)

    def lte_wifi_watchdog_thread_func(self, ticks):
        """LTE / WiFi watchdog thread.
        Monitors proper configuration of LTE modem. The modem is configured
        and connected to provider by 'add-lte' request received from flexiManage
        with no relation to vpp. As long as it was not removed by 'remove-lte',
        it should stay connected and the IP address and other configuration
        parameters received from provider should match these configured in linux
        for the correspondent interface.
        """
        if fwglobals.g.router_api.state_is_starting_stopping():
            return

        try:
            self.lte_watchdog(ticks)
        except Exception as e:
            self.log.error(f'lte_watchdog failed. {str(e)}')

        try:
            self.wifi_watchdog(ticks)
        except Exception as e:
            self.log.error(f'wifi_watchdog failed. {str(e)}')

    def lte_watchdog(self, ticks):
        is_all_lte_interfaces_connected = True
        check_lte_disconnection = ticks % self.lte_reconnect_interval.current == 0

        wan_list = fwglobals.g.system_cfg.dump(types=['add-lte'])
        for wan in wan_list:
            dev_id = wan['params']['dev_id']
            metric = wan['params']['metric']

            modem = fwglobals.g.lte.get(dev_id)

            if modem.is_connecting_or_resetting():
                continue

            # "ifc_name" can be "wwan0" if vpp does not run, or "vppX" if vpp does run
            ifc_name = fwutils.dev_id_to_tap(dev_id, check_vpp_state=True, print_log=False)
            if not ifc_name:
                ifc_name = modem.nicname # -> "wwan0"

            # Ensure that lte connection is opened.
            # Sometimes, the connection between modem and provider becomes disconnected
            #
            if check_lte_disconnection:
                cmd = "fping 8.8.8.8 -C 1 -q -R -I %s > /dev/null 2>&1" % ifc_name
                ok = not subprocess.call(cmd, shell=True)
                if not ok:
                    connected = modem.is_connected()
                    if not connected:
                        self.log.debug("lte modem is disconnected on %s" % dev_id)

                        is_all_lte_interfaces_connected = False

                        fwglobals.g.system_api.restore_configuration(types=['add-lte'])
                    else:
                        # Make sure that LTE Linux interface is up
                        os.system(f'ifconfig {modem.nicname} up')

                        if fwglobals.g.router_api.state_is_started():
                            # if GW exists, ensure ARP entry exists in Linux
                            gw, _ = fwutils.get_interface_gateway(ifc_name)
                            if gw:
                                arp_entries = fwutils.get_gateway_arp_entries(gw)
                                valid_arp_entries = list(filter(lambda entry: 'PERMANENT' in entry, arp_entries))
                                if not valid_arp_entries:
                                    self.log.debug(f'no valid ARP entry found. gw={gw}, name={ifc_name}, dev_id={dev_id}, \
                                        arp_entries={str(arp_entries)}. adding now')
                                    fwglobals.g.lte.get(dev_id).set_arp_entry(is_add=True, gw=gw)

                            # ensure traffic control settings are configured
                            modem.ensure_tc_config()

            # Ensure that provider did not change IP provisioned to modem,
            # so the IP that we assigned to the modem interface is still valid.
            # If it was changed, go and update the interface, vpp, etc.
            #
            if ticks % 30 == 0:
                modem_addr, new_gw, _ = modem.get_ip_configuration(cache=False)
                if modem_addr:
                    iface_addr = fwutils.get_interface_address(ifc_name, log=False)

                    if iface_addr != modem_addr:
                        self.log.debug("%s: LTE IP change detected: %s -> %s" % (dev_id, iface_addr, modem_addr))

                        # If vpp runs, just update the interface IP and gateway.
                        # Our IP monitoring thread should detect the change in Linux IPs
                        # and continue with applying rest configuration related to IP changes
                        if fwglobals.g.router_api.state_is_started():
                            mtu = fwutils.get_linux_interface_mtu(ifc_name)

                            fwnetplan.add_remove_netplan_interface(\
                                is_add=True,
                                dev_id=dev_id,
                                ip=modem_addr,
                                gw=new_gw,
                                metric=int(metric),
                                dhcp='no',
                                type='WAN',
                                dnsServers=fwglobals.g.DEFAULT_DNS_SERVERS,
                                dnsDomains=None,
                                mtu=mtu
                            )
                        else:
                            modem.configure_interface(metric)

                        self.log.debug("%s: LTE IP was changed: %s -> %s" % (dev_id, iface_addr, modem_addr))

        if check_lte_disconnection:
            self.lte_reconnect_interval.update(failure=not is_all_lte_interfaces_connected)

    def sync_full(self, incoming_requests):
        if len(incoming_requests) == 0:
            self.log.info("sync_full: incoming_requests is empty, no need to full sync")
            return True

        self.log.debug("sync_full: start system full sync")

        fwutils.reset_system_cfg(reset_lte_db=False)
        FwCfgRequestHandler.sync_full(self, incoming_requests)

        self.log.debug("sync_full: system full sync succeeded")

