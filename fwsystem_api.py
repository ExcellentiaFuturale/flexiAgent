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
        check_lte_connectivity = ticks % self.lte_reconnect_interval.current == 0
        check_lte_ip = ticks % 30 == 0

        wan_list = fwglobals.g.system_cfg.dump(types=['add-lte'])
        for wan in wan_list:
            dev_id = wan['params']['dev_id']
            metric = wan['params']['metric'] or '0'

            modem = fwglobals.g.modems.get(dev_id)

            if modem.is_connecting_or_resetting():
                continue

            # Ensure that lte connection is opened.
            # Sometimes, the connection between modem and provider becomes disconnected
            #
            if check_lte_connectivity:
                is_connected = modem.check_connectivity()
                if not is_connected:
                    is_all_lte_interfaces_connected = False

            # Ensure that provider did not change IP provisioned to modem,
            # so the IP that we assigned to the modem interface is still valid.
            # If it was changed, go and update the interface, vpp, etc.
            #
            if check_lte_ip:
                modem.check_ip_change(metric)

        if check_lte_connectivity:
            self.lte_reconnect_interval.update(failure=not is_all_lte_interfaces_connected)


    def sync_full(self, incoming_requests):
        if len(incoming_requests) == 0:
            self.log.info("sync_full: incoming_requests is empty, no need to full sync")
            return True

        self.log.debug("sync_full: start system full sync")

        fwutils.reset_system_cfg(reset_lte_db=False)
        FwCfgRequestHandler.sync_full(self, incoming_requests)

        self.log.debug("sync_full: system full sync succeeded")

