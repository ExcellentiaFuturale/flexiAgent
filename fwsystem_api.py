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
import fwlte

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
        self.thread_lte_watchdog = None
        self.lte_reconnect_interval_default = 10
        self.lte_reconnect_interval_max = 120
        self.lte_reconnect_interval = self.lte_reconnect_interval_default
        self.lte_reconnect_retrials = 1

    def initialize(self):
        if self.thread_lte_watchdog is None:
            self.thread_lte_watchdog = fwthread.FwRouterThread(target=self.lte_watchdog_thread_func, name='LTE Watchdog', log=self.log)
            self.thread_lte_watchdog.start()

    def finalize(self):
        if self.thread_lte_watchdog:
            self.thread_lte_watchdog.join()
            self.thread_lte_watchdog = None

    def lte_watchdog_thread_func(self, ticks):
        """LTE watchdog thread.
        Monitors proper configuration of LTE modem. The modem is configured
        and connected to provider by 'add-lte' request received from flexiManage
        with no relation to vpp. As long as it was not removed by 'remove-lte',
        it should stay connected and the IP address and other configuration
        parameters received from provider should match these configured in linux
        for the correspondent interface.
        """
        if  fwglobals.g.router_api.state_is_starting_stopping():
            return

        is_all_lte_interfaces_connected = True
        check_lte_disconnection = ticks % self.lte_reconnect_interval == 0

        wan_list = fwglobals.g.system_cfg.dump(types=['add-lte'])
        for wan in wan_list:
            dev_id = wan['params']['dev_id']
            metric = wan['params']['metric']
            modem_mode = fwlte.get_cache_val(dev_id, 'state')
            if modem_mode == 'resetting' or modem_mode == 'connecting':
                continue

            name = fwutils.dev_id_to_tap(dev_id, check_vpp_state=True, print_log=False)
            if not name:
                name = fwutils.dev_id_to_linux_if(dev_id)

            # Ensure that lte connection is opened.
            # Sometimes, the connection between modem and provider becomes disconnected
            #
            if check_lte_disconnection:
                cmd = "fping 8.8.8.8 -C 1 -q -R -I %s > /dev/null 2>&1" % name
                ok = not subprocess.call(cmd, shell=True)
                if not ok:
                    connected = fwlte.mbim_is_connected(dev_id)
                    if not connected:
                        self.log.debug("lte modem is disconnected on %s" % dev_id)

                        is_all_lte_interfaces_connected = False

                        fwglobals.g.system_api.restore_configuration(types=['add-lte'])

                        if self.lte_reconnect_retrials % 3 == 0:
                            self.lte_reconnect_interval = min(self.lte_reconnect_interval_max, self.lte_reconnect_interval * 2)
                    else:
                        # Make sure that LTE Linux interface is up
                        linux_ifc_name = fwutils.dev_id_to_linux_if(dev_id)
                        os.system('ifconfig %s up' % linux_ifc_name)

            # Ensure that provider did not change IP provisioned to modem,
            # so the IP that we assigned to the modem interface is still valid.
            # If it was changed, go and update the interface, vpp, etc.
            #
            if ticks % 30 == 0:
                modem_addr = fwlte.get_ip_configuration(dev_id, 'ip', False)
                if modem_addr:
                    iface_addr = fwutils.get_interface_address(name, log=False)

                    if iface_addr != modem_addr:
                        self.log.debug("%s: LTE IP change detected: %s -> %s" % (dev_id, iface_addr, modem_addr))

                        # If vpp runs, just update the interface IP and gateway.
                        # Our IP monitoring thread should detect the change in Linux IPs
                        # and continue with applying rest configuration related to IP changes
                        if fwglobals.g.router_api.state_is_started():
                            new_gw = fwlte.get_ip_configuration(dev_id, 'gateway')
                            mtu = fwutils.get_linux_interface_mtu(name)
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
                                mtu=mtu,
                                if_name=None,
                                netplan_apply=True
                            )
                        else:
                            fwlte.configure_interface({
                                'dev_id': dev_id,
                                'metric': wan['params']['metric']
                            })

                        self.log.debug("%s: LTE IP was changed: %s -> %s" % (dev_id, iface_addr, modem_addr))

        if check_lte_disconnection:
            if is_all_lte_interfaces_connected:
                self.lte_reconnect_interval = self.lte_reconnect_interval_default
                self.lte_reconnect_retrials = 0
            else:
                self.lte_reconnect_retrials += 1

    def sync_full(self, incoming_requests):
        if len(incoming_requests) == 0:
            self.log.info("sync_full: incoming_requests is empty, no need to full sync")
            return True

        self.log.debug("sync_full: start system full sync")

        fwutils.reset_system_cfg()
        FwCfgRequestHandler.sync_full(self, incoming_requests)

        self.log.debug("sync_full: system full sync succeeded")

