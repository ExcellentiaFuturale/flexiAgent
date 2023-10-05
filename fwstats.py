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

# Either psutil.sensors_temperatures() or psutil.cpu_persent() generates a lot of warnings:
#  /usr/lib/python3/dist-packages/psutil/_pslinux.py:1222: RuntimeWarning: ignoring FileNotFoundError(2, 'No such file or directory') for file '/sys/class/hwmon/hwmon0/temp1_input'
#    warnings.warn("ignoring %r for file %r" % (err, path),
# That happens for psutil 5.5.1 on Ubuntu 20.04 (Kernel 5.4).
# More info why it happens can be found here:
#   https://github.com/giampaolo/psutil/issues/1650
# We suppress this warning to have a clean screen, when running fwagent daemon from command line.
#
import warnings

warnings.filterwarnings(action="ignore", message="ignoring.*/sys/class/hwmon/hwmon", category=RuntimeWarning, module=".*psutil")
import copy
import math
import time
import os
import psutil
import sys
import yaml

import fw_os_utils
import fwglobals
import fwlte
import fwthread
import fwutils
import fwwifi
from fwobject import FwObject
from fwtunnel_stats import tunnel_stats_get

system_checker_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tools/system_checker/")
sys.path.append(system_checker_path)
import fwsystem_checker_common

# Keep updates up to 1 hour ago
UPDATE_LIST_MAX_SIZE = 120

class FwStatistics(FwObject):
    """This object collects various statistics about FlexiWAN system.
    """
    def __init__(self):
        FwObject.__init__(self)

        self.updates_list   = []   # list of probes - keeps probes that are not fetched by flexiManage
        self.stats          = {}   # latest probe
        self.device_info    = {}   # various data that are not exactly statistics, like reconfig hash
        self.vpp_pid        = ''

        self._reset_stats()

    def _reset_stats(self):
        self.stats = {
            'ok':                   0,
            'running':              False,
            'last':                 {},
            'bytes':                {},
            'tunnel_stats':         {},
            'health':               {},
            'period':               0,
            'lte_stats':            {},
            'wifi_stats':           {},
            'application_stats':    {},
            'vrrp':                 {},
            'bgp':                  {},
            'alerts':               {},
            'alerts_hash':          ''
        }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.finalize()

    def initialize(self):
        self.thread_statistics = fwthread.FwThread(target=self.statistics_thread_func, name='Statistics', log=self.log)
        self.thread_statistics.start()
        self.thread_device_info = fwthread.FwRouterThread(target=self.device_info_thread_func, name='Device Info', log=self.log)
        self.thread_device_info.start()
        super().initialize()

    def finalize(self):
        """Destructor method
        """
        if self.thread_statistics:
            self.thread_statistics.join()
            self.thread_statistics = None
        if self.thread_device_info:
            self.thread_device_info.join()
            self.thread_device_info = None
        super().finalize()

    def statistics_thread_func(self, ticks):
        timeout = 30
        if (ticks % timeout) == 0:
            if fwglobals.g.loadsimulator:
                fwglobals.g.loadsimulator.update_stats()
            else:
                if ticks == timeout: # on first time, add the info
                    renew_lte_wifi_stats = True
                    add_bgp_stats = True
                else:
                    renew_lte_wifi_stats = ticks % (timeout * 2) == 0 # Renew LTE and WiFi statistics every second update
                    add_bgp_stats = ticks % (timeout * 6) == 0 # Add bgp info to stats once in 3 minutes
                self._update_stats(renew_lte_wifi_stats=renew_lte_wifi_stats, add_bgp_stats=add_bgp_stats)

    def device_info_thread_func(self, ticks):
        if (ticks % 10) == 0:
            self.get_device_info(cached=False)

    def _get_vrrp_status(self):

        def _get_vrrp_state_str(enum):
            if enum & 0:
                return 'Initialize'
            if enum & 1:
                return 'Backup'
            if enum & 2:
                return 'Master'
            if enum & 3:
                return 'Interface Down'
            return ''

        states = {}
        vrrp_dump = fwglobals.g.router_api.vpp_api.vpp.call('vrrp_vr_dump')
        for vrrp in vrrp_dump:
            vrid = vrrp.config.vr_id
            states[vrid] = {}
            states[vrid]['state'] = _get_vrrp_state_str(vrrp.runtime.state)
            states[vrid]['adjusted_priority'] = vrrp.runtime.tracking.priority

        return states

    def _update_stats(self, renew_lte_wifi_stats=True, add_bgp_stats=False):
        """Update statistics dictionary using values retrieved from VPP interfaces.

        :returns: None.
        """
        # If vpp is not running or has crashed (at least one of its process
        # IDs has changed), reset the statistics and update the vpp pids list
        current_vpp_pid = fw_os_utils.vpp_pid()
        if not current_vpp_pid or current_vpp_pid != self.vpp_pid:
            self._reset_stats()
            self.vpp_pid = current_vpp_pid

        prev_stats = dict(self.stats)  # copy of prev self.stats
        if not self.vpp_pid or not fwglobals.g.router_api.state_is_started():
            self.stats['ok'] = 0
        else:
            new_stats = fwutils.get_vpp_if_count()
            if not new_stats:
                self.stats['ok'] = 0
            else:
                self.stats['time'] = time.time()
                self.stats['last'] = new_stats
                self.stats['ok'] = 1
                # Update info if previous self.stats valid
                if prev_stats['ok'] == 1:
                    if_bytes = {}
                    tunnel_stats = tunnel_stats_get()
                    fwglobals.g.stun_wrapper.handle_down_tunnels(tunnel_stats)
                    for iface, counts in list(self.stats['last'].items()):
                        if (iface.startswith('gre') or
                            iface.startswith('loop') or
                            iface.startswith('ppp') or
                            iface.startswith('tun')): continue
                        prev_stats_if = prev_stats['last'].get(iface, None)
                        if prev_stats_if != None:
                            rx_bytes = 1.0 * (counts['rx_bytes'] - prev_stats_if['rx_bytes'])
                            rx_pkts  = 1.0 * (counts['rx_pkts'] - prev_stats_if['rx_pkts'])
                            tx_bytes = 1.0 * (counts['tx_bytes'] - prev_stats_if['tx_bytes'])
                            tx_pkts  = 1.0 * (counts['tx_pkts'] - prev_stats_if['tx_pkts'])
                            calc_stats = {
                                    'rx_bytes': rx_bytes,
                                    'rx_pkts': rx_pkts,
                                    'tx_bytes': tx_bytes,
                                    'tx_pkts': tx_pkts
                                }
                            if (iface.startswith('vxlan_tunnel')):
                                vxlan_id = int(iface[12:])
                                tunnel_id = math.floor(vxlan_id/2)
                                t_stats = tunnel_stats.get(tunnel_id)
                                if t_stats:
                                    t_stats.update(calc_stats)
                            elif (iface.startswith('ipip')):
                                ipip_id = int(iface[4:])
                                tunnel_id = math.floor(ipip_id/2)
                                t_stats = tunnel_stats.get(tunnel_id)
                                if t_stats:
                                    t_stats.update(calc_stats)
                            else:
                                # For other interfaces try to get interface id
                                dev_id = fwutils.vpp_if_name_to_dev_id(iface)
                                if dev_id:
                                    if_bytes[dev_id] = calc_stats

                    self.stats['bytes'] = if_bytes
                    self.stats['tunnel_stats'] = tunnel_stats
                    self.stats['period'] = self.stats['time'] - prev_stats['time']
                    self.stats['running'] = True if fw_os_utils.vpp_does_run() else False
                    self.stats['vrrp'] = self._get_vrrp_status()

        if renew_lte_wifi_stats:
            self.stats['lte_stats'] = fwglobals.g.modems.get_stats()
            self.stats['wifi_stats'] = fwwifi.get_stats()
        else:
            self.stats['lte_stats'] = prev_stats['lte_stats']
            self.stats['wifi_stats'] = prev_stats['wifi_stats']

        if add_bgp_stats:
            self.stats['bgp'] = fwglobals.g.router_api.frr.get_bgp_summary_json()
        else:
            self.stats['bgp'] = {}

        if len(self.updates_list) is UPDATE_LIST_MAX_SIZE:
            self.updates_list.pop(0)

        stats = dict(self.stats)
        system_health = self._get_system_health()
        self.updates_list.append({
                'ok': stats['ok'],
                'running': stats['running'],
                'stats': stats['bytes'],
                'period': stats['period'],
                'tunnel_stats': stats['tunnel_stats'],
                'lte_stats': stats['lte_stats'],
                'wifi_stats': stats['wifi_stats'],
                'health': system_health,
                'utc': time.time(),
                'vrrp': stats['vrrp'],
                'bgp': stats['bgp'],
                'alerts': fwglobals.g.notifications.calculate_alerts(stats['tunnel_stats'], system_health),
                'alerts_hash': fwglobals.g.notifications.get_alerts_hash()
            })

    def _get_system_health(self):
        # Get CPU info
        try:
            cpu_stats = psutil.cpu_percent(percpu = True)
        except Exception as e:
            fwglobals.log.excep("Error getting cpu stats: %s" % str(e))
            cpu_stats = [0]
        # Get memory info
        try:
            memory_stats = psutil.virtual_memory().percent
        except Exception as e:
            fwglobals.log.excep("Error getting memory stats: %s" % str(e))
            memory_stats = 0
        # Get disk info
        try:
            disk_stats = psutil.disk_usage('/').percent
        except Exception as e:
            fwglobals.log.excep("Error getting disk stats: %s" % str(e))
            disk_stats = 0
        # Get temperature info
        try:
            temp_stats = {'value':0.0, 'high':100.0, 'critical':100.0}
            all_temp = psutil.sensors_temperatures()
            for ttype, templist in list(all_temp.items()):
                if ttype == 'coretemp':
                    temp = templist[0]
                    if temp.current: temp_stats['value'] = temp.current
                    if temp.high: temp_stats['high'] = temp.high
                    if temp.critical: temp_stats['critical'] = temp.critical
        except Exception as e:
            fwglobals.log.excep("Error getting temperature stats: %s" % str(e))

        return {'cpu': cpu_stats, 'mem': memory_stats, 'disk': disk_stats, 'temp': temp_stats}

    def get_device_stats(self):
        """Return a new statistics dictionary.

        :returns: Statistics dictionary.
        """
        res_update_list = list(self.updates_list)
        del self.updates_list[:]

        reconfig                     = self.device_info.get('reconfig',"")
        ikev2_certificate_expiration = self.device_info.get('ikev2', {})
        apps_stats = fwglobals.g.applications_api.get_stats()

        # If the list of updates is empty, append a dummy update to
        # set the most up-to-date status of the router. If not, update
        # the last element in the list with the current status of the router
        if fwglobals.g.loadsimulator:
            status = True
            state = 'running'
            reason = ''
            reconfig = ''
        else:
            status = True if fw_os_utils.vpp_does_run() else False
            (state, reason) = fwutils.get_router_status()
        if not res_update_list:
            info = {
                'ok': self.stats['ok'],
                'running': status,
                'state': state,
                'stateReason': reason,
                'stats': {},
                'application_stats': apps_stats,
                'tunnel_stats': {},
                'vrrp': {},
                'bgp': {},
                'lte_stats': {},
                'wifi_stats': {},
                'health': {},
                'period': 0,
                'utc': time.time(),
                'ikev2': ikev2_certificate_expiration,
                'reconfig': reconfig,
                'alerts': fwglobals.g.notifications.alerts,
                'alerts_hash': fwglobals.g.notifications.get_alerts_hash()
            }
            res_update_list.append(info)
        else:
            res_update_list[-1]['running'] = status
            res_update_list[-1]['state'] = state
            res_update_list[-1]['stateReason'] = reason
            res_update_list[-1]['reconfig'] = reconfig
            res_update_list[-1]['application_stats'] = apps_stats
            res_update_list[-1]['health'] = self._get_system_health()
            res_update_list[-1]['ikev2'] = ikev2_certificate_expiration
        return res_update_list

    def get_device_info(self, cached=True, job_ids=None, tunnel_ids=None):

        if not self.device_info or cached == False:

            info = {}

            with open(fwglobals.g.VERSIONS_FILE, 'r') as stream:
                info = yaml.load(stream, Loader=yaml.BaseLoader)

            predefined_job_ids = fwglobals.g.jobs.get_job_ids_by_request(['upgrade-device-sw', 'upgrade-linux-sw'])
            info['jobs'] = fwglobals.g.jobs.dump(predefined_job_ids)

            version, codename = fwutils.get_linux_distro()
            info['distro'] = {'version': version, 'codename': codename}

            # The device info parts below might be impacted by configuration requests,
            # so we take a lock to avoid re-configuration under our legs.
            #
            with fwglobals.g.handle_request_lock:
                info['network'] = {}
                info['network']['interfaces'] = list(fwutils.get_linux_interfaces(cached=False).values())
                previous_reconfig             = self.device_info.get('reconfig')
                info['reconfig']              = '' if fwglobals.g.loadsimulator else fwutils.get_reconfig_hash(previous_reconfig)
                info['ikev2']                 = fwglobals.g.ikev2.get_certificate_expiration()
                info['cpuInfo']               = fwsystem_checker_common.Checker().get_cpu_info()

            self.device_info = info


        info = copy.deepcopy(self.device_info)
        if job_ids:
            info.update({'jobs': info['jobs'] + fwglobals.g.jobs.dump(job_ids)})
        if tunnel_ids:
            info.update({'tunnels': self._prepare_tunnel_info(tunnel_ids)})
        return info


    def update_vpp_state(self, running):
        """Update router state field.

        :param update_state: True if vRouter (VPP) is running, False otherwise.

        :returns: None.
        """
        self.stats['running'] = running

    def update_ikev2_certificate_expiration(self, info):
        # No lock for simplicity, the penalty might be one more unnecessary
        # 'get-device-certificate' transaction
        #
        self.device_info['ikev2'] = info