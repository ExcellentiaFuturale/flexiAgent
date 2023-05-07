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
import math
import time
import psutil

import fw_os_utils
import fwglobals
import fwlte
import fwthread
import fwutils
import fwwifi
import hashlib
from fwobject import FwObject
from fwtunnel_stats import tunnel_stats_get

# Keep updates up to 1 hour ago
UPDATE_LIST_MAX_SIZE = 120
# Number of success/failure samples to turn off an alert/define a severity to an alert
CRITICAL_SAMPLES_THRESHOLD = 6
WARNING_SAMPLES_THRESHOLD = 6
SUCCESS_SAMPLES_THRESHOLD = 6
# Numbers to mark success/warning/critical samples in the samples array
MARKED_AS_SUCCESS = 0
MARKED_AS_WARNING = 1
MARKED_AS_CRITICAL = 2

SAMPLES_ARRAY_SIZE = 10

alerts = {}
event_counts = {}

class EventMonitor:
    """
    This class monitors statistics data and updates an alerts dictionary based on the last 10 samples of each event type and tunnel.
    If there are more than 6 warning or critical samples, an alert is created.
    Only one active alert can exist per event type or tunnel at a time.
    Alerts are turned off after counting 6 successes for warning alerts, and after counting 6 warnings and successes for critical alerts.
    """
    def __init__(self):
       global event_counts
       global alerts

    # add success(0)/warning(1)/critical(2) to the count array of the event_type
    def add_value(self, event_type, value, event_unit, warning_threshold=None, critical_threshold=None, tunnel_id=None):
        # Initialize event type count array if not present
        if event_type not in event_counts:
            if tunnel_id:
                event_counts[event_type] = {tunnel_id: [MARKED_AS_SUCCESS] * SAMPLES_ARRAY_SIZE}
            else:
                event_counts[event_type] = [MARKED_AS_SUCCESS] * SAMPLES_ARRAY_SIZE

        if tunnel_id and event_type in event_counts:
            if tunnel_id not in event_counts[event_type]:
                event_counts[event_type][tunnel_id] = [MARKED_AS_SUCCESS] * SAMPLES_ARRAY_SIZE
            else:
                event_counts[event_type][tunnel_id].pop(0)

        elif event_type in event_counts:
            event_counts[event_type].pop(0)

        if critical_threshold and value >= critical_threshold:
            if tunnel_id:
                event_counts[event_type][tunnel_id].append(MARKED_AS_CRITICAL)
            else:
                event_counts[event_type].append(MARKED_AS_CRITICAL)
        elif warning_threshold and value >= warning_threshold:
            if tunnel_id:
                event_counts[event_type][tunnel_id].append(MARKED_AS_WARNING)
            else:
                event_counts[event_type].append(MARKED_AS_WARNING)
        else:
            if tunnel_id:
                event_counts[event_type][tunnel_id].append(MARKED_AS_SUCCESS)
            else:
                event_counts[event_type].append(MARKED_AS_SUCCESS)

        # Update alerts if necessary
        self.update_alerts(event_type, value, warning_threshold, critical_threshold, event_unit, tunnel_id)

    def is_critical(self, event_type, tunnel_id=None):
        if not tunnel_id:
            count_array = event_counts.get(event_type, [])
        else:
            count_array = event_counts.get(event_type).get(tunnel_id)
        return count_array.count(MARKED_AS_CRITICAL) >= CRITICAL_SAMPLES_THRESHOLD

    def is_warning(self, event_type, tunnel_id=None):
        if not tunnel_id:
            count_array = event_counts.get(event_type, [])
        else:
            count_array = event_counts.get(event_type).get(tunnel_id)
        return count_array.count(MARKED_AS_WARNING) + count_array.count(MARKED_AS_CRITICAL) >= WARNING_SAMPLES_THRESHOLD

    def update_alerts(self, event_type, value, warning_threshold, critical_threshold, event_unit, tunnel_id=None):
        event_samples = event_counts[event_type]
        if self.is_critical(event_type, tunnel_id):
            if not tunnel_id:
                alerts[event_type] = {'value': value,'threshold': critical_threshold, 'severity':'critical', 'unit': event_unit}
            else:
                if event_type not in alerts:
                    alerts[event_type] = {}
                if tunnel_id not in alerts[event_type]:
                    alerts[event_type][tunnel_id] = {}
                alerts[event_type][tunnel_id] = {'value': value,'threshold': critical_threshold, 'severity':'critical', 'unit': event_unit}
        elif self.is_warning(event_type, tunnel_id):
            if not tunnel_id:
                alerts[event_type] = {'value': value,'threshold': warning_threshold, 'severity':'warning', 'unit': event_unit}
            else:
                if event_type not in alerts:
                    alerts[event_type] = {}
                if tunnel_id not in alerts[event_type]:
                    alerts[event_type][tunnel_id] = {}
                alerts[event_type][tunnel_id] = {'value': value,'threshold': warning_threshold, 'severity':'warning', 'unit': event_unit}
        # Turn off alerts if necessary
        elif event_type in alerts:
            if not tunnel_id:
                if alerts[event_type]['severity'] == 'warning' and event_samples.count(MARKED_AS_SUCCESS) >= SUCCESS_SAMPLES_THRESHOLD:
                    del alerts[event_type]
                elif alerts[event_type]['severity'] == 'critical' and (event_samples.count(MARKED_AS_SUCCESS) + event_samples.count(MARKED_AS_WARNING)) >= SUCCESS_SAMPLES_THRESHOLD:
                    del alerts[event_type]
            elif tunnel_id in event_samples and tunnel_id in alerts[event_type]:
             if alerts[event_type].get(tunnel_id) and alerts[event_type][tunnel_id]['severity'] == 'warning' and event_samples[tunnel_id].count(MARKED_AS_SUCCESS) >= SUCCESS_SAMPLES_THRESHOLD:
                del alerts[event_type][tunnel_id]
                if not alerts[event_type]:
                    del alerts[event_type]
            elif alerts[event_type].get(tunnel_id) and alerts[event_type][tunnel_id]['severity'] == 'critical' and (event_samples[tunnel_id].count(MARKED_AS_SUCCESS) + event_samples[tunnel_id].count(MARKED_AS_WARNING)) >= SUCCESS_SAMPLES_THRESHOLD:
                del alerts[event_type][tunnel_id]
                if not alerts[event_type]:
                    del alerts[event_type]


class FwStatistics(FwObject):
    """This object collects various statistics about FlexiWAN system.
    """
    def __init__(self):
        FwObject.__init__(self)

        self.updates_list   = []   # list of probes - keeps probes that are not fetched by flexiManage
        self.stats          = {}   # latest probe
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

    def finalize(self):
        """Destructor method
        """
        if self.thread_statistics:
            self.thread_statistics.join()
            self.thread_statistics = None

    def statistics_thread_func(self, ticks):
        timeout = 30
        if (ticks % timeout) == 0:
            if fwglobals.g.loadsimulator:
                fwglobals.g.loadsimulator.update_stats()
            else:
                renew_lte_wifi_stats = ticks % (timeout * 2) == 0 # Renew LTE and WiFi statistics every second update
                self._update_stats(renew_lte_wifi_stats=renew_lte_wifi_stats)

    def get_alerts_hash(self):
        """
        This function iterates the alerts dictionary and returns a hash of its contents.
        The hash is calculated by concatenating the key-value pairs of the dictionary
        and then running the resulting string through an MD5 hashing algorithm.

        :return: A string containing the MD5 hash of the dictionary contents.
        """
        global alerts
        alert_data = {}
        for key, value in alerts.items():
            alert_data[key] = {k: v for k, v in value.items() if k not in ('value', 'threshold')}
        return hashlib.md5(json.dumps(alert_data, sort_keys=True).encode()).hexdigest() if alerts else ''

    def _update_stats(self, renew_lte_wifi_stats=True):
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

        if renew_lte_wifi_stats:
            self.stats['lte_stats'] = fwlte.get_stats()
            self.stats['wifi_stats'] = fwwifi.get_stats()
        else:
            self.stats['lte_stats'] = prev_stats['lte_stats']
            self.stats['wifi_stats'] = prev_stats['wifi_stats']

        if len(self.updates_list) is UPDATE_LIST_MAX_SIZE:
            self.updates_list.pop(0)

        stats = dict(self.stats)
        self.updates_list.append({
                'ok': stats['ok'],
                'running': stats['running'],
                'stats': stats['bytes'],
                'period': stats['period'],
                'tunnel_stats': stats['tunnel_stats'],
                'lte_stats': stats['lte_stats'],
                'wifi_stats': stats['wifi_stats'],
                'health': self._get_system_health(),
                'utc': time.time(),
                'alerts': self.calculate_alerts(stats['tunnel_stats']),
                'alerts_hash': self.get_alerts_hash()
            })

    def get_threshold(self, event_type, rule, health_stats):
        if event_type != 'Temperature':
            event_critical_threshold = rule.get('criticalThreshold')
            event_warning_threshold = rule.get('warningThreshold')
        else:
            if health_stats['temp']['high'] != health_stats['temp']['critical']:
                event_critical_threshold = health_stats['temp']['critical']
                event_warning_threshold = health_stats['temp']['high']
            else:
                event_critical_threshold = health_stats['temp']['critical']
                event_warning_threshold = None
        return event_critical_threshold, event_warning_threshold

    def get_current_value(self, event_type, health_stats=None, tunnel=None):
        type_to_stats = {
            'Device memory usage': 'mem',
            'Hard drive usage': 'disk',
            'Temperature':'temp',
            'Link/Tunnel round trip time':'rtt',
            'Link/Tunnel default drop rate':'drop_rate'
        }
        if tunnel:
            current_value = tunnel[type_to_stats.get(event_type)]
        elif event_type != 'Temperature':
            current_value = health_stats[type_to_stats.get(event_type)]
        else:
            current_value = health_stats[type_to_stats.get(event_type)]['value']
        return current_value

    def calculate_alerts(self, tunnel_stats):
        health_stats = self._get_system_health()
        global alerts
        health_tracker = EventMonitor()
        config = fwglobals.g.system_api.cfg_db.get_notifications_config()
        tunnels = fwglobals.g.router_api.cfg_db.get_tunnels()
        tunnel_dict = {tunnel['tunnel-id']: tunnel for tunnel in tunnels}
        if not config:
            return {}
        rules = config.get('rules', [])
        tunnel_rules = {}
        for rule in rules:
            event_type = rule.get('event')
            event_unit = rule.get('thresholdUnit')
            event_critical_threshold, event_warning_threshold = self.get_threshold(event_type, rule, health_stats)
            if event_type.startswith('Link/Tunnel'):
                tunnel_rules[event_type]=(event_warning_threshold, event_critical_threshold)
                continue
            current_value = self.get_current_value(event_type, health_stats)
            health_tracker.add_value(event_type, current_value, event_unit, event_warning_threshold, event_critical_threshold)
        for tunnel_id in tunnel_stats:
            tunnel = tunnel_stats[tunnel_id]
            tunnel_notifications = tunnel_dict[tunnel_id].get('notificationsSettings', [])
            for tunnel_rule in tunnel_rules:
                warning = tunnel_notifications[tunnel_rule].get('warningThreshold') if tunnel_notifications else tunnel_rules[tunnel_rule][0]
                critical = tunnel_notifications[tunnel_rule].get('criticalThreshold') if tunnel_notifications else tunnel_rules[tunnel_rule][1]
                current_value = self.get_current_value(tunnel_rule, tunnel=tunnel)
                health_tracker.add_value(tunnel_rule, current_value, event_unit, warning, critical, tunnel_id)
        return alerts

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

    def get_stats(self):
        """Return a new statistics dictionary.

        :returns: Statistics dictionary.
        """
        res_update_list = list(self.updates_list)
        del self.updates_list[:]

        reconfig = fwutils.get_reconfig_hash()
        ikev2_certificate_expiration = fwglobals.g.ikev2.get_certificate_expiration()
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
                'lte_stats': {},
                'wifi_stats': {},
                'health': {},
                'period': 0,
                'utc': time.time(),
                'reconfig': reconfig,
                'alerts': alerts,
                'alerts_hash':self.get_alerts_hash()
            }
            if fwglobals.g.ikev2.is_private_key_created():
                info['ikev2'] = ikev2_certificate_expiration
            res_update_list.append(info)
        else:
            res_update_list[-1]['running'] = status
            res_update_list[-1]['state'] = state
            res_update_list[-1]['stateReason'] = reason
            res_update_list[-1]['reconfig'] = reconfig
            res_update_list[-1]['application_stats'] = apps_stats
            res_update_list[-1]['health'] = self._get_system_health()
            if fwglobals.g.ikev2.is_private_key_created():
                res_update_list[-1]['ikev2'] = ikev2_certificate_expiration
        return res_update_list

    def update_vpp_state(self, running):
        """Update router state field.

        :param update_state: True if vRouter (VPP) is running, False otherwise.

        :returns: None.
        """
        self.stats['running'] = running