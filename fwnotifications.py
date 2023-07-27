#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2023  flexiWAN Ltd.
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

import hashlib
import json

import fwglobals


class FwNotifications:
    """
    This class monitors statistics data and updates an alerts dictionary based on the last 10 samples of each event type and tunnel.
    If there are more than 6 warning or critical samples, an alert is created.
    Only one active alert can exist per event type or tunnel at a time.
    Alerts are turned off after counting 6 successes for warning alerts, and after counting 6 warnings and successes for critical alerts.
    """
    # Number of success/failure samples to turn off an alert/define a severity to an alert
    NOTIFICATIONS_CRITICAL_SAMPLES_THRESHOLD = 6
    NOTIFICATIONS_WARNING_SAMPLES_THRESHOLD = 6
    NOTIFICATIONS_SUCCESS_SAMPLES_THRESHOLD = 6
    # Numbers to mark success/warning/critical samples in the samples array
    MARKED_AS_SUCCESS = 0
    MARKED_AS_WARNING = 1
    MARKED_AS_CRITICAL = 2
    SAMPLES_ARRAY_SIZE = 10


    def __init__(self):
        self.alerts = {}
        self.event_counts = {}

    def get_alerts_hash(self):
        """
        This function iterates the alerts dictionary and returns a hash of its contents.
        The hash is calculated by concatenating the key-value pairs of the dictionary
        and then running the resulting string through an MD5 hashing algorithm.

        :return: A string containing the MD5 hash of the dictionary contents.
        """
        # global alerts
        alert_data = {}
        for key, value in self.alerts.items():
            alert_data[key] = {k: v for k, v in value.items() if k not in ('value', 'threshold')}
        return hashlib.md5(json.dumps(alert_data, sort_keys=True).encode()).hexdigest() if self.alerts else ''

    def calculate_alerts(self, tunnel_stats, system_health):
        config = fwglobals.g.system_api.cfg_db.get_notifications_config()
        if not config:
            return {}
        rules = config.get('rules', {})
        tunnel_rules = []
        for event_type, event_settings in rules.items():
            if event_settings.get('type') == 'tunnel':
                tunnel_rules.append(event_type)
                continue
            self._analyze_stats_value(event_type, event_settings, system_health)
        tunnels = fwglobals.g.router_api.cfg_db.get_tunnels()
        tunnel_dict = {tunnel['tunnel-id']: tunnel for tunnel in tunnels}
        for tunnel_id in tunnel_stats:
            tunnel_statistics = tunnel_stats[tunnel_id]
            tunnel_notifications = tunnel_dict[tunnel_id].get('notificationsSettings', {})
            for tunnel_rule in tunnel_rules:
                self._analyze_stats_value(tunnel_rule, tunnel_notifications.get(tunnel_rule, rules[tunnel_rule]), tunnel_statistics, tunnel_id)
        self.alerts = self._get_dict_without_empty_entries_recursive(self.alerts)
        return self.alerts

    def _get_entry(self, dictionary, event_type, initial_value, tunnel_id=None):
        if tunnel_id:
            if event_type not in dictionary:
                dictionary[event_type] = {tunnel_id: initial_value}
            elif tunnel_id not in dictionary[event_type]:
                dictionary[event_type][tunnel_id] = initial_value
            entry = dictionary[event_type][tunnel_id]
        else:
            if event_type not in dictionary:
                dictionary[event_type] = initial_value
            entry = dictionary[event_type]
        return entry

    def _get_value_from_stats(self, event_type, stats):
        stats_key_by_event_type = {
            'Device memory usage': 'mem',
            'Hard drive usage': 'disk',
            'Temperature':'temp',
            'Link/Tunnel round trip time':'rtt',
            'Link/Tunnel default drop rate':'drop_rate'
        }
        if event_type == 'Temperature':
            current_value = stats[stats_key_by_event_type.get(event_type)]['value']
        else:
            current_value = stats[stats_key_by_event_type.get(event_type)]
        return current_value

    def _get_threshold(self, event_type, event_settings, stats):
        if event_type == 'Temperature':
            event_critical_threshold = stats['temp']['critical']
            if stats['temp']['high'] != event_critical_threshold:
                event_warning_threshold = stats['temp']['high']
            else:
                event_warning_threshold = None
        else:
            event_critical_threshold = event_settings.get('criticalThreshold')
            event_warning_threshold = event_settings.get('warningThreshold')
        return event_critical_threshold, event_warning_threshold

    def _analyze_stats_value(self, event_type, event_settings, stats, tunnel_id=None):
        stats_value = self._get_value_from_stats(event_type, stats)
        critical_threshold, warning_threshold = self._get_threshold(event_type, event_settings, stats)

        if critical_threshold and stats_value >= critical_threshold:
            event_status = self.MARKED_AS_CRITICAL
        elif warning_threshold and stats_value >= warning_threshold:
            event_status = self.MARKED_AS_WARNING
        else:
            event_status = self.MARKED_AS_SUCCESS

        counts_entry = self._get_entry(self.event_counts, event_type, [self.MARKED_AS_SUCCESS] * (self.SAMPLES_ARRAY_SIZE), tunnel_id)
        counts_entry.append(event_status)
        del counts_entry[0] # Keep WINDOWS SIZE
        event_unit = event_settings.get('thresholdUnit')
        event_entry = self._get_entry(self.alerts, event_type, {}, tunnel_id)
        last_severity = self._get_last_severity(event_entry)
        is_critical = self._is_critical(counts_entry)
        is_warning = self._is_warning(counts_entry)
        if is_critical and last_severity != 'critical':
            event_entry.update({'value': stats_value,'threshold': critical_threshold, 'severity': 'critical', 'unit': event_unit})
        elif is_warning and last_severity != 'warning':
            event_entry.update({'value': stats_value,'threshold': warning_threshold, 'severity': 'warning', 'unit': event_unit})
        # an alert removal operation can be done only if the current sample is success/warning
        elif not is_critical:
            success_count = counts_entry.count(self.MARKED_AS_SUCCESS)
            warning_count = counts_entry.count(self.MARKED_AS_WARNING)
            if ((last_severity == 'warning' and success_count >= self.NOTIFICATIONS_SUCCESS_SAMPLES_THRESHOLD)
                        or (last_severity == 'critical' and (success_count + warning_count) >= self.NOTIFICATIONS_SUCCESS_SAMPLES_THRESHOLD)):
                        self._delete_alerts_entry(event_type, tunnel_id)

    def _create_or_get_alert_object(self, event_type, tunnel_id):
        self.alerts.setdefault(event_type, {})
        if tunnel_id:
            self.alerts[event_type].setdefault(tunnel_id, {})
        return self.alerts[event_type][tunnel_id] if tunnel_id else self.alerts[event_type]

    def _get_last_severity(self, event_entry):
        return event_entry.get('severity')

    def _is_critical(self, counts_entry):
        return counts_entry.count(self.MARKED_AS_CRITICAL) >= self.NOTIFICATIONS_CRITICAL_SAMPLES_THRESHOLD

    def _is_warning(self, counts_entry):
        return counts_entry.count(self.MARKED_AS_WARNING) + counts_entry.count(self.MARKED_AS_CRITICAL) >= self.NOTIFICATIONS_WARNING_SAMPLES_THRESHOLD

    def _delete_alerts_entry(self, event_type, tunnel_id):
        if tunnel_id and tunnel_id in self.alerts[event_type]:
            del self.alerts[event_type][tunnel_id]
            # Delete event_type key from alerts if its associated dictionary is empty
            if not self.alerts[event_type]:
                del self.alerts[event_type]
        elif not tunnel_id:
            del self.alerts[event_type]

     # Discard empty dictionaries from initialization; final alerts dictionary only requires keys with data
    def _get_dict_without_empty_entries_recursive(self, dictionary):
        new_dict = {}
        for key, value in dictionary.items():
            if isinstance(value, dict):
                value = self._get_dict_without_empty_entries_recursive(value)
            if value:
                new_dict[key] = value
        return new_dict





