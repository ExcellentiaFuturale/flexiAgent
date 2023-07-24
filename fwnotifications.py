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


class EventMonitor:
    """
    This class monitors statistics data and updates an alerts dictionary based on the last 10 samples of each event type and tunnel.
    If there are more than 6 warning or critical samples, an alert is created.
    Only one active alert can exist per event type or tunnel at a time.
    Alerts are turned off after counting 6 successes for warning alerts, and after counting 6 warnings and successes for critical alerts.
    """
    # Number of success/failure samples to turn off an alert/define a severity to an alert
    NOTIFICATIONS_CRITICAL_SAMPLES_THRESHOLD = 2
    NOTIFICATIONS_WARNING_SAMPLES_THRESHOLD = 2
    NOTIFICATIONS_SUCCESS_SAMPLES_THRESHOLD = 2
    # Numbers to mark success/warning/critical samples in the samples array
    MARKED_AS_SUCCESS = 0
    MARKED_AS_WARNING = 1
    MARKED_AS_CRITICAL = 2
    SAMPLES_ARRAY_SIZE = 3

    alerts = {}
    event_counts = {}

    def __init__(self):
        pass

    def get_alerts_hash(self):
        """
        This function iterates the alerts dictionary and returns a hash of its contents.
        The hash is calculated by concatenating the key-value pairs of the dictionary
        and then running the resulting string through an MD5 hashing algorithm.

        :return: A string containing the MD5 hash of the dictionary contents.
        """
        # global alerts
        alerts = EventMonitor.alerts
        alert_data = {}
        for key, value in alerts.items():
            alert_data[key] = {k: v for k, v in value.items() if k not in ('value', 'threshold')}
        return hashlib.md5(json.dumps(alert_data, sort_keys=True).encode()).hexdigest() if alerts else ''

    # add success(0)/warning(1)/critical(2) to the count array of the event_type
    def _add_value(self, event_type, value, event_unit, warning_threshold=None, critical_threshold=None, tunnel_id=None):
        if event_type not in self.event_counts:
            self.event_counts[event_type] = {tunnel_id: [self.MARKED_AS_SUCCESS] * (self.SAMPLES_ARRAY_SIZE-1)} if tunnel_id else [self.MARKED_AS_SUCCESS] * (self.SAMPLES_ARRAY_SIZE-1)
        elif tunnel_id:
            self.event_counts[event_type].setdefault(tunnel_id, [self.MARKED_AS_SUCCESS] * self.SAMPLES_ARRAY_SIZE).pop(0)
        # there is no tunnel_id but the event_type is present in the event_counts
        else:
            self.event_counts[event_type].pop(0)

        event_status = self.MARKED_AS_SUCCESS
        if critical_threshold and value >= critical_threshold:
            event_status = self.MARKED_AS_CRITICAL
        elif warning_threshold and value >= warning_threshold:
            event_status = self.MARKED_AS_WARNING
        self.event_counts[event_type][tunnel_id].append(event_status) if tunnel_id else self.event_counts[event_type].append(event_status)
        # Update alerts if necessary
        self._update_alerts(event_type, value, warning_threshold, critical_threshold, event_unit, tunnel_id)

    def _is_critical(self, event_type, tunnel_id=None):
        count_array = self.event_counts.get(event_type, []) if not tunnel_id else self.event_counts.get(event_type).get(tunnel_id)
        return count_array.count(self.MARKED_AS_CRITICAL) >= self.NOTIFICATIONS_CRITICAL_SAMPLES_THRESHOLD

    def _is_warning(self, event_type, tunnel_id=None):
        count_array = self.event_counts.get(event_type, []) if not tunnel_id else self.event_counts.get(event_type).get(tunnel_id)
        return count_array.count(self.MARKED_AS_WARNING) + count_array.count(self.MARKED_AS_CRITICAL) >= self.NOTIFICATIONS_WARNING_SAMPLES_THRESHOLD

    def _get_last_severity(self, event_type, tunnel_id=None):
        alerts = EventMonitor.alerts
        alerts.setdefault(event_type, {})
        if tunnel_id and tunnel_id not in alerts[event_type]:
            return None
        last_severity = alerts[event_type].get('severity') if not tunnel_id else alerts[event_type][tunnel_id].get('severity')
        return last_severity

    def _create_or_get_alert_object(self, event_type, tunnel_id):
        alerts = EventMonitor.alerts
        alerts.setdefault(event_type, {})
        if tunnel_id:
            alerts[event_type].setdefault(tunnel_id, {})
        return alerts[event_type][tunnel_id] if tunnel_id else alerts[event_type]

    def _update_alert(self, alert_object, value, threshold, severity, event_unit):
        alert_object.update({'value': value,'threshold': threshold, 'severity': severity, 'unit': event_unit})

    def _update_alerts(self, event_type, value, warning_threshold, critical_threshold, event_unit, tunnel_id=None):
        alerts = EventMonitor.alerts
        if self._is_critical(event_type, tunnel_id) and self._get_last_severity(event_type, tunnel_id) != 'critical':
            alert_object = self._create_or_get_alert_object(event_type, tunnel_id)
            self._update_alert(alert_object, value, critical_threshold, 'critical', event_unit)

        elif self._is_warning(event_type, tunnel_id) and self._get_last_severity(event_type, tunnel_id) != 'warning':
            alert_object = self._create_or_get_alert_object(event_type, tunnel_id)
            self._update_alert(alert_object, value, warning_threshold, 'warning', event_unit)

        # an alert removal operation can be done only if the current sample is success/warning
        if event_type in alerts and not self._is_critical:
            event_samples = self.event_counts[event_type] if not tunnel_id else self.event_counts[event_type][tunnel_id]
            last_severity = self._get_last_severity(event_type, tunnel_id)
            success_count = event_samples.count(self.MARKED_AS_SUCCESS)
            warning_count = event_samples.count(self.MARKED_AS_WARNING)

            if ((last_severity == 'warning' and success_count >= self.NOTIFICATIONS_SUCCESS_SAMPLES_THRESHOLD)
                or (last_severity == 'critical' and (success_count + warning_count) >= self.NOTIFICATIONS_SUCCESS_SAMPLES_THRESHOLD)):
                if tunnel_id and tunnel_id in alerts[event_type]:
                    del alerts[event_type][tunnel_id]
                    # Delete event_type key from alerts if its associated dictionary is empty
                    if not alerts[event_type]:
                        del alerts[event_type]
                elif not tunnel_id:
                    del alerts[event_type]

    def _get_threshold(self, event_type, rule, health_stats):
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

    def _get_current_value(self, event_type, health_stats=None, tunnel_statistics=None):
        stats_key_by_event_type = {
            'Device memory usage': 'mem',
            'Hard drive usage': 'disk',
            'Temperature':'temp',
            'Link/Tunnel round trip time':'rtt',
            'Link/Tunnel default drop rate':'drop_rate'
        }
        if tunnel_statistics:
            current_value = tunnel_statistics[stats_key_by_event_type.get(event_type)]
        elif event_type == 'Temperature':
            current_value = health_stats[stats_key_by_event_type.get(event_type)]['value']
        else:
            current_value = health_stats[stats_key_by_event_type.get(event_type)]

        return current_value

    def calculate_alerts(self, tunnel_stats):
        health_stats = fwglobals.g.statistics.get_system_health()
        # global alerts
        # notifications = EventMonitor()
        config = fwglobals.g.system_api.cfg_db.get_notifications_config()
        if not config:
            return {}
        rules = config.get('rules', {})
        tunnel_rules = []
        for event_type, event_settings in rules.items():
            if event_settings.get('type') == 'tunnel':
                tunnel_rules.append(event_type)
                continue
            event_unit = event_settings.get('thresholdUnit')
            event_critical_threshold, event_warning_threshold = self._get_threshold(event_type, event_settings, health_stats)
            current_value = self._get_current_value(event_type, health_stats)
            self._add_value(event_type, current_value, event_unit, event_warning_threshold, event_critical_threshold)
        tunnels = fwglobals.g.router_api.cfg_db.get_tunnels()
        tunnel_dict = {tunnel['tunnel-id']: tunnel for tunnel in tunnels}
        for tunnel_id in tunnel_stats:
            tunnel_statistics = tunnel_stats[tunnel_id]
            tunnel_notifications = tunnel_dict[tunnel_id].get('notificationsSettings', {})
            for tunnel_rule in tunnel_rules:
                if tunnel_notifications:
                    warning = tunnel_notifications[tunnel_rule].get('warningThreshold')
                    critical = tunnel_notifications[tunnel_rule].get('criticalThreshold')
                else:
                    warning  = rules[tunnel_rule].get('warningThreshold')
                    critical = rules[tunnel_rule].get('criticalThreshold')
                event_unit = rules[tunnel_rule].get('thresholdUnit')
                current_value = self._get_current_value(tunnel_rule, tunnel_statistics=tunnel_statistics)
                self._add_value(tunnel_rule, current_value, event_unit, warning, critical, tunnel_id)
        return EventMonitor.alerts

