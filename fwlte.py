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

import json
import os
import re
import subprocess
import time
from datetime import datetime, timedelta

import serial

import fw_os_utils
import fwglobals
import fwutils
from fwcfg_request_handler import FwCfgMultiOpsWithRevert
from fwobject import FwObject


class MODEM_STATES():
    IDLE = 'IDLE'
    CONNECTING = 'CONNECTING'
    RESETTING = 'RESETTING'

class FwLinuxModem(FwObject):
    def __init__(self, usb_device):
        FwObject.__init__(self)

        self.usb_device = usb_device
        self.modem_manager_id = None
        self.linux_if = None
        self.at_ports = []
        self.driver = None
        self.vendor = None
        self.model = None
        self.imei = None
        self.sim_presented = None
        self.mode = None
        self.ip = None
        self.gateway = None
        self.dns_servers = []

        self.mbim_session = '0'

        self._initialize()

    def _initialize(self):
        modem_data = self._load_modem_manager_info()
        drivers = modem_data.get('generic', {}).get('drivers', [])
        if 'cdc_mbim' in drivers:
            self.driver = 'cdc_mbim'
            self.mode = 'MBIM'
        elif 'qmi_wwan' in drivers:
            self.driver = 'qmi_wwan'
            self.mode = 'QMI'

    def is_connected(self):
        return self._get_connection_state() == 'activated'

    def _get_connection_state(self):
        lines, err = self._run_mbimcli_command('--query-connection-state', print_error=True)
        # [/dev/cdc-wdm0] Connection status:
        #             Session ID: '0'
        #         Activation state: 'deactivated'
        #         Voice call state: 'none'
        #                 IP type: 'default'
        #             Context type: 'internet'
        #         Network error: 'unknown'
        for line in lines:
            if 'Activation state' in line:
                return line.split(':')[-1].strip().replace("'", '')
        return ''

    def _get_sim_card_status(self, data=None):
        modem_state, reason = self._get_modem_state(data)
        if modem_state == 'failed' and reason == 'sim-missing':
            # if modem failed due to another reason, it means that sim is presented
            return reason
        return 'present' # to keep backward compatibility, this string indicates in flexiManage that sim is ok

    def _mmcli_exec(self, flag, json_format=True):
        # -J at the end tells modem manager to return output in JSON format
        success, output = fwutils.exec(f'mmcli {flag} {"-J" if json_format else ""}')
        if not success:
            raise Exception(output)

        if json_format:
            output = json.loads(output)
        return output

    def _get_modem_state(self, data=None):
        if not data:
            data = self._get_modem_manager_data()
        state = data.get('generic', {}).get('state')
        reason = data.get('generic', {}).get('state-failed-reason')
        return state, reason

    def _mmcli_modem_exec(self, flag = None, json_format=True):
        '''
        Run ModemManager command for a specific modem index by adding the "-m {modem_path}  flag
        '''
        modem_path = self.modem_manager_id
        try:
            output = self._mmcli_exec(f'-m {modem_path} {flag}', json_format)
            return output
        except Exception as e:
            if "modem is not enabled yet" in str(e):
                self._mmcli_modem_exec('-e', False)
            elif "couldn't find modem" not in str(e):
                raise e

            # try to load modem once again. ModemManager may re-index it with a different "modem_path".
            self._load_modem_manager_info()
            if modem_path != self.modem_manager_id:
                return self._mmcli_exec(f'-m {self.modem_manager_id} {flag}', json_format)
            raise e

    def _load_modem_manager_info(self):
        # {
        #     "modem": {
        #         ...
        #         "dbus-path": "/org/freedesktop/ModemManager1/Modem/0",
        #         ...
        #      }
        # }
        modem_list_output = self._mmcli_exec('-L')
        modem_list = modem_list_output.get('modem-list', [])
        if not modem_list:
            # send scan command and check after few moments
            self._mmcli_exec('-S', False)
            time.sleep(5)
            modem_list = modem_list_output.get('modem-list', [])

        modem_info = None
        for modem in modem_list:
            modem_info_output = self._mmcli_exec(f'-m {modem}')
            modem_info = modem_info_output.get('modem')
            generic = modem_info.get('generic', {})

            primary_port = generic.get('primary-port')
            if primary_port != self.usb_device:
                continue

            self.modem_manager_id = modem_info.get('dbus-path')
            self.vendor = generic.get('manufacturer')
            self.model = generic.get('model')
            self.imei = modem_info.get('3gpp', {}).get('imei')
            self.sim_presented = self._get_sim_card_status(modem_info) == 'present'

            ports = generic.get('ports', [])
            for port in ports:
                if '(net)' in port:
                    self.linux_if = port.split('(net)')[0].strip()
                elif '(at)' in port:
                    at_port = port.split('(at)')[0].strip()
                    self.at_ports.append(at_port)

            try:
                self._mmcli_modem_exec(f'-e', False)
                self._mmcli_modem_exec(f'--signal-setup=5', False)
            except:
                pass

            break

        return modem_info

    def _run_qmicli_command(self, cmd, print_error=False):
        if self.mode != 'QMI':
            raise Exception("modem not in QMI mode")

        try:
            qmicli_cmd = f'qmicli --device=/dev/{self.usb_device} --device-open-proxy {cmd}'
            self.log.debug(f"_run_qmicli_command: {qmicli_cmd}")
            output = subprocess.check_output(qmicli_cmd, shell=True, stderr=subprocess.STDOUT).decode()
            if not output:
                self.log.debug('_run_qmicli_command: no output from command')
                return ([], None)
            return (output.splitlines(), None)
        except subprocess.CalledProcessError as err:
            err_str = str(err.output.strip())
            if print_error:
                self.log.error(f'_run_qmicli_command({cmd}): err={err_str}')
            raise Exception(err_str)

    def _run_mbimcli_command(self, cmd, print_error=False):
        if self.mode != 'MBIM':
            raise Exception("modem not in MBIM mode")
        try:
            mbimcli_cmd = f'mbimcli --device=/dev/{self.usb_device} --device-open-proxy {cmd}'
            if '--attach-packet-service' in mbimcli_cmd:
                # This command might take a long or even get stuck.
                # Hence, send SIGTERM after 10 seconds.
                # '-k 5' is to ensure that SIGTERM is not handled and ignored by the service
                # and it sends SIGKILL if process doesn't terminate after 5 second
                mbimcli_cmd = f'timeout -k 5 10 {mbimcli_cmd}'

            self.log.debug(f"_run_mbimcli_command: {mbimcli_cmd}")
            output = subprocess.check_output(mbimcli_cmd, shell=True, stderr=subprocess.STDOUT).decode()
            if not output:
                self.log.debug('_run_mbimcli_command: no output from command')
                return ([], None)
            return (output.splitlines(), None)
        except subprocess.CalledProcessError as err:
            err_str = str(err.output.strip())
            if print_error:
                self.log.error(f'_run_mbimcli_command({cmd}): err={err_str}')
            raise Exception(err_str)

    def _prepare_connection_params(self, apn=None, user=None, password=None, auth=None):
        connection_params = ['ip-type=ipv4'] # ask for IPv4 only. Available options are ipv4, ipv6, ipv4v6
        if apn:
            connection_params.append(f'apn={apn}')
        if user:
            connection_params.append(f'username={user}')
        if password:
            connection_params.append(f'password={password}')
        if auth:
            connection_params.append(f'auth={auth}')

        return ",".join(connection_params)

    def connect(self, apn=None, user=None, password=None, auth=None):
        connection_params = self._prepare_connection_params(apn, user, password, auth)
        mbim_commands = [
            '--query-subscriber-ready-status',
            '--query-registration-state',
            '--attach-packet-service',
            f'--connect={connection_params}'
        ]
        for cmd in mbim_commands:
            lines, err = self._run_mbimcli_command(cmd, print_error=True)
            if err:
                raise Exception(err)

        for idx, line in enumerate(lines):
            if 'IPv4 configuration available' in line and 'none' in line:
                self.log.debug(f'connect: failed to get IPv4 from the ISP. lines={str(lines)}')
                raise Exception(f'Failed to get IPv4 configuration from the ISP')
            if 'Session ID:' in line:
                session = line.split(':')[-1].strip().replace("'", '')
                self.mbim_session = session
                continue
            if 'IP [0]:' in line:
                ip = line.split(':')[-1].strip().replace("'", '')
                self.ip = ip
                continue
            if 'Gateway:' in line:
                gateway = line.split(':')[-1].strip().replace("'", '')
                self.gateway = gateway
                continue
            if 'DNS [0]:' in line:
                dns_primary = line.split(':')[-1].strip().replace("'", '')
                dns_secondary = lines[idx + 1].split(':')[-1].strip().replace("'", '')
                self.dns_servers = [dns_primary, dns_secondary]
                break

    def disconnect(self):
        self._run_mbimcli_command(f'--disconnect={self.mbim_session}')
        self.ip = None
        self.gateway = None
        self.dns_servers = []

    def get_ip_configuration(self, cache=True, config_name=None):
        # if not exists, take from modem and update cache
        if not self.ip or not self.gateway or not self.dns_servers or cache == False:
            lines, _ = self._run_mbimcli_command('--query-ip-configuration')
            for idx, line in enumerate(lines):
                if not 'IPv4 configuration' in line:
                    continue
                self.ip = lines[idx + 1].split(':')[-1].strip().replace("'", '')
                self.gateway = lines[idx + 2].split(':')[-1].strip().replace("'", '')
                primary_dns = lines[idx + 3].split(':')[-1].strip().replace("'", '')
                secondary_dns = lines[idx + 4].split(':')[-1].strip().replace("'", '')
                self.dns_servers = [primary_dns, secondary_dns]
                break

        if config_name == 'ip':
            return self.ip
        elif config_name == 'gateway':
            return self.gateway
        elif config_name == 'dns_servers':
            return self.dns_servers
        return self.ip, self.gateway, self.dns_servers

    def reset(self):
        self._mmcli_modem_exec(f'-r', False)
        self.modem_manager_id = None # modem manager gives another id after reset

        # In the reset process, the LTE interface (wwan) is deleted from Linux, and then comes back up.
        # We verify these two steps to make sure the reset process is completed successfully

        # if vpp runs, we have the tap_wwan0 interface, so we filter it out to make sure that the LTE interface (wwan0) doesn't exist
        cmd = f"sudo ls -l /sys/class/net/ | grep -v tap_ | grep {self.linux_if}"
        ifc_removed = fwutils.exec_with_retrials(cmd, retrials=60, expected_to_fail=True)
        if not ifc_removed:
            raise Exception('the modem exists after reset. it was expected to be temporarily removed')
        ifc_restored = fwutils.exec_with_retrials(cmd)
        if not ifc_restored:
            raise Exception('The modem has not recovered from the reset')

        # give modem manager little time to detect the modem
        fwutils.exec_with_retrials('mmcli -L | grep -q -v "No modems were found"', retrials=60)

        self._initialize()

    def _get_modem_manager_data(self):
        modem_data = self._mmcli_modem_exec()
        # {
        #     "modem": {
        #         "3gpp": {
        #             "enabled-locks": [
        #                 "fixed-dialing"
        #             ],
        #             "eps": {
        #                 "initial-bearer": {
        #                     "dbus-path": "--",
        #                     "settings": {
        #                         "apn": "--",
        #                         "ip-type": "--",
        #                         "password": "--",
        #                         "user": "--"
        #                     }
        #                 },
        #                 "ue-mode-operation": "ps-2"
        #             },
        #             "imei": "866680040112569",
        #             "operator-code": "--",
        #             "operator-name": "--",
        #             "pco": "--",
        #             "registration-state": "--"
        #         },
        #         "cdma": {
        #             "activation-state": "--",
        #             "cdma1x-registration-state": "--",
        #             "esn": "--",
        #             "evdo-registration-state": "--",
        #             "meid": "--",
        #             "nid": "--",
        #             "sid": "--"
        #         },
        #         "dbus-path": "/org/freedesktop/ModemManager1/Modem/0",
        #         "generic": {
        #             "access-technologies": [],
        #             "bearers": [],
        #             "carrier-configuration": "ROW_Generic_3GPP",
        #             "carrier-configuration-revision": "06010821",
        #             "current-bands": [
        #                 "utran-1",
        #                 "utran-3",
        #                 "utran-5",
        #                 "utran-8",
        #                 "eutran-1",
        #                 "eutran-3",
        #                 "eutran-5",
        #                 "eutran-7",
        #                 "eutran-8",
        #                 "eutran-20",
        #                 "eutran-28",
        #                 "eutran-32",
        #                 "eutran-38",
        #                 "eutran-40",
        #                 "eutran-41"
        #             ],
        #             "current-capabilities": [
        #                 "gsm-umts, lte"
        #             ],
        #             "current-modes": "allowed: 3g, 4g; preferred: 4g",
        #             "device": "/sys/devices/pci0000:00/0000:00:15.0/usb1/1-3",
        #             "device-identifier": "1cb7aed10665c820d13fa8459b4797c957d76059",
        #             "drivers": [
        #                 "cdc_mbim",
        #                 "option"
        #             ],
        #             "equipment-identifier": "866680040112569",
        #             "hardware-revision": "EM06-E",
        #             "manufacturer": "Quectel",
        #             "model": "EM06-E",
        #             "own-numbers": [],
        #             "plugin": "generic",
        #             "ports": [
        #                 "cdc-wdm0 (mbim)",
        #                 "ttyUSB0 (qcdm)",
        #                 "ttyUSB1 (gps)",
        #                 "ttyUSB2 (at)",
        #                 "ttyUSB3 (at)",
        #                 "wwan0 (net)"
        #             ],
        #             "power-state": "on",
        #             "primary-port": "cdc-wdm0",
        #             "primary-sim-slot": "--",
        #             "revision": "EM06ELAR03A08M4G",
        #             "signal-quality": {
        #                 "recent": "no",
        #                 "value": "0"
        #             },
        #             "sim": "/org/freedesktop/ModemManager1/SIM/0",
        #             "sim-slots": [],
        #             "state": "disabled",
        #             "state-failed-reason": "--",
        #             "supported-bands": [
        #                 "utran-1",
        #                 "utran-3",
        #                 "utran-5",
        #                 "utran-8",
        #                 "eutran-1",
        #                 "eutran-3",
        #                 "eutran-5",
        #                 "eutran-7",
        #                 "eutran-8",
        #                 "eutran-20",
        #                 "eutran-28",
        #                 "eutran-32",
        #                 "eutran-38",
        #                 "eutran-40",
        #                 "eutran-41"
        #             ],
        #             "supported-capabilities": [
        #                 "gsm-umts, lte"
        #             ],
        #             "supported-ip-families": [
        #                 "ipv4",
        #                 "ipv6",
        #                 "ipv4v6"
        #             ],
        #             "supported-modes": [
        #                 "allowed: 3g; preferred: none",
        #                 "allowed: 4g; preferred: none",
        #                 "allowed: 3g, 4g; preferred: 4g",
        #                 "allowed: 3g, 4g; preferred: 3g"
        #             ],
        #             "unlock-required": "--",
        #             "unlock-retries": [
        #                 "sim-pin2 (5)"
        #             ]
        #         }
        #     }
        # }
        return modem_data.get('modem')

    def _enable_pin(self, pin):
        return self._run_pin_command(f'--enable-pin --pin={pin}')

    def _disable_pin(self, pin):
        return self._run_pin_command(f'--disable-pin --pin={pin}')

    def _change_pin(self, current, new):
        return self._run_pin_command(f'--pin={current} --change-pin={new}')

    def _unblock_pin(self, puk, new):
        return self._run_pin_command(f'--puk={puk} --pin={new}')

    def _verify_pin(self, pin):
        self.log.debug('verifying lte pin number')
        return self._run_pin_command(f'--pin={pin}')

    def _run_pin_command(self, mmcli_pin_flag):
        data = self._get_modem_manager_data()
        sim_path = data.get('generic', {}).get('sim')
        try:
            self._mmcli_exec(f'-i {sim_path} {mmcli_pin_flag}', False)
            return (self.get_pin_state(), None)
        except Exception as e:
            return (self.get_pin_state(), str(e))

    def _mbimcli_get_pin_status(self):
        enabled_disabled = None
        pin_list_lines = self._run_mbimcli_command('--query-pin-list')[0]
        for idx, line in enumerate(pin_list_lines):
            if 'PIN1:' in line:
                enabled_disabled = pin_list_lines[idx + 1].split(':')[-1].strip().replace("'", '')
                break

        if enabled_disabled == 'disabled':
            return enabled_disabled
        else:
            pin_state_lines = self._run_mbimcli_command('--query-pin-state')[0]
            if not pin_state_lines:
                return 'sim-missing'

            pin_state = pin_state_lines[1].split(':')[-1].strip().replace("'", '')
            pin_type = pin_state_lines[2].split(':')[-1].strip().replace("'", '')
            if pin_type == 'pin1':
                if pin_state == 'locked':
                    return 'enabled-not-verified'
                else:
                    return 'enabled-verified'
            elif pin_type == 'puk1':
                return 'blocked'
            else:
                return 'enabled-verified'

    def get_pin_state(self, data=None):
        res = {
            'pin1_status': self._mbimcli_get_pin_status(),
            'pin1_retries': '',
            'puk1_retries': '',
        }

        if not data:
            data = self._get_modem_manager_data()
        unlock_retries = data.get('generic', {}).get('unlock-retries', [])
        # "unlock-retries": [
        #     "sim-puk (5)"
        # ]
        for pin in unlock_retries:
            if 'sim-puk' in pin:
                res['puk1_retries'] = re.search(r'\((.*?)\)', pin).group(1)
                continue
            elif 'sim-pin ' in pin: # the space is to exclude 'sim-pin2'.
                res['pin1_retries'] = re.search(r'\((.*?)\)', pin).group(1)
                continue
        return res

    def _get_signal(self):
        result = {
            'rssi' : 0,
            'rsrp' : 0,
            'rsrq' : 0,
            'sinr' : 0,
            'snr'  : 0,
            'text' : 'N/A'
        }
        if not self.sim_presented:
            return result

        output = self._mmcli_modem_exec('--signal-get')
        lte_signal = output.get('modem', {}).get('signal', {}).get('lte', {})
        evdo_signal = output.get('modem', {}).get('signal', {}).get('evdo', {})

        result['rssi'] = lte_signal.get('rssi')
        result['rsrp'] = lte_signal.get('rsrp')
        result['rsrq'] = lte_signal.get('rsrq')
        result['sinr'] = evdo_signal.get('sinr')
        result['snr'] = lte_signal.get('snr')

        if result['rssi'] != '--':
            dbm_num = int(float(result['rssi']))
            if -95 >= dbm_num:
                result['text'] = 'Marginal'
            elif -85 >= dbm_num:
                result['text'] = 'Very low'
            elif -80 >= dbm_num:
                result['text'] = 'Low'
            elif -70 >= dbm_num:
                result['text'] = 'Good'
            elif -60 >= dbm_num:
                result['text'] = 'Very Good'
            else:
                result['text'] = 'Excellent'
        return result

    def _get_system_info(self, data=None):
        result = {
            'cell_id'        : '',
            'mcc'            : '',
            'mnc'            : '',
            'operator_name'  : self._get_operator_name(data)
        }
        if not self.sim_presented:
            return result

        output = self._mmcli_modem_exec('--location-get')
        location = output.get('modem', {}).get('location', {}).get('3gpp', {})
        # "location": {
        #     "3gpp": {
        #         "cid": "000D5C10",
        #         "lac": "FFFE",
        #         "mcc": "425",
        #         "mnc": "03",
        #         "tac": "001CD5"
        #     },
        #     "cdma-bs": {
        #         "latitude": "--",
        #         "longitude": "--"
        #     },
        #     "gps": {
        #         "altitude": "--",
        #         "latitude": "--",
        #         "longitude": "--",
        #         "nmea": [],
        #         "utc": "--"
        #     }
        #     }
        cell = location.get('cid', '--')
        if cell == '--':
            cell = 0
        else:
            cell = int(cell, base=16)

        result['cell_id'] = cell
        result['mcc'] = location.get('mcc')
        result['mnc'] = location.get('mnc')
        return result

    def _get_operator_name(self, data=None):
        if not data:
            data = self._get_modem_manager_data()
        return data.get('3gpp', {}).get('operator-name')

    def set_mbim_mode(self, log=None):
        """Switch LTE modem to the MBIM mode
        """
        try:
            if not log:
                log = self.log

            lte_driver = self.driver
            if lte_driver == 'cdc_mbim':
                return

            log.debug(f'Modem Vendor: {self.vendor}. Modem Model: {self.model}')

            at_commands = []
            if 'Quectel' in self.vendor or re.match('Quectel', self.model, re.IGNORECASE): # Special fix for Quectel ec25 mini pci card
                at_commands = ['AT+QCFG="usbnet",2']

                if not self.at_ports:
                    raise Exception(f'No serial port is found')

                ser = serial.Serial(f'/dev/{self.at_ports[0]}')
                for at in at_commands:
                    at_cmd = bytes(at + '\r', 'utf-8')
                    ser.write(at_cmd)
                    time.sleep(0.5)
                ser.close()
            elif 'Sierra Wireless' in self.vendor:
                self._run_qmicli_command('--dms-swi-set-usb-composition=8')
            else:
                log.error("Your card is not officially supported. It might work, But you have to switch manually to the MBIM modem")
                raise Exception('vendor or model are not supported. (vendor: %s, model: %s)' % (self.vendor, self.model))

            log.debug(f'Modem was switched to MBIM. Resetting the modem')

            # at this point the modem switched to mbim mode without errors
            # but we have to reset the modem in order to apply it
            self.reset()

            log.debug(f'The reset process was completed successfully')

            os.system('modprobe cdc_mbim') # sometimes driver doesn't register to the device after reset

            return
        except Exception as e:
            # Modem cards sometimes get stuck and recover only after disconnecting the router from the power supply
            self.log.error("Failed to switch modem to MBIM. You can unplug the router, wait a few seconds and try again. (%s)" % str(e))
            raise e

    def _get_packets_state(self):
        result = {
            'uplink_speed'  : 0,
            'downlink_speed': 0
        }
        try:
            lines, _ = self._run_mbimcli_command('--query-packet-service-state')
            for line in lines:
                if 'Uplink speed' in line:
                    result['uplink_speed'] = line.split(':')[-1].strip().replace("'", '')
                    continue
                if 'Downlink speed' in line:
                    result['downlink_speed'] = line.split(':')[-1].strip().replace("'", '')
                    continue
        except Exception:
            pass

        return result

    def _get_registration_state(self):
        res = {
            'register_state': '',
            'network_error' : '',
        }
        lines, _ = self._run_mbimcli_command('--query-registration-state')
        for line in lines:
            if 'Network error:' in line:
                res['network_error'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'Register state:' in line:
                res['register_state'] = line.split(':')[-1].strip().replace("'", '')
                break
        return res

    def _get_phone_number(self, data=None):
        if not data:
            data = self._get_modem_manager_data()
        own_numbers = data.get('generic', {}).get('own-numbers', [])
        return ', '.join(own_numbers)

    def get_default_settings(self, data=None):
        default_settings = {
            'APN'     : '',
            'username': '',
            'password': '',
            'auth'    : ''
        }

        if not data:
            data = self._get_modem_manager_data()
        bearer_path = data.get('3gpp', {}).get('eps', {}).get('initial-bearer', {}).get('dbus-path', '--')
        if bearer_path == '--': # modem manager sets "--" as default if not exists
            return default_settings

        bearer_data_output = self._mmcli_exec(f'-b {bearer_path}')
        bearer_data = bearer_data_output.get('bearer', {}).get('properties', {})

        apn = bearer_data.get('apn', '--')
        user = bearer_data.get('user', '--')
        password = bearer_data.get('password', '--')

        default_settings['APN'] = apn if apn != '--' else ''
        default_settings['username'] = user if user != '--' else ''
        default_settings['password'] = password if password != '--' else ''

        allowed_auth = bearer_data.get('allowed-auth', [])
        if allowed_auth:
            default_settings['auth'] = allowed_auth[0]
        return default_settings

    def _get_hardware_info(self):
        return {
            'vendor'   : self.vendor,
            'model'    : self.model,
            'imei'     : self.imei,
        }

class PIN_ERROR_MESSAGES():
    NEW_PIN_IS_REQUIRED = 'NEW_PIN_IS_REQUIRED'
    PIN_IS_DISABLED = 'PIN_IS_DISABLED'
    PIN_IS_REQUIRED = 'PIN_IS_REQUIRED'
    PIN_IS_WRONG = 'PIN_IS_WRONG'
    PUK_IS_REQUIRED = 'PUK_IS_REQUIRED'
    PUK_IS_WRONG = 'PUK_IS_WRONG'

class FwModem(FwLinuxModem):
    def __init__(self, dev_id):
        FwObject.__init__(self)

        self.state = MODEM_STATES.IDLE
        self.dev_id = dev_id

        usb_device = self._dev_id_to_usb_device()
        FwLinuxModem.__init__(self, usb_device)

    def _dev_id_to_usb_device(self):
        try:
            # do not use here self.driver, as "FwLinuxModem.__init__" has not been called yet
            driver = fwutils.get_interface_driver_by_dev_id(self.dev_id)
            usb_addr = self.dev_id.split('/')[-1]
            output = subprocess.check_output(f'ls /sys/bus/usb/drivers/{driver}/{usb_addr}/usbmisc/', shell=True).decode().strip()
            return output
        except subprocess.CalledProcessError:
            return None

    def ensure_tc_config(self):
        devices = [self.linux_if]
        tap_if_name = fwutils.linux_tap_by_interface_name(self.linux_if)
        if tap_if_name:
            devices.append(tap_if_name)

        need_to_recreate = False
        for device in devices:
            try:
                output = subprocess.check_output(f'tc -j filter show dev {device} root', shell=True).decode().strip()
                if not output or output == '[]':
                    need_to_recreate = True
                    break
            except Exception as e:
                need_to_recreate = True
                break

        if need_to_recreate:
            self.log.debug('ensure_tc_config(): No traffic control configurations were found. Adding them now')
            os.system(f'sudo tc -force qdisc del dev {self.linux_if} ingress handle ffff:')
            # Note, don't remove qdisc from "tap_if_name" (tap_wwan0) as it is configured in vpp startup.conf as part of QoS
            os.system(f'sudo tc -force filter del dev {self.linux_if} root')
            if tap_if_name:
                os.system(f'sudo tc -force filter del dev {tap_if_name} root')

            self.add_del_traffic_control(is_add=True)

    def connect(self, apn=None, user=None, password=None, auth=None, pin=None):
        # To avoid wan failover monitor and lte watchdog at this time
        self.state = MODEM_STATES.CONNECTING

        try:
            if self.mode == 'QMI':
                raise Exception("Unsupported modem mode (QMI)")

            # check if sim exists
            if self._get_sim_card_status() != "present":
                raise Exception("SIM not present")

            # check PIN status
            pin_state = self.get_pin_state().get('pin1_status', 'disabled')
            if pin_state not in ['disabled', 'enabled-verified']:
                if not pin:
                    raise Exception("PIN is required")

                # If a user enters a wrong pin, the function will fail, but flexiManage will send three times `sync` jobs.
                # As a result, the SIM may be locked. So we save the wrong pin in the cache
                # and we will not try again with this wrong one.
                wrong_pin = self._get_db_entry('wrong_pin')
                if wrong_pin and wrong_pin == pin:
                    raise Exception("Wrong PIN provisioned")

                _, err = self._verify_pin(pin)
                if err:
                    self._set_db_entry('wrong_pin', pin)
                    raise Exception("PIN is wrong")

            # At this point, we sure that the sim is unblocked.
            # After a block, the sim might open it from different places (manually qmicli command, for example),
            # so we need to make sure to clear this cache
            self._set_db_entry('wrong_pin', None)

            # Check if modem already connected to ISP.
            if self.is_connected():
                return

            # Make sure context is released and set the interface to up
            self.disconnect()
            os.system(f'ip link set dev {self.linux_if} up')
            FwLinuxModem.connect(self, apn, user, password, auth)
        except Exception as e:
            self.log.debug('connect: failed to connect lte. %s' % str(e))
            self.state = None
            self.disconnect()
            return (False, str(e))
        finally:
            self.state = MODEM_STATES.IDLE

    def configure_interface(self, metric='0'):
        '''
        To get LTE connectivity, two steps are required:
        1. Creating a connection between the modem and cellular provider.
        2. Setting up the Linux interface with the IP/gateway received from the cellular provider
        This function is responsible for the second stage.
        If the vpp is running, we have special logic to configure LTE. This logic handled by the add_interface translator.
        '''
        try:
            # If VPP is running, add-interface translation configures the relevant data.
            # Hence, just ensure that interface is up
            if fw_os_utils.vpp_does_run() and fwutils.is_interface_assigned_to_vpp(self.dev_id):
                fwutils.os_system(f'ip link set dev {self.linux_if} up')
                return

            ip, gateway, dns_servers = self.get_ip_configuration()

            os.system(f'sudo ip link set dev {self.linux_if} up && ip addr add {ip} dev {self.linux_if}')

            # remove old default route
            output = os.popen('ip route list match default | grep %s' % self.linux_if).read()
            if output:
                routes = output.splitlines()
                for r in routes:
                    fwutils.os_system(f"ip route del {r}")
            # set updated default route
            fwutils.os_system(f"ip route add default via {gateway} proto static metric {metric}")

            # configure dns servers for the interface.
            # If the LTE interface is configured in netplan, the user must set the dns servers manually in netplan.
            set_dns_str = ' '.join(map(lambda server: '--set-dns=' + server, dns_servers))
            if set_dns_str:
                fwutils.os_system(f"systemd-resolve {set_dns_str} --interface {self.linux_if}")

            fwutils.clear_linux_interfaces_cache() # remove this code when move ip configuration to netplan
        except Exception as e:
            return (False, "Failed to configure lte for dev_id %s. (%s)" % (self.dev_id, str(e)))

    def disconnect(self):
        try:
            FwLinuxModem.disconnect(self)
            os.system(f'sudo ip link set dev {self.linux_if} down && sudo ip addr flush dev {self.linux_if}')
            fwutils.clear_linux_interfaces_cache() # remove this code when move ip configuration to netplan
        except subprocess.CalledProcessError as e:
            return (False, str(e))

    def reset(self):
        '''
        The function resets the modem while handling the consequences created by the reset in Linux.
        '''
        recreate_tc_filters = False
        if fw_os_utils.vpp_does_run() and fwutils.is_interface_assigned_to_vpp(self.dev_id):
            recreate_tc_filters = True

        try:
            self.state = MODEM_STATES.RESETTING
            self.log.debug('reset(): reset starting')

            if recreate_tc_filters:
                self.log.debug('reset(): removing TC configuration')
                try:
                    self.add_del_traffic_control(is_add=False)
                except Exception as e:
                    # Forgive a failure in TC removal here, as it will prevent code to from resetting the modem.
                    self.log.error('reset: failed to remove traffic control. Continue to reset...')

            # do the reset
            FwLinuxModem.reset(self)

            # To re-apply set-name for LTE interface we have to call netplan apply here
            fwutils.netplan_apply("reset_modem")

            if recreate_tc_filters:
                self.log.debug('reset(): applying TC configuration')
                self.add_del_traffic_control(is_add=True)

            self.log.debug('reset(): reset finished')
        finally:
            self.state = MODEM_STATES.IDLE
            # clear wrong PIN cache on reset
            self._set_db_entry('wrong_pin', None)

    def get_lte_info(self, data=None):
        lte_info = {
            'address'             : '',
            'signals'             : {},
            'connectivity'        : False,
            'packet_service_state': {},
            'hardware_info'       : {},
            'system_info'         : {},
            'sim_status'          : '',
            'default_settings'    : {},
            'phone_number'        : '',
            'pin_state'           : {},
            'connection_state'    : '',
            'registration_network': {},
            'state'               : self.state,
            'mode'                : self.mode,
        }

        if self.mode == 'QMI' or self.is_resetting() or not self.sim_presented:
            return lte_info

        data = self._get_modem_manager_data()

        # There is no need to check the tap name if the router is not entirely run.
        # When the router is in the start process, and the LTE is not yet fully configured,
        # the "dev_id_to_tap()" causes a chain of unnecessary functions to be called,
        # and eventually, the result is empty.
        if_name  = self.linux_if #fwutils.dev_id_to_linux_if(dev_id)
        if fwglobals.g.router_api.state_is_started():
            tap_name = fwutils.dev_id_to_tap(self.dev_id, check_vpp_state=True)
            if tap_name:
                if_name = tap_name

        addr = fwutils.get_interface_address(if_name)
        connectivity = os.system("ping -c 1 -W 1 -I %s 8.8.8.8 > /dev/null 2>&1" % if_name) == 0

        lte_info['sim_status']           = self._get_sim_card_status(data)
        lte_info['address']              = addr
        lte_info['signals']              = self._get_signal()
        lte_info['connectivity']         = connectivity
        lte_info['packet_service_state'] = self._get_packets_state()
        lte_info['hardware_info']        = self._get_hardware_info()
        lte_info['system_info']          = self._get_system_info(data)
        lte_info['default_settings']     = self.get_default_settings(data)
        lte_info['phone_number']         = self._get_phone_number(data)
        lte_info['pin_state']            = self.get_pin_state(data)
        lte_info['connection_state']     = self._get_connection_state()
        lte_info['registration_network'] = self._get_registration_state()
        return lte_info

    def set_arp_entry(self, is_add, gw=None):
        '''
        :param is_add:      if True the static ARP entry is added, o/w it is removed.
        :param gw:          the IP of GW for which the ARP entry should be added/removed.
        '''
        vpp_if_name = fwutils.dev_id_to_vpp_if_name(self.dev_id)
        if not vpp_if_name:
            raise Exception(f"set_arp_entry: failed to resolve {self.dev_id} to vpp_if_name")

        if not gw:
            _, gw, _ = self.get_ip_configuration(cache=False)
            if not gw:
                self.log.debug(f"set_arp_entry: no GW was found for {self.dev_id}")
                return

        log_prefix=f"set_arp_entry({self.dev_id})"

        if is_add:
            cmd = f"sudo arp -s {gw} 00:00:00:00:00:00"
            fwutils.os_system(cmd, log_prefix=log_prefix, raise_exception_on_error=True)
            cmd = f"set ip neighbor static {vpp_if_name} {gw} ff:ff:ff:ff:ff:ff"
            fwutils.vpp_cli_execute([cmd], log_prefix=log_prefix, raise_exception_on_error=True)
        else:
            cmd = f"sudo arp -d {gw} > /dev/null 2>&1"
            fwutils.os_system(cmd, log_prefix=log_prefix, print_error=False, raise_exception_on_error=False) # Suppress exception as arp entry might not exists if interface was taken down for some reason
            cmd = f"set ip neighbor del static {vpp_if_name} {gw} ff:ff:ff:ff:ff:ff"
            fwutils.vpp_cli_execute([cmd], log_prefix=log_prefix, raise_exception_on_error=True)

    def _get_db_entry(self, key):
        lte_db = fwglobals.g.db.get('lte' ,{})
        dev_id_entry = lte_db.get(self.dev_id ,{})
        return dev_id_entry.get(key)

    def _set_db_entry(self, key, value):
        lte_db = fwglobals.g.db.get('lte' ,{})
        dev_id_entry = lte_db.get(self.dev_id ,{})
        dev_id_entry[key] = value

        lte_db[self.dev_id] = dev_id_entry
        fwglobals.g.db['lte'] = lte_db # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict

    def _run_qmicli_command(self, cmd, print_error=False):
        try:
            return FwLinuxModem._run_qmicli_command(self, cmd, print_error)
        except Exception as e:
            err_str = str(e)
            modem_was_reset = self._reset_if_needed(err_str)
            if modem_was_reset:
                return self._run_qmicli_command(cmd, print_error)
            return ([], err_str)

    def _run_mbimcli_command(self, cmd, print_error=False):
        try:
            return FwLinuxModem._run_mbimcli_command(self, cmd, print_error)
        except Exception as e:
            err_str = str(e)
            modem_was_reset = self._reset_if_needed(err_str)
            if modem_was_reset:
                return self._run_mbimcli_command(cmd, print_error)
            return ([], err_str)

    def _reset_if_needed(self, err_str):
        '''The qmi and mbim commands can sometimes get stuck and return errors.
        It is not clear if this is the modem that get stuck or the way commands are run to it.
        The solution we found is to do a modem reset.
        But, to avoid a loop of error -> reset -> error -> reset,
        we will only perform it if a period of time has passed since the last reset.

        :param err_str: the error string returned from the mbim/qmi clients

        :return: boolean indicates if reset is performed or not.

        '''
        reset_modem_error_triggers = [
            "couldn't create client for the",
            "operation failed: Failure",
            "operation failed: Busy",
            "operation failed: RadioPowerOff"
        ]

        if not any(x in err_str for x in reset_modem_error_triggers):
            return False

        last_reset_time = self._get_db_entry('healing_reset_last_time')

        now = datetime.now()
        if last_reset_time:
            last_reset_time = datetime.fromtimestamp(last_reset_time)
            if last_reset_time > (now - timedelta(hours=1)):
                return False

        # do reset
        self.log.debug(f"_reset_if_needed(): resetting modem while error. err: {err_str}")

        self._set_db_entry('healing_reset_last_time', datetime.timestamp(now))

        self.reset()
        return True

    def add_del_traffic_control(self, is_add):
        """
        Add or remove the needed traffic control command for LTE.

        After configuring the TAP interface in VPP, we have three interfaces in Linux that belong to LTE.
        1. LTE interface itself - wwan0.
        2. TAP interface - tap_wwan0.
        3. VPPSB interface - vppX.

        The IP in Linux is on the vppX interface and the Linux default route is through the vppX interface.

        Outbound traffic originating from Linux goes as follows:
        Linux application (ping) -> vppX -> VPP -> tap_wwan0 -> wwan0 -> internet.

        Outbound traffic originating from LAN client goes as follows:
        Client -> VPP -> tap_wwan0 -> wwan0 -> internet.

        Incoming traffic goes:
        Internet -> wwan0 -> tap_wwan0 -> VPP -> (client or Linux via VPPSB).

        See that:
        * wwan0 mirrors incoming traffic to tap_wwan0
        * tap_wwan0 mirrors incoming traffic to wwan0.

        This mirroring is done by traffic control tool.

        We create a filter on both interface to mirrot traffic between them.

        To apply a traffic control policy on an incoming interface, we must add them a "ingress" qdisc.
        """
        lte_if_name = self.linux_if

        linux_tap_if_name = fwutils.linux_tap_by_interface_name(lte_if_name)
        if not linux_tap_if_name:
            raise Exception(f'add_del_traffic_control(dev_id={self.dev_id}, {lte_if_name}): linux_tap_if_name not found')

        lte_mac_addr = fwutils.get_interface_mac_addr(lte_if_name)
        vpp_mac_addr = fwutils.get_vpp_tap_interface_mac_addr(self.dev_id)

        # Since we run multiple commands here, we need to take care of the failure case.
        # If a command fails, it throws an error.
        # Hence, after each command, we know that it succeeded, and we add the revert function of it to a list.
        # In case of an error, we call each function within the revert list to clean up the configuration.
        with FwCfgMultiOpsWithRevert() as handler:
            try:
                if is_add:
                    # first, apply the ingress qdisc
                    handler.exec(
                        func=fwutils.traffic_control_add_del_qdisc,
                        params={ 'is_add': True, 'dev_name': lte_if_name },
                        revert_func=fwutils.traffic_control_add_del_qdisc,
                        revert_params={ 'is_add': False, 'dev_name': lte_if_name }
                    )
                    '''
                    When DPDK is used to initialize the tap interface created as part of LTE init,
                    the ingress qdisc setup is taken care as part of dpdk initialization
                    Below setup is need only if the tap is initialized by VPP (not DPDK)
                    handler.exec(
                        func=fwutils.traffic_control_add_del_qdisc,
                        params={ 'is_add': True, 'dev_name': linux_tap_if_name },
                        revert_func=fwutils.traffic_control_add_del_qdisc,
                        revert_params={ 'is_add': True, 'dev_name': linux_tap_if_name },
                    )
                    '''
                    # then, apply the mirroring
                    handler.exec(
                        func=fwutils.traffic_control_add_del_mirror_policy,
                        params={ 'is_add': True, 'from_ifc': linux_tap_if_name, 'to_ifc': lte_if_name, 'set_dst_mac': lte_mac_addr },
                        revert_func=fwutils.traffic_control_add_del_mirror_policy,
                        revert_params={ 'is_add': False, 'from_ifc': linux_tap_if_name, 'to_ifc': lte_if_name, 'set_dst_mac': lte_mac_addr }
                    )

                    handler.exec(
                        func=fwutils.traffic_control_add_del_mirror_policy,
                        params={ 'is_add': True, 'from_ifc': lte_if_name, 'to_ifc': linux_tap_if_name, 'set_dst_mac': vpp_mac_addr },
                        revert_func=fwutils.traffic_control_add_del_mirror_policy,
                        revert_params={ 'is_add': False, 'from_ifc': lte_if_name, 'to_ifc': linux_tap_if_name, 'set_dst_mac': vpp_mac_addr }
                    )
                else:
                    # first, remove the mirroring
                    fwutils.traffic_control_add_del_mirror_policy(is_add=False, from_ifc=linux_tap_if_name, to_ifc=lte_if_name, set_dst_mac=lte_mac_addr)
                    fwutils.traffic_control_add_del_mirror_policy(is_add=False, from_ifc=lte_if_name, to_ifc=linux_tap_if_name, set_dst_mac=vpp_mac_addr)
                    # then, remove the ingress qdisc
                    fwutils.traffic_control_add_del_qdisc(is_add=False, dev_name=lte_if_name)
                    '''
                    Below teardown is need only if the tap is initialized by VPP (not DPDK)
                    fwutils.traffic_control_add_del_qdisc(is_add=False, dev_name=linux_tap_if_name)
                    '''
            except Exception as e:
                self.log.error(f"add_del_traffic_control({self.dev_id}, {lte_if_name}): {str(e)}")
                handler.revert(e)

    def _handle_unblock_sim(self, puk, new_pin):
        if not puk:
            raise Exception(PIN_ERROR_MESSAGES.PUK_IS_REQUIRED)

        if not new_pin:
            raise Exception(PIN_ERROR_MESSAGES.NEW_PIN_IS_REQUIRED)

        # unblock the sim and get the updated status
        updated_status, err = self._unblock_pin(puk, new_pin)
        if err:
            raise Exception(PIN_ERROR_MESSAGES.PIN_IS_WRONG)
        updated_pin_state = updated_status.get('pin1_status')

        # if SIM status is not one of below statuses, it means that puk code is wrong
        if updated_pin_state not in['disabled', 'enabled-verified']:
            raise Exception(PIN_ERROR_MESSAGES.PUK_IS_WRONG)

    def _set_pin_protection(self, pin, is_enable):
        if is_enable:
            return self._enable_pin(pin)
        return self._disable_pin(pin)

    def _handle_change_pin_status(self, current_pin, enable):
        _, err = self._set_pin_protection(current_pin, enable)
        if err:
            raise Exception(PIN_ERROR_MESSAGES.PIN_IS_WRONG)

        # at this point, pin is verified so we reset wrong pin protection
        self._set_db_entry('wrong_pin', None)

    def _handle_change_pin_code(self, current_pin, new_pin, is_currently_enabled):
        if not is_currently_enabled: # can't change disabled pin
            raise Exception(PIN_ERROR_MESSAGES.PIN_IS_DISABLED)

        _, err = self._change_pin(current_pin, new_pin)
        if err:
            raise Exception(PIN_ERROR_MESSAGES.PIN_IS_WRONG)

        # at this point, pin is changed so we reset wrong pin protection
        self._set_db_entry('wrong_pin', None)

    def _handle_verify_pin_code(self, current_pin, is_currently_enabled, retries_left):
        updated_status, err = self._verify_pin(current_pin)
        if err and not is_currently_enabled: # can't verify disabled pin
            raise Exception(PIN_ERROR_MESSAGES.PIN_IS_DISABLED)
        if err:
            raise Exception(PIN_ERROR_MESSAGES.PIN_IS_WRONG)

        updated_pin_state = updated_status.get('pin1_status')
        updated_retries_left = updated_status.get('pin1_retries', '3')
        if updated_retries_left != '3' and int(retries_left) > int(updated_retries_left):
            raise Exception(PIN_ERROR_MESSAGES.PIN_IS_WRONG)
        if updated_pin_state not in['disabled', 'enabled-verified']:
            raise Exception(PIN_ERROR_MESSAGES.PIN_IS_WRONG)

        # at this point, pin is verified so we reset wrong pin protection
        self.set_db_entry('wrong_pin', None)

    def handle_pin_modifications(self, current_pin, new_pin, enable, puk):
        current_pin_state = self.get_pin_state()
        is_currently_enabled = current_pin_state.get('pin1_status') != 'disabled'
        retries_left = current_pin_state.get('pin1_retries', '3')

        # Handle blocked SIM card. In order to unblock it a user should provide PUK code and new PIN code
        if current_pin_state.get('pin1_status') == 'blocked' or retries_left == '0':
            self._handle_unblock_sim(puk, new_pin)
            return True

        # for the following operations we need current pin
        if not current_pin:
            raise Exception(PIN_ERROR_MESSAGES.PIN_IS_REQUIRED)

        need_to_verify = True
        # check if need to enable/disable PIN
        if is_currently_enabled != enable:
            self._handle_change_pin_status(current_pin, enable)
            need_to_verify = False

        # check if need to change PIN
        if new_pin and new_pin != current_pin:
            self._handle_change_pin_code(current_pin, new_pin, is_currently_enabled)
            need_to_verify = False

        # verify PIN if no other change requested by the user.
        # no need to verify if we enabled or disabled the pin since it's already verified
        if need_to_verify:
            self._handle_verify_pin_code(current_pin, is_currently_enabled, retries_left)

    def _is_connecting(self):
        return self.state == MODEM_STATES.CONNECTING

    def is_resetting(self):
        return self.state == MODEM_STATES.RESETTING

    def is_connecting_or_resetting(self):
        return self.is_resetting() or self._is_connecting()

class FwModemManager():
    def __init__(self):
        self.modems = {}
        self.initialized = False

        self.initialize()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        return

    def scan(self):
        self.modems = {}
        dev_ids_dict = get_dev_id_if_name_mapping(allow_qmi=True)
        for dev_id in dev_ids_dict:
            try:
                modem = FwModem(dev_id)
                self.modems[dev_id] = modem
            except Exception as e:
                self.log.error(f'failed to load modem. dev_id={dev_id}, err={str(e)}')

    def get(self, dev_id):
        modem = self.modems.get(dev_id)
        if not modem:
            raise Exception(f"No modem found. dev_id={dev_id}")
        return modem

    def get_safe(self, dev_id):
        modem = self.modems.get(dev_id)
        return modem

    def initialize(self):
        self.scan()
        self.initialized = True

    def finalize(self):
        self.modems = {}
        self.initialized = False

    def call(self, dev_id, func, *args, **kwargs):
        modem = self.get(dev_id)
        modem_func = getattr(modem, func)
        return modem_func(*args, **kwargs)

    def get_stats(self):
        out = {}
        for modem in self.modems:
            if self.modems[modem].is_connecting_or_resetting():
                continue

            try:
                info = self.modems[modem].get_lte_info()
                out[modem] = info
            except:
                pass

        return out

def get_ip_configuration(dev_id, key):
    return fwglobals.g.modems.get(dev_id).get_ip_configuration(config_name=key)

def disconnect_all():
    """ Disconnect all modems safely
    """
    if fwglobals.g.modems:
        for modem in fwglobals.g.modems.modems:
            modem.disconnect()
    else:
        with FwModemManager() as fw_modem_manager:
            for modem in fw_modem_manager.modems:
                fw_modem_manager.modems[modem].disconnect()

def reload_lte_drivers_if_needed():
    if is_need_to_reload_lte_drivers():
        reload_lte_drivers()

def is_need_to_reload_lte_drivers():
    # 2c7c:0125 is the vendor Id and product Id of quectel EC25 card.
    ec25_card_exists = os.popen('lsusb | grep 2c7c:0125').read()
    if not ec25_card_exists:
        return False

    # check if driver is associated with the modem. (see the problematic output "Driver=").
    # venko@PCENGINE2:~$ lsusb -t
    # /:  Bus 02.Port 1: Dev 1, Class=root_hub, Driver=ehci-pci/2p, 480M
    #     |__ Port 1: Dev 2, If 0, Class=Hub, Driver=hub/4p, 480M
    #         |__ Port 3: Dev 3, If 0, Class=Vendor Specific Class, Driver=option, 480M
    #         |__ Port 3: Dev 3, If 1, Class=Vendor Specific Class, Driver=option, 480M
    #         |__ Port 3: Dev 3, If 2, Class=Vendor Specific Class, Driver=option, 480M
    #         |__ Port 3: Dev 3, If 3, Class=Vendor Specific Class, Driver=option, 480M
    #         |__ Port 3: Dev 3, If 4, Class=Communications, Driver=, 480M
    #         |__ Port 3: Dev 3, If 5, Class=CDC Data, Driver=option, 480M
    cmd = 'lsusb -t | grep "Class=Communications" | awk -F "Driver=" {\'print $2\'} | awk -F "," {\'print $1\'}'
    driver = os.popen(cmd).read().strip()
    if not driver:
        return True
    return False

def reload_lte_drivers():
    modules = [
        'cdc_mbim',
        'qmi_wwan',
        'option',
        'cdc_wdm',
        'cdc_ncm',
        'usbnet',
        'qcserial',
        'usb_wwan',
        'mii',
        'usbserial'
    ]

    for module in modules:
        os.system('rmmod %s 2>/dev/null' % module)

    for module in modules:
        os.system('modprobe %s' % module)

    time.sleep(2)

    fwutils.netplan_apply("reload_lte_drivers")

def dump(lte_if_name, prefix_path=''):
    devices = [lte_if_name]
    tap_if_name = fwutils.linux_tap_by_interface_name(lte_if_name)
    if tap_if_name:
        devices.append(tap_if_name)

    for device in devices:
        fwutils.exec_to_file(f'tc -j filter show dev {device} root', f'{prefix_path}_{device}_tc_filter.json')
        fwutils.exec_to_file(f'tc -j qdisc show dev {device}', f'{prefix_path}_{device}_tc_qdisc.json')

def get_dev_id_if_name_mapping(allow_qmi=False):
    out = {}
    lines = subprocess.check_output('sudo ls -l /sys/class/net', shell=True).decode().splitlines()
    for line in lines:
        nicname = line.split('/')[-1]
        driver = fwutils.get_interface_driver(nicname, cache=False)
        if not driver:
            continue

        if driver == 'cdc_mbim' or (allow_qmi and driver == 'qmi_wwan'):
            dev_id = fwutils.get_interface_dev_id(nicname)
            out[dev_id] = nicname
            continue
    return out

def is_lte_interface_by_dev_id(dev_id):
    if_name = fwutils.dev_id_to_linux_if(dev_id)
    if not if_name:
        return False
    return is_lte_interface(if_name)

def is_lte_interface(if_name, allow_qmi=False):
    """Check if interface is LTE.

    :param dev_id: Bus address of interface to check.

    :returns: Boolean.
    """
    driver = fwutils.get_interface_driver(if_name)
    supported_lte_drivers = ['cdc_mbim']
    if driver in supported_lte_drivers or (allow_qmi and driver == 'qmi_wwan'):
        return True

    return False