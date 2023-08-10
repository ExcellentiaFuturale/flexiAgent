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
import fwnetplan
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

        self._initialize_ip_config()

        self.mbim_session = '0'

        self._initialize()

    def _initialize(self):
        self._enable()
        modem_data = self._load_info_from_modem_manager()
        drivers = modem_data.get('generic', {}).get('drivers', [])
        if 'cdc_mbim' in drivers:
            self.driver = 'cdc_mbim'
            self.mode = 'MBIM'
        elif 'qmi_wwan' in drivers:
            self.driver = 'qmi_wwan'
            self.mode = 'QMI'

    def _initialize_ip_config(self):
        self.ip = None
        self.gateway = None
        self.dns_servers = []

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
        modem_manager_id = self.modem_manager_id
        try:
            output = self._mmcli_exec(f'-m {modem_manager_id} {flag}', json_format)
            return output
        except Exception as e:
            err_str = str(e)
            if "modem not enabled yet" in err_str:
                self._modem_manager_enable_modem()
            if "modem has no extended signal capabilities" in err_str:
                self._modem_manager_signal_setup()
            elif "couldn't find modem" not in err_str:
                raise e

            # try to load modem once again. ModemManager may re-index it with a different "modem_path".
            current_modem_manager_id = self._enable()
            if modem_manager_id != current_modem_manager_id:
                return self._mmcli_exec(f'-m {current_modem_manager_id} {flag}', json_format)
            raise e

    def _enable(self):
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
            modem_info = self._mmcli_exec(f'-m {modem}').get('modem', {})
            primary_port =  modem_info.get('generic', {}).get('primary-port')
            if primary_port != self.usb_device:
                continue

            self.modem_manager_id = modem_info.get('dbus-path')

            modem_state, _ = self._get_modem_state(modem_info)
            if modem_state != 'locked': # locked modem will be enabled once PIN will be verified
                self._modem_manager_enable_modem()
                self._modem_manager_signal_setup()

        if not modem_info:
            raise Exception(f"modem {self.usb_device} not found in modem list: {str(modem_list)}")
        return self.modem_manager_id

    def _load_info_from_modem_manager(self):
        # {
        #     "modem": {
        #         ...
        #         "dbus-path": "/org/freedesktop/ModemManager1/Modem/0",
        #         ...
        #      }
        # }
        info = self._get_modem_manager_data()
        generic = info.get('generic', {})

        self.imei = generic.get('equipment-identifier')
        self.model = generic.get('model')
        self.sim_presented = self._get_sim_card_status(info) == 'present'
        self.vendor = generic.get('manufacturer')

        ports = generic.get('ports', [])
        for port in ports:
            if '(net)' in port:
                self.linux_if = port.split('(net)')[0].strip()
            elif '(at)' in port:
                at_port = port.split('(at)')[0].strip()
                self.at_ports.append(at_port)
        return info

    def _modem_manager_enable_modem(self):
        try:
            self._mmcli_exec(f'-m {self.modem_manager_id} -e', False)
        except Exception as e:
            self.log.error(f"_modem_manager_enable_modem: failed to enable modem. err={str(e)}")
            pass

    def _modem_manager_signal_setup(self):
        try:
            self._mmcli_exec(f'-m {self.modem_manager_id} --signal-setup=5', False)
        except Exception as e:
            self.log.error(f"_modem_manager_signal_setup: failed to setup signal. err={str(e)}")
            pass

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

    def _update_ip_configuration(self):
        lines, _ = self._run_mbimcli_command('--query-ip-configuration')
        # [/dev/cdc-wdm0] IPv4 configuration available: 'address, gateway, dns, mtu'
        #     IP [0]: '10.196.122.165/30'
        #     Gateway: '10.196.122.166'
        #     DNS [0]: '91.135.102.8'
        #     DNS [1]: '91.135.104.8'
        #         MTU: '1500'
        # [/dev/cdc-wdm0] IPv6 configuration available: 'none'
        for line in lines:
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
                self.dns_servers = [dns_primary]
                continue
            if 'DNS [1]:' in line:
                dns_secondary = line.split(':')[-1].strip().replace("'", '')
                self.dns_servers.append(dns_secondary)

    def _ensure_pdp_context(self, apn):
        '''
        Check deeply in modem if Packet Data Protocol is defined.
        This check is not mandatory for most of the ISPs,
        but we found that for AT&T it is required in order to connect to the network.
        '''
        try:
            exists = False
            pdp_context_lines = self._run_at_command('AT+CGDCONT?').splitlines()
            # response = '+CGDCONT: 1,"IP","internet.rl","0.0.0.0",0,0,0,0'
            for pdp_context_line in pdp_context_lines:
                line_params = pdp_context_line.split(',')
                if len(line_params) > 3 and line_params[2].strip('"') == apn:
                    exists = True
                    break

            if not exists:
                self.log.info(f'_ensure_pdp_context({apn}): APN not found in {str(pdp_context_lines)}. Adding now')
                self._run_at_command(f'AT+CGDCONT=1,\\"IP\\",\\"{apn}\\"')
                # in order to apply it, run "CFUN" commands which is kind of soft reboot.
                self._run_at_command(f'AT+CFUN=0')
                self._run_at_command(f'AT+CFUN=1')
                # give it a bit time. If it is not enough, watchdog takes care to connect it again
                time.sleep(2)
        except Exception as e:
            self.log.error(f'_ensure_pdp_context({apn}): {str(e)}')
            # do not raise error as it not mandatory for most of ISPs

    def connect(self, apn=None, user=None, password=None, auth=None):
        if apn:
            self._ensure_pdp_context(apn)

        connection_params = self._prepare_connection_params(apn, user, password, auth)
        mbim_commands = [
            '--query-subscriber-ready-status',
            '--query-registration-state',
            '--attach-packet-service',
        ]
        for cmd in mbim_commands:
            lines, err = self._run_mbimcli_command(cmd, print_error=True)
            if err:
                raise Exception(err)

        lines, err = self._run_mbimcli_command(f'--connect={connection_params}')
        if err:
            raise Exception(err)
        for line in lines:
            if 'IPv4 configuration available' in line and 'none' in line:
                self.log.debug(f'connect: failed to get IPv4 from the ISP. lines={str(lines)}')
                raise Exception(f'Failed to get IPv4 configuration from the ISP')
            elif 'Session ID:' in line:
                session = line.split(':')[-1].strip().replace("'", '')
                self.mbim_session = session

        self._update_ip_configuration()

    def disconnect(self):
        self._run_mbimcli_command(f'--disconnect={self.mbim_session}')
        self._initialize_ip_config()

    def get_ip_configuration(self, cache=True):
        if cache == False:
            self._initialize_ip_config()

        # if not exists, take from modem and update cache
        if not self.ip or not self.gateway or not self.dns_servers:
            self._update_ip_configuration()

        return self.ip, self.gateway, self.dns_servers

    def reset(self):
        try:
            self._mmcli_modem_exec(f'-r', False)
        except Exception as e:
            # if it doesn't work with modem manager, do reset with AT command
            if 'Quectel' in self.vendor:
                self._run_at_command('AT+QPOWD=0')
            elif 'Sierra' in self.vendor:
                self._run_at_command('AT!RESET')
            else:
                raise e

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
        output, err = self._run_pin_command(f'--pin={pin}')
        if not err:
            # after verifying pin, ensure the modem is not locked
            modem_state, _ = self._get_modem_state()
            if modem_state == 'disabled':
                self._modem_manager_enable_modem()
                self._modem_manager_signal_setup()
        return (output, err)

    def _get_modem_manager_sim_data(self, modem_data=None):
        if not modem_data:
            modem_data = self._get_modem_manager_data()
        sim_path = modem_data.get('generic', {}).get('sim')
        sim_data = self._mmcli_exec(f'-i {sim_path}')
        return sim_data.get('sim', {})

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
            'rssi'        : '',
            'rsrp'        : '',
            'rsrq'        : '',
            'rscp'        : '',
            'sinr'        : '',
            'ecio'        : '',
            'snr'         : '',
            'quality'     : '',
            'technologies': []
        }
        if not self.sim_presented:
            return result

        output = self._mmcli_modem_exec('--signal-get')
        rate = output.get('modem', {}).get('signal', {}).get('refresh', {}).get('rate')
        if rate == '0':
            self._modem_manager_signal_setup()
            output = self._mmcli_modem_exec('--signal-get')

        signal = output.get('modem', {}).get('signal', {})

        def _fill_result_if_has_value(signal_dict):
            for key in signal_dict:
                val = signal_dict[key]
                if not val or val == '--':
                    continue
                result[key] = val

        _fill_result_if_has_value(signal.get('lte', {}))
        _fill_result_if_has_value(signal.get('evdo', {}))
        _fill_result_if_has_value(signal.get('umts', {}))
        _fill_result_if_has_value(signal.get('gsm', {}))
        _fill_result_if_has_value(signal.get('cdma1x', {}))
        _fill_result_if_has_value(signal.get('5g', {}))

        data = self._get_modem_manager_data()
        result['quality'] = data.get('generic', {}).get('signal-quality', {}).get('value', '0')
        result['technologies'] = data.get('generic', {}).get('access-technologies', [])
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

    def _run_at_command(self, at_command):
        output = self._mmcli_modem_exec(f'--command={at_command}', False)
        output = output.replace('response:', '').replace("\'", '').strip()
        return output

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

            if 'Quectel' in self.vendor or re.match('Quectel', self.model, re.IGNORECASE): # Special fix for Quectel ec25 mini pci card
                self._run_at_command('AT+QCFG=\\"usbnet\\",2')
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

    def get_sim_info(self, data=None):
        sim_data = self._get_modem_manager_sim_data(data)
        sim_info = {
            'iccid': sim_data.get('properties', {}).get('iccid'),
            'imsi': sim_data.get('properties', {}).get('imsi')
        }
        return sim_info

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

    def configure_interface(self, metric=None):
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
            if not metric:
                metric = '0'
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
            'sim'                 : {},
            'state'               : self.state,
            'mode'                : self.mode,
        }

        if self.mode == 'QMI' or self.is_resetting():
            return lte_info

        data = self._get_modem_manager_data()

        lte_info['sim_status'] = self._get_sim_card_status(data)
        if not self.sim_presented:
            return lte_info

        lte_info['packet_service_state'] = self._get_packets_state()
        lte_info['hardware_info']        = self._get_hardware_info()
        lte_info['default_settings']     = self.get_default_settings(data)
        lte_info['phone_number']         = self._get_phone_number(data)
        lte_info['pin_state']            = self.get_pin_state(data)
        lte_info['connection_state']     = self._get_connection_state()
        lte_info['registration_network'] = self._get_registration_state()
        lte_info['sim']                  = self.get_sim_info()

        # to fetch information below, modem cannot be locked
        modem_state, _ = self._get_modem_state(data)
        if modem_state == 'locked':
            return lte_info

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
        lte_info['address']              = addr
        lte_info['connectivity']         = connectivity
        lte_info['signals']              = self._get_signal()
        lte_info['system_info']          = self._get_system_info(data)
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

        if_name = self._get_lte_if_name()
        if_addr = fwutils.get_interface_address(if_name, log=False)
        if not if_addr:
            self.log.debug(f"set_arp_entry: no IP was found for {if_name} interfaces")
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
        self._set_db_entry('wrong_pin', None)

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

    def _get_lte_if_name(self):
        # "if_name" can be "wwan0" if vpp does not run, or "vppX" if vpp does run
        if_name = fwutils.dev_id_to_tap(self.dev_id, check_vpp_state=True, print_log=False)
        if not if_name:
            if_name = self.linux_if # -> "wwan0"
        return if_name

    def check_connectivity(self):
        if_name = self._get_lte_if_name()
        cmd = "fping 8.8.8.8 -C 1 -q -R -I %s > /dev/null 2>&1" % if_name
        ok = not subprocess.call(cmd, shell=True)
        if ok:
            return True

        connected = self.is_connected()

        if not connected:
            self.log.debug("lte modem is disconnected on %s" % self.dev_id)
            fwglobals.g.system_api.restore_configuration(types=['add-lte'])

        # Make sure that LTE Linux interface is up
        # "modem.linux_if" is always "wwan0".
        # The tap interface should be up by Netplan.
        os.system(f'ip link set dev {self.linux_if} up')

        if fwglobals.g.router_api.state_is_started():
            # if GW exists, ensure ARP entry exists in Linux
            gw, _ = fwutils.get_interface_gateway(if_name)
            if gw:
                arp_entries = fwutils.get_gateway_arp_entries(gw)
                valid_arp_entries = list(filter(lambda entry: 'PERMANENT' in entry, arp_entries))
                if not valid_arp_entries:
                    self.log.debug(f'no valid ARP entry found. gw={gw}, name={if_name}, dev_id={self.dev_id}, \
                            arp_entries={str(arp_entries)}. adding now')
                    self.set_arp_entry(is_add=True, gw=gw)

                # ensure traffic control settings are configured
            self.ensure_tc_config()

        return False

    def check_ip_change(self, metric):
        modem_addr, new_gw, _ = self.get_ip_configuration(cache=False)
        if not modem_addr:
            return

        if_name = self._get_lte_if_name()
        iface_addr = fwutils.get_interface_address(if_name, log=False)
        if iface_addr == modem_addr:
            return

        self.log.debug("%s: LTE IP change detected: %s -> %s" % (self.dev_id, iface_addr, modem_addr))

        # If vpp runs, just update the interface IP and gateway.
        # Our IP monitoring thread should detect the change in Linux IPs
        # and continue with applying rest configuration related to IP changes
        if fwglobals.g.router_api.state_is_started():
            mtu = fwutils.get_linux_interface_mtu(if_name)

            fwnetplan.add_remove_netplan_interface(\
                        is_add=True,
                        dev_id=self.dev_id,
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
            self.configure_interface(metric)

        self.log.debug("%s: LTE IP was changed: %s -> %s" % (self.dev_id, iface_addr, modem_addr))

    def validate_modem(self):
        if self.mode == 'QMI':
            return (False, "Unsupported modem mode (QMI)")

    def validate_sim(self, pin):
        pin_state = self.get_pin_state().get('pin1_status', 'disabled')
        # pin state can be: disabled, sim-missing, blocked, enabled-verified, enabled-not-verified.

        # check if sim exists
        if pin_state == 'sim-missing' or self._get_sim_card_status() != "present":
            return (False, "SIM not present")

        if pin_state == 'disabled':
            self._set_db_entry('wrong_pin', None)
            return

        if pin_state == 'blocked':
            return (False, "SIM is blocked with PUK")

        # At this point, sim status is enabled-verified or enabled-not-verified.
        if not pin:
            return (False, "PIN is required")

        # In case of an incorrect PIN entry,
        # we store the PIN and refrain from attempting it again to prevent the SIM from being blocked.
        wrong_pin = self._get_db_entry('wrong_pin')
        if wrong_pin and wrong_pin == pin:
            return (False, "Wrong PIN provisioned")

        if pin_state == 'enabled-not-verified': # We cannot verify a SIM card that has already been verified
            _, err = self._verify_pin(pin)
            if err:
                self._set_db_entry('wrong_pin', pin)
                return (False, "PIN is wrong")

        if pin_state == 'enabled-verified':
            # If a user changes the PIN and it has already been verified,
            # it is not possible to directly confirm whether the new PIN is correct.
            # To check, we use a "trick" by executing the change PIN command with
            # the requested PIN entered as both the old and new PIN.
            # If the command fails, then the PIN is incorrect.
            # If the command succeeds, then the new PIN is correct.
            _, err = self._change_pin(pin, pin)
            if err:
                self._set_db_entry('wrong_pin', pin)
                return (False, "PIN is wrong")

        # We can now confirm that the PIN is either valid or disabled,
        # which means we can remove the protection for incorrect PINs.
        self._set_db_entry('wrong_pin', None)

class FwModemManager():
    def __init__(self):
        self.modems = {}
        self.scan()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        return

    def scan(self):
        self.modems = {}
        if_names_by_dev_ids = get_if_names_by_dev_ids(allow_qmi=True)
        for dev_id in if_names_by_dev_ids:
            try:
                modem = FwModem(dev_id)
                self.modems[dev_id] = modem
            except Exception as e:
                fwglobals.log.error(f'failed to load modem. dev_id={dev_id}, err={str(e)}')

    def get(self, dev_id):
        modem = self.modems.get(dev_id)
        if not modem:
            raise Exception(f"No modem found. dev_id={dev_id}")
        return modem

    def get_safe(self, dev_id):
        modem = self.modems.get(dev_id)
        return modem

    def call(self, dev_id, func, args = {}):
        modem = self.get(dev_id)
        modem_func = getattr(modem, func)
        return modem_func(**args)

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

def get_one_ip_configuration(dev_id, config_name):
    """ Get IP configuration by a config name.

    :param config_name: The config name to return - One of: ip, gateway, dns_servers

    :return: Config value or empty string.
    """
    ip, gateway, dns_servers = fwglobals.g.modems.get(dev_id).get_ip_configuration()
    if config_name == 'ip':
        return ip or '' # do not return None to translation substitute function
    elif config_name == 'gateway':
        return gateway or '' # do not return None to translation substitute function
    elif config_name == 'dns_servers':
        return dns_servers or '' # do not return None to translation substitute function

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

def get_if_names_by_dev_ids(allow_qmi=False):
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