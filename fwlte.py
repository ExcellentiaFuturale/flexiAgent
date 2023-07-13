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

import serial

import fw_os_utils
import fwglobals
import fwlte_utils
import fwutils
from fwcfg_request_handler import FwCfgMultiOpsWithRevert
from fwobject import FwObject


class MODEM_STATES():
    CONNECTING = 'CONNECTING'
    CONNECTED = 'CONNECTED'
    NOT_CONNECTED = 'CONNECTED'
    RESETTING = 'RESETTING'
    FAILED = 'FAILED'
    UNDEFINED = 'UNDEFINED'

class FwLteModem(FwObject):
    def __init__(self, dev_id):
        FwObject.__init__(self)
        self.dev_id = dev_id
        self.nicname = None
        self.modem_manager_path = None
        self.driver = None
        self.vendor = None
        self.model = None
        self.imei = None
        self.usb_device = None
        self.ip = None
        self.gateway = None
        self.dns_servers = []
        self.sim_presented = None
        self.state = MODEM_STATES.UNDEFINED

        self.initialize()

    def initialize(self):
        if not self.dev_id:
            return

        self.nicname = fwutils.dev_id_to_linux_if(self.dev_id)
        self.driver = fwutils.get_interface_driver(self.nicname, cache=False)

        if self.driver == 'cdc_mbim':
            self.mode = 'MBIM'
        elif self.driver == 'qmi_wwan':
            self.mode = 'QMI'

        self.usb_device = fwlte_utils.dev_id_to_usb_device(self.dev_id)
        self.modem_manager_path = self._get_modem_manager_path()

        self._initialize_state()

    def _initialize_state(self):
        if self.mode == 'QMI':
            return

        if self.is_connected():
            self.state = MODEM_STATES.CONNECTED
            return

        state, _ = self.get_state()
        if state == 'failed':
            self.state = MODEM_STATES.FAILED
            return

        self.state = MODEM_STATES.NOT_CONNECTED

    def is_connecting(self):
        return self.state == MODEM_STATES.CONNECTING

    def is_resetting(self):
        return self.state == MODEM_STATES.RESETTING

    def is_connecting_or_resetting(self):
        return self.is_resetting() or self.is_connecting()

    def get_state(self, data=None):
        if not data:
            data = self.get_modem_manager_data()
        state = data.get('generic', {}).get('state')
        reason = data.get('generic', {}).get('state-failed-reason')
        return state, reason

    def _get_modem_manager_path(self):
        # {
        #     "modem": {
        #         ...
        #         "dbus-path": "/org/freedesktop/ModemManager1/Modem/0",
        #         ...
        #      }
        # }
        if not self.modem_manager_path:
            modem_list_output = _mmcli_exec('-L')
            modem_list = modem_list_output.get('modem-list', [])
            if not modem_list:
                # send scan command and check after few moments
                _mmcli_exec('-S', False)
                time.sleep(5)
                modem_list = modem_list_output.get('modem-list', [])

            for modem in modem_list:
                modem_object_output = _mmcli_exec(f'-m {modem}')
                modem_object = modem_object_output.get('modem')
                generic = modem_object.get('generic', {})

                primary_port = generic.get('primary-port')
                if primary_port == self.usb_device:
                    self.modem_manager_path = modem_object.get('dbus-path')
                    self.vendor = generic.get('manufacturer')
                    self.model = generic.get('model')
                    self.imei = modem_object.get('3gpp', {}).get('imei')

                    self.sim_presented = self.get_sim_card_status(modem_object) == 'present'

                    try:
                        self.mmcli_get(f'-e', False)
                        self.mmcli_get(f'--signal-setup=5', False)
                    except:
                        pass

                    break

        return self.modem_manager_path

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

    def ensure_tc_config(self):
        devices = [self.nicname]
        tap_if_name = fwutils.linux_tap_by_interface_name(self.nicname)
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
            os.system(f'sudo tc -force qdisc del dev {self.nicname} ingress handle ffff:')
            # Note, don't remove qdisc from "tap_if_name" (tap_wwan0) as it is configured in vpp startup.conf as part of QoS
            os.system(f'sudo tc -force filter del dev {self.nicname} root')
            if tap_if_name:
                os.system(f'sudo tc -force filter del dev {tap_if_name} root')

            self.add_del_traffic_control(is_add=True)

    def get_connection_state(self):
        lines, err = fwlte_utils._run_mbimcli_command(self.dev_id, '--query-connection-state', print_error=True, device=self.usb_device)
        for line in lines:
            if 'Activation state' in line:
                return line.split(':')[-1].strip().replace("'", '')
        return ''

    def is_connected(self, cache=False):
        if cache:
            return self.state == MODEM_STATES.CONNECTED
        return self.get_connection_state() == 'activated'

    def connect(self, apn=None, user=None, password=None, auth=None, pin=None):
        # To avoid wan failover monitor and lte watchdog at this time
        self.state = MODEM_STATES.CONNECTING

        try:
            if self.mode == 'QMI':
                raise Exception("Unsupported modem mode (QMI)")

            # check if sim exists
            if self.get_sim_card_status() != "present":
                raise Exception("SIM not present")

            # check PIN status
            pin_state = self.get_pin_state().get('pin1_status', 'disabled')
            if pin_state not in ['disabled', 'enabled-verified']:
                if not pin:
                    raise Exception("PIN is required")

                # If a user enters a wrong pin, the function will fail, but flexiManage will send three times `sync` jobs.
                # As a result, the SIM may be locked. So we save the wrong pin in the cache
                # and we will not try again with this wrong one.
                wrong_pin = fwlte_utils.get_db_entry(self.dev_id, 'wrong_pin')
                if wrong_pin and wrong_pin == pin:
                    raise Exception("Wrong PIN provisioned")

                _, err = self.verify_pin(pin)
                if err:
                    fwlte_utils.set_db_entry(self.dev_id, 'wrong_pin', pin)
                    raise Exception("PIN is wrong")

            # At this point, we sure that the sim is unblocked.
            # After a block, the sim might open it from different places (manually qmicli command, for example),
            # so we need to make sure to clear this cache
            fwlte_utils.set_db_entry(self.dev_id, 'wrong_pin', None)

            # Check if modem already connected to ISP.
            if self.is_connected():
                self.state = MODEM_STATES.CONNECTED
                return

            # Make sure context is released and set the interface to up
            self.disconnect()
            os.system(f'ifconfig {self.nicname} up')

            connection_params = self._prepare_connection_params(apn, user, password, auth)
            mbim_commands = [
                '--query-subscriber-ready-status',
                '--query-registration-state',
                '--attach-packet-service',
                f'--connect={connection_params}'
            ]
            for cmd in mbim_commands:
                lines, err = fwlte_utils._run_mbimcli_command(self.dev_id, cmd, print_error=True, device=self.usb_device)
                if err:
                    raise Exception(err)

            for idx, line in enumerate(lines):
                if 'IPv4 configuration available' in line and 'none' in line:
                    fwglobals.log.debug(f'connect: failed to get IPv4 from the ISP. lines={str(lines)}')
                    raise Exception(f'Failed to get IPv4 configuration from the ISP')
                if 'Session ID:' in line:
                    session = line.split(':')[-1].strip().replace("'", '')
                    fwlte_utils.set_db_entry(self.dev_id, 'session', session)
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

            self.state = MODEM_STATES.CONNECTED
            return (True, None)
        except Exception as e:
            fwglobals.log.debug('connect: failed to connect lte. %s' % str(e))
            self.state = None
            self.disconnect()
            return (False, str(e))

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
                fwutils.os_system(f"ifconfig {self.nicname} up")
                return

            ip, gateway, dns_servers = self.get_ip_configuration()

            fwutils.os_system(f"ifconfig {self.nicname} {ip} up")

            # remove old default router
            output = os.popen('ip route list match default | grep %s' % self.nicname).read()
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
                fwutils.os_system(f"systemd-resolve {set_dns_str} --interface {self.nicname}")

            fwutils.clear_linux_interfaces_cache() # remove this code when move ip configuration to netplan
        except Exception as e:
            return (False, "Failed to configure lte for dev_id %s. (%s)" % (self.dev_id, str(e)))

    def disconnect(self):
        try:
            session = fwlte_utils.get_db_entry(self.dev_id, 'session')
            if not session:
                session = '0' # default session

            fwlte_utils._run_mbimcli_command(self.dev_id, '--disconnect=%s' % session, device=self.usb_device)
            os.system(f'sudo ip link set dev {self.nicname} down && sudo ip addr flush dev {self.nicname}')

            # update the cache
            self.ip = None
            self.gateway = None
            self.dns_servers = []

            fwutils.clear_linux_interfaces_cache() # remove this code when move ip configuration to netplan

            return (True, None)
        except subprocess.CalledProcessError as e:
            return (False, str(e))

    def get_ip_configuration(self, cache=True, config_name=None):
        try:
            # if not exists, take from modem and update cache
            if not self.ip or not self.gateway or not self.dns_servers or cache == False:
                ip, gateway, primary_dns, secondary_dns = fwlte_utils.mbim_get_ip_configuration(self.dev_id)

                if ip:
                    self.ip = ip
                if gateway:
                    self.gateway = gateway
                if primary_dns and secondary_dns:
                    self.dns_servers = [primary_dns, secondary_dns]
        except Exception as e:
            fwglobals.log.debug(f"get_ip_configuration({self.dev_id}, {cache}) failed: {str(e)}")
            pass

        if config_name == 'ip':
            return self.ip
        elif config_name == 'gateway':
            return self.gateway
        elif config_name == 'dns_servers':
            return self.dns_servers
        return self.ip, self.gateway, self.dns_servers

    def reset_modem(self):
        self.state = MODEM_STATES.RESETTING

        recreate_tc_filters = False
        if fw_os_utils.vpp_does_run() and fwutils.is_interface_assigned_to_vpp(self.dev_id):
            recreate_tc_filters = True

        try:
            fwglobals.log.debug('reset_modem: reset starting')

            if recreate_tc_filters:
                fwglobals.log.debug('reset_modem: removing TC configuration')
                try:
                    self.add_del_traffic_control(is_add=False)
                except Exception as e:
                    # Forgive a failure in TC removal here, as it will prevent code to from resetting the modem.
                    fwglobals.log.error('reset_modem: failed to remove traffic control. Continue to reset...')


            # do the reset
            self.mmcli_get(f'-r', False)
            self.modem_manager_path = None

            # In the reset process, the LTE interface (wwan) is deleted from Linux, and then comes back up.
            # We verify these two steps to make sure the reset process is completed successfully

            # if vpp runs, we have the tap_wwan0 interface, so we filter it out to make sure that the LTE interface (wwan0) doesn't exist
            cmd = f"sudo ls -l /sys/class/net/ | grep -v tap_ | grep {self.nicname}"
            ifc_removed = fwutils.exec_with_retrials(cmd, retrials=60, expected_to_fail=True)
            if not ifc_removed:
                raise Exception('the modem exists after reset. it was expected to be temporarily removed')
            ifc_restored = fwutils.exec_with_retrials(cmd)
            if not ifc_restored:
                raise Exception('The modem has not recovered from the reset')

            # give modem manager little time to detect the modem
            fwutils.exec_with_retrials('mmcli -L | grep -q -v "No modems were found"', retrials=60)
            self.initialize()

            # To re-apply set-name for LTE interface we have to call netplan apply here
            fwutils.netplan_apply("reset_modem")

            if recreate_tc_filters:
                fwglobals.log.debug('reset_modem: applying TC configuration')
                self.add_del_traffic_control(is_add=True)

            fwglobals.log.debug('reset_modem: reset finished')
        finally:
            self.state = None
            # clear wrong PIN cache on reset
            fwlte_utils.set_db_entry(self.dev_id, 'wrong_pin', None)

    def get_sim_card_status(self, data=None):
        modem_state, reason = self.get_state(data)
        if modem_state == 'failed' and reason == 'sim-missing':
            # if modem failed due to another reason, it means that sim is presented
            return reason
        return 'present' # to keep backward compatibility, this string indicates in flexiManage that sim is ok

    def enable_pin(self, pin):
        return self._run_pin_command(f'--enable-pin --pin={pin}')

    def disable_pin(self, pin):
        return self._run_pin_command(f'--disable-pin --pin={pin}')

    def change_pin(self, current, new):
        return self._run_pin_command(f'--pin={current} --change-pin={new}')

    def unblock_pin(self, puk, new):
        return self._run_pin_command(f'--puk={puk} --pin={new}')

    def verify_pin(self, pin):
        fwglobals.log.debug('verifying lte pin number')
        return self._run_pin_command(f'--pin={pin}')

    def _run_pin_command(self, mmcli_pin_flag):
        data = self.get_modem_manager_data()
        sim_path = data.get('generic', {}).get('sim')
        try:
            _mmcli_exec(f'-i {sim_path} {mmcli_pin_flag}', False)
            return (self.get_pin_state(), None)
        except Exception as e:
            return (self.get_pin_state(), str(e))

    def get_pin_state(self, data=None):
        res = {
            'pin1_status': fwlte_utils.mbimcli_get_pin_status(self.dev_id),
            'pin1_retries': '',
            'puk1_retries': '',
        }

        if not data:
            data = self.get_modem_manager_data()
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

    def get_signal(self):
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

        output = self.mmcli_get('--signal-get')
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

    def get_system_info(self, data=None):
        result = {
            'cell_id'        : '',
            'mcc'            : '',
            'mnc'            : '',
            'operator_name'  : self.get_operator_name(data)
        }
        if not self.sim_presented:
            return result

        output = self.mmcli_get('--location-get')
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

    def get_operator_name(self, data=None):
        if not data:
            data = self.get_modem_manager_data()
        return data.get('3gpp', {}).get('operator-name')

    def get_phone_number(self, data=None):
        if not data:
            data = self.get_modem_manager_data()
        own_numbers = data.get('generic', {}).get('own-numbers', [])
        return ', '.join(own_numbers)

    def mmcli_get(self, flag = None, json_format=True):
        modem_path = self.modem_manager_path
        try:
            output = _mmcli_exec(f'-m {modem_path} {flag}', json_format)
            return output
        except Exception as e:
            if "modem is not enabled yet" in str(e):
                self.mmcli_get('-e', False)
            elif "couldn't find modem" not in str(e):
                raise e

            # try to load modem once again. ModemManager may re-index it with a different "modem_path".
            self.modem_manager_path = None
            updated_modem_path = self._get_modem_manager_path()
            if modem_path != updated_modem_path:
                return _mmcli_exec(f'-m {updated_modem_path} {flag}', json_format)
            raise e

    def get_default_settings(self, data=None):
        default_settings = {
            'APN'     : '',
            'username': '',
            'password': '',
            'auth'    : ''
        }

        if not data:
            data = self.get_modem_manager_data()
        bearer_path = data.get('3gpp', {}).get('eps', {}).get('initial-bearer', {}).get('dbus-path', '--')
        if bearer_path == '--': # modem manager sets "--" as default if not exists
            return default_settings

        bearer_data_output = _mmcli_exec(f'-b {bearer_path}')
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

    def get_modem_manager_data(self):
        modem_data = self.mmcli_get()
        # {
        #     "modem": {
        #         "3gpp": {
        #         "enabled-locks": [
        #             "fixed-dialing"
        #         ],
        #         "eps": {
        #             "initial-bearer": {
        #             "dbus-path": "--",
        #             "settings": {
        #                 "apn": "--",
        #                 "ip-type": "--",
        #                 "password": "--",
        #                 "user": "--"
        #             }
        #             },
        #             "ue-mode-operation": "ps-2"
        #         },
        #         "imei": "866680040112569",
        #         "operator-code": "--",
        #         "operator-name": "--",
        #         "pco": "--",
        #         "registration-state": "--"
        #         },
        #         "cdma": {
        #         "activation-state": "--",
        #         "cdma1x-registration-state": "--",
        #         "esn": "--",
        #         "evdo-registration-state": "--",
        #         "meid": "--",
        #         "nid": "--",
        #         "sid": "--"
        #         },
        #         "dbus-path": "/org/freedesktop/ModemManager1/Modem/0",
        #         "generic": {
        #         "access-technologies": [],
        #         "bearers": [],
        #         "carrier-configuration": "ROW_Generic_3GPP",
        #         "carrier-configuration-revision": "06010821",
        #         "current-bands": [
        #             "utran-1",
        #             "utran-3",
        #             "utran-5",
        #             "utran-8",
        #             "eutran-1",
        #             "eutran-3",
        #             "eutran-5",
        #             "eutran-7",
        #             "eutran-8",
        #             "eutran-20",
        #             "eutran-28",
        #             "eutran-32",
        #             "eutran-38",
        #             "eutran-40",
        #             "eutran-41"
        #         ],
        #         "current-capabilities": [
        #             "gsm-umts, lte"
        #         ],
        #         "current-modes": "allowed: 3g, 4g; preferred: 4g",
        #         "device": "/sys/devices/pci0000:00/0000:00:15.0/usb1/1-3",
        #         "device-identifier": "1cb7aed10665c820d13fa8459b4797c957d76059",
        #         "drivers": [
        #             "cdc_mbim",
        #             "option"
        #         ],
        #         "equipment-identifier": "866680040112569",
        #         "hardware-revision": "EM06-E",
        #         "manufacturer": "Quectel",
        #         "model": "EM06-E",
        #         "own-numbers": [],
        #         "plugin": "generic",
        #         "ports": [
        #             "cdc-wdm0 (mbim)",
        #             "ttyUSB0 (qcdm)",
        #             "ttyUSB1 (gps)",
        #             "ttyUSB2 (at)",
        #             "ttyUSB3 (at)",
        #             "wwan0 (net)"
        #         ],
        #         "power-state": "on",
        #         "primary-port": "cdc-wdm0",
        #         "primary-sim-slot": "--",
        #         "revision": "EM06ELAR03A08M4G",
        #         "signal-quality": {
        #             "recent": "no",
        #             "value": "0"
        #         },
        #         "sim": "/org/freedesktop/ModemManager1/SIM/0",
        #         "sim-slots": [],
        #         "state": "disabled",
        #         "state-failed-reason": "--",
        #         "supported-bands": [
        #             "utran-1",
        #             "utran-3",
        #             "utran-5",
        #             "utran-8",
        #             "eutran-1",
        #             "eutran-3",
        #             "eutran-5",
        #             "eutran-7",
        #             "eutran-8",
        #             "eutran-20",
        #             "eutran-28",
        #             "eutran-32",
        #             "eutran-38",
        #             "eutran-40",
        #             "eutran-41"
        #         ],
        #         "supported-capabilities": [
        #             "gsm-umts, lte"
        #         ],
        #         "supported-ip-families": [
        #             "ipv4",
        #             "ipv6",
        #             "ipv4v6"
        #         ],
        #         "supported-modes": [
        #             "allowed: 3g; preferred: none",
        #             "allowed: 4g; preferred: none",
        #             "allowed: 3g, 4g; preferred: 4g",
        #             "allowed: 3g, 4g; preferred: 3g"
        #         ],
        #         "unlock-required": "--",
        #         "unlock-retries": [
        #             "sim-pin2 (5)"
        #         ]
        #         }
        #     }
        # }
        return modem_data.get('modem')

    def get_hardware_info(self):
        return {
            'vendor'   : self.vendor,
            'model'    : self.model,
            'imei'     : self.imei,
        }

    def get_lte_info(self, data=None):
        lte_info = {
            'address'             : '',
            'signals'             : {},
            'connectivity'        : False,
            'packet_service_state': {},
            'hardware_info'       : {},
            'system_info'         : {},
            'sim_status'          : self.get_sim_card_status(),
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

        data = self.get_modem_manager_data()

        # There is no need to check the tap name if the router is not entirely run.
        # When the router is in the start process, and the LTE is not yet fully configured,
        # the "dev_id_to_tap()" causes a chain of unnecessary functions to be called,
        # and eventually, the result is empty.
        interface_name = self.nicname #fwutils.dev_id_to_linux_if(dev_id)
        if fwglobals.g.router_api.state_is_started():
            tap_name = fwutils.dev_id_to_tap(self.dev_id, check_vpp_state=True)
            if tap_name:
                interface_name = tap_name

        addr = fwutils.get_interface_address(interface_name)
        connectivity = os.system("ping -c 1 -W 1 -I %s 8.8.8.8 > /dev/null 2>&1" % interface_name) == 0

        lte_info['address']              = addr
        lte_info['signals']              = self.get_signal()
        lte_info['connectivity']         = connectivity
        lte_info['packet_service_state'] = fwlte_utils.mbimcli_get_packets_state(self.dev_id)
        lte_info['hardware_info']        = self.get_hardware_info()
        lte_info['system_info']          = self.get_system_info(data)
        lte_info['default_settings']     = self.get_default_settings(data)
        lte_info['phone_number']         = self.get_phone_number(data)
        lte_info['pin_state']            = self.get_pin_state(data)
        lte_info['connection_state']     = self.get_connection_state()
        lte_info['registration_network'] = fwlte_utils.mbimcli_registration_state(self.dev_id)
        return lte_info

    def set_arp_entry(self, is_add, gw=None):
        '''
        :param is_add:      if True the static ARP entry is added, o/w it is removed.
        :param dev_id:      the dev-id of the interface, the GW of which should be
                            used for the ARP entry. We used it to find the vpp_if_name,
                            which is needed to update VPP with the ARP entry.
                            As well it is needed to find the GW, of the last was not provided.
        :param gw:          the IP of GW for which the ARP entry should be added/removed.
        '''
        vpp_if_name = fwutils.dev_id_to_vpp_if_name(self.dev_id)
        if not vpp_if_name:
            raise Exception(f"set_arp_entry: failed to resolve {self.dev_id} to vpp_if_name")

        if not gw:
            _, gw, _ = self.get_ip_configuration(cache=False)
            if not gw:
                fwglobals.log.debug(f"set_arp_entry: no GW was found for {self.dev_id}")
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

    def set_mbim_mode(self):
        """Switch LTE modem to the MBIM mode
        """
        try:
            lte_driver = self.driver
            if lte_driver == 'cdc_mbim':
                return

            fwglobals.log.debug(f'Modem Vendor: {self.vendor}. Modem Model: {self.model}')

            at_commands = []
            if 'Quectel' in self.vendor or re.match('Quectel', self.model, re.IGNORECASE): # Special fix for Quectel ec25 mini pci card
                at_commands = ['AT+QCFG="usbnet",2']
                at_serial_port = fwlte_utils.get_at_port(self.dev_id)
                if at_serial_port and len(at_serial_port) > 0:
                    fwglobals.log.debug(f'The serial port is found. {at_serial_port[0]}')
                    ser = serial.Serial(at_serial_port[0])
                    for at in at_commands:
                        at_cmd = bytes(at + '\r', 'utf-8')
                        ser.write(at_cmd)
                        time.sleep(0.5)
                    ser.close()
                else:
                    raise Exception(f'The serial port is not found. dev_id: {self.dev_id}')
            elif 'Sierra Wireless' in self.vendor:
                fwlte_utils._run_qmicli_command(self.dev_id, 'dms-swi-set-usb-composition=8', device=self.usb_device)
            else:
                fwglobals.log.error("Your card is not officially supported. It might work, But you have to switch manually to the MBIM modem")
                raise Exception('vendor or model are not supported. (vendor: %s, model: %s)' % (self.vendor, self.model))

            fwglobals.log.debug(f'Modem was switched to MBIM. Resetting the modem')

            # at this point the modem switched to mbim mode without errors
            # but we have to reset the modem in order to apply it
            self.reset_modem()

            fwglobals.log.debug(f'The reset process was completed successfully')

            os.system('modprobe cdc_mbim') # sometimes driver doesn't register to the device after reset

            return
        except Exception as e:
            # Modem cards sometimes get stuck and recover only after disconnecting the router from the power supply
            self.log.error("Failed to switch modem to MBIM. You can unplug the router, wait a few seconds and try again. (%s)" % str(e))
            raise e

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
        lte_if_name = self.nicname

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
                fwglobals.log.error(f"add_del_traffic_control({self.dev_id}, {lte_if_name}): {str(e)}")
                handler.revert(e)

class FwLte():
    def __init__(self):
        self.modems = {}
        self.initialized = False

        self.initialize()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        return

    def scan(self):
        dev_ids = fwlte_utils.get_dev_ids(allow_qmi=True)
        for dev_id in dev_ids:
            modem = FwLteModem(dev_id)
            self.modems[dev_id] = modem

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


def _mmcli_exec(flag, json_format=True):
    # -J at the end tells modem manager to return output in JSON format
    success, output = fwutils.exec(f'mmcli {flag} {"-J" if json_format else ""}')
    if not success:
        raise Exception(output)

    if json_format:
        output = json.loads(output)
    return output

def get_ip_configuration(dev_id, key):
    return fwglobals.g.lte.get(dev_id).get_ip_configuration(config_name=key)

def disconnect_all():
    """ Disconnect all modems safely
    """
    if fwglobals.g.lte:
        for modem in fwglobals.g.lte.modems:
            modem.disconnect()
    else:
        with FwLte() as fwlte:
            for modem in fwlte.modems:
                modem.disconnect()
