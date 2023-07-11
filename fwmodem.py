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

import fw_os_utils
import fwglobals
import fwlte
import fwutils
from fwcfg_request_handler import FwCfgMultiOpsWithRevert
from fwobject import FwObject
import time

class MODEM_STATES():
    CONNECTING = 'CONNECTING'
    CONNECTED = 'CONNECTED'
    RESETTING = 'RESETTING'

class FwModem(FwObject):
    def __init__(self, dev_id):
        FwObject.__init__(self)
        self.dev_id = dev_id
        self.nicname = None
        self.modem_manager_path = None
        self.mode = None
        self.driver = None
        self.vendor = None
        self.model = None
        self.imei = None
        self.usb_device = None
        self.ip = None
        self.gateway = None
        self.dns_servers = []

        self.sim_presented = None

        self.state = None

    def load_modem(self):
        if not self.dev_id:
            return

        self.nicname = self._get_nicname()
        self.driver = self._get_driver()
        self.mode = self._get_mode()
        self.usb_device = fwlte.dev_id_to_usb_device(self.dev_id)
        self.modem_manager_path = self._get_modem_manager_path()

    def _get_nicname(self):
        if not self.nicname:
            self.nicname = fwutils.dev_id_to_linux_if(self.dev_id)
        return self.nicname

    def is_connecting(self):
        return self.state == MODEM_STATES.CONNECTING

    def is_resetting(self):
        return self.state == MODEM_STATES.RESETTING

    def _get_driver(self):
        if not self.driver:
            nicname = self._get_nicname()
            self.driver = fwutils.get_interface_driver(nicname, cache=False)
        return self.driver

    def get_usb_device(self):
        if not self.usb_device:
            self.usb_device = fwlte.dev_id_to_usb_device(self.dev_id)
        return self.usb_device

    def _get_mode(self):
        if not self.mode:
            driver = self._get_driver()
            if driver == 'cdc_mbim':
                self.mode = 'MBIM'
            elif driver == 'qmi_wwan':
                self.mode = 'QMI'
        return self.mode

    def _get_modem_manager_path(self):
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
        #     }
        if not self.modem_manager_path:
            modem_list_output = exec_modem_manager_cmd('-L')
            modem_list = modem_list_output.get('modem-list', [])
            if not modem_list:
                # send scan command and check after few moments
                exec_modem_manager_cmd('-S', False)
                time.sleep(5)
                modem_list = modem_list_output.get('modem-list', [])

            usb_device = self.get_usb_device()
            for modem in modem_list:
                modem_object_output = exec_modem_manager_cmd(f'-m {modem}')
                modem_object = modem_object_output.get('modem')
                generic = modem_object.get('generic', {})

                primary_port = generic.get('primary-port')
                if primary_port == usb_device:
                    self.modem_manager_path = modem_object.get('dbus-path')
                    self.vendor = generic.get('manufacturer')
                    self.model = generic.get('model')
                    self.imei = modem_object.get('3gpp', {}).get('imei')

                    self.sim_presented = self.get_sim_card_status(modem_object) == 'present'

                    try:
                        self.fetch_from_modem_manager(f'-e', False)
                        self.fetch_from_modem_manager(f'--signal-setup=5', False)
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
                data = json.loads(output)
                if not data:
                    need_to_recreate = True
                    break
            except:
                need_to_recreate = True
                break
        
        if need_to_recreate:
            os.system(f'sudo tc -force qdisc del dev {self.nicname} ingress handle ffff:')
            # Note, don't remove qdisc from "tap_if_name" (tap_wwan0) as it is configured in vpp startup.conf as part of QoS
            os.system(f'sudo tc -force filter del dev {self.nicname} root')
            if tap_if_name:
                os.system(f'sudo tc -force filter del dev {tap_if_name} root')
            
            self.add_del_traffic_control(is_add=True)
        
    def connect(self, apn=None, user=None, password=None, auth=None, pin=None):
        # To avoid wan failover monitor and lte watchdog at this time
        self.state = MODEM_STATES.CONNECTING

        try:
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
                wrong_pin = fwlte.get_db_entry(self.dev_id, 'wrong_pin')
                if wrong_pin and wrong_pin == pin:
                    raise Exception("Wrong PIN provisioned")

                _, err = self.verify_pin(pin)
                if err:
                    fwlte.set_db_entry(self.dev_id, 'wrong_pin', pin)
                    raise Exception("PIN is wrong")

            # At this point, we sure that the sim is unblocked.
            # After a block, the sim might open it from different places (manually qmicli command, for example),
            # so we need to make sure to clear this cache
            fwlte.set_db_entry(self.dev_id, 'wrong_pin', None)

            # Check if modem already connected to ISP.
            if fwlte.mbim_is_connected(self.dev_id):
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
                lines, err = fwlte._run_mbimcli_command(self.dev_id, cmd, print_error=True, device=self.usb_device)
                if err:
                    raise Exception(err)

            for idx, line in enumerate(lines):
                if 'IPv4 configuration available' in line and 'none' in line:
                    fwglobals.log.debug(f'connect: failed to get IPv4 from the ISP. lines={str(lines)}')
                    raise Exception(f'Failed to get IPv4 configuration from the ISP')
                if 'Session ID:' in line:
                    session = line.split(':')[-1].strip().replace("'", '')
                    fwlte.set_db_entry(self.dev_id, 'session', session)
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
            session = fwlte.get_db_entry(self.dev_id, 'session')
            if not session:
                session = '0' # default session

            fwlte._run_mbimcli_command(self.dev_id, '--disconnect=%s' % session, device=self.usb_device)
            os.system(f'sudo ip link set dev {self.nicname} down && sudo ip addr flush dev {self.nicname}')

            # update the cache
            self.ip = None
            self.gateway = None

            fwutils.clear_linux_interfaces_cache() # remove this code when move ip configuration to netplan

            return (True, None)
        except subprocess.CalledProcessError as e:
            return (False, str(e))

    def get_ip_configuration(self, cache=True):
        try:
            # if not exists, take from modem and update cache
            if not self.ip or not self.gateway or not self.dns_servers or cache == False:
                ip, gateway, primary_dns, secondary_dns = fwlte.mbim_get_ip_configuration(self.dev_id)

                if ip:
                    self.ip = ip
                if gateway:
                    self.gateway = gateway
                if primary_dns and secondary_dns:
                    self.dns_servers = [primary_dns, secondary_dns]
        except Exception as e:
            fwglobals.log.debug(f"get_ip_configuration({self.dev_id}, {cache}) failed: {str(e)}")
            pass

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
            self.fetch_from_modem_manager(f'-r', False)
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
            self.load_modem()

            # To re-apply set-name for LTE interface we have to call netplan apply here
            fwutils.netplan_apply("reset_modem")

            if recreate_tc_filters:
                fwglobals.log.debug('reset_modem: applying TC configuration')
                self.add_del_traffic_control(is_add=True)

            fwglobals.log.debug('reset_modem: reset finished')
        finally:
            self.state = None
            # clear wrong PIN cache on reset
            fwlte.set_db_entry(self.dev_id, 'wrong_pin', None)

    def get_sim_card_status(self, info=None):
        if not info:
            info = self.get_modem_manager_info()
        modem_state = info.get('generic', {}).get('state')
        if modem_state == 'failed':
            reason = info.get('generic', {}).get('state-failed-reason')
            if reason == 'sim-missing':
                return reason
        return 'present' # to keep backward compatibility, this string indicates in flexiManage that sim is ok.

    def enable_pin(self, pin):
        info = self.get_modem_manager_info()
        sim_path = info.get('generic', {}).get('sim')
        try:
            exec_modem_manager_cmd(f'-i {sim_path} --enable-pin --pin={pin}', False)
            return (self.get_pin_state(), None)
        except Exception as e:
            return (self.get_pin_state(), str(e))

    def disable_pin(self, pin):
        info = self.get_modem_manager_info()
        sim_path = info.get('generic', {}).get('sim')
        try:
            exec_modem_manager_cmd(f'-i {sim_path} --disable-pin --pin={pin}', False)
            return (self.get_pin_state(), None)
        except Exception as e:
            return (self.get_pin_state(), str(e))

    def change_pin(self, current, new):
        info = self.get_modem_manager_info()
        sim_path = info.get('generic', {}).get('sim')
        try:
            exec_modem_manager_cmd(f'-i {sim_path} --pin={current} --change-pin={new}', False)
            return (self.get_pin_state(), None)
        except Exception as e:
            return (self.get_pin_state(), str(e))

    def unblock_pin(self, puk, new):
        info = self.get_modem_manager_info()
        sim_path = info.get('generic', {}).get('sim')
        try:
            exec_modem_manager_cmd(f'-i {sim_path} --puk={puk} --pin={new}', False)
            return (self.get_pin_state(), None)
        except Exception as e:
            return (self.get_pin_state(), str(e))

    def verify_pin(self, pin):
        info = self.get_modem_manager_info()
        sim_path = info.get('generic', {}).get('sim')
        try:
            fwglobals.log.debug('verifying lte pin number')
            exec_modem_manager_cmd(f'-i {sim_path} --pin={pin}', False)
            return (self.get_pin_state(), None)
        except Exception as e:
            return (self.get_pin_state(), str(e))

    def get_pin_state(self, info=None):
        res = {
            'pin1_status': fwlte.mbimcli_get_pin_status(self.dev_id),
            'pin1_retries': '',
            'puk1_retries': '',
        }

        if not info:
            info = self.get_modem_manager_info()
        unlock_retries = info.get('generic', {}).get('unlock-retries', [])
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
            'text' : ''
        }
        if not self.sim_presented:
            return result
        
        output = self.fetch_from_modem_manager('--signal-get')
        lte_signal = output.get('modem', {}).get('signal', {}).get('lte', {})
        evdo_signal = output.get('modem', {}).get('signal', {}).get('evdo', {})

        result['rssi'] = lte_signal.get('rssi')
        result['rsrp'] = lte_signal.get('rsrp')
        result['rsrq'] = lte_signal.get('rsrq')
        result['sinr'] = evdo_signal.get('sinr')
        result['snr'] = lte_signal.get('snr')

        if result['rssi'] == '--':
            result['text'] = 'N/A'
        else:
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

    def get_system_info(self, info=None):
        result = {
            'cell_id'        : '',
            'mcc'            : '',
            'mnc'            : '',
            'operator_name'  : self.get_operator_name(info)
        }
        if not self.sim_presented:
            return result

        output = self.fetch_from_modem_manager('--location-get')
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

    def get_operator_name(self, info=None):
        if not info:
            info = self.get_modem_manager_info()
        return info.get('3gpp', {}).get('operator-name')

    def get_phone_number(self, info=None):
        if not info:
            info = self.get_modem_manager_info()
        own_numbers = info.get('generic', {}).get('own-numbers', [])
        return ', '.join(own_numbers)

    def fetch_from_modem_manager(self, flag = None, json_format=True):
        modem_path = self.modem_manager_path
        try:
            output = exec_modem_manager_cmd(f'-m {modem_path} {flag}', json_format)
            return output
        except Exception as e:
            if "modem is not enabled yet" in str(e):
                self.fetch_from_modem_manager('-e', False)
            elif "couldn't find modem" not in str(e):
                raise e

            # try to load modem once again. ModemManager may re-index it with a different "modem_path".
            self.modem_manager_path = None
            updated_modem_path = self._get_modem_manager_path()
            if modem_path != updated_modem_path:
                return exec_modem_manager_cmd(f'-m {updated_modem_path} {flag}', json_format)
            raise e

    def get_default_bearer(self, info=None):
        default_settings = {
            'APN'     : '',
            'username': '',
            'password': '',
            'auth'    : ''
        }

        if not info:
            info = self.get_modem_manager_info()
        bearer_path = info.get('3gpp', {}).get('eps', {}).get('initial-bearer', {}).get('dbus-path', '--')
        if bearer_path == '--': # modem manager sets "--" as default if not exists
            return default_settings

        bearer_info_output = exec_modem_manager_cmd(f'-b {bearer_path}')
        bearer_info = bearer_info_output.get('bearer', {}).get('properties', {})

        apn = bearer_info.get('apn', '--')
        user = bearer_info.get('user', '--')
        password = bearer_info.get('password', '--')

        default_settings['APN'] = apn if apn != '--' else ''
        default_settings['username'] = user if user != '--' else ''
        default_settings['password'] = password if password != '--' else ''

        allowed_auth = bearer_info.get('allowed-auth', [])
        if allowed_auth:
            default_settings['auth'] = allowed_auth[0]
        return default_settings

    def get_modem_manager_info(self):
        modem_info = self.fetch_from_modem_manager()
        return modem_info.get('modem')

    def get_hardware_info(self):
        return {
            'vendor'   : self.vendor,
            'model'    : self.model,
            'imei'     : self.imei,
        }

    def collect_lte_info(self, info=None):
        info = self.get_modem_manager_info()

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

        response = {
            'address'             : addr,
            'signals'             : self.get_signal(),
            'connectivity'        : connectivity,
            'packet_service_state': fwlte.mbimcli_get_packets_state(self.dev_id),
            'hardware_info'       : self.get_hardware_info(),
            'system_info'         : self.get_system_info(info),
            'sim_status'          : self.get_sim_card_status(info),
            'default_settings'    : self.get_default_bearer(info),
            'phone_number'        : self.get_phone_number(info),
            'pin_state'           : self.get_pin_state(info),
            'connection_state'    : fwlte.mbimcli_query_connection_state(self.dev_id),
            'registration_network': fwlte.mbimcli_registration_state(self.dev_id)
        }
        return response

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

class FwModems():
    def __init__(self):
        self.modems = {}

        self.scan()

        self.initialized = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        return

    def scan(self):
        lte_interfaces_dev_ids = fwlte.get_lte_interfaces_dev_ids(allow_qmi=True)
        for lte_interface_dev_id in lte_interfaces_dev_ids:
            modem = FwModem(lte_interface_dev_id)
            modem.load_modem()
            self.modems[lte_interface_dev_id] = modem

    def get(self, dev_id, exception_if_not_found = True):
        modem = self.modems.get(dev_id, None)
        if not modem and exception_if_not_found:
            raise Exception(f"No modem found. dev_id={dev_id}")
        return modem

    def finalize(self):
        self.modems = {}
        self.initialized = False

    def reset_modem(self, dev_id):
        modem = self.get(dev_id)
        return modem.reset_modem()

    def get_pin_state(self, dev_id):
        modem = self.get(dev_id)
        return modem.get_pin_state()

    def collect_lte_info(self, dev_id):
        modem = self.get(dev_id)
        return modem.collect_lte_info()

    def get_sim_card_status(self, dev_id):
        modem = self.get(dev_id)
        return modem.get_sim_card_status()

    def verify_pin(self, dev_id, pin):
        modem = self.get(dev_id)
        return modem.verify_pin(pin)

    def enable_pin(self, dev_id, pin):
        modem = self.get(dev_id)
        return modem.enable_pin(pin)

    def disable_pin(self, dev_id, pin):
        modem = self.get(dev_id)
        return modem.disable_pin(pin)

    def change_pin(self, dev_id, old_pin, new_pin):
        modem = self.get(dev_id)
        return modem.change_pin(old_pin, new_pin)

    def unblock_pin(self, dev_id, puk, new_pin):
        modem = self.get(dev_id)
        return modem.unblock_pin(puk, new_pin)

    def get_hardware_info(self, dev_id):
        modem = self.get(dev_id)
        return modem.get_hardware_info()

    def set_arp_entry(self, is_add, dev_id, gw=None):
        modem = self.get(dev_id)
        return modem.set_arp_entry(is_add, gw)

    def add_del_traffic_control(self, dev_id, is_add):
        modem = self.get(dev_id)
        return modem.add_del_traffic_control(is_add)

    def get_ip_configuration(self, dev_id, cache=True):
        modem = self.get(dev_id)
        return modem.get_ip_configuration(cache)

    def connect(self, dev_id, apn=None, user=None, password=None, auth=None, pin=None):
        modem = self.get(dev_id)
        return modem.connect(apn=apn, user=user, password=password, auth=auth, pin=pin)

    def disconnect(self, dev_id):
        modem = self.get(dev_id)
        return modem.disconnect()

    def configure_interface(self, dev_id, metric):
        modem = self.get(dev_id)
        return modem.configure_interface(metric)

    def get_usb_device(self, dev_id):
        modem = self.get(dev_id)
        return modem.get_usb_device()


def exec_modem_manager_cmd(flag, json_format=True):
    success, output = fwutils.exec(f'mmcli {flag} {"-J" if json_format else ""}')
    if not success:
        raise Exception(output)

    if json_format:
        # -J at the end tells modem manager to return output in JSON format
        output = json.loads(output)
    return output

def get_modem_ip_config(dev_id, key):
    ip, gw, dns_servers = fwglobals.g.modems.get_ip_configuration(dev_id)
    if key == 'ip':
        return ip
    elif key == 'gateway':
        return gw
    elif key == 'dns_servers':
        return dns_servers
    return None

def disconnect(dev_id):
    """ Disconnect modem safely
    """
    if fwglobals.g.modems:
        return fwglobals.g.modems.disconnect(dev_id)
    else:
        with FwModems() as modems:
            return modems.disconnect(dev_id)
