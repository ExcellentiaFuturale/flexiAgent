################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2022  flexiWAN Ltd.
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

import os
import re
import serial
import subprocess
import time

from netaddr import IPAddress

import fwglobals
import fwutils

class LTE_ERROR_MESSAGES():
    PIN_IS_WRONG = 'PIN_IS_WRONG'
    PIN_IS_REQUIRED = 'PIN_IS_REQUIRED'
    PIN_IS_DISABLED = 'PIN_IS_DISABLED'

    NEW_PIN_IS_REQUIRED = 'NEW_PIN_IS_REQUIRED'

    PUK_IS_WRONG = 'PUK_IS_WRONG'
    PUK_IS_REQUIRED = 'PUK_IS_REQUIRED'

def _run_qmicli_command(dev_id, flag, print_error=False):
    try:
        device = dev_id_to_usb_device(dev_id) if dev_id else 'cdc-wdm0'
        qmicli_cmd = 'qmicli --device=/dev/%s --device-open-proxy --%s' % (device, flag)
        fwglobals.log.debug("_run_qmicli_command: %s" % qmicli_cmd)
        output = subprocess.check_output(qmicli_cmd, shell=True, stderr=subprocess.STDOUT).decode()
        if output:
            return (output.splitlines(), None)
        else:
            fwglobals.log.debug('_run_qmicli_command: no output from command (%s)' % qmicli_cmd)
            return ([], None)
    except subprocess.CalledProcessError as err:
        if print_error:
            fwglobals.log.debug('_run_qmicli_command: flag: %s. err: %s' % (flag, err.output.strip()))
        return ([], err.output.strip())

def _run_mbimcli_command(dev_id, cmd, print_error=False):
    try:
        device = dev_id_to_usb_device(dev_id) if dev_id else 'cdc-wdm0'
        mbimcli_cmd = 'mbimcli --device=/dev/%s --device-open-proxy %s' % (device, cmd)
        fwglobals.log.debug("_run_mbimcli_command: %s" % mbimcli_cmd)
        output = subprocess.check_output(mbimcli_cmd, shell=True, stderr=subprocess.STDOUT).decode()
        if output:
            return (output.splitlines(), None)
        else:
            fwglobals.log.debug('_run_mbimcli_command: no output from command (%s)' % mbimcli_cmd)
            return ([], None)
    except subprocess.CalledProcessError as err:
        if print_error:
            fwglobals.log.debug('_run_mbimcli_command: cmd: %s. err: %s' % (cmd, err.output.strip()))
        return ([], err.output.strip())


def qmi_get_simcard_status(dev_id):
    return _run_qmicli_command(dev_id, 'uim-get-card-status')

def qmi_get_signals_state(dev_id):
    return _run_qmicli_command(dev_id, 'nas-get-signal-strength')

def qmi_get_ip_configuration(dev_id):
    try:
        ip = None
        gateway = None
        primary_dns = None
        secondary_dns = None
        cmd = 'wds-get-current-settings | grep "IPv4 address\\|IPv4 subnet mask\\|IPv4 gateway address\\|IPv4 primary DNS\\|IPv4 secondary DNS"'
        lines, _ = _run_qmicli_command(dev_id, cmd)
        for idx, line in enumerate(lines):
            if 'IPv4 address:' in line:
                ip_without_mask = line.split(':')[-1].strip().replace("'", '')
                mask = lines[idx + 1].split(':')[-1].strip().replace("'", '')
                ip = ip_without_mask + '/' + str(IPAddress(mask).netmask_bits())
                continue
            if 'IPv4 gateway address:' in line:
                gateway = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'IPv4 primary DNS:' in line:
                primary_dns = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'IPv4 secondary DNS:' in line:
                secondary_dns = line.split(':')[-1].strip().replace("'", '')
                break
        return (ip, gateway, primary_dns, secondary_dns)
    except Exception:
        return (None, None, None, None)

def qmi_get_operator_name(dev_id):
    return _run_qmicli_command(dev_id, 'nas-get-operator-name')

def qmi_get_home_network(dev_id):
    return _run_qmicli_command(dev_id, 'nas-get-home-network')

def qmi_get_system_info(dev_id):
    return _run_qmicli_command(dev_id, 'nas-get-system-info')

def qmi_get_packet_service_state(dev_id):
    '''
    The function will return the connection status.
    This is not about existsin session to the modem. But connectivity between modem to the cellular provider
    '''
    return _run_qmicli_command(dev_id, 'wds-get-channel-rates')

def qmi_get_manufacturer(dev_id):
    return _run_qmicli_command(dev_id, 'dms-get-manufacturer')

def qmi_get_model(dev_id):
    return _run_qmicli_command(dev_id, 'dms-get-model')

def qmi_get_imei(dev_id):
    return _run_qmicli_command(dev_id, 'dms-get-ids')

def qmi_get_default_settings(dev_id):
    return _run_qmicli_command(dev_id, 'wds-get-default-settings=3gpp')

def qmi_sim_power_off(dev_id):
    return _run_qmicli_command(dev_id, 'uim-sim-power-off=1')

def qmi_sim_power_on(dev_id):
    return _run_qmicli_command(dev_id, 'uim-sim-power-on=1')

def qmi_get_phone_number(dev_id):
    return _run_qmicli_command(dev_id, 'dms-get-msisdn')

def get_phone_number(dev_id, cached=True):
    cached_values = get_cache_val(dev_id, 'phone_number')
    if cached_values and cached:
        return cached_values

    lines, _ = qmi_get_phone_number(dev_id)
    for line in lines:
        if 'MSISDN:' in line:
            phone_number = line.split(':')[-1].strip().replace("'", '')
            set_cache_val(dev_id, 'phone_number', phone_number)
            return phone_number
    return ''

def get_at_port(dev_id):
    at_ports = []
    try:
        _, addr = fwutils.dev_id_parse(dev_id)
        search_dev = '/'.join(addr.split('/')[:-1])
        output = subprocess.check_output('find /sys/bus/usb/devices/%s*/ -name dev' % search_dev, shell=True).decode().splitlines()
        pattern = '(ttyUSB[0-9])'
        tty_devices = []

        if output:
            for line in output:
                match = re.search(pattern, line)
                if match:
                    tty_devices.append(match.group(1))

        if len(tty_devices) > 0:
            for usb_port in tty_devices:
                try:
                    with serial.Serial('/dev/%s' % usb_port, 115200, timeout=1) as ser:
                        ser.write(bytes('AT\r', 'utf-8')) # check response to AT command
                        t_end = time.time() + 1
                        while time.time() < t_end:
                            response = ser.readline().decode()
                            if "OK" in response:
                                at_ports.append(ser.name)
                                break
                        ser.close()
                except:
                    pass
        return at_ports
    except:
        return at_ports

def get_default_settings(dev_id):
    default_settings = get_cache_val(dev_id, 'default_settings')
    if not default_settings:
        lines, _ = qmi_get_default_settings(dev_id)
        default_settings = {
            'APN'     : '',
            'username': '',
            'password': '',
            'auth'    : ''
        }
        for line in lines:
            if 'APN' in line:
                default_settings['APN'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'UserName' in line:
                default_settings['username'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'Password' in line:
                default_settings['password'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'Auth' in line:
                default_settings['auth'] = line.split(':')[-1].strip().replace("'", '')
                continue

        set_cache_val(dev_id, 'default_settings', default_settings)
    return default_settings

def get_pin_state(dev_id):
    res = {
        'pin1_status': '',
        'pin1_retries': '',
        'puk1_retries': '',
    }
    lines, _ = qmi_get_simcard_status(dev_id)
    for index, line in enumerate(lines):
        if 'PIN1 state:' in line:
            res['pin1_status']= line.split(':')[-1].strip().replace("'", '').split(' ')[0]
            res['pin1_retries']= lines[index + 1].split(':')[-1].strip().replace("'", '').split(' ')[0]
            res['puk1_retries']= lines[index + 2].split(':')[-1].strip().replace("'", '').split(' ')[0]
            break
    return res

def get_sim_status(dev_id):
    lines, err = qmi_get_simcard_status(dev_id)
    if err:
        raise Exception(err)

    for line in lines:
        if 'Card state:' in line:
            state = line.split(':')[-1].strip().replace("'", '').split(' ')[0]
            return state
    return ''


def is_sim_inserted(dev_id):
    status = get_sim_status(dev_id)
    return status == "present"

def get_db_entry(dev_id, key):
    lte_db = fwglobals.g.db.get('lte' ,{})
    dev_id_entry = lte_db.get(dev_id ,{})
    return dev_id_entry.get(key)

def set_db_entry(dev_id, key, value):
    lte_db = fwglobals.g.db.get('lte' ,{})
    dev_id_entry = lte_db.get(dev_id ,{})
    dev_id_entry[key] = value

    lte_db[dev_id] = dev_id_entry
    fwglobals.g.db['lte'] = lte_db # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict

def get_cache_val(dev_id, key):
    cache = fwglobals.g.cache.lte
    lte_interface = cache.get(dev_id, {})
    return lte_interface.get(key)

def set_cache_val(dev_id, key, value):
    cache = fwglobals.g.cache.lte
    lte_interface = cache.get(dev_id)
    if not lte_interface:
        fwglobals.g.cache.lte[dev_id] = {}
        lte_interface = fwglobals.g.cache.lte[dev_id]
    lte_interface[key] = value

def disconnect(dev_id, hard_reset_service=False):
    try:
        session = get_cache_val(dev_id, 'session')
        if_name = get_cache_val(dev_id, 'if_name')
        if not session:
            session = '0' # default session
        if not if_name:
            if_name = fwutils.dev_id_to_linux_if(dev_id)

        _run_mbimcli_command(dev_id, '--disconnect=%s' % session)
        os.system('sudo ip link set dev %s down && sudo ip addr flush dev %s' % (if_name, if_name))

        # update the cache
        set_cache_val(dev_id, 'ip', '')
        set_cache_val(dev_id, 'gateway', '')

        if hard_reset_service:
            _run_qmicli_command(dev_id, 'wds-reset')
            _run_qmicli_command(dev_id, 'nas-reset')
            _run_qmicli_command(dev_id, 'uim-reset')

        fwutils.clear_linux_interfaces_cache() # remove this code when move ip configuration to netplan

        return (True, None)
    except subprocess.CalledProcessError as e:
        return (False, str(e))

def prepare_connection_params(params):
    connection_params = []
    if 'apn' in params and params['apn']:
        connection_params.append('apn=%s' % params['apn'])
    if 'user' in params and params['user']:
        connection_params.append('username=%s' % params['user'])
    if 'password' in params and params['password']:
        connection_params.append('password=%s' % params['password'])
    if 'auth' in params and params['auth']:
        connection_params.append('auth=%s' % params['auth'])

    return ",".join(connection_params)

def qmi_verify_pin(dev_id, pin):
    fwglobals.log.debug('verifying lte pin number')
    lines, err = _run_qmicli_command(dev_id, 'uim-verify-pin=PIN1,%s' % pin)
    time.sleep(2)
    return (get_pin_state(dev_id), err)

def qmi_set_pin_protection(dev_id, pin, is_enable):
    lines, err = _run_qmicli_command(dev_id, 'uim-set-pin-protection=PIN1,%s,%s' % ('enable' if is_enable else 'disable', pin))
    time.sleep(1)
    return (get_pin_state(dev_id), err)

def qmi_change_pin(dev_id, old_pin, new_pin):
    lines, err = _run_qmicli_command(dev_id, 'uim-change-pin=PIN1,%s,%s' % (old_pin, new_pin))
    time.sleep(1)
    return (get_pin_state(dev_id), err)

def qmi_unblocked_pin(dev_id, puk, new_pin):
    _run_qmicli_command(dev_id, 'uim-unblock-pin=PIN1,%s,%s' % (puk, new_pin))
    time.sleep(1)
    return get_pin_state(dev_id)

def mbim_connection_state(dev_id):
    lines, _ = _run_mbimcli_command(dev_id, '--query-connection-state')
    for line in lines:
        if 'Activation state' in line:
            return line.split(':')[-1].strip().replace("'", '')
    return ''

def mbim_is_connected(dev_id):
    return mbim_connection_state(dev_id) == 'activated'

def mbim_registration_state(dev_id):
    res = {
        'register_state': '',
        'network_error' : '',
    }
    lines, _ = _run_mbimcli_command(dev_id, '--query-registration-state --no-open=3 --no-close')
    for line in lines:
        if 'Network error:' in line:
            res['network_error'] = line.split(':')[-1].strip().replace("'", '')
            continue
        if 'Register state:' in line:
            res['register_state'] = line.split(':')[-1].strip().replace("'", '')
            break
    return res

def reset_modem(dev_id):

    def _wait_for_interface_to_be_restored(if_name):
        retries = 30
        for _ in range(retries):
            try:
                output = subprocess.check_output("sudo ls -l /sys/class/net/ | grep -v tap_ | grep " + if_name, shell=True).decode()
                if output:
                    return True
            except:
                pass

            time.sleep(1)

        return False

    def _wait_for_interface_to_be_removed(if_name):
        retries = 30
        for _ in range(retries):
            try:
                # if vpp runs, we have the tap_wwan0 interfae, so we filter it out to make sure that LTE pyshical interface does not exists
                output = subprocess.check_output("sudo ls -l /sys/class/net/ | grep -v tap_ | grep " + if_name, shell=True).decode()
            except:
                return True

            time.sleep(1)

        return False

    set_cache_val(dev_id, 'state', 'resetting')
    try:
        # If the modem switched between QMI and MBIM modes, the dev_id might change.
        # Hence, we check the reset by interface name, which is a consistent name in both modes.
        lte_if_name = fwutils.dev_id_to_linux_if(dev_id)

        fwglobals.log.debug('reset_modem: reset starting')

        _run_qmicli_command(dev_id,'dms-set-operating-mode=offline')
        _run_qmicli_command(dev_id,'dms-set-operating-mode=reset')

        # After resetting, the modem should be deleted from Linux and then back up.
        # We verify these two steps to make sure the reset process is completed successfully
        ifc_removed = _wait_for_interface_to_be_removed(lte_if_name)
        if not ifc_removed:
            raise Exception('the modem exists after reset. it was expected to be temporarily removed')
        ifc_restored = _wait_for_interface_to_be_restored(lte_if_name)
        if not ifc_restored:
            raise Exception('The modem has not recovered from the reset')

        _run_qmicli_command(dev_id,'dms-set-operating-mode=online')

        # To re-apply set-name for LTE interface we have to call netplan apply here
        fwutils.netplan_apply("reset_modem")

        fwglobals.log.debug('reset_modem: reset finished')
    finally:
        set_cache_val(dev_id, 'state', '')
        # clear wrong PIN cache on reset
        set_db_entry(dev_id, 'wrong_pin', None)

def connect(params):
    dev_id = params['dev_id']

    # To avoid wan failover monitor and lte watchdog at this time
    set_cache_val(dev_id, 'state', 'connecting')

    try:
        # check if sim exists
        if not is_sim_inserted(dev_id):
            qmi_sim_power_off(dev_id)
            time.sleep(1)
            qmi_sim_power_on(dev_id)
            time.sleep(1)
            inserted = is_sim_inserted(dev_id)
            if not inserted:
                raise Exception("Sim is not presented")

        # check PIN status
        pin_state = get_pin_state(dev_id).get('pin1_status', 'disabled')
        if pin_state not in ['disabled', 'enabled-verified']:
            pin = params.get('pin')
            if not pin:
                raise Exception("PIN is required")

            # If a user enters a wrong pin, the function will fail, but flexiManage will send three times `sync` jobs.
            # As a result, the SIM may be locked. So we save the wrong pin in the cache
            # and we will not try again with this wrong one.
            wrong_pin = get_db_entry(dev_id, 'wrong_pin')
            if wrong_pin and wrong_pin == pin:
                raise Exception("PIN is wrong")

            _, err = qmi_verify_pin(dev_id, pin)
            if err:
                set_db_entry(dev_id, 'wrong_pin', pin)
                raise Exception("PIN is wrong")

        # At this point, we sure that the sim is unblocked.
        # After a block, the sim might open it from different places (manually qmicli command, for example),
        # so we need to make sure to clear this cache
        set_db_entry(dev_id, 'wrong_pin', None)

        # Check if modem already connected to ISP.
        is_modem_connected = mbim_is_connected(dev_id)
        if is_modem_connected:
            set_cache_val(dev_id, 'state', '')
            return (True, None)

        if_name = fwutils.dev_id_to_linux_if(dev_id)
        set_cache_val(dev_id, 'if_name', fwutils.dev_id_to_linux_if(dev_id))

        # Make sure context is released and set the interface to up
        disconnect(dev_id)
        os.system('ifconfig %s up' % if_name)

        connection_params = prepare_connection_params(params)
        mbim_commands = [
            r'--query-subscriber-ready-status --no-close',
            r'--query-registration-state --no-open=3 --no-close',
            r'--attach-packet-service --no-open=4 --no-close',
            r'--connect=%s --no-open=5 --no-close | grep "Session ID\|IP\|Gateway\|DNS"' % connection_params
        ]
        for cmd in mbim_commands:
            lines, err = _run_mbimcli_command(dev_id, cmd, True)
            if err:
                raise Exception(err)

        for idx, line in enumerate(lines) :
            if 'Session ID:' in line:
                session = line.split(':')[-1].strip().replace("'", '')
                set_cache_val(dev_id, 'session', session)
                continue
            if 'IP [0]:' in line:
                ip = line.split(':')[-1].strip().replace("'", '')
                set_cache_val(dev_id, 'ip', ip)
                continue
            if 'Gateway:' in line:
                gateway = line.split(':')[-1].strip().replace("'", '')
                set_cache_val(dev_id, 'gateway', gateway)
                continue
            if 'DNS [0]:' in line:
                dns_primary = line.split(':')[-1].strip().replace("'", '')
                dns_secondary = lines[idx + 1].split(':')[-1].strip().replace("'", '')
                set_cache_val(dev_id, 'dns_servers', [dns_primary, dns_secondary])
                break

        set_cache_val(dev_id, 'state', '')
        return (True, None)
    except Exception as e:
        fwglobals.log.debug('connect: faild to connect lte. %s' % str(e))
        set_cache_val(dev_id, 'state', '')
        return (False, str(e))

def get_system_info(dev_id, cached=True):
    cached_values = get_cache_val(dev_id, 'system_info')
    if cached_values and cached:
        return cached_values

    result = {
        'cell_id'        : '',
        'operator_name'  : '',
        'mcc'            : '',
        'mnc'            : ''
    }
    try:
        lines, _ = qmi_get_system_info(dev_id)
        for line in lines:
            if 'Cell ID' in line:
                result['cell_id'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'MCC' in line:
                result['mcc'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'MNC' in line:
                result['mnc'] = line.split(':')[-1].strip().replace("'", '')
                continue

        lines, _ = qmi_get_operator_name(dev_id)
        for line in lines:
            if '\tName' in line:
                name = line.split(':', 1)[-1].strip().replace("'", '')
                result['Operator_Name'] = name if bool(re.match("^[a-zA-Z0-9_ :]*$", name)) else ''
                break

    except Exception:
        pass

    set_cache_val(dev_id, 'system_info', result)
    return result

def get_hardware_info(dev_id, cached=True):
    cached_values = get_cache_val(dev_id, 'hardware_info')
    if cached_values and cached:
        return (cached_values, None)

    result = {
        'vendor'   : '',
        'model'    : '',
        'imei': '',
    }

    try:
        lines, err = qmi_get_manufacturer(dev_id)
        if err:
            raise Exception(err)
        for line in lines:
            if 'Manufacturer' in line:
                result['vendor'] = line.split(':')[-1].strip().replace("'", '')
                break

        lines, err = qmi_get_model(dev_id)
        if err:
            raise Exception(err)
        for line in lines:
            if 'Model' in line:
                result['model'] = line.split(':')[-1].strip().replace("'", '')
                break

        lines, err = qmi_get_imei(dev_id)
        if err:
            raise Exception(err)
        for line in lines:
            if 'IMEI' in line:
                result['imei'] = line.split(':')[-1].strip().replace("'", '')
                break
    except Exception as e:
        return (result, str(e))

    set_cache_val(dev_id, 'hardware_info', result)
    return (result, None)

def get_packets_state(dev_id, cached=True):
    cached_values = get_cache_val(dev_id, 'packets_state')
    if cached_values and cached:
        return cached_values

    result = {
        'uplink_speed'  : 0,
        'downlink_speed': 0
    }
    try:
        lines, _ = qmi_get_packet_service_state(dev_id)
        for line in lines:
            if 'Max TX rate' in line:
                result['uplink_speed'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'Max RX rate' in line:
                result['downlink_speed'] = line.split(':')[-1].strip().replace("'", '')
                continue
    except Exception:
        pass

    set_cache_val(dev_id, 'packets_state', result)
    return result

def get_radio_signals_state(dev_id):
    result = {
        'rssi' : 0,
        'rsrp' : 0,
        'rsrq' : 0,
        'sinr' : 0,
        'snr'  : 0,
        'text' : ''
    }
    try:
        lines, _ = qmi_get_signals_state(dev_id)
        for index, line in enumerate(lines):
            if 'RSSI' in line:
                result['rssi'] = lines[index + 1].split(':')[-1].strip().replace("'", '')
                dbm_num = int(result['rssi'].split(' ')[0])
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
                continue
            if 'SINR' in line:
                result['sinr'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'RSRQ' in line:
                result['rsrq'] = lines[index + 1].split(':')[-1].strip().replace("'", '')
                continue
            if 'SNR' in line:
                result['snr'] = lines[index + 1].split(':')[-1].strip().replace("'", '')
                continue
            if 'RSRP' in line:
                result['rsrp'] = lines[index + 1].split(':')[-1].strip().replace("'", '')
                continue
    except Exception:
        pass
    return result

def mbim_get_ip_configuration(dev_id):
    ip = None
    gateway = None
    try:
        lines, _ = _run_mbimcli_command(dev_id, '--query-ip-configuration --no-close --no-open=6')
        for line in lines:
            if 'IP [0]:' in line:
                ip = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'Gateway:' in line:
                gateway = line.split(':')[-1].strip().replace("'", '')
                break
        return (ip, gateway)
    except Exception:
        return (ip, gateway)

def get_ip_configuration(dev_id, key=None, cache=True):
    response = {
        'ip'           : '',
        'gateway'      : '',
        'dns_servers'  : []
    }
    try:
        # try to get it from cache
        ip = get_cache_val(dev_id, 'ip')
        gateway =  get_cache_val(dev_id, 'gateway')
        dns_servers =  get_cache_val(dev_id, 'dns_servers')

        # if not exists in cache, take from modem and update cache
        if not ip or not gateway or not dns_servers or cache == False:
            ip, gateway, primary_dns, secondary_dns = qmi_get_ip_configuration(dev_id)

            if ip:
                set_cache_val(dev_id, 'ip', ip)
            if gateway:
                set_cache_val(dev_id, 'gateway', gateway)
            if primary_dns and secondary_dns:
                dns_servers = [primary_dns, secondary_dns]
                set_cache_val(dev_id, 'dns_servers', dns_servers)

        response['ip'] = ip
        response['gateway'] = gateway
        response['dns_servers'] = dns_servers

        if key:
            return response[key]
    except Exception:
        pass
    return response

def dev_id_to_usb_device(dev_id):
    try:
        usb_device = get_cache_val(dev_id, 'usb_device')
        if usb_device:
            return usb_device

        driver = fwutils.get_interface_driver_by_dev_id(dev_id)
        usb_addr = dev_id.split('/')[-1]
        output = subprocess.check_output('ls /sys/bus/usb/drivers/%s/%s/usbmisc/' % (driver, usb_addr), shell=True).decode().strip()
        set_cache_val(dev_id, 'usb_device', output)
        return output
    except subprocess.CalledProcessError:
        return None

def configure_interface(params):
    '''
    To get LTE connectivity, two steps are required:
    1. Creating a connection between the modem and cellular provider.
    2. Setting up the Linux interface with the IP/gateway received from the cellular provider
    This function is responsible for the second stage.
    If the vpp is running, we have special logic to configure LTE. This logic handled by the add_interface translator.
    '''
    try:
        dev_id = params['dev_id']
        if fwutils.vpp_does_run() and fwutils.is_interface_assigned_to_vpp(dev_id):
            # Make sure interface is up. It might be down due to suddenly disconnected
            nic_name = fwutils.dev_id_to_linux_if(dev_id)
            os.system('ifconfig %s up' % nic_name)
            return (True, None)

        if not is_lte_interface_by_dev_id(dev_id):
            return (False, "dev_id %s is not a lte interface" % dev_id)

        ip_config = get_ip_configuration(dev_id)
        ip = ip_config['ip']
        gateway = ip_config['gateway']
        metric = params.get('metric', '0')
        if not metric:
            metric = '0'

        nic_name = fwutils.dev_id_to_linux_if(dev_id)
        os.system('ifconfig %s %s up' % (nic_name, ip))

        # remove old default router
        output = os.popen('ip route list match default | grep %s' % nic_name).read()
        if output:
            routes = output.splitlines()
            for r in routes:
                os.system('ip route del %s' % r)
        # set updated default route
        os.system(f"ip route add default via {gateway} proto static metric {metric}")

        # configure dns servers for the interface.
        # If the LTE interface is configured in netplan, the user must set the dns servers manually in netplan.
        set_dns_str = ' '.join(map(lambda server: '--set-dns=' + server, ip_config['dns_servers']))
        if set_dns_str:
            os.system('systemd-resolve %s --interface %s' % (set_dns_str, nic_name))

        fwutils.clear_linux_interfaces_cache() # remove this code when move ip configuration to netplan
        return (True , None)
    except Exception as e:
        return (False, "Failed to configure lte for dev_id %s. (%s)" % (dev_id, str(e)))


def reload_lte_drivers_if_needed():
    if fwutils.is_need_to_reload_lte_drivers():
        reload_lte_drivers()

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

def collect_lte_info(dev_id):
    interface_name = fwutils.dev_id_to_linux_if(dev_id)

    hardware_info, _ = get_hardware_info(dev_id)
    packet_service_state = get_packets_state(dev_id)
    system_info = get_system_info(dev_id)
    default_settings = get_default_settings(dev_id)
    phone_number = get_phone_number(dev_id)

    sim_status = get_sim_status(dev_id)
    signals = get_radio_signals_state(dev_id)
    pin_state = get_pin_state(dev_id)
    connection_state = mbim_connection_state(dev_id)
    registration_network = mbim_registration_state(dev_id)

    tap_name = fwutils.dev_id_to_tap(dev_id, check_vpp_state=True)
    if tap_name:
        interface_name = tap_name

    addr = fwutils.get_interface_address(interface_name)
    connectivity = os.system("ping -c 1 -W 1 -I %s 8.8.8.8 > /dev/null 2>&1" % interface_name) == 0

    response = {
        'address'             : addr,
        'signals'             : signals,
        'connectivity'        : connectivity,
        'packet_service_state': packet_service_state,
        'hardware_info'       : hardware_info,
        'system_info'         : system_info,
        'sim_status'          : sim_status,
        'default_settings'    : default_settings,
        'phone_number'        : phone_number,
        'pin_state'           : pin_state,
        'connection_state'    : connection_state,
        'registration_network': registration_network
    }
    return response

def handle_unblock_sim(dev_id, puk, new_pin):
    if not puk:
        raise Exception(LTE_ERROR_MESSAGES.PUK_IS_REQUIRED)

    if not new_pin:
        raise Exception(LTE_ERROR_MESSAGES.NEW_PIN_IS_REQUIRED)

    # unblock the sim and get the updated status
    updated_status = fwutils.qmi_unblocked_pin(dev_id, puk, new_pin)
    updated_pin_state = updated_status.get('pin1_status')

    # if SIM status is not one of below statuses, it means that puk code is wrong
    if updated_pin_state not in['disabled', 'enabled-verified']:
        raise Exception(LTE_ERROR_MESSAGES.PUK_IS_WRONG)

def handle_change_pin_status(dev_id, current_pin, enable):
    _, err = qmi_set_pin_protection(dev_id, current_pin, enable)
    if err:
        raise Exception(LTE_ERROR_MESSAGES.PIN_IS_WRONG)

    # at this point, pin is verified so we reset wrong pin protection
    set_db_entry(dev_id, 'wrong_pin', None)

def handle_change_pin_code(dev_id, current_pin, new_pin, is_currently_enabled):
    if not is_currently_enabled: # can't change disabled pin
        raise Exception(LTE_ERROR_MESSAGES.PIN_IS_DISABLED)

    _, err = qmi_change_pin(dev_id, current_pin, new_pin)
    if err:
        raise Exception(LTE_ERROR_MESSAGES.PIN_IS_WRONG)

    # at this point, pin is changed so we reset wrong pin protection
    set_db_entry(dev_id, 'wrong_pin', None)

def handle_verify_pin_code(dev_id, current_pin, is_currently_enabled, retries_left):
    updated_status, err = qmi_verify_pin(dev_id, current_pin)
    if err and not is_currently_enabled: # can't verify disabled pin
        raise Exception(LTE_ERROR_MESSAGES.PIN_IS_DISABLED)
    if err:
        raise Exception(LTE_ERROR_MESSAGES.PIN_IS_WRONG)

    updated_pin_state = updated_status.get('pin1_status')
    updated_retries_left = updated_status.get('pin1_retries', '3')
    if updated_retries_left != '3' and int(retries_left) > int(updated_retries_left):
        raise Exception(LTE_ERROR_MESSAGES.PIN_IS_WRONG)
    if updated_pin_state not in['disabled', 'enabled-verified']:
        raise Exception(LTE_ERROR_MESSAGES.PIN_IS_WRONG)

    # at this point, pin is verified so we reset wrong pin protection
    set_db_entry(dev_id, 'wrong_pin', None)

def handle_pin_modifications(dev_id, current_pin, new_pin, enable, puk):
    current_pin_state = get_pin_state(dev_id)
    is_currently_enabled = current_pin_state.get('pin1_status') != 'disabled'
    retries_left = current_pin_state.get('pin1_retries', '3')

    # Handle blocked SIM card. In order to unblock it a user should provide PUK code and new PIN code
    if current_pin_state.get('pin1_status') == 'blocked' or retries_left == '0':
        handle_unblock_sim(dev_id, puk, new_pin)
        return True

    # for the following operations we need current pin
    if not current_pin:
        raise Exception(LTE_ERROR_MESSAGES.PIN_IS_REQUIRED)

    need_to_verify = True
    # check if need to enable/disable PIN
    if is_currently_enabled != enable:
        handle_change_pin_status(dev_id, current_pin, enable)
        need_to_verify = False

    # check if need to change PIN
    if new_pin and new_pin != current_pin:
        handle_change_pin_code(dev_id, current_pin, new_pin, is_currently_enabled)
        need_to_verify = False

    # verify PIN if no other change requested by the user.
    # no need to verify if we enabled or disabled the pin since it's already verified
    if need_to_verify:
        handle_verify_pin_code(dev_id, current_pin, is_currently_enabled, retries_left)

def is_lte_interface_by_dev_id(dev_id):
    if_name = fwutils.dev_id_to_linux_if(dev_id)
    if not if_name:
        return False
    return is_lte_interface(if_name)

def is_lte_interface(if_name):
    """Check if interface is LTE.

    :param dev_id: Bus address of interface to check.

    :returns: Boolean.
    """
    driver = fwutils.get_interface_driver(if_name)
    supported_lte_drivers = ['cdc_mbim']
    if driver in supported_lte_drivers:
        return True

    return False