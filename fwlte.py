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

from datetime import datetime, timedelta

import fwglobals
import fw_os_utils
import fwutils

class LTE_ERROR_MESSAGES():
    PIN_IS_WRONG = 'PIN_IS_WRONG'
    PIN_IS_REQUIRED = 'PIN_IS_REQUIRED'
    PIN_IS_DISABLED = 'PIN_IS_DISABLED'

    NEW_PIN_IS_REQUIRED = 'NEW_PIN_IS_REQUIRED'

    PUK_IS_WRONG = 'PUK_IS_WRONG'
    PUK_IS_REQUIRED = 'PUK_IS_REQUIRED'

def reset_modem_if_needed(err_str, dev_id):
    '''The qmi and mbim commands can sometimes get stuck and return errors.
    It is not clear if this is the modem that get stuck or the way commands are run to it.
    The solution we found is to do a modem reset.
    But, to avoid a loop of error -> reset -> error -> reset,
    we will only perform it if a period of time has passed since the last reset.

    :param err_str: the error string returned from the mbim/qmi clients
    :param dev_id: lte dev id

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

    last_reset_time = get_db_entry(dev_id, 'healing_reset_last_time')

    now = datetime.now()
    if last_reset_time:
        last_reset_time = datetime.fromtimestamp(last_reset_time)
        if last_reset_time > (now - timedelta(hours=1)):
            return False

    # do reset
    fwglobals.log.debug(f"reset_modem_if_needed: resetting modem while error. err: {err_str}")

    set_db_entry(dev_id, 'healing_reset_last_time', datetime.timestamp(now))

    fwglobals.g.modems.call(dev_id, 'reset_modem')
    return True

def _run_qmicli_command(dev_id, flag, device=None):
    try:
        if not device:
            device = fwglobals.g.modems.call(dev_id, 'get_usb_device')
        qmicli_cmd = 'qmicli --device=/dev/%s --device-open-proxy --%s' % (device, flag)
        fwglobals.log.debug("_run_qmicli_command: %s" % qmicli_cmd)
        output = subprocess.check_output(qmicli_cmd, shell=True, stderr=subprocess.STDOUT).decode()
        if output:
            return (output.splitlines(), None)
        else:
            fwglobals.log.debug('_run_qmicli_command: no output from command (%s)' % qmicli_cmd)
            return ([], None)
    except subprocess.CalledProcessError as err:
        err_str = str(err.output.strip())
        modem_resetted = reset_modem_if_needed(err_str, dev_id)
        if modem_resetted:
            return _run_qmicli_command(dev_id, flag)
        return ([], err_str)

def _run_mbimcli_command(dev_id, cmd, print_error=False, device=None):
    try:
        if not device:
            device = fwglobals.g.modems.call(dev_id, 'get_usb_device')
        mbimcli_cmd = 'mbimcli --device=/dev/%s --device-open-proxy %s' % (device, cmd)
        if '--attach-packet-service' in mbimcli_cmd:
            # This command might take a long or even get stuck.
            # Hence, send SIGTERM after 10 seconds.
            # '-k 5' is to ensure that SIGTERM is not handled and ignored by the service
            # and it sends SIGKILL if process doesn't terminate after 5 second
            mbimcli_cmd = f'timeout -k 5 10 {mbimcli_cmd}'
        fwglobals.log.debug("_run_mbimcli_command: %s" % mbimcli_cmd)
        output = subprocess.check_output(mbimcli_cmd, shell=True, stderr=subprocess.STDOUT).decode()
        if output:
            return (output.splitlines(), None)
        else:
            fwglobals.log.debug('_run_mbimcli_command: no output from command (%s)' % mbimcli_cmd)
            return ([], None)
    except subprocess.CalledProcessError as err:
        err_str = str(err.output.strip())
        if print_error:
            fwglobals.log.debug('_run_mbimcli_command: cmd: %s. err: %s' % (cmd, err_str))

        modem_resetted = reset_modem_if_needed(err_str, dev_id)
        if modem_resetted:
            return _run_mbimcli_command(dev_id, cmd, print_error)
        return ([], err_str)

def mbim_get_ip_configuration(dev_id):
    ip, gateway, primary_dns, secondary_dns  = '', '', '', ''
    try:
        # cmd = 'wds-get-current-settings | grep "IPv4 address\\|IPv4 subnet mask\\|IPv4 gateway address\\|IPv4 primary DNS\\|IPv4 secondary DNS"'
        lines, _ = _run_mbimcli_command(dev_id, '--query-ip-configuration')
        # [root@flexiwan-router ~/flexiagent]# mbimcli --device /dev/cdc-wdm0 -p --query-ip-configuration
        # [/dev/cdc-wdm0] IPv4 configuration available: 'address, gateway, dns, mtu'
        #      IP [0]: '10.39.138.29/30'
        #     Gateway: '10.39.138.30'
        #     DNS [0]: '91.135.104.8'
        #     DNS [1]: '91.135.102.8'
        #         MTU: '1500'

        # [/dev/cdc-wdm0] IPv6 configuration available: 'address, gateway, dns, mtu'
        #      IP [0]: '2a02:6680:1102:ed59:a187:bc51:27ff:2474/64'
        #     Gateway: '2a02:6680:1102:ed59:c132:a046:7fe7:b62d'
        #     DNS [0]: '2a02:6680:1:100:91:135:104:8'
        #     DNS [1]: '2a02:6680:2:100:91:135:102:8'
        #         MTU: '1358'
        for idx, line in enumerate(lines):
            if 'IPv4 configuration' in line:
                ip = lines[idx + 1].split(':')[-1].strip().replace("'", '')
                gateway = lines[idx + 2].split(':')[-1].strip().replace("'", '')
                primary_dns = lines[idx + 3].split(':')[-1].strip().replace("'", '')
                secondary_dns = lines[idx + 4].split(':')[-1].strip().replace("'", '')
                break
        return (ip, gateway, primary_dns, secondary_dns)
    except Exception as e:
        fwglobals.log.debug(f'mbim_get_ip_configuration({dev_id}) failed: ip={ip}, \
            gateway={gateway}, primary_dns={primary_dns}, secondary_dns={secondary_dns}: {str(e)}')
        return (ip, gateway, primary_dns, secondary_dns)

def mbim_get_packet_service_state(dev_id):
    return _run_mbimcli_command(dev_id, '--query-packet-service-state')

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

def mbimcli_get_pin_status(dev_id):
    enabled_disabled = None
    pin_list_lines = _run_mbimcli_command(dev_id, '--query-pin-list')[0]
    for idx, line in enumerate(pin_list_lines):
        if 'PIN1:' in line:
            enabled_disabled = pin_list_lines[idx + 1].split(':')[-1].strip().replace("'", '')
            break

    if enabled_disabled == 'disabled':
        return enabled_disabled
    else:
        pin_state_lines = _run_mbimcli_command(dev_id, '--query-pin-state')[0]
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

def get_cache_val(dev_id, key, default=None):
    cache = fwglobals.g.cache.lte
    lte_interface = cache.get(dev_id, {})
    return lte_interface.get(key, default)

def set_cache_val(dev_id, key, value):
    cache = fwglobals.g.cache.lte
    lte_interface = cache.get(dev_id)
    if not lte_interface:
        fwglobals.g.cache.lte[dev_id] = {}
        lte_interface = fwglobals.g.cache.lte[dev_id]
    lte_interface[key] = value

def set_pin_protection(dev_id, pin, is_enable):
    if is_enable:
        return fwglobals.g.modems.call(dev_id, 'enable_pin', pin)
    return fwglobals.g.modems.call(dev_id, 'disable_pin', pin)

def mbimcli_query_connection_state(dev_id):
    lines, _ = _run_mbimcli_command(dev_id, '--query-connection-state')
    for line in lines:
        if 'Activation state' in line:
            return line.split(':')[-1].strip().replace("'", '')
    return ''

def mbim_is_connected(dev_id):
    return mbimcli_query_connection_state(dev_id) == 'activated'

def mbimcli_registration_state(dev_id):
    res = {
        'register_state': '',
        'network_error' : '',
    }
    lines, _ = _run_mbimcli_command(dev_id, '--query-registration-state')
    for line in lines:
        if 'Network error:' in line:
            res['network_error'] = line.split(':')[-1].strip().replace("'", '')
            continue
        if 'Register state:' in line:
            res['register_state'] = line.split(':')[-1].strip().replace("'", '')
            break
    return res

def mbimcli_get_packets_state(dev_id, cached=True):
    cached_values = get_cache_val(dev_id, 'packets_state')
    if cached_values and cached:
        return cached_values

    result = {
        'uplink_speed'  : 0,
        'downlink_speed': 0
    }
    try:
        lines, _ = mbim_get_packet_service_state(dev_id)
        for line in lines:
            if 'Uplink speed' in line:
                result['uplink_speed'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'Downlink speed' in line:
                result['downlink_speed'] = line.split(':')[-1].strip().replace("'", '')
                continue
    except Exception:
        pass

    if result['uplink_speed'] != 0:
        # store only if there is value. Sometimes value is populated only after modem registration
        set_cache_val(dev_id, 'packets_state', result)
    return result

def dev_id_to_usb_device(dev_id):
    try:
        driver = fwutils.get_interface_driver_by_dev_id(dev_id)
        usb_addr = dev_id.split('/')[-1]
        output = subprocess.check_output('ls /sys/bus/usb/drivers/%s/%s/usbmisc/' % (driver, usb_addr), shell=True).decode().strip()
        return output
    except subprocess.CalledProcessError:
        return None

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

def handle_unblock_sim(dev_id, puk, new_pin):
    if not puk:
        raise Exception(LTE_ERROR_MESSAGES.PUK_IS_REQUIRED)

    if not new_pin:
        raise Exception(LTE_ERROR_MESSAGES.NEW_PIN_IS_REQUIRED)

    # unblock the sim and get the updated status
    updated_status, err = fwglobals.g.modems.call(dev_id, 'unblock_pin', puk, new_pin)
    if err:
        raise Exception(LTE_ERROR_MESSAGES.PIN_IS_WRONG)
    updated_pin_state = updated_status.get('pin1_status')

    # if SIM status is not one of below statuses, it means that puk code is wrong
    if updated_pin_state not in['disabled', 'enabled-verified']:
        raise Exception(LTE_ERROR_MESSAGES.PUK_IS_WRONG)

def handle_change_pin_status(dev_id, current_pin, enable):
    _, err = set_pin_protection(dev_id, current_pin, enable)
    if err:
        raise Exception(LTE_ERROR_MESSAGES.PIN_IS_WRONG)

    # at this point, pin is verified so we reset wrong pin protection
    set_db_entry(dev_id, 'wrong_pin', None)

def handle_change_pin_code(dev_id, current_pin, new_pin, is_currently_enabled):
    if not is_currently_enabled: # can't change disabled pin
        raise Exception(LTE_ERROR_MESSAGES.PIN_IS_DISABLED)

    _, err = fwglobals.g.modems.call(dev_id, 'change_pin', current_pin, new_pin)
    if err:
        raise Exception(LTE_ERROR_MESSAGES.PIN_IS_WRONG)

    # at this point, pin is changed so we reset wrong pin protection
    set_db_entry(dev_id, 'wrong_pin', None)

def handle_verify_pin_code(dev_id, current_pin, is_currently_enabled, retries_left):
    updated_status, err = fwglobals.g.modems.call(dev_id, 'verify_pin', current_pin)
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
    current_pin_state = fwglobals.g.modems.call(dev_id, 'get_pin_state')
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

def get_lte_interfaces_dev_ids(allow_qmi=False):
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

def get_stats():
    out = {}
    lte_dev_ids = get_lte_interfaces_dev_ids()
    for lte_dev_id in lte_dev_ids:
        modem = fwglobals.g.modems.get(lte_dev_id)
        if modem.is_connecting() or modem.is_resetting():
            continue

        try:
            info = fwglobals.g.modems.call(lte_dev_id, 'collect_lte_info')
            out[lte_dev_id] = info
        except:
            pass

    return out

def dump(dev_id, lte_if_name, prefix_path=''):
    devices = [lte_if_name]
    tap_if_name = fwutils.linux_tap_by_interface_name(lte_if_name)
    if tap_if_name:
        devices.append(tap_if_name)

    for device in devices:
        fwutils.exec_to_file(f'tc -j filter show dev {device} root', f'{prefix_path}_{device}_tc_filter.json')
        fwutils.exec_to_file(f'tc -j qdisc show dev {device}', f'{prefix_path}_{device}_tc_qdisc.json')
