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

import glob
import psutil
import os
import time
import subprocess
import re
import fwglobals
import fwutils

def configure_hostapd(dev_id, configuration):
    try:

        for band in configuration:
            config = configuration[band]

            if config['enable'] == False:
                continue

            if_name = fwutils.dev_id_to_linux_if(dev_id)
            data = {
                'ssid'                 : config.get('ssid', 'fwrouter_ap_%s' % band),
                'interface'            : if_name,
                'macaddr_acl'          : 0,
                'driver'               : 'nl80211',
                'auth_algs'            : 3,
                'ignore_broadcast_ssid': 1 if config.get('hideSsid', 0) == True else 0,
                'eap_server'           : 0,
                'logger_syslog'        : -1,
                'logger_syslog_level'  : 2,
                'logger_stdout'        : -1,
                'logger_stdout_level'  : 2,
                'max_num_sta'          : 128,
                'ctrl_interface'       : '/var/run/hostapd',
                'ctrl_interface_group' : 0,
                'wmm_enabled'          : 1
            }

            if band == '5GHz':
                data['uapsd_advertisement_enabled'] = 1
                data['wmm_ac_bk_cwmin'] = 4
                data['wmm_ac_bk_cwmax'] = 10
                data['wmm_ac_bk_aifs'] = 7
                data['wmm_ac_bk_txop_limit'] = 0
                data['wmm_ac_bk_acm'] = 0
                data['wmm_ac_be_aifs'] = 3
                data['wmm_ac_be_cwmin'] = 4
                data['wmm_ac_be_cwmax'] = 10
                data['wmm_ac_be_txop_limit'] = 0
                data['wmm_ac_be_acm'] = 0
                data['wmm_ac_vi_aifs'] = 2
                data['wmm_ac_vi_cwmin'] = 3
                data['wmm_ac_vi_cwmax'] = 4
                data['wmm_ac_vi_txop_limit'] = 94
                data['wmm_ac_vi_acm'] = 0
                data['wmm_ac_vo_aifs'] = 2
                data['wmm_ac_vo_cwmin'] = 2
                data['wmm_ac_vo_cwmax'] = 3
                data['wmm_ac_vo_txop_limit'] = 47
                data['wmm_ac_vo_acm'] = 0

                data['tx_queue_data3_aifs'] = 7
                data['tx_queue_data3_cwmin'] = 15
                data['tx_queue_data3_cwmax'] = 1023
                data['tx_queue_data3_burst'] = 0
                data['tx_queue_data2_aifs'] = 3
                data['tx_queue_data2_cwmin'] = 15
                data['tx_queue_data2_cwmax'] = 63
                data['tx_queue_data2_burst'] = 0
                data['tx_queue_data1_aifs'] = 1
                data['tx_queue_data1_cwmin'] = 7
                data['tx_queue_data1_cwmax'] = 15
                data['tx_queue_data1_burst'] = 3.0
                data['tx_queue_data0_aifs'] = 1
                data['tx_queue_data0_cwmin'] = 3
                data['tx_queue_data0_cwmax'] = 7
                data['tx_queue_data0_burst'] = 1.5

            # Channel
            channel = config.get('channel', '0')
            data['channel'] = channel

            country_code = config.get('region', 'US')
            data['country_code'] = country_code
            if channel == '0':
                data['ieee80211d'] = 1
            data['ieee80211h'] = 0

            ap_mode = config.get('operationMode', 'g')

            if ap_mode == "g": # for b/g/n
                data['hw_mode']       = 'g'
                data['ieee80211n']    = 1

            elif ap_mode == "n": # for n only
                if band == '5GHz':
                    data['hw_mode']       = 'a'
                else:
                    data['hw_mode']       = 'g'

                data['ieee80211n']    = 1
                data['ht_capab']      = '[HT40+][LDPC][SHORT-GI-20][SHORT-GI-40][TX-STBC][RX-STBC1][DSSS_CCK-40]'

            elif ap_mode == "a": # for a only
                data['hw_mode']       = 'a'
                data['ieee80211n']    = 1
                data['ieee80211ac']   = 0
                data['wmm_enabled']   = 0

            elif ap_mode == "ac": # for a/c
                data['hw_mode']       = 'a'
                data['ieee80211ac']   = 1
                data['ieee80211n']    = 1
                data['ht_capab']      = '[HT40+][LDPC][SHORT-GI-20][SHORT-GI-40][TX-STBC][RX-STBC1][DSSS_CCK-40]'
                data['wmm_enabled']   = 1
                data['vht_oper_chwidth']   = 0
                data['vht_capab']      = '[MAX-MPDU-11454][RXLDPC][SHORT-GI-80][TX-STBC-2BY1][RX-STBC-1]'

            security_mode = config.get('securityMode', 'wpa2-psk')

            if security_mode == "wep":
                data['wep_default_key']       = 1
                data['wep_key1']              = '"%s"' % config.get('password', 'fwrouter_ap')
                data['wep_key_len_broadcast'] = 5
                data['wep_key_len_unicast']   = 5
                data['wep_rekey_period']      = 300
            elif security_mode == "wpa-psk":
                data['wpa'] = 1
                data['wpa_passphrase'] = config.get('password', 'fwrouter_ap')
                data['wpa_pairwise']   = 'TKIP CCMP'
            elif security_mode == "wpa2-psk":
                data['wpa'] = 2
                data['wpa_passphrase'] = config.get('password', 'fwrouter_ap')
                data['wpa_pairwise']   = 'CCMP'
                data['rsn_pairwise']   = 'CCMP'
                data['wpa_key_mgmt']   = 'WPA-PSK'
            elif security_mode == "wpa-psk/wpa2-psk":
                data['wpa'] = 3
                data['wpa_passphrase'] = config.get('password', 'fwrouter_ap')
                data['wpa_pairwise']   = 'TKIP CCMP'
                data['rsn_pairwise']   = 'CCMP'

            with open(fwglobals.g.HOSTAPD_CONFIG_DIRECTORY + 'hostapd_%s_fwrun.conf' % band, 'w+') as f:
                txt = ''
                for key in data:
                    txt += '%s=%s\n' % (key, data[key])

                fwutils.file_write_and_flush(f, txt)

        return (True, None)
    except Exception as e:
        return (False, str(e))

def ap_get_clients(interface_name):
    response = []
    try:
        output = subprocess.check_output('iw dev %s station dump' % interface_name, shell=True).decode()
        if not output:
            return response

        data = output.splitlines()
        # data example:
        #   Station d6:84:e5:49:fe:e1 (on wlan0)
        #       inactive time:  856 ms
        #       rx bytes:       893878
        #       rx packets:     9521
        #       tx bytes:       13123202
        #       tx packets:     9950
        #       tx retries:     0
        #       tx failed:      5
        #       rx drop misc:   102
        #       signal:         -38 [-53, -38] dBm
        #       signal avg:     -33 [-51, -33] dBm
        #       tx bitrate:     5.4 MBit/s
        #       rx bitrate:     1.0 MBit/s
        #       rx duration:    1595393 us
        #       authorized:     yes
        #       authenticated:  yes
        #       associated:     yes
        #       preamble:       short
        #       WMM/WME:        yes
        #       MFP:            no
        #       TDLS peer:      no
        #       DTIM period:    2
        #       beacon interval:100
        #       short slot time:yes
        #       connected time: 456 seconds
        for (idx, line) in enumerate(data):
            if 'Station' in line:
                mac = line.split(' ')[1]

                if 'signal' in data[idx + 9]:
                    signal =  data[idx + 9].split(':')[-1].strip().replace("'", '')
                else:
                    signal = ''

                try:
                    arp_output = subprocess.check_output('arp -a -n | grep %s' % mac, shell=True).decode()
                    ip = arp_output[arp_output.find("(")+1:arp_output.find(")")]
                except:
                    ip = ''

                entry = {
                    'mac'   : mac,
                    'ip'    : ip,
                    'signal': signal
                }
                response.append(entry)
    except Exception:
        pass
    return response

def start_hostapd():
    try:
        if fwutils.pid_of('hostapd'):
            return (True, None)

        files = glob.glob("%s*fwrun.conf" % fwglobals.g.HOSTAPD_CONFIG_DIRECTORY)
        fwglobals.log.debug("get_hostapd_filenames: %s" % files)

        if not files:
            raise Exception('Error in activating your access point. No configuration files was found')

        files = ' '.join(files)

        # Start hostapd in background
        subprocess.check_call('sudo hostapd %s -B -t -f %s' % (files, fwglobals.g.HOSTAPD_LOG_FILE), stderr=subprocess.STDOUT, shell=True)
        time.sleep(2)

        pid = fwutils.pid_of('hostapd')
        if pid:
            return (True, None)

        raise Exception('Error in activating your access point. Your hardware may not support the selected settings')
    except Exception as err:
        stop_hostapd()
        return (False, str(err))


def stop_hostapd():
    try:
        if fwutils.pid_of('hostapd'):
            os.system('killall hostapd')

        files = glob.glob("%s*fwrun.conf" % fwglobals.g.HOSTAPD_CONFIG_DIRECTORY)
        for filePath in files:
            try:
                os.remove(filePath)
            except:
                fwglobals.log.debug(f"Error while deleting file: {filePath}")
        return (True, None)
    except Exception as e:
        return (False, str(e))


def wifi_get_capabilities(dev_id):

    result = {
        'Band 1': {
            'Exists': False
        },
        'Band 2': {
            'Exists': False
        }
    }

    def _get_band(output, band_number):
        regex = r'(Band ' + str(band_number) + r':.*?\\n\\t(?!\\t))'
        match = re.search(regex, output,  re.MULTILINE | re.IGNORECASE)
        if match:
            return match.group(1)

        return ""

    def _parse_key_data(text, output, negative_look_count = 1):
        match = re.search(text, output,  re.MULTILINE | re.IGNORECASE)

        res = list()

        if match:
            result = match.group()
            splitted = result.replace('\\t', '\t').replace('\\n', '\n').splitlines()
            for line in splitted[1:-1]:
                res.append(line.lstrip('\t').strip(' *'))
            return res

        return res

    try:
        output = subprocess.check_output('iw dev', shell=True).decode().splitlines()
        linux_if = fwutils.dev_id_to_linux_if(dev_id)
        if linux_if in output[1]:
            phy_name = output[0].replace('#', '')

            output = subprocess.check_output('iw %s info' % phy_name, shell=True).decode().replace('\t', '\\t').replace('\n', '\\n')
            result['SupportedModes'] = _parse_key_data('Supported interface modes', output)


            band1 = _get_band(output, 1)
            band2 = _get_band(output, 2)

            if band1:
                result['Band 1']['Exists'] = True
            if band2:
                result['Band 2']['Exists'] = True
        return result
    except Exception:
        return result

def collect_wifi_info(dev_id):
    interface_name = fwutils.dev_id_to_linux_if(dev_id)
    ap_status = fwutils.pid_of('hostapd')

    clients = ap_get_clients(interface_name)

    response = {
        'clients'             : clients,
        'ap_status'           : ap_status != None
    }

    return response

def is_wifi_interface_by_dev_id(dev_id):
    linux_if = fwutils.dev_id_to_linux_if(dev_id)
    return is_wifi_interface(linux_if)

def is_wifi_interface(if_name):
    """Check if interface is WIFI.

    :param if_name: Interface name to check.

    :returns: Boolean.
    """
    try:
        lines = subprocess.check_output('iwconfig | grep %s' % if_name, shell=True, stderr=subprocess.STDOUT).decode().splitlines()
        for line in lines:
            if if_name in line and not 'no wireless extensions' in line:
                return True
    except Exception:
        return False

    return False

def get_wifi_interfaces_dev_ids():
    out = {}
    interfaces = psutil.net_if_addrs()
    for nic_name, _ in list(interfaces.items()):
        if is_wifi_interface(nic_name):
            dev_id = fwutils.get_interface_dev_id(nic_name)
            if dev_id:
                out[dev_id] = nic_name
    return out

def get_stats():
    out = {}
    wifi_dev_ids = get_wifi_interfaces_dev_ids()
    for wifi_dev_id in wifi_dev_ids:
        info = collect_wifi_info(wifi_dev_id)
        out[wifi_dev_id] = info
    return out