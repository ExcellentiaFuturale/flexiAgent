#! /usr/bin/python3

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
import json
import os

import yaml
from netaddr import IPAddress

from scripts_logger import Logger

logger = Logger()

from application_cfg import config

app_database_file = config['app_database_file']

def add_to_ospf(ifconfig_local_ip, ifconfig_netmask):
    mask = IPAddress(ifconfig_netmask).netmask_bits()
    vtysh_cmd = f'sudo /usr/bin/vtysh -c "configure" -c "router ospf" -c "network {ifconfig_local_ip}/{mask} area 0.0.0.0"'
    rc = os.system(vtysh_cmd)
    if rc:
        raise Exception('Failed to add openvpn network to ospf')

def remove_from_ospf(ifconfig_local_ip, ifconfig_netmask):
    try:
        mask = IPAddress(ifconfig_netmask).netmask_bits()
        vtysh_cmd = f'sudo /usr/bin/vtysh -c "configure" -c "router ospf" -c "no network {ifconfig_local_ip}/{mask} area 0.0.0.0"'
        os.system(vtysh_cmd)
    except Exception as e:
        logger.error(f'remove_from_ospf({ifconfig_local_ip, ifconfig_netmask}): {str(e)}')
        pass

def add_to_bgp(ifconfig_local_ip, ifconfig_netmask):
    bgp_data = os.popen('vtysh -c "show bgp json" 2>/dev/null').read()
    parsed = json.loads(bgp_data)
    local_asn = parsed.get('localAS')
    if local_asn: # if not, bgp is not enabled
        mask = IPAddress(ifconfig_netmask).netmask_bits()
        vtysh_cmd = f'sudo /usr/bin/vtysh \
            -c "configure" \
            -c "router bgp {local_asn}" \
            -c "address-family ipv4 unicast" \
            -c "network {ifconfig_local_ip}/{mask}"'
        rc = os.system(vtysh_cmd)
        if rc:
            raise Exception('Failed to add openvpn network to BGP')

def remove_from_bgp(ifconfig_local_ip, ifconfig_netmask):
    try:
        bgp_data = os.popen('vtysh -c "show bgp json" 2>/dev/null').read()
        parsed = json.loads(bgp_data)
        local_asn = parsed.get('localAS')
        if local_asn: # if not, bgp is not enabled
            mask = IPAddress(ifconfig_netmask).netmask_bits()
            vtysh_cmd = f'sudo /usr/bin/vtysh \
                -c "configure" \
                -c "router bgp {local_asn}" \
                -c "address-family ipv4 unicast" \
                -c "no network {ifconfig_local_ip}/{mask}"'
            os.system(vtysh_cmd)
    except Exception as e:
        logger.error(f'remove_from_bgp({ifconfig_local_ip, ifconfig_netmask}): {str(e)}')
        pass

def add_tc_commands(ifconfig_local_ip):
    tc_cmd = [
        # configure mirror ingress traffic from the tun interface created by vpp to the the openvpn tun interface
        'sudo tc qdisc add dev t_vpp_remotevpn handle ffff: ingress',
        'sudo tc filter add dev t_vpp_remotevpn parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev t_remotevpn',

        # configure mirror ingress traffic from vpn tun interace to the tun interface that created by vpp
        'sudo tc qdisc add dev t_remotevpn handle ffff: ingress',

        # don't mirror traffic that its destination address is the vpn server itself (traffic originated by linux).
        f'sudo tc filter add dev t_remotevpn parent ffff: protocol all priority 1 u32 match ip dst {ifconfig_local_ip}/32 action pass',
        'sudo tc filter add dev t_remotevpn parent ffff: protocol all priority 2 u32 match u32 0 0 action mirred egress mirror dev t_vpp_remotevpn',
    ]

    for cmd in tc_cmd:
        rc = os.system(cmd)
        if rc:
            logger.error(f'Failed to create traffic control command. reverting')
            raise Exception(f'Failed to create traffic control command: {cmd}')

def remove_tc_commands(vpn_tun_is_up):
    try:
        tc_cmd = ['sudo tc qdisc del dev t_vpp_remotevpn handle ffff: ingress']

        # This function can be called from the revert of the "up" script.
        # In such a case, the t_remotevpn interface exists.
        # Hence, we need to remove the traffic control commands we applied to this interface.
        # If the script is called from the "down" script,
        # it means that the t_remotevpn interface is already closed,
        # and traffic control settings were removed from this interface automatically.
        # Hence, we don't need to remove the traffic control commands we applied to this interface.
        if vpn_tun_is_up:
            tc_cmd.append('sudo tc qdisc del dev t_remotevpn handle ffff: ingress')

        run_linux_commands(tc_cmd, exception_on_error=False)
    except:
        pass

def run_linux_commands(commands, exception_on_error=True):
    for command in commands:
        ret = os.system(command)
        if ret and exception_on_error:
            raise Exception(f'failed to run "{command}". error code is {ret}')
    return True

def create_tun_in_vpp(ifconfig_local_ip, ifconfig_netmask):
    mask = IPAddress(ifconfig_netmask).netmask_bits()

    # ensure that tun is not exists in case of down-script failed
    tun_exists = os.popen('sudo vppctl show tun | grep -B 1 "t_vpp_remotevpn"').read().strip()
    if tun_exists:
        # root@flexiwan-zn1:/home/shneorp# sudo vppctl show tun | grep -B 1 "t_vpp_remotevpn"
        # Interface: tun0 (ifindex 7)
        #   name "t_vpp_remotevpn"
        tun_name = tun_exists.splitlines()[0].split(' ')[1]
        os.system(f'sudo vppctl delete tap {tun_name}')

    # configure the vpp interface
    tun_vpp_if_name = os.popen('sudo vppctl create tap host-if-name t_vpp_remotevpn tun').read().strip()
    if not tun_vpp_if_name:
        raise Exception('Cannot create tun device in vpp')

    logger.info(f'TUN created in vpp. vpp_if_name={tun_vpp_if_name}')

    # We need to save information between the script called when running (up)
    # and the script called when the daemon goes down.
    # For this purpose we create a file in the library of the application where we store the required information
    data = { 'tun_vpp_if_name': tun_vpp_if_name }
    with open(app_database_file, 'w') as f:
        json.dump(data, f)

    vpp_cmd = [
        f'sudo vppctl set interface ip address {tun_vpp_if_name} {ifconfig_local_ip}/{mask}',
        f'sudo vppctl set interface state {tun_vpp_if_name} up'
    ]

    run_linux_commands(vpp_cmd)

def remove_tun_from_vpp():
    try:
        data = None
        with open(app_database_file, 'r') as json_file:
            data = json.load(json_file)
            tun_vpp_if_name = data.get('tun_vpp_if_name')
            if tun_vpp_if_name:
                os.system(f'sudo vppctl delete tap {tun_vpp_if_name}')
                logger.info(f'TUN removed from vpp. vpp_if_name={tun_vpp_if_name}')
                del data['tun_vpp_if_name']

        # update
        with open(app_database_file, 'w+') as json_file:
            json.dump(data, json_file)
    except Exception as e:
        logger.error(f'remove_tun_from_vpp(): {str(e)}')
        pass

def get_device_versions():
    """Get agent version.

    :returns: Tuple with major and minor versions value.
    """
    try:
        with open('/etc/flexiwan/agent/.versions.yaml', 'r') as stream:
            versions = yaml.load(stream, Loader=yaml.BaseLoader)
            agent_version = versions['components']['agent']['version']
            major, minor, patch = agent_version.split('.')
            return int(major), int(minor), int(patch)
    except Exception as e:
        logger.error(f'get_device_versions(): {str(e)}')
        return (None, None, None)

def is_device_higher_than_5_3():
    major, minor, _ = get_device_versions()
    return major > 5 or major == 5 and minor >= 3
