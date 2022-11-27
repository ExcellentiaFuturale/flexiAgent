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
import subprocess

import yaml
from netaddr import IPAddress

from scripts_logger import Logger

logger = Logger()

from application_cfg import config

app_database_file = config['app_database_file']

def add_tc_commands(ifconfig_local_ip):
    try:
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
    except Exception as e:
        remove_tc_commands(vpn_tun_is_up=True)
        raise e

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

def get_saved_vpp_interface_name():
    with open(app_database_file, 'r') as json_file:
        data = json.load(json_file)
        tun_vpp_if_name = data.get('tun_vpp_if_name')
        return tun_vpp_if_name

def create_tun_in_vpp(addr):
    try:
        cmd = f'fwagent configure interfaces create --type lan --host_if_name t_vpp_remotevpn --addr {addr}'
        out = subprocess.check_output(cmd, shell=True).decode()
        response_data = json.loads(out)
        tun_vpp_if_name = response_data.get('tun_vpp_if_name')
        if not tun_vpp_if_name:
            raise Exception('create_tun_in_vpp(): Failed to parse response')

        data = { 'tun_vpp_if_name': tun_vpp_if_name }
        with open(app_database_file, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        logger.error(f'create_tun_in_vpp({addr}): {str(e)}')
        raise e

def remove_tun_from_vpp(addr):
    try:
        data = None
        with open(app_database_file, 'r') as json_file:
            data = json.load(json_file)
            tun_vpp_if_name = data.get('tun_vpp_if_name')
            if not tun_vpp_if_name:
                raise Exception('remove_tun_from_vpp(): Failed to find the VPP tun interface')

            cmd = f'fwagent configure interfaces delete --type lan --vpp_if_name {tun_vpp_if_name} --addr {addr}'
            subprocess.check_output(cmd, shell=True).decode()

        # update
        with open(app_database_file, 'w+') as json_file:
            json.dump(data, json_file)
    except Exception as e:
        logger.error(f'remove_tun_from_vpp(): {str(e)}')
        raise e

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

def is_device_higher_than(major, minor):
    current_major, current_minor, _ = get_device_versions()
    return current_major > major or (current_major == major and current_minor >= minor)
