#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2019  flexiWAN Ltd.
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
import sys
import fwglobals

system_checker_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tools/system_checker/")
sys.path.append(system_checker_path)
import fwsystem_checker_common

def set_cpu_info(params):

    cmd_list = []

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "_set_cpu_info"
    cmd['cmd']['module']    = "fwtranslate_set_cpu_info"
    cmd['cmd']['descr']     = f"Set cpu info"
    cmd['cmd']['params']    = { 'params': params }

    cmd_list.append(cmd)

    return cmd_list

def _set_cpu_info(params):

    """Get device information.

    :param params: Parameters from flexiManage.

    :returns: Dictionary with information and status code.
    """

    try:
        vpp_cores = params.get('vppCores')
        power_saving = params.get('powerSaving')
        with fwsystem_checker_common.Checker() as checker:
            update_vpp, update_grub = checker.set_cpu_info(vpp_cores, power_saving)
            reply = {'ok': 1, 'message': {'cpuInfo' : checker.get_cpu_info()} }
            if update_grub:
                fwglobals.log.info("_set_cpu_info: Rebooting the system for changes to take effect.")
                os.system('sudo reboot')
            elif update_vpp and fwglobals.g.router_api.state_is_started():
                fwglobals.log.info("_set_cpu_info: Restart the router to apply changes in VPP configuration.")
                fwglobals.g.handle_request({'message':'stop-router'})
                fwglobals.g.handle_request({'message': 'start-router'})
    except Exception as e:
        reply = {'ok': 0, 'message': str(e) }
    return reply

def get_request_key(*params):
    """Get set cpu info command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'set-cpu-info'
