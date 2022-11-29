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

import os
import subprocess
import time

def run_linux_commands(commands, exception_on_error=True):
    for command in commands:
        ret = os.system(command)
        if ret and exception_on_error:
            raise Exception(f'failed to run "{command}". error code is {ret}')
    return True

def vpp_pid():
    """Get pid of VPP process.

    :returns:           process identifier.
    """
    try:
        pid = subprocess.check_output(['pidof', 'vpp'])
    except:
        pid = None
    return pid

def router_is_running():
    return True if vpp_pid() else False

def kill_process(name, timeout=10):
    os.system(f'sudo killall {name}')
    while timeout >= 0:
        try:
            _ = subprocess.check_output(['pidof', name])
            timeout -= 1
            time.sleep(1)
        except:
            return True
    return False
