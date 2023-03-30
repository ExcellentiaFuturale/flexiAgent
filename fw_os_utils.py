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

import importlib.util
import os
import subprocess
import time

def pid_of(process_name):
    """Get pid of process.

    :param process_name:   Process name.

    :returns:           process identifier.
    """
    try:
        # There is an issue with pidof on Ubuntu 20.04 so replaced it with pgrep.
        pid = subprocess.check_output(['pgrep', '-x', process_name]).decode().strip()
    except:
        pid = None
    return pid

def kill_process(name, timeout=10):
    os.system(f'sudo killall {name}')
    while timeout >= 0:
        if pid_of(name):
            timeout -= 1
            time.sleep(1)
        else:
            return True
    return False

def vpp_pid():
    """Get pid of VPP process.

    :returns:           process identifier.
    """
    pid = pid_of('vpp_main')
    if not pid:
        pid = pid_of('vpp')

    return pid

def vpp_does_run():
    """Check if VPP is running.

    :returns:           Return 'True' if VPP is running.
    """
    return True if vpp_pid() else False

def run_linux_commands(commands, exception_on_error=True):
    for command in commands:
        ret = os.system(command)
        if ret and exception_on_error:
            raise Exception(f'failed to run "{command}". error code is {ret}')
    return True

def load_python_module(entry_point, module_name):
    module = None
    for root, dirs, files in os.walk(entry_point):
        for name in files:
            if module_name in name:
                spec = importlib.util.spec_from_file_location(module_name, f'{root}/{name}')
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                break

        # If the inner loop completes without encountering
        # the break statement then the following else
        # block will be executed and outer loop will
        # continue to the next iteration
        else:
            continue

        # If the inner loop terminates due to the
        # break statement, the else block will not
        # be executed and the following break
        # statement will terminate the outer loop also
        break

    return module
