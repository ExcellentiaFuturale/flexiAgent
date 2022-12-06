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
import os
import subprocess
import sys
import time

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')

def _openvpn_pid():
    try:
        pid = subprocess.check_output(['pidof', 'openvpn']).decode()
    except:
        pid = None
    return pid


def test():
     with fwtests.TestFwagent() as agent:

        steps = sorted(glob.glob(cli_path + '/' + '*.cli'))

        for (idx, step) in enumerate(steps):
            if idx == 0:
                print("")
            print("   " + os.path.basename(step))

            agent.clean_log()

            (ok, err_str) = agent.cli('-f %s' % step, daemon=(idx == 0))
            assert ok, err_str

            # now ensure that VPN is running
            time.sleep(5)
            openvpn_pid = _openvpn_pid()
            assert openvpn_pid, 'VPN daemon should be up'

            # ensure that VPN interface has firewall installed

            # in this test case, vpn interface is with index 3
            output = subprocess.check_output('vppctl show acl-plugin interface sw_if_index 3', shell=True).decode()
            # expected output is:
            #   sw_if_index 3:
            #      input acl(s): 1, 0
            #      output acl(s): 2, 0
            #
            # non-expected output is:
            #   sw_if_index 3:
            assert 'input acl(s): 1, 0' in output, 'Firewall outbound rules are not applied on VPN interface'


if __name__ == '__main__':
    test()
