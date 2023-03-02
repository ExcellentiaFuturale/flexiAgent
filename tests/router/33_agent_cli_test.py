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

import glob
import os
import sys

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
sys.path.append(code_root)
import fwtests
import fwutils

cli_path = __file__.replace('.py', '')
cli_add_config_start_router_file = os.path.join(cli_path, 'cli_add_config_start_router_file.cli')

tests = [
    { 'cmd': f'fwagent reset -q',   'expected_result': { 'vpp_runs': False, 'cfg_cleaned': True  } },
    { 'cmd': f'fwagent reset -s',   'expected_result': { 'vpp_runs': True,  'cfg_cleaned': False } },
    { 'cmd': f'fwkill',             'expected_result': { 'vpp_runs': False, 'cfg_cleaned': False } },
    { 'cmd': f'fwkill --clean_cfg', 'expected_result': { 'vpp_runs': False, 'cfg_cleaned': True  } },
]

def test():
    for (idx,test) in enumerate(tests):
        with fwtests.TestFwagent() as agent:
            if idx == 0:
                print("")
            cmd = test['cmd']
            if 'fwagent' in cmd:
                cmd = cmd.replace('fwagent', agent.fwagent_py)
            elif 'fwkill' in cmd:
                cmd = cmd.replace('fwkill', agent.fwkill_py)

            print(f"   cmd: {cmd}")

            # cmd before starting vpp
            ok = os.system(cmd) == 0
            assert ok

            (ok, _) = agent.cli('-f %s' % cli_add_config_start_router_file)
            assert ok

            # cmd after starting vpp
            ok = os.system(cmd) == 0
            assert ok

            expected_vpp_runs = test['expected_result']['vpp_runs']
            expected_cfg_cleaned = test['expected_result']['cfg_cleaned']

            is_vpp_runs = fwtests.vpp_does_run()
            assert expected_vpp_runs == is_vpp_runs, 'VPP should %srun after "%s"' % ("" if expected_vpp_runs else "not ", cmd)

            dump_configuration = agent.show("--configuration")
            assert expected_cfg_cleaned == (dump_configuration == ''), 'agent configuration should %sbe empty after "%s"' % ("" if expected_cfg_cleaned else "not ", cmd)

if __name__ == '__main__':
    test()
