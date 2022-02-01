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
import fwtests

cli_path = __file__.replace('.py', '')

################################################################################
# This test feeds agent with router configuration out of step1_X.cli file.
# Than it injects a number of 'aggregated' requests each of them include list of
# 'add-X', 'remove-X' and 'modify-X' requests to test modification of router
# configuration.
# Every injected 'aggregated' request is named a 'step'.
#   After every step test ensures that resulted VPP configuration and
# configuration database dump match the expected VPP configuration and dump.
#   As well test ensures that vpp is restarted if needed after modificaion.
# For example the 'add-interface' and 'remove-interface' requests require vpp
# restart.
################################################################################
def test():
    with fwtests.TestFwagent() as agent:

        steps             = sorted(glob.glob(cli_path + '/' + 'step*.cli'))
        expected_vpp_cfg  = sorted(glob.glob(cli_path + '/' + 'step*vpp*.json'))
        expected_dump_cfg = sorted(glob.glob(cli_path + '/' + 'step*dump*.json'))

        for (idx, step) in enumerate(steps):

            if idx == 0:
                print("")
            print("   " + os.path.basename(step))

            agent.clean_log()

            # Inject request.
            # Note the first request comes with 'daemon=True' to leave agent
            # running on background, so it could receive further injects.
            #
            daemon = True if idx == 0 else False
            (ok, err_str) = agent.cli('-f %s' % step,
                                    daemon=daemon,
                                    expected_vpp_cfg=expected_vpp_cfg[idx],
                                    expected_router_cfg=expected_dump_cfg[idx],
                                    check_log=True)
            assert ok, err_str

            # Get test index out of name,
            # e.g. '5' out of '/home/.../step5_cfg_modify-tunnel_no_change.cli'
            #
            step_number = int(os.path.basename(step).split('_')[0].split('step')[1])

            if step_number % 4 == 1:
                # step1_cfg_modify-interface_no_change.cli
                # step5_cfg_modify-tunnel_no_change.cli
                #
                lines = agent.grep_log('=== start execution', print_findings=False)
                assert len(lines) == 0, "log has not expected executed requests: %s" % ('\n'.join(lines))
                lines = agent.grep_log('_strip_noop_request: request has no impact', print_findings=False)
                assert len(lines) == 1, "log has no expected 'no impact' notion: %s" % ('\n'.join(lines))

            elif step_number == 2:
                # step2_cfg_modify-interface_stripped_out_cfg_updated.cli
                #
                lines = agent.grep_log('=== start execution', print_findings=False)
                assert len(lines) == 0, "log has not expected executed requests: %s" % ('\n'.join(lines))
                lines = agent.grep_log('_strip_noop_request: request has no impact', print_findings=False)
                assert len(lines) == 1, "log has no expected 'no impact' notion: %s" % ('\n'.join(lines))
                lines = agent.grep_log('not impacting modifications', print_findings=False)
                assert len(lines) == 1, "log has no expected 'not impacting modifications' notion: %s" % ('\n'.join(lines))

            elif step_number == 3:
                # step3_cfg_modify-interface_replaced_by_remove_add.cli
                #
                lines = agent.grep_log('=== start execution', print_findings=False)
                assert len(lines) == 2, "log has no expected execution of remove-X & add-X pair: %s" % ('\n'.join(lines))

            elif step_number == 6:
                # step6_cfg_modify-tunnel_modified.cli - includes 2 modified tunnels
                #
                lines = agent.grep_log('=== start execution of modify-tunnel', print_findings=False)
                assert len(lines) == 2, "log has not expected executed modify-tunnel: %s" % ('\n'.join(lines))

            elif step_number == 7:
                # step7_cfg_modify-tunnel_replace_by_remove_add.cli - includes 2 remove & add pairs
                #
                lines = agent.grep_log('=== start execution', print_findings=False)
                assert len(lines) == 4, "log has no expected execution of remove-X & add-X pair: %s" % ('\n'.join(lines))



if __name__ == '__main__':
    test()
