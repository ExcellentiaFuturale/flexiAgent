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
import pytest
import os
import sys

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests
import fwutils
import subprocess
import fwglobals
import json
import time
fwglobals.initialize()

cli_path = __file__.replace('.py', '')
cli_add_config_file = os.path.join(cli_path, 'add-config.cli')
cli_start_router_file = os.path.join(cli_path, 'start-router.cli')
cli_reset_modem_file = os.path.join(cli_path, 'reset-modem.cli')

###########################################################################################
# This test checks the LTE reset process and ensures that LTE has connectivity after reset
###########################################################################################

def test():
    with fwtests.TestFwagent() as agent:

        def _check_connectivity(router_is_running=False):
            lte_dev_id = pytest.lte_dev_id
            if router_is_running: # if router is running, we need to take the vppsb interface
                config = agent.show("--agent cache")
                config = json.loads(config)
                lte_ifc_name = config['DEV_ID_TO_VPP_TAP_NAME'][lte_dev_id]
            else:
                lte_ifc_name = fwutils.dev_id_to_linux_if(lte_dev_id)

            cmd = f"fping 8.8.8.8 -C 1 -q -R -I {lte_ifc_name} > /dev/null 2>&1"
            ok = not subprocess.call(cmd, shell=True)
            return ok

        # make sure LTE has connectivity
        (ok, _) = agent.cli('-f %s' % cli_add_config_file)
        assert ok
        assert _check_connectivity(), 'LTE has no connectivity after add-lte'

        # reset modem and make sure LTE has connectivity when router is not running
        (ok, _) = agent.cli('-f %s' % cli_reset_modem_file)
        assert ok
        assert _check_connectivity(), 'LTE has no connectivity after reset'

        # start router
        (ok, _) = agent.cli('-f %s' % cli_start_router_file, daemon=True)
        assert ok
        assert _check_connectivity(router_is_running=True), 'LTE has no connectivity after start-router'

        # reset modem and make sure LTE has connectivity when router is running
        (ok, _) = agent.cli('-f %s' % cli_reset_modem_file)
        assert ok

        time.sleep(30) # usually after reset, LTE IP is changed. Give some time to agent to detect changes

        assert _check_connectivity(router_is_running=True), 'LTE has no connectivity after reset when router is running'


if __name__ == '__main__':
    test()
