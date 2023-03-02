################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2023  flexiWAN Ltd.
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
import json

CODE_ROOT = os.path.realpath(__file__).replace('\\', '/').split('/tests/')[0]
TEST_ROOT = CODE_ROOT + '/tests/'
sys.path.append(CODE_ROOT)
sys.path.append(TEST_ROOT)

cli_path = __file__.replace('.py', '')

import fwglobals
from fwfrr import FwFrr

route_map_name = 'test_route_map'
route_map_description = 'test_route_map_description'

def test():
    with FwFrr(fwglobals.g.FRR_DB_FILE) as frr:
        tests  = sorted(glob.glob(cli_path + '/' + '*.json'))
        for (idx, test_case) in enumerate(tests):
            if idx == 0:
                print("")

            with open(test_case) as json_file:
                test = json.load(json_file)

                input_rules = test['input']
                expected_commands = test['expected']

                add_ret_val, _ = frr.translate_routing_filter_to_frr_commands(route_map_name, route_map_description, input_rules)
                assert add_ret_val == expected_commands, f'{add_ret_val} is not as expected {expected_commands}'

if __name__ == '__main__':
    test()
