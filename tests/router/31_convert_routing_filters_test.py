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

import os
import sys

CODE_ROOT = os.path.realpath(__file__).replace('\\', '/').split('/tests/')[0]
TEST_ROOT = CODE_ROOT + '/tests/'
sys.path.append(CODE_ROOT)
sys.path.append(TEST_ROOT)
from fwtranslate_add_routing_filter import _convert_params_to_frr_configs

route_map_name = 'test_route_map'
route_map_description = 'test_route_map_description'

test_cases = [
    {
        'input': [
            {
                "route":"0.0.0.0/0",
                "action":"allow",
                "nextHop":"",
                "priority":4
            },
            {
                "route":"5.5.5.5/32",
                "action":"allow",
                "nextHop":"",
                "priority":2
            },
            {
                "route":"8.8.8.8/32",
                "action":"allow",
                "nextHop":"2.2.2.2",
                "priority":1
            },
            {
                "route":"9.9.9.9/32",
                "action":"allow",
                "nextHop":"",
                "priority":3
            }
        ],
        'expected': [
            f'access-list rm_test_route_map_group_0 permit 8.8.8.8/32',
            f'route-map {route_map_name} permit 5',
            f'  description {route_map_description}',
            f'  match ip address rm_test_route_map_group_0',
            f'  set ip next-hop 2.2.2.2',
            f'route-map {route_map_name} permit 10',
            f'  description {route_map_description}'
        ]
    },
    {
        'input': [
            {
                "route":"0.0.0.0/0",
                "action":"deny",
                "nextHop":"",
                "priority":4
            },
            {
                "route":"5.5.5.5/32",
                "action":"allow",
                "nextHop":"",
                "priority":2
            },
            {
                "route":"8.8.8.8/32",
                "action":"allow",
                "nextHop":"2.2.2.2",
                "priority":1
            },
            {
                "route":"9.9.9.9/32",
                "action":"allow",
                "nextHop":"",
                "priority":3
            }
        ],
        'expected': [
            f'access-list rm_test_route_map_group_0 permit 8.8.8.8/32',
            f'route-map {route_map_name} permit 5',
            f'  description {route_map_description}',
            f'  match ip address rm_test_route_map_group_0',
            f'  set ip next-hop 2.2.2.2',
            f'access-list rm_test_route_map_group_1 permit 5.5.5.5/32',
            f'access-list rm_test_route_map_group_1 permit 9.9.9.9/32',
            f'route-map {route_map_name} permit 10',
            f'  description {route_map_description}',
            f'  match ip address rm_test_route_map_group_1',
            f'route-map {route_map_name} deny 15',
            f'  description {route_map_description}'
        ]
    },
    {
        'input': [
            {
                "route":"0.0.0.0/0",
                "action":"allow",
                "nextHop":"",
                "priority":4
            },
            {
                "route":"5.5.5.5/32",
                "action":"deny",
                "nextHop":"",
                "priority":2
            },
            {
                "route":"8.8.8.8/32",
                "action":"deny",
                "nextHop":"",
                "priority":1
            },
            {
                "route":"9.9.9.9/32",
                "action":"allow",
                "nextHop":"",
                "priority":3
            }
        ],
        'expected': [
            f'access-list rm_test_route_map_group_0 permit 8.8.8.8/32',
            f'access-list rm_test_route_map_group_0 permit 5.5.5.5/32',
            f'route-map {route_map_name} deny 5',
            f'  description {route_map_description}',
            f'  match ip address rm_test_route_map_group_0',
            f'route-map {route_map_name} permit 10',
            f'  description {route_map_description}'
        ]
    },
    {
        'input': [
            {
                "route":"0.0.0.0/0",
                "action":"deny",
                "nextHop":"",
                "priority":0
            },
        ],
        'expected': [
            f'route-map {route_map_name} deny 5',
            f'  description {route_map_description}',
        ]
    },
    {
        'input': [
            {
                "route":"0.0.0.0/0",
                "action":"allow",
                "nextHop":"",
                "priority":0
            },
        ],
        'expected': [
            f'route-map {route_map_name} permit 5',
            f'  description {route_map_description}',
        ]
    },
]

def test():
    for (idx, test_case) in enumerate(test_cases):
        if idx == 0:
            print("")

        input_rules = test_case['input']
        expected_commands = test_case['expected']
        add_ret_val, _ = _convert_params_to_frr_configs(route_map_name, route_map_description, input_rules)
        assert add_ret_val == expected_commands, f'{add_ret_val} is not as expected {expected_commands}'

if __name__ == '__main__':
    test()
