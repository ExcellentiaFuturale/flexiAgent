################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
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
#
################################################################################

"""
This whitebox script tests different test scenarios for Internet monitoring
with a combination of different steps. The test scenarios are:
 - Monitor assigned dhcp interface
 - Monitor assigned static interface
 - Monitor assigned zero metric route
 - Monitor assigned non-zero metric route
 - Monitor assigned primary interface
 - Monitor assigned secondary interface
 - Monitor unassigned interface
 - Monitor unassigned with monitor_unassigned_interfaces flag disabled
 - Monitor assigned interface after fwagent restart
 - Monitor unassigned interface after fwagent restart

 Test Environment : This test has to be tested on Ubuntu 18.04 Virtualbox with
 3 intf: Bridge - 0000:00:03.0, internal n/w - 0000:00:08.0 and 0000:00:09.0

 Each step will first block Bridge intf with Firewall rule and ping internet.
 Ping must fail and metric of Bridge intf must be increased to higher value.
 After removal of Firewall, ping must be successful and metric must be retained
 to lesser value.

 To run the script : pytest -s -k 51
"""

import glob
import os
import sys
import re
import time
import yaml
import pytest

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')
cli_start_router_file = os.path.join(cli_path, 'start-router.cli')
cli_add_monitor_dhcp_config_file  = os.path.join(cli_path, 'monitor-assigned-dhcp-interface.cli')
cli_stop_router_file = os.path.join(cli_path, 'stop-router.cli')
debug_path = os.path.join(cli_path, 'debug_conf.yaml')

# pylint: disable=redefined-outer-name
@pytest.fixture
def internet_monitor_restore_config():
    '''This is a fixture to teardown the setup after test execution'''
    #Nothing in setup
    yield

    #Remove Firewall rule
    cmd = f'iptables -D OUTPUT -p icmp -j DROP'
    os.system(cmd)
    #Change the flag to true in fwagent_config.yaml
    change_monitor_unassigned_interfaces_flag(True)

def change_monitor_unassigned_interfaces_flag(state=True):
    '''This function changes the flag in /etc/flexiwan/agent/fwagent_conf.yaml'''
    with open('/etc/flexiwan/agent/fwagent_conf.yaml', 'r+') as f_out:
        doc = yaml.load(f_out)
        agent = doc['agent']
        if agent.get('monitor_unassigned_interfaces') == state:
            return
        agent['monitor_unassigned_interfaces'] = state
        conf_str = yaml.dump(doc)
        f_out.seek(0)
        f_out.write(conf_str)
        f_out.truncate()

def apply_firewall_rule_and_ping(action='unblock'):
    '''This function applies firewall rule through iptable cmd'''
    if action == 'block':
        #Block the Bridge interface through Firewall rule
        status = os.system('iptables -A OUTPUT -p icmp -j DROP')
        assert status == 0, 'Failed to apply Firewall rule'
        ping_status = os.system('ping -w 3 -c 2 8.8.8.8')
        assert ping_status != 0, 'ping failure check passed'
    else:
        #Unblock the Bridge interface through Firewall rule
        status = os.system('iptables -D OUTPUT -p icmp -j DROP')
        assert status == 0, 'Failed to apply Firewall rule'
        time.sleep(8)
        ping_status = os.system('ping -w 3 -c 2 8.8.8.8')
        assert ping_status == 0, 'ping success check failed'

def get_default_route_metric():
    '''This function returns the default route metric'''
    output = os.popen('ip route').read()
    metric_value = re.search(r"default via .*metric ([0-9]+).*", output)
    if not metric_value:
        return 0
    elif len(metric_value.groups()) == 1:
        return metric_value.group(1)
    else:
        return None

def check_default_route_metric(old_metric='100', verify=False, timeout=120):
    ''''''
    while not timeout<=0:
        metric = get_default_route_metric()
        if verify:
            if old_metric == metric:
                return True
        else:
            if old_metric != metric:
                return True
        time.sleep(5)  # Check status every 5 seconds
        timeout -= 5
    else:
        return False


##########################################################################
# This flow checks if default metric changes as per internet reachability:
# - check default route metric before starting router
# - add monitor-dhcp-config
# - add firewall rule to block traffic
# - ensure default route metric has increased
# - drop firewall rule to block traffic
# - ensure default route metric is back to original value
# - stop-router
# - ensure vpp doesn't run
# - ensure default route metric is back to value before starting
######################################################################
def flow_01():
    with fwtests.TestFwagent() as agent:
        orig_metric_before_start = get_default_route_metric()
        (ok, _) = agent.cli('-f %s' % cli_add_monitor_dhcp_config_file, daemon=True, debug_conf_file=debug_path)
        assert ok

        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        #time.sleep(10)

        metric = get_default_route_metric() # fetching default route metric before firewall
        apply_firewall_rule_and_ping('block')

        assert check_default_route_metric(metric)

        apply_firewall_rule_and_ping('unblock')

        metric = get_default_route_metric()
        assert check_default_route_metric(metric)
        (ok, _) = agent.cli('-f %s' % cli_stop_router_file, daemon=False)
        assert ok

        assert not fwtests.vpp_does_run()    # Ensure vpp doesn't run
        assert check_default_route_metric(orig_metric_before_start, True)

def test(internet_monitor_restore_config):
    print("")
    print("    flow_01")
    flow_01()

if __name__ == '__main__':
    test()
