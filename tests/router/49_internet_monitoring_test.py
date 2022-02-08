################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
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
#
################################################################################

"""
This whitebox script tests different test scenarios for Internet monitoring
with a combination of different steps. The test scenarios are:
 - Monitor assigned interface
 - Monitor unassigned interface
 - Monitor with monitor_unassigned_interfaces flag disabled
 - Monitor assigned interface after fwagent restart
 - Monitor unassigned interface after fwagent
 Steps to be tested for each of the above test scenarios:
 1) Interface with DHCP address
 2) Interface with static address
 3) Default route with zero metric
 4) Default route with non-zero metric
 5) For Primary interface
 6) For Secondary interface

 Test Environment : This test has to be tested on Ubuntu 18.04 Virtualbox with
 3 intf: Bridge - 0000:00:03.0, internal n/w - 0000:00:08.0 and 0000:00:09.0

 Each step will first block Bridge intf with Firewall rule and ping internet.
 Ping must fail and metric of Bridge intf must be increased to higher value.
 After removal of Firewall, ping must be successful and metric must be retained
 to lesser value.

 To run the script : pytest -s -k 49
"""

import glob
import os
import sys
import re
import time
import yaml
import pytest
import fwtests

CODE_ROOT = os.path.realpath(__file__).replace('\\', '/').split('/tests/')[0]
TEST_ROOT = CODE_ROOT + '/tests/'
sys.path.append(TEST_ROOT)

CLI_PATH = __file__.replace('.py', '')
CLI_STOP_ROUTER = os.path.join(CLI_PATH, 'stop-router.cli')
CLI_START_ROUTER = os.path.join(CLI_PATH, 'start-router.cli')

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
    with open('/etc/flexiwan/agent/fwagent_conf.yaml', 'r+') as f:
        doc = yaml.load(f)
        agent = doc['agent']
        if agent['monitor_unassigned_interfaces'] == state:
            return
        agent['monitor_unassigned_interfaces'] = state
        conf_str = yaml.dump(doc)
        f.seek(0)
        f.write(conf_str)
        f.truncate()

def test_internet_monitor(internet_monitor_restore_config):
    '''
    This tests internet monitoring under different scenarios
    '''
    tests = sorted(glob.glob(f'{CLI_PATH}/*test.cli'))
    steps = sorted(glob.glob(f'{CLI_PATH}/step*.cli'))
    with fwtests.TestFwagent() as agent:
        for test in tests:
            test_name = test.split('/')[-1]
            print(f"Testing with {test_name} file")

            #Set flag as False in fwagent_conf for monitor_unassigned_interface_flag
            if "monitor_unassigned_interface_flag" in test:
                change_monitor_unassigned_interfaces_flag(False)
                time.sleep(5)
                #Stop and start router to consider the new fwagent_conf.yaml 
                cmd = "fwagent stop"
                os.system(cmd)
                time.sleep(5)
                cmd = "fwagent start"
                os.system(cmd)
                time.sleep(5)

            #Stop the router before starting test cli inject
            (stop_ok, _) = agent.cli(f'-f {CLI_STOP_ROUTER}')
            assert stop_ok, "Failed to stop router"

            #Inject the test cli
            (cli_ok, _) = agent.cli(f'-f {test}')
            assert cli_ok, f"Failed to inject request with {test_name} file"

            #Start the router before test cli inject
            (start_ok, _) = agent.cli(f'-f {CLI_START_ROUTER}')
            assert start_ok, "Failed to start router"
            cmd = "systemctl start flexiwan-router"
            status = os.system(cmd)
            assert status == 0, 'Failed to start the Flexiwan-router service'
            time.sleep(5)

            #Run fwagent reset for monitor after fwagent restart test
            if 'fwagent_restart' in test:
                os.system('systemctl restart flexiwan-router')
                time.sleep(10)

            #Run through all steps for this test
            for step in steps:
                step_name = step.split('/')[-1]
                print(f"Step: {step_name}")

                #Inject the step cli
                (cli_ok, _) = agent.cli(f'-f {step}')
                assert cli_ok, f"Failed to inject request with {test_name} file"
                time.sleep(5)

                #Block the Bridge interface through Firewall rule
                cmd = f'iptables -A OUTPUT -p icmp -j DROP'
                status = os.system(cmd)
                assert status == 0, 'Failed to apply Firewall rule'

                #Check if ping fails and metric value has increased
                ping_status = os.system('ping -w 3 -c 2 8.8.8.8')
                assert ping_status != 0, 'ping check failed'
                time.sleep(15)

                output = os.popen('ip route').read()
                metric_value = re.search(r"default via .*metric ([0-9]+).*", output)
                assert metric_value and len(metric_value.groups()) == 1,\
                        "Default route has no metric value"
                if "monitor_unassigned_interface_flag" in test:
                    assert int(metric_value.group(1)) < 2000000000,\
                                f'Failed: Wrong Metric value {metric_value.group(1)}\
                                  for test {test_name}, step {step_name}'
                else:
                    assert int(metric_value.group(1)) >= 2000000000,\
                                f'Failed: Wrong Metric value {metric_value.group(1)}\
                                  for test {test_name}, step {step_name}'

                #Unblock Bridge interface by deleting added Firewall rule
                cmd = f'iptables -D OUTPUT -p icmp -j DROP'
                status = os.system(cmd)
                assert status == 0, 'Failed to apply Firewall rule'

                #Correct IP and gateway has to be assigned for static address
                #Hence skipping the post ping check for static address
                if "assign_static_address" in step:
                    continue

                #Check if ping is successful and metric value has been retained
                ping_status = os.system('ping -w 3 -c 2 8.8.8.8')
                assert ping_status == 0, 'ping check failed'
                time.sleep(15)

                output = os.popen('ip route').read()
                metric_value = re.search(r"default via .*metric ([0-9]+).*", output)

                #Zero metric for unassigned interface does not take effect
                if "assign_zero_metric" in step and "monitor_unassigned_interface" not in test:
                    assert not metric_value, f"Default route has metric value in {step_name}"
                else:
                    assert metric_value and len(metric_value.groups()) == 1,\
                            "Default route has no metric value"
                    assert int(metric_value.group(1)) < 2000000000,\
                                f'Failed: Wrong Metric value {metric_value.group(1)}\
                                  for test {test_name}, step {step_name}'

            #If the test is monitor_unassigned_interface, reset flag to True in yaml
            if "monitor_unassigned_interface_flag" in test:
                change_monitor_unassigned_interfaces_flag(True)
                time.sleep(5)
                cmd = "fwagent stop"
                os.system(cmd)
                time.sleep(5)
                cmd = "fwagent start"
                os.system(cmd)
                time.sleep(5)

if __name__ == '__main__':
    test_internet_monitor()
