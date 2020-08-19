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
This is a whitebox script to test netplan under different scenarios and with 
 combination of netplans.
 The script start with loading a initial configuration in netplan. These initial
 configurations are:
 - Basic netplan with all interfaces
 - Multiple netplan files for different interfaces
 - With metrics configuration in netplan and without as static and as dhcp
 - Use default route in netplan configuration and without
 - Use match in netplan and set name
 - Use incomplete configurations in netplan
 After loading the initial configuration the script will start the loading test 
 configurations which are:
 1) two WANs + LAN, 
 2) two LANs + WAN, 
 3) One WAN + One LAN + Unassigned  
 4) Two dhcp + One Static
 After each test the initial netplan file is again loaded.
 
 Test Environment : This test has to be run on a Ubuntu 18.04 Virtualbox with 
 3 intf: 0000:00:03.0, 0000:00:08.0 and 0000:00:09.0
 
 REMEMBER TO STOP THE ROUTER BEFORE RUNNING THE SCRIPT
 
 Use : sudo systemctl stop flexiwan-router
 
 To run the script : pytest -k 13
 """

import glob
import os
import re
import sys
import shutil

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')
cli_stop_router_file = os.path.join(cli_path, 'stop-router.cli')
cli_start_router_file = os.path.join(cli_path, 'start-router.cli')
multiple_netplan = os.path.join(cli_path, 'multiple_netplans/')

def test():
    tests_path = __file__.replace('.py', '')
    test_cases = sorted(glob.glob('%s/*.cli' % tests_path))
    yaml_config = sorted(glob.glob('%s/*.yaml' % tests_path))
    orig_yaml = glob.glob("/etc/netplan/50*.yaml")
    #take backup of original netplan yaml file
    orig_backup = orig_yaml[0].replace('yaml', 'yaml.backup')
    shutil.move(orig_yaml[0], orig_backup)
    for yaml in yaml_config:
        
        for t in test_cases:
            #copy the netplan file to netplan dir
	    if 'multiple_netplan' in yaml:
                os.system('cp -R %s* /etc/netplan/' % multiple_netplan) 
            else:
	        shutil.copy(yaml, '/etc/netplan/50-cloud-init.yaml')
	        #apply netplan
	        os.system('netplan apply')
            with fwtests.TestFwagent() as agent:
                print("   " + os.path.basename(t))

	        agent.cli('-f %s' % cli_start_router_file)
                # Load router configuration with spoiled lists
                agent.cli('--api inject_requests filename=%s ignore_errors=True' % t)

                # Ensure that spoiled lists were reverted completely
                configured = fwtests.wait_vpp_to_be_configured([('interfaces', 0),('tunnels', 0)], timeout=30)
                assert configured

                agent.cli('-f %s' % cli_stop_router_file)

            os.system('rm -f /etc/netplan/*.yaml')
    #restoring the original yaml file
    #orig_backup = orig_yaml[0].replace('yaml.backup', 'yaml')
    shutil.move(orig_backup, orig_yaml[0])
if __name__ == '__main__':
    test()
