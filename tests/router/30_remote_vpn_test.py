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
import json

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')

cli_add_app_install_file = os.path.join(cli_path, 'add_app_install.cli')
cli_remove_app_install_file = os.path.join(cli_path, 'remove_app_install.cli')
cli_add_app_config_file = os.path.join(cli_path, 'add_app_config.cli')
cli_start_router_file = os.path.join(cli_path, 'start_router.cli')
cli_stop_router_file = os.path.join(cli_path, 'stop_router.cli')
cli_add_firewall_file = os.path.join(cli_path, 'add_firewall_policy.cli')
cli_add_firewall_2_file = os.path.join(cli_path, 'add_firewall_policy_2.cli')
cli_remove_firewall_file = os.path.join(cli_path, 'remove_firewall_policy.cli')
cli_add_firewall_app_specific = os.path.join(cli_path, 'add_firewall_policy_app_specific.cli')
cli_add_firewall_app_specific_2 = os.path.join(cli_path, 'add_firewall_policy_app_specific_2.cli')
cli_add_firewall_mix = os.path.join(cli_path, 'add_firewall_policy_mix.cli')


flow_01_expected_json = os.path.join(cli_path, 'flow_01_expected.json')
flow_02_expected_json = os.path.join(cli_path, 'flow_02_expected.json')
flow_03_expected_json = os.path.join(cli_path, 'flow_03_expected.json')
flow_04_expected_json = os.path.join(cli_path, 'flow_04_expected.json')
flow_05_expected_json = os.path.join(cli_path, 'flow_05_expected.json')
flow_06_expected_json = os.path.join(cli_path, 'flow_06_expected.json')
flow_07_expected_json = os.path.join(cli_path, 'flow_07_expected.json')
flow_08_expected_json = os.path.join(cli_path, 'flow_08_expected.json')
flow_09_expected_json = os.path.join(cli_path, 'flow_09_expected.json')
flow_10_expected_json = os.path.join(cli_path, 'flow_10_expected.json')
flow_11_expected_json = os.path.join(cli_path, 'flow_11_expected.json')

def _openvpn_pid():
    try:
        pid = subprocess.check_output(['pidof', 'openvpn']).decode()
    except:
        pid = None
    return pid

def check_expected_firewall_and_close(agent, expected_file):
    try:
        output = subprocess.check_output('vppctl show acl-plugin interface', shell=True).decode()

        with open(expected_file) as json_file:
            expected_output = json.load(json_file)
            assert output.splitlines() == expected_output, f'Firewall outbound rules were not applied correctly - cli {expected_file}'
    finally:
        (ok, _) = agent.cli('-f %s' % cli_stop_router_file)
        (ok, _) = agent.cli('-f %s' % cli_remove_app_install_file)
        (ok, _) = agent.cli('-f %s' % cli_remove_firewall_file)

def flow_01():
    with fwtests.TestFwagent() as agent:
        (ok, _) = agent.cli('-f %s' % cli_add_app_install_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_app_config_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_firewall_file)
        assert ok

        time.sleep(10)
        assert _openvpn_pid(), 'VPN daemon should be up'
        check_expected_firewall_and_close(agent, flow_01_expected_json)

def flow_02():
    with fwtests.TestFwagent() as agent:
        (ok, _) = agent.cli('-f %s' % cli_add_app_install_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_firewall_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_app_config_file)
        assert ok

        time.sleep(10)
        assert _openvpn_pid(), 'VPN daemon should be up'
        check_expected_firewall_and_close(agent, flow_02_expected_json)

def flow_03():
    with fwtests.TestFwagent() as agent:
        (ok, _) = agent.cli('-f %s' % cli_add_app_install_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_firewall_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_app_config_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_firewall_2_file)
        assert ok

        time.sleep(10)
        assert _openvpn_pid(), 'VPN daemon should be up'
        check_expected_firewall_and_close(agent, flow_03_expected_json)

def flow_04():
    with fwtests.TestFwagent() as agent:
        (ok, _) = agent.cli('-f %s' % cli_add_app_install_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_firewall_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_firewall_2_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_app_config_file)
        assert ok

        time.sleep(10)
        assert _openvpn_pid(), 'VPN daemon should be up'
        check_expected_firewall_and_close(agent, flow_04_expected_json)

def flow_05():
    with fwtests.TestFwagent() as agent:
        (ok, _) = agent.cli('-f %s' % cli_add_firewall_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_app_install_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_app_config_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok

        time.sleep(10)
        assert _openvpn_pid(), 'VPN daemon should be up'
        check_expected_firewall_and_close(agent, flow_05_expected_json)

def flow_06():
    with fwtests.TestFwagent() as agent:
        (ok, _) = agent.cli('-f %s' % cli_add_app_install_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_app_config_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_firewall_app_specific)
        assert ok

        time.sleep(10)
        assert _openvpn_pid(), 'VPN daemon should be up'
        check_expected_firewall_and_close(agent, flow_06_expected_json)

def flow_07():
    with fwtests.TestFwagent() as agent:
        (ok, _) = agent.cli('-f %s' % cli_add_app_install_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_firewall_app_specific)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_app_config_file)
        assert ok

        time.sleep(10)
        assert _openvpn_pid(), 'VPN daemon should be up'
        check_expected_firewall_and_close(agent, flow_07_expected_json)

def flow_08():
    with fwtests.TestFwagent() as agent:
        (ok, _) = agent.cli('-f %s' % cli_add_app_install_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_firewall_app_specific)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_app_config_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_firewall_app_specific_2)
        assert ok

        time.sleep(10)
        assert _openvpn_pid(), 'VPN daemon should be up'
        check_expected_firewall_and_close(agent, flow_08_expected_json)

def flow_09():
    with fwtests.TestFwagent() as agent:
        (ok, _) = agent.cli('-f %s' % cli_add_app_install_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_app_config_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_firewall_mix)
        assert ok

        time.sleep(10)
        assert _openvpn_pid(), 'VPN daemon should be up'
        check_expected_firewall_and_close(agent, flow_09_expected_json)

def flow_10():
    with fwtests.TestFwagent() as agent:
        (ok, _) = agent.cli('-f %s' % cli_add_app_install_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_app_config_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_firewall_mix)
        assert ok

        time.sleep(10)
        assert _openvpn_pid(), 'VPN daemon should be up'
        check_expected_firewall_and_close(agent, flow_10_expected_json)

def flow_11():
    with fwtests.TestFwagent() as agent:
        (ok, _) = agent.cli('-f %s' % cli_add_app_install_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_app_config_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_firewall_mix)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok

        time.sleep(10)
        assert _openvpn_pid(), 'VPN daemon should be up'
        check_expected_firewall_and_close(agent, flow_11_expected_json)


def test():
    print("")
    print("    flow_01")
    flow_01() # install vpn and configure -> start router -> add firewall

    print("    flow_02")
    flow_02() # start router -> add firewall -> install vpn and configure

    print("    flow_03")
    flow_03() # start router -> add firewall -> install vpn and configure -> add another firewall

    print("    flow_04")
    flow_04() # start router -> add firewall -> add another firewall -> install vpn and configure

    print("    flow_05")
    flow_05() # add firewall -> install vpn and configure -> start router

    print("    flow_06")
    flow_06() # install vpn and configure -> start router -> add firewall specific

    print("    flow_07")
    flow_07() # start router -> add firewall specific -> install vpn and configure

    print("    flow_08")
    flow_08() # start router -> add firewall specific -> install vpn and configure -> add another firewall specific

    print("    flow_09")
    flow_09() # install vpn and configure -> start router -> add firewall mix

    print("    flow_10")
    flow_10() # start router -> install vpn and configure -> add firewall mix

    print("    flow_11")
    flow_11() # install vpn and configure -> add firewall mix -> start router


if __name__ == '__main__':
    test()
