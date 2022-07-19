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
import sys

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')
cli_start_router_dhcp_no_ip_file = os.path.join(cli_path, 'start-router_with_dhcp_no_ip.cli')
cli_start_router_static_no_ip_file = os.path.join(cli_path, 'start-router_with_dhcp_no_ip.cli')
cli_start_router_file = os.path.join(cli_path, 'start-router.cli')
cli_stop_router_file = os.path.join(cli_path, 'stop-router.cli')
cli_add_config_file = os.path.join(cli_path, 'cfg.cli')
cli_remove_pending_tunnel_file = os.path.join(cli_path, 'remove_pending_tunnel.cli')
cli_remove_pending_routes_file = os.path.join(cli_path, 'remove_pending_routes.cli')
cli_modify_interface_set_ip_file = os.path.join(cli_path, 'modify-interface_set_ip.cli')
cli_sync_device_no_ip_file = os.path.join(cli_path, 'sync-device_no_ip.cli')
cli_sync_device_with_ip_file = os.path.join(cli_path, 'sync-device_with_ip.cli')

json_expected_pending_cfg_empty_dump = os.path.join(cli_path, 'expected_pending_cfg_empty_dump.json')
json_expected_pending_cfg_error_dump = os.path.join(cli_path, 'expected_pending_cfg_error_dump.json')
json_expected_pending_cfg_full_dump = os.path.join(cli_path, 'expected_pending_cfg_full_dump.json')
json_expected_pending_cfg_no_tunnels_dump = os.path.join(cli_path, 'expected_pending_cfg_no_tunnels_dump.json')

################################################################################
# This flow checks if the 'start-router' succeeds even if one of the WAN
# interfaces is configured for DHCP and has no IP & GW.
# The interface has DIA labels, the configuration has tunnels and routes that
# depend on this interface. It is expected, that 'start-router' will succeed
# even with interface without IP, and  tunnels and routes that depend on this
# interface, will be not executed, but will be stored in the pending request
# database.
#   Few notes,
#   1. There are few types of 'add-route' requests:
#       - route for WAN interface via IP
#       - route for WAN interface via dev-id
#       - route for LAN interface via IP (LAN interface has no GW)
#       - route via tunnel (either pending or working)
#   2. The test uses router configuration that includes both working interfaces,
#      tunnels and routes and pending tunnels, routes. This is as follows:
#       - 3 interfaces     - primary WAN with IP, LAN, secondary WAN without IP
#       - 1 working tunnel - uses primary WAN interface
#       - 1 pending tunnel - uses secondary WAN interface without IP & GW
#       - 1 working route  - via working WAN interface
#       - 1 pending route  - via pending WAN interface by IP
#       - 1 pending route  - via pending WAN interface by interface dev-id
#       - 1 working route  - via working tunnel (by tunnel loopback IP)
#       - 1 working route  - via pending tunnel (by tunnel loopback IP)
################################################################################
def flow_01():
    with fwtests.TestFwagent() as agent:

        # Check no failure on 'start-router' and storing pending requests
        #
        (ok, _) = agent.cli('-f %s' % cli_add_config_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_dhcp_no_ip_file)
        assert ok
        assert fwtests.vpp_is_configured([('interfaces', 5),('tunnels', 1)])
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_full_dump, fwagent_py=agent.fwagent_py)

        # Check proper update of pending request database on 'remove-X'
        #
        (ok, _) = agent.cli('-f %s' % cli_remove_pending_tunnel_file)
        assert ok
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_no_tunnels_dump, fwagent_py=agent.fwagent_py)

        (ok, _) = agent.cli('-f %s' % cli_remove_pending_routes_file)
        assert ok
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_empty_dump, fwagent_py=agent.fwagent_py)

        # Check empty pending request database on 'start-router' without pending requests
        #
        (ok, _) = agent.cli('-f %s' % cli_stop_router_file)
        assert ok
        assert not fwtests.vpp_does_run()    # Ensure vpp doesn't run
        (ok, _) = agent.cli('-f %s' % cli_start_router_dhcp_no_ip_file)
        assert ok
        assert fwtests.vpp_is_configured([('interfaces', 5),('tunnels', 1)])
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_empty_dump, fwagent_py=agent.fwagent_py)

        # 'stop-router' and ensure no errors in log
        #
        agent.cli('-f %s' % cli_stop_router_file)

        lines = agent.grep_log('error: ', print_findings=False)
        assert len(lines) == 0, "log has %d not expected errors: %s" % \
                                (len(lines), '\n'.join(lines))

################################################################################
# This flow is pretty same as the flow_01, but:
# 1. It firstly applies configuration and then starts router
# 2. The 'remove-X' is injected after router was stopped and not before
################################################################################
def flow_02():
    with fwtests.TestFwagent() as agent:

        # Check no failure on 'start-router' and storing pending requests
        #
        (ok, _) = agent.cli('-f %s' % cli_start_router_dhcp_no_ip_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_config_file)
        assert ok
        assert fwtests.vpp_is_configured([('interfaces', 5),('tunnels', 1)])
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_full_dump, fwagent_py=agent.fwagent_py)

        # Check proper update of pending request database on 'remove-X'
        #
        (ok, _) = agent.cli('-f %s' % cli_stop_router_file)
        assert ok
        assert not fwtests.vpp_does_run()    # Ensure vpp doesn't run
        (ok, _) = agent.cli('-f %s' % cli_remove_pending_tunnel_file)
        assert ok
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_no_tunnels_dump, fwagent_py=agent.fwagent_py)

        (ok, _) = agent.cli('-f %s' % cli_remove_pending_routes_file)
        assert ok
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_empty_dump, fwagent_py=agent.fwagent_py)

        # Check empty pending request database on 'start-router' without pending requests
        #
        (ok, _) = agent.cli('-f %s' % cli_start_router_dhcp_no_ip_file)
        assert ok
        assert fwtests.vpp_is_configured([('interfaces', 5),('tunnels', 1)])
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_empty_dump, fwagent_py=agent.fwagent_py)

        # 'stop-router' and ensure no errors in log
        #
        agent.cli('-f %s' % cli_stop_router_file)

        lines = agent.grep_log('error: ', print_findings=False)
        assert len(lines) == 0, "log has %d not expected errors: %s" % \
                                (len(lines), '\n'.join(lines))

################################################################################
# This flow is pretty same as the flow_01, but:
# 1. It uses WAN interface without IP configured as a static, and not as DHCP.
# 2. It does not test proper cleaning of the pending request DB (using 'remove-X').
# 3. It tests recovery from pending condition (using 'modify-interface' to assing
#    IP to the WAN interface that was without IP).
################################################################################
def flow_03():
    with fwtests.TestFwagent() as agent:

        # Check no failure on 'start-router' and storing pending requests
        #
        (ok, _) = agent.cli('-f %s' % cli_add_config_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_static_no_ip_file)
        assert ok
        assert fwtests.vpp_is_configured([('interfaces', 5),('tunnels', 1)])
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_full_dump, fwagent_py=agent.fwagent_py)

        # Check recovery from pending condition by assigning IP to the WAN interface.
        #
        (ok, _) = agent.cli('-f %s' % cli_stop_router_file)
        assert ok
        assert not fwtests.vpp_does_run()    # Ensure vpp doesn't run
        (ok, _) = agent.cli('-f %s' % cli_modify_interface_set_ip_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        assert fwtests.vpp_is_configured([('interfaces', 7),('tunnels', 2)])
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_error_dump, fwagent_py=agent.fwagent_py)

        # 'stop-router' and ensure no errors in log
        #
        agent.cli('-f %s' % cli_stop_router_file)

        lines = agent.grep_log('error: ', print_findings=False)
        assert len(lines) == 0, "log has %d not expected errors: %s" % \
                                (len(lines), '\n'.join(lines))

################################################################################
# This flow is pretty same as the flow_03, but:
# 1. It firstly applies configuration and then starts router
################################################################################
def flow_04():
    with fwtests.TestFwagent() as agent:

        # Check no failure on 'start-router' and storing pending requests
        #
        (ok, _) = agent.cli('-f %s' % cli_start_router_static_no_ip_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_add_config_file)
        assert ok
        assert fwtests.vpp_is_configured([('interfaces', 5),('tunnels', 1)])
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_full_dump, fwagent_py=agent.fwagent_py)

        # Check recovery from pending condition by assigning IP to the WAN interface.
        #
        (ok, _) = agent.cli('-f %s' % cli_stop_router_file)
        assert ok
        assert not fwtests.vpp_does_run()    # Ensure vpp doesn't run
        (ok, _) = agent.cli('-f %s' % cli_modify_interface_set_ip_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        assert fwtests.vpp_is_configured([('interfaces', 7),('tunnels', 2)])
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_error_dump, fwagent_py=agent.fwagent_py)

        # 'stop-router' and ensure no errors in log
        #
        agent.cli('-f %s' % cli_stop_router_file)

        lines = agent.grep_log('error: ', print_findings=False)
        assert len(lines) == 0, "log has %d not expected errors: %s" % \
                                (len(lines), '\n'.join(lines))

################################################################################
# This flow tests handling of the 'sync-device' request.
# The 'sync-device' moves requests from pending database to main configuration
# database and than starts synchronization. As a result,
# 1. If pending condition still exists, the pending database should be recreated
#    as it was before 'sync-device' was received.
# 2. If pending condition was removed, the peding database should become empty
#    after the 'sync-device' handling was finished.
################################################################################
def flow_05():
    with fwtests.TestFwagent() as agent:

        # Start router under the peding condition.
        #
        (ok, _) = agent.cli('-f %s' % cli_add_config_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_static_no_ip_file)
        assert ok
        assert fwtests.vpp_is_configured([('interfaces', 5),('tunnels', 1)])
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_full_dump, fwagent_py=agent.fwagent_py)

        # Inject 'sync-device' with no-IP and ensure the same peding requests were detected.
        #
        (ok, _) = agent.cli('-f %s' % cli_sync_device_no_ip_file)
        assert ok
        assert fwtests.vpp_is_configured([('interfaces', 5),('tunnels', 1)])
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_full_dump, fwagent_py=agent.fwagent_py)

        # Inject 'sync-device' with IP and ensure the peding state was recovered.
        #
        (ok, _) = agent.cli('-f %s' % cli_sync_device_with_ip_file)
        assert ok
        assert fwtests.vpp_is_configured([('interfaces', 7),('tunnels', 2)])
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_error_dump, fwagent_py=agent.fwagent_py)

        # 'stop-router' and ensure no errors in log
        #
        agent.cli('-f %s' % cli_stop_router_file)

        lines = agent.grep_log('error: ', print_findings=False)
        assert len(lines) == 0, "log has %d not expected errors: %s" % \
                                (len(lines), '\n'.join(lines))

################################################################################
# This flow is pretty same as the flow_05, but it tests 'sync-device' when VPP
# does not run.
################################################################################
def flow_06():
    with fwtests.TestFwagent() as agent:

        # Start router under the peding condition and stop it.
        #
        (ok, _) = agent.cli('-f %s' % cli_add_config_file, daemon=True)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_static_no_ip_file)
        assert ok
        agent.cli('-f %s' % cli_stop_router_file)
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_full_dump, fwagent_py=agent.fwagent_py)

        # Inject 'sync-device' with no-IP and ensure that peding request DB was
        # cleaned and main configuration database has full configuration.
        #
        (ok, _) = agent.cli('-f %s' % cli_sync_device_no_ip_file)
        assert ok
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_empty_dump, fwagent_py=agent.fwagent_py)

        # Inject 'sync-device' with IP and ensure that peding request DB is still
        # empty and main configuration database has full configuration.
        #
        (ok, _) = agent.cli('-f %s' % cli_sync_device_with_ip_file)
        assert ok
        assert fwtests.router_is_pending_configured(
            json_expected_pending_cfg_empty_dump, fwagent_py=agent.fwagent_py)

        lines = agent.grep_log('error: ', print_findings=False)
        assert len(lines) == 0, "log has %d not expected errors: %s" % \
                                (len(lines), '\n'.join(lines))


def test():
    print("")
    print("    flow_01")
    flow_01()
    print("    flow_02")
    flow_02()
    print("    flow_03")
    flow_03()
    print("    flow_04")
    flow_04()
    print("    flow_05")
    flow_05()
    print("    flow_06")
    flow_06()

if __name__ == '__main__':
    test()
