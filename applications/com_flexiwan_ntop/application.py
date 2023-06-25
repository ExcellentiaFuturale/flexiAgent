#! /usr/bin/python3

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

# nnoww - remove this together with application_cfg.py
# sys.path.append(current_dir)
# from application_cfg import config as cfg

import json
import os
import subprocess
import sys

applications_dir = os.path.join(os.path.realpath(__file__), "../")
sys.path.append(applications_dir)
from applications.fwapplication_interface import FwApplicationInterface

agent_dir = os.path.join(applications_dir, "../")
sys.path.append(agent_dir)
import fw_os_utils

class Application(FwApplicationInterface):

    def install(self, params):
        """Install Remote VPN server on host.

        :param params - remote vpn parameters

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        # nnoww - implement
        try:
            installed = os.popen("dpkg -l | grep -E '^ii' | grep openvpn").read()
            dir_is_empty = exists('/etc/openvpn/server') and len(os.listdir('/etc/openvpn/server')) == 0
            if installed and not dir_is_empty:
                return

            os.system('mkdir -p /etc/openvpn/server')

            # copy the scripts to openvpn directory
            path = os.path.dirname(os.path.realpath(__file__))
            shutil.copyfile('{}/scripts/auth.py'.format(path), '/etc/openvpn/server/auth-script.py')
            shutil.copyfile('{}/scripts/up.py'.format(path), '/etc/openvpn/server/up-script.py')
            shutil.copyfile('{}/scripts/down.py'.format(path), '/etc/openvpn/server/down-script.py')
            shutil.copyfile('{}/scripts/client-connect.py'.format(path), '/etc/openvpn/server/client-connect.py')
            shutil.copyfile('{}/scripts/scripts_logger.py'.format(path), '/etc/openvpn/server/scripts_logger.py')
            shutil.copyfile('{}/scripts/script_utils.py'.format(path), '/etc/openvpn/server/script_utils.py')
            shutil.copyfile('{}/application_cfg.py'.format(path), '/etc/openvpn/server/application_cfg.py')

            distro = os.popen('lsb_release -cs').read().strip()
            try:
                fw_os_utils.run_linux_commands( [
                    'wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg|apt-key add -',
                    f'echo "deb http://build.openvpn.net/debian/openvpn/release/2.5 {distro} main" > /etc/apt/sources.list.d/openvpn-aptrepo.list',
                ])
            except Exception as e:
                self.log.error(f"failed to install from openvpn repo. trying another way: {str(e)}")
                fw_os_utils.run_linux_commands([
                    'wget -O - https://vpnrepo.flexiwan.com/debian/openvpn/release/2.5/pubkey.gpg | apt-key add -',
                    f'echo "deb https://vpnrepo.flexiwan.com/debian/openvpn/release/2.5/ {distro} main" > /etc/apt/sources.list.d/openvpn-aptrepo.list'
                ]
            )

            commands = [
                'apt install -y ca-certificates && apt-get update && apt-get install -y openvpn',

                'chmod +x /etc/openvpn/server/auth-script.py',
                'chmod +x /etc/openvpn/server/up-script.py',
                'chmod +x /etc/openvpn/server/down-script.py',
                'chmod +x /etc/openvpn/server/client-connect.py',
            ]
            fw_os_utils.run_linux_commands(commands)
            self.log.info(f'application installed successfully')

        except Exception as e:
            self.log.error(f"install(): {str(e)}")
            # call uninstall function to revert the installation
            self.uninstall()
            raise e

        # nnoww - implement
    def _openvpn_pid(self):
        return fw_os_utils.pid_of('openvpn')

    def configure(self, params):
        """Configure Open VPN server on host.

        :param params: params - open vpn parameters

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        # nnoww - add migration script to move remote-vpn to new naming convention!!!
        # nnoww - move to new naming convention inside "interfaces create" CLI
        # nnoww - add differentiation tun/tap to CLI !!!
        # nnoww - implement - recreate interface on watchdog
        # nnoww - test - basic test
        # nnoww - test - vpp watchdog test
        # nnoww - test - sync-device watchdog

        # nnoww - implement - add sw_if_index to both VPP and CLI !!!

        # nnoww - implement - use json as a parameters for CLI !!! - check with Shneor/Nir/etc if this is OK!!!

        cmd = f'fwagent configure router interfaces create --type lan --host_if_name vpp_appntop --dev_id app_com.flexiwan.ntop --no_vppsb'
        res = json.loads(subprocess.check_output(cmd, shell=True).decode())
        tap_vpp_if_name = res['tun_vpp_if_name']

        # nnoww - implement - add CLI wrapper for VPPAPI commands
        #                     Create ACL for example, that should not pass the 'fwagent/router_api' !!!

        # nnoww - implement - make ACL optional (in vpp)!!!
        # nnoww - implement - get rid "<tap|dpdk>" argument - deduce out of interface referenced by name!

        #cmd = f'vppctl fwapp app add ntop divert acl {index} interface tap app sw_if_index {sw_if_index}'
        cmd = f'vppctl fwapp app add ntop divert interface tap app {tap_vpp_if_name}'
        subprocess.check_call(cmd, shell=True)
        return (True,None)

    def uninstall(self, files_only=False):
        """Remove Open VPN server from host.

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        # nnoww - implement
        try:
            self.stop()

            commands = ['rm -rf /etc/openvpn/server/*']
            if not files_only:
                commands.append('apt-get remove -y openvpn')

            fw_os_utils.run_linux_commands(commands)

        except Exception as e:
            self.log.error(f"uninstall(): {str(e)}")
            raise e

    def on_router_is_started(self):
        # This hook should start the VPN server immediately after the VPP is begun.
        # If the VPN is already running for some reason,
        # we restart it to make sure our unique settings to mirror traffic into the VPP are applied.
        # nnoww - implement
        return self.start(restart=True)

    def on_router_is_stopped(self):
        # nnoww - implement
        return self.stop()

    def on_router_is_stopping(self):
        # nnoww - implement
        return self.stop()

    def start(self, restart=False):
        # don't start if vpp is down
        router_is_running = fw_os_utils.vpp_does_run()
        if not router_is_running:
            return
        # ttoww

        if self.is_app_running():
            if not restart:
                return
            self.log.info(f'start({restart}): restarting daemon')
            self.stop()

        self.log.info(f'daemon is being started')
        os.system(f'sudo openvpn --config {cfg["openvpn_server_conf_file"]} --daemon')

    def stop(self):
        # nnoww - implement
        # if self.is_app_running():
        #     killed = fw_os_utils.kill_process('openvpn')
        #     if killed:
        #         self.log.info(f'daemon is stopped')
        #         os.system(f'echo "" > {cfg["openvpn_status_file"]}')
        #     else:
        #         self.log.excep('stop(): failed to kill openvpn')
        return None

    def on_watchdog(self):
        # nnoww - implement
        # vpn_runs = self.is_app_running()
        # router_is_running = fw_os_utils.vpp_does_run()
        # if not vpn_runs and router_is_running:
        #     self.start()
        return None

    def is_app_running(self):
        # nnoww - implement
        return True if self._openvpn_pid() else False

    def get_log_filename(self):
        # nnoww - implement
        return cfg['openvpn_log_file']

    def get_interfaces(self, type='lan', vpp_interfaces=False, linux_interfaces=False):
        # nnoww - implement
        if type == 'wan':
            return []

        if not self.is_app_running():
            return []

        if not fw_os_utils.vpp_does_run():
            return []

        res = []
        if vpp_interfaces:
            with open(cfg['app_database_file'], 'r') as json_file:
                data = json.load(json_file)
                tun_vpp_if_name = data.get('tun_vpp_if_name')
                if tun_vpp_if_name:
                    res.append(tun_vpp_if_name)

        if linux_interfaces:
            res.append(cfg['openvpn_interface_name'])

        return res

    def get_statistics(self):
        # nnoww - implement
        # response = {
        #     'clients': {}
        # }

        # if not exists(cfg["openvpn_status_file"]):
        #     return response

        # try:
        #     with open(cfg["openvpn_status_file"], 'r') as logfile:
        #         status_lines = logfile.read().splitlines()

        #         # sometimes the log file contains one line with empty string
        #         if not status_lines or (len(status_lines) == 1 and status_lines[0] == ''):
        #             return response

        #         routing_table_idx = status_lines.index("ROUTING TABLE")
        #         global_stats_idx = status_lines.index("GLOBAL STATS")

        #         client_list = status_lines[:routing_table_idx]
        #         for line in client_list[3:]:
        #             # line = 'test@flexiwan.com ,192.168.1.1:57662,22206,13194,2021-12-22 11:57:33'
        #             fields = line.split(',')
        #             username = fields[0]
        #             real_addr = fields[1]
        #             key = username + real_addr
        #             response['clients'][key] = { # support multiple clients with same username
        #                 'Common Name': username,
        #                 'Real Address': real_addr,
        #                 'Bytes Received':  fields[2],
        #                 'Bytes Sent': fields[3],
        #                 'Connected Since': fields[4],
        #             }

        #         routing_table = status_lines[routing_table_idx:global_stats_idx]
        #         for line in routing_table[2:]:
        #             # line = '50.50.50.2,shneorp@flexiwan.com ,192.168.1.1:1052,2021-12-22 11:57:33'
        #             fields = line.split(',')
        #             username = fields[1]
        #             real_addr = fields[2]
        #             key = username + real_addr
        #             if key in response['clients']:
        #                 response['clients'][key]['Virtual Address'] = fields[0]

        #     return response
        # except Exception as e:
        #     self.log.error(f"get_statistics(): {str(e)}")
        #     return response
        return {}

    def get_fwdump_files(self):
        # nnoww - implement
        # return [
        #     cfg["openvpn_status_file"],
        #     cfg["openvpn_server_conf_file"],
        #     cfg["openvpn_scripts_log_file"],
        #     cfg["openvpn_log_file"],
        # ]
        return []

    def get_networks(self, for_bgp=False, for_ospf=False):
        networks = []
        with open(cfg['app_database_file'], 'r') as json_file:
            data = json.load(json_file)
            tun_vpp_if_addr = data.get('tun_vpp_if_addr')
            if tun_vpp_if_addr:
                networks.append(tun_vpp_if_addr)
        return networks
