#! /usr/bin/python3

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

import json
import os
import re
import shutil
import subprocess
import sys
import time
from os.path import exists

from netaddr import IPNetwork

this_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(this_dir)

from application_cfg import config as cfg

up_dir   = os.path.dirname(this_dir)
sys.path.append(up_dir)

import applications.fwapplication_utils as fwapplication_utils
from applications.fwapplication_interface import FwApplicationInterface

class Application(FwApplicationInterface):

    def install(self, params):
        """Install Remote VPN server on host.

        :param params - remote vpn parameters

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        try:
            # create open vpn directories
            os.system('mkdir -p /etc/openvpn/server')

            # check if openvpn is already installed
            installed = os.popen("dpkg -l | grep -E '^ii' | grep openvpn").read()

            if not installed:
                # copy the scripts to openvpn directory
                dir = os.path.dirname(os.path.realpath(__file__))
                shutil.copyfile('{}/scripts/auth.py'.format(dir), '/etc/openvpn/server/auth-script.py')
                shutil.copyfile('{}/scripts/up.py'.format(dir), '/etc/openvpn/server/up-script.py')
                shutil.copyfile('{}/scripts/down.py'.format(dir), '/etc/openvpn/server/down-script.py')
                shutil.copyfile('{}/scripts/client-connect.py'.format(dir), '/etc/openvpn/server/client-connect.py')
                shutil.copyfile('{}/scripts/scripts_logger.py'.format(dir), '/etc/openvpn/server/scripts_logger.py')
                shutil.copyfile('{}/scripts/script_utils.py'.format(dir), '/etc/openvpn/server/script_utils.py')
                shutil.copyfile('{}/application_cfg.py'.format(dir), '/etc/openvpn/server/application_cfg.py')

                commands = [
                    'wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg|apt-key add -',
                    'echo "deb http://build.openvpn.net/debian/openvpn/release/2.5 bionic main" > /etc/apt/sources.list.d/openvpn-aptrepo.list',
                    'apt-get update && apt-get install -y openvpn',

                    'chmod +x /etc/openvpn/server/auth-script.py',
                    'chmod +x /etc/openvpn/server/up-script.py',
                    'chmod +x /etc/openvpn/server/down-script.py',
                    'chmod +x /etc/openvpn/server/client-connect.py',
                ]
                fwapplication_utils.run_linux_commands(commands)
                self.log.info("remoteVPN installed successfully")

            return (True, None)
        except Exception as e:
            self.log.error(f"install(): {str(e)}")
            # call uninstall function to revert the installation
            self.uninstall()
            return (False, str(e))

    def _openvpn_pid(self):
        """Get pid of OpenVpn process.

        :returns:           process identifier.
        """
        try:
            pid = subprocess.check_output(['pidof', 'openvpn'])
        except:
            pid = None
        return pid

    def configure(self, params):
        """Configure Open VPN server on host.

        :param params: params - open vpn parameters

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        try:
            self.log.info(f"remote vpn configurations: {str(cfg)}")

            escaped_url = re.escape(params['vpnPortalServer'])

            commands = [
                'echo "%s" > /etc/openvpn/server/ca.crt' % params['caCrt'],
                'echo "%s" > /etc/openvpn/server/server.key' % params['serverKey'],
                'echo "%s" > /etc/openvpn/server/server.crt' % params['serverCrt'],
                'echo "%s" > /etc/openvpn/server/tc.key' % params['tlsKey'],
                'echo "%s" > /etc/openvpn/server/dh.pem' % params['dhKey'],

                'chmod 600 /etc/openvpn/server/server.key',

                "sed -i 's/__VPN_SERVER__/%s/g' /etc/openvpn/server/auth-script.py" % escaped_url
            ]

            fwapplication_utils.run_linux_commands(commands)

            success, err = self._configure_server_file(params)
            if not success:
                raise Exception(err)

            # if vpn already runs, restart it
            success, err = self.start(restart=True)
            if not success:
                raise Exception(err)

            return (True, None)
        except Exception as e:
            self.log.error(f"configure({params}): {str(e)}")
            return (False, str(e))

    def uninstall(self):
        """Remove Open VPN server from host.

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        try:
            self.stop()

            commands = [
                'apt-get remove -y openvpn',
                'rm -rf /etc/openvpn/server/*'
            ]
            fwapplication_utils.run_linux_commands(commands)

            return (True, None)
        except Exception as e:
            self.log.error(f"uninstall(): {str(e)}")
            return (False, str(e))

    def _configure_server_file(self, params):
        try:
            ip = IPNetwork(params['vpnNetwork'])

            commands = [
                # Which TCP/UDP port should OpenVPN listen on?
                f'port {params.get("port", "1194")}',

                # TCP or UDP server?
                'proto udp',

                # set dev (NIC) name
                f'dev {cfg["openvpn_interface_name"]}',

                # use dev tun
                'dev-type tun',

                # SSL/TLS root certificate
                'ca /etc/openvpn/server/ca.crt',
                'cert /etc/openvpn/server/server.crt',
                'key /etc/openvpn/server/server.key',

                # Diffie hellman parameters.
                'dh /etc/openvpn/server/dh.pem',

                # Select a cryptographic cipher.
                'auth SHA512',

                # The server and each client must have a copy of this key
                'tls-crypt /etc/openvpn/server/tc.key',

                # Network topology
                'topology subnet',

                # Log
                f'log {cfg["openvpn_log_file"]}',

                # Configure server mode and supply a VPN subnet
                # for OpenVPN to draw client addresses from.
                f'server {ip.ip} {ip.netmask}',

                # Limit server to a maximum of concurrent clients.
                f'max-clients {params.get("connections")}',

                'keepalive 10 120',

                # Select a cryptographic cipher.
                'data-ciphers AES-256-CBC',
                'cipher AES-256-CBC',

                # The persist options will try to avoid accessing certain resources on restart
                # that may no longer be accessible because of the privilege downgrade.
                'persist-key',
                'persist-tun',

                # Output a short status file showing current connections, truncated
                # and rewritten every minute.
                f'status {cfg["openvpn_status_file"]} 10',

                # Set the appropriate level of log file verbosity.
                'verb 3',

                # Require the client to provide a username/password for authentication.
                # OpenVPN will run this script to validate the username/password provided by the client.
                'auth-user-pass-verify /etc/openvpn/server/auth-script.py via-file',

                # Specify a directory dir for temporary files
                'tmp-dir /dev/shm',

                'script-security 2',

                # The client is required to supply a valid certificate
                'verify-client-cert require',

                # Use the authenticated username as the common name
                'username-as-common-name',

                # After successful user/password authentication, the OpenVPN server will generate tmp token valid for 12 hours
                # On the following renegotiations, the OpenVPN client will pass this token instead of the users password
                f'auth-gen-token {params.get("vpnTmpTokenTime", "43200")}',

                # Allow multiple clients with the same common name to concurrently connect
                'duplicate-cn',

                # OpenVPN will internally route client-to-client traffic rather than pushing all client-originating traffic to the TUN/TAP interface.
                'client-to-client',

                'explicit-exit-notify',

                # call these scripts once OpenVPN starts and stops
                'up /etc/openvpn/server/up-script.py',
                'down /etc/openvpn/server/down-script.py'
            ]

            # Split tunnel
            if params['routeAllTrafficOverVpn'] is True:
                # this directive will configure all clients to redirect their default
                # network gateway through the VPN
                commands.append('push \\"redirect-gateway def1 bypass-dhcp\\"')
            else:
                # we are using client-connect script only if we need to send ospf routes to the client dynamically
                commands.append('client-connect /etc/openvpn/server/client-connect.py')

            # DNS options
            for ip in params.get('dnsIps', []):
                commands.append(f'push \\"dhcp-option DNS {ip}\\"')

            for name in params.get('dnsDomains', []):
                commands.append(f'push \\"dhcp-option DOMAIN {name}\\"')

            # clean the config file
            os.system(f' > {cfg["openvpn_server_conf_file"]}')

            # run the commands
            for command in sorted(commands):
                ret = os.system(f'echo "{command}" >> {cfg["openvpn_server_conf_file"]}')
                if ret:
                    return (False, f'install: failed to run "{command}". error code is {ret}')

            self.log.info("remoteVPN server.conf configured successfully")

            return (True, None)
        except Exception as e:
            self.log.error(f"failed to configure remoteVPN server.conf. err={str(e)}")
            return (False, str(e))

    def on_router_is_started(self):
        # This hook should start the VPN server immediately after the VPP is begun.
        # If the VPN is already running for some reason,
        # we restart it to make sure our unique settings to mirror traffic into the VPP are applied.
        return self.start(restart=True)

    def on_router_is_stopped(self):
        return self.stop()

    def on_router_is_stopping(self):
        return self.stop()

    def start(self, restart=False):
        try:
            # don't start if vpp is down
            router_is_running = fwapplication_utils.router_is_running()
            if not router_is_running:
                return (True, None)

            # check if vpn is already running
            vpn_runs = True if self._openvpn_pid() else False
            if vpn_runs:
                if restart:
                    self.stop()
                else:
                    # no need to run it again
                    return (True, None)

            os.system(f'sudo openvpn --config {cfg["openvpn_server_conf_file"]} --daemon')

            # make sure openvpn started. Otherwise it means that it failed (we can find the reason in the log file)
            vpn_runs = True if self._openvpn_pid() else False
            if not vpn_runs:
                raise Exception('removeVPN failed to start')

            self.log.info("remoteVPN server is running")
            return (True, None)
        except Exception as e:
            self.log.error(f"start({restart}): {str(e)}")
            return (False, str(e))

    def stop(self):
        try:
            vpn_runs = True if self._openvpn_pid() else False
            if vpn_runs:
                os.system('sudo killall openvpn')
                time.sleep(5)  # 5 sec
                self.log.info("remoteVPN server is stopped")

            # cleanup static log file
            os.system(f'echo "" > {cfg["openvpn_status_file"]}')
            return (True, None)
        except Exception as e:
            self.log.error(f"stop(): {str(e)}")
            return (False, str(e))

    def on_watchdog(self):
        vpn_runs = True if self._openvpn_pid() else False
        router_is_running = fwapplication_utils.router_is_running()
        if not vpn_runs and router_is_running:
            self.start()

    def is_app_running(self):
        return True if self._openvpn_pid() else False

    def get_log_filename(self):
        return cfg['openvpn_log_file']

    def get_interfaces(self, type='lan', vpp_interfaces=False):
        vpn_runs = True if self._openvpn_pid() else False
        if not vpn_runs:
            return []

        if not fwapplication_utils.router_is_running():
            return []

        res = []
        if vpp_interfaces:
            with open(cfg['app_database_file'], 'r') as json_file:
                data = json.load(json_file)
                tun_vpp_if_name = data.get('tun_vpp_if_name')
                if tun_vpp_if_name:
                    res.append(tun_vpp_if_name)
        else:
            res.append(cfg['openvpn_interface_name'])

        return res

    def get_statistics(self):
        response = {
            'clients': {}
        }

        if not exists(cfg["openvpn_status_file"]):
            return response

        try:
            with open(cfg["openvpn_status_file"], 'r') as logfile:
                status_lines = logfile.read().splitlines()

                # sometimes the log file contains one line with empty string
                if not status_lines or (len(status_lines) == 1 and status_lines[0] == ''):
                    return response

                routing_table_idx = status_lines.index("ROUTING TABLE")
                global_stats_idx = status_lines.index("GLOBAL STATS")

                client_list = status_lines[:routing_table_idx]
                for line in client_list[3:]:
                    # line = 'test@flexiwan.com ,192.168.1.1:57662,22206,13194,2021-12-22 11:57:33'
                    fields = line.split(',')
                    username = fields[0]

                    response['clients'][username] = {
                        'Common Name': username,
                        'Real Address': fields[1],
                        'Bytes Received':  fields[2],
                        'Bytes Sent': fields[3],
                        'Connected Since': fields[4],
                    }

                routing_table = status_lines[routing_table_idx:global_stats_idx]
                for line in routing_table[2:]:
                    # line = '50.50.50.2,shneorp@flexiwan.com ,192.168.1.1:1052,2021-12-22 11:57:33'
                    fields = line.split(',')
                    username = fields[1]
                    if username in response['clients']:
                        response['clients'][username]['Virtual Address'] = fields[0]

            return response
        except Exception as e:
            self.log.error(f"get_statistics(): {str(e)}")
            return response

    def get_fwdump_files(self):
        return [
            cfg["openvpn_status_file"],
            cfg["openvpn_server_conf_file"],
            cfg["openvpn_scripts_log_file"],
            cfg["openvpn_log_file"],
        ]