#! /usr/bin/python

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2021  flexiWAN Ltd.
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
import shutil
import subprocess
import time
from netaddr import IPNetwork
import re

OPENVPN_LOG_FILE    = '/var/log/openvpn/openvpn.log'

def install(params):
    """Install Remote VPN server on host.

    :param params: params - remote vpn parameters:
        version - the version to be installed

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """

    try:
        os.system('mkdir -p /etc/openvpn/server')
        os.system('mkdir -p /etc/openvpn/client')

        installed = os.popen("dpkg -l | grep -E '^ii' | grep openvpn").read()
        if not installed:
            commands = [
                'wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg|apt-key add -',
                'echo "deb http://build.openvpn.net/debian/openvpn/release/2.5 bionic main" > /etc/apt/sources.list.d/openvpn-aptrepo.list',
                'apt-get update && apt-get install -y openvpn',
            ]

            for command in commands:
                ret = os.system(command)
                if ret:
                    return (False, f'install: failed to run "{command}". error code is {ret}')

            print("RemoteVPN installed successfully")
        else:
            # if vpn is running but a user wants to install it again, stop it
            # it will be started with the new config in the configure() function
            stop({})

        configParams = params.get('configParams')
        if not configParams:
            raise Exception('configParams is missing')

        res, err = configure(configParams)

        router_is_running = params.get('router_is_running')
        if router_is_running:
            res, err = start(configParams)

        return (res, err)   # 'True' stands for success, 'None' - for the returned object or error string.
    except Exception as e:
        # call uninstall function to clean the machine on installation error
        uninstall(params)
        return (False, str(e))

def _openvpn_pid():
    """Get pid of OpenVpn process.

    :returns:           process identifier.
    """
    try:
        pid = subprocess.check_output(['pidof', 'openvpn'])
    except:
        pid = None
    return pid

def _vpp_pid():
    """Get pid of VPP process.

    :returns:           process identifier.
    """
    try:
        pid = subprocess.check_output(['pidof', 'vpp'])
    except:
        pid = None
    return pid

def configure(params):
    """Configure Open VPN server on host.

    :param params: params - open vpn parameters:
        local - the dev id of interface to listen on
        vpnNetwork    -
        routeAllTrafficOverVpn    - false to use split tunnel

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    try:
        dir = os.path.dirname(os.path.realpath(__file__))
        shutil.copyfile('{}/scripts/auth.py'.format(dir), '/etc/openvpn/server/auth-script.py')
        shutil.copyfile('{}/scripts/up.py'.format(dir), '/etc/openvpn/server/up-script.py')
        shutil.copyfile('{}/scripts/down.py'.format(dir), '/etc/openvpn/server/down-script.py')
        shutil.copyfile('{}/scripts/client-connect.py'.format(dir), '/etc/openvpn/server/client-connect.py')

        # set global variable for VPN server - it will use by openvpn scripts
        escaped_url = re.escape(params['vpnPortalServer'])
        os.system("sed -i 's/__VPN_SERVER__/%s/g' /etc/openvpn/server/auth-script.py" % escaped_url)

        commands = [
            'chmod +x /etc/openvpn/server/auth-script.py',
            'chmod +x /etc/openvpn/server/up-script.py',
            'chmod +x /etc/openvpn/server/down-script.py',
            'chmod +x /etc/openvpn/server/client-connect.py',


            'echo "%s" > /etc/openvpn/server/ca.key' % params['caKey'],
            'echo "%s" > /etc/openvpn/server/ca.crt' % params['caCrt'],
            'echo "%s" > /etc/openvpn/server/server.key' % params['serverKey'],
            'echo "%s" > /etc/openvpn/server/server.crt' % params['serverCrt'],
            'echo "%s" > /etc/openvpn/server/tc.key' % params['tlsKey'],
            'echo "%s" > /etc/openvpn/server/dh.pem' % params['dhKey'],
        ]

        for command in commands:
            ret = os.system(command)
            if ret:
                return (False, f'install: failed to run "{command}". error code is {ret}')

        success, err = _configure_server_file(params)
        if not success:
            raise Exception(err)

        success, err = _configure_client_file(params)
        if not success:
            raise Exception(err)

        if _openvpn_pid():
            # restart vpn server after configurations changed
            start(params, restart=True)

        return (True, None)
    except Exception as e:
        return (False, str(e))

def uninstall(params):
    """Remove Open VPN server on host.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """

    stop({})

    commands = [
        'apt-get remove -y openvpn',
        'rm -rf /etc/openvpn/server/*',
        'rm -rf /etc/openvpn/client/*'
    ]

    try:
        for command in commands:
            ret = os.system(command)
            if ret:
                return (False, f'install: failed to run "{command}". error code is {ret}')
        return (True, None)
    except Exception as e:
        return (False, str(e))

def upgrade(params):
    return install(params)

def _configure_server_file(params):
    try:
        destFile = '/etc/openvpn/server/server.conf'
        ip = IPNetwork(params['vpnNetwork'])

        commands = [
            # Which local IP address should OpenVPN listen on
            # f'local {params.get("wanIp")}',

            # Which TCP/UDP port should OpenVPN listen on?
            f'port {params.get("serverPort", "1194")}',

            # TCP or UDP server?
            'proto udp',

            # set dev (NIC) name
            'dev t_remotevpn',

            # use dev tap
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
            f'log {OPENVPN_LOG_FILE}',

            # Configure server mode and supply a VPN subnet
            # for OpenVPN to draw client addresses from.
            f'server {ip.ip} {ip.netmask}',

            # Limit server to a maximum of concurrent clients.
            f'max-clients {params.get("connections")}',

            # Maintain a record of client <-> virtual IP address associations in this file
            'ifconfig-pool-persist /etc/openvpn/server/ipp.txt',

            'keepalive 10 120',

            # Select a cryptographic cipher.
            'data-ciphers AES-256-CBC',
            'cipher AES-256-CBC',

            #'echo "user nobody" >> %s' % destFile,
            #'echo "group nogroup" >> %s' % destFile,

            # The persist options will try to avoid ccessing certain resources on restart
            # that may no longer be accessible because of the privilege downgrade.
            'persist-key',
            'persist-tun',

            # Output a short status file showing current connections, truncated
            # and rewritten every minute.
            'status /etc/openvpn/server/openvpn-status.log 10',

            # Set the appropriate level of log file verbosity.
            'verb 3',

            # 'echo "plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /tmp/script.sh" >> %s' % destFile,
            'auth-user-pass-verify /etc/openvpn/server/auth-script.py via-file',
            'tmp-dir /dev/shm',
            'script-security 2',

            'verify-client-cert none',
            'client-config-dir /etc/openvpn/client',
            'username-as-common-name',
            'reneg-sec 43200',
            'duplicate-cn',
            'client-to-client',
            'explicit-exit-notify',
            'up /etc/openvpn/server/up-script.py',
            'down /etc/openvpn/server/down-script.py'
        ]

        # Split tunnel
        if params['routeAllTrafficOverVpn'] is True:
            # this directive will configure all clients to redirect their default
            # network gateway through the VPN
            commands.append('push \\"redirect-gateway def1 bypass-dhcp\\"')
        else:
            commands.append('client-connect /etc/openvpn/server/client-connect.py')

        # DNS options
        for ip in params.get('dnsIps', []):
            commands.append(f'push \\"dhcp-option DNS {ip}\\"')

        for name in params.get('dnsDomains', []):
            commands.append(f'push \\"dhcp-option DOMAIN {name}\\"')

        # clean the config file
        os.system(f' > {destFile}')

        # tun the commands
        for command in commands:
            ret = os.system(f'echo "{command}" >> {destFile}')
            if ret:
                return (False, f'install: failed to run "{command}". error code is {ret}')

        print("remoteVPN server.conf configured successfully")
        return (True, None)
    except Exception as e:
        print("Failed to configure remoteVPN server.conf")
        return (False, str(e))

def _configure_client_file(params):
    try:
        destFile = '/etc/openvpn/client/client.conf'

        commands = [
            ' > %s' % destFile,
            'echo "client" >> %s' % destFile,
            'echo "dev tap0" >> %s' % destFile,
            'echo "proto udp" >> %s' % destFile,
            # 'echo "remote %s" >> %s' % (params['wanIp'], destFile),
            'echo "resolv-retry infinite" >> %s' % destFile,
            'echo "auth-user-pass" >> %s' % destFile,
            'echo "nobind" >> %s' % destFile,
            'echo "persist-key" >> %s' % destFile,
            'echo "persist-tun" >> %s' % destFile,
            # 'echo "remote-cert-tls server" >> %s' % destFile,
            'echo "auth SHA512" >> %s' % destFile,
            'echo "cipher AES-256-CBC" >> %s' % destFile,
            'echo "ignore-unknown-option block-outside-dns" >> %s' % destFile,
            'echo "block-outside-dns" >> %s' % destFile,
            'echo "verb 3" >> %s' % destFile,
            'echo "tls-client" >> %s' % destFile,
            "echo '<ca>\n' >> %s" % destFile,
            'cat /etc/openvpn/server/ca.crt >> %s' % destFile,
            "echo '</ca>\n' >> %s" % destFile,
            "echo '<tls-crypt>' >> %s" % destFile,
            'cat /etc/openvpn/server/tc.key >> %s' % destFile,
            "echo '</tls-crypt>' >> %s" % destFile
        ]

        for command in commands:
            ret = os.system(command)
            if ret:
                return (False, f'install: failed to run "{command}". error code is {ret}')

        print("remoteVPN client.conf configured successfully")
        return (True, None)
    except Exception as e:
        print("Failed to configure remoteVPN client.conf")
        return (False, str(e))

def router_is_started(params):
    # This hook should start the VPN server immediately after the VPP is started.
    # If the VPN is already running for some reason,
    # we will restart it to make sure our unique settings to move traffic into the VPP are applied.
    return start(params, restart=True)

def router_is_stopped(params):
    return stop(params)

def router_is_being_to_stop(params):
    return stop(params)

def start(params, restart=False):
    try:
        # don't start if vpp is down
        router_is_running = True if _vpp_pid() else False
        if not router_is_running:
            return (True, None)

        # if vpn is already run, return true
        vpnIsRun = True if _openvpn_pid() else False
        if vpnIsRun:
            if not restart:
                return (True, None)
            else:
                stop({})

        os.system('sudo openvpn --config /etc/openvpn/server/server.conf --daemon')

        vpnIsRun = True if _openvpn_pid() else False
        if not vpnIsRun:
            raise Exception('removeVPN failed to start')

        print("remoteVPN server is running!")
        return (True, None)
    except Exception as e:
        return (False, str(e))

def stop(params):
    try:
        vpnIsRun = True if _openvpn_pid() else False
        if vpnIsRun:
            os.system('sudo killall openvpn')
            time.sleep(5)  # 5 sec
            print("remoteVPN server is stopped!")

        # cleanup static log file
        os.system('echo "" > /etc/openvpn/server/openvpn-status.log')
        return (True, None)
    except Exception as e:
        return (False, str(e))

def status(params):
    try:
        vpnIsRun = True if _openvpn_pid() else False
        return (True, vpnIsRun)
    except Exception as e:
        return (False, str(e))

def get_log_file(params):
    return (True, OPENVPN_LOG_FILE)

def get_monitoring(params):
    try:
        response = {
            'clients': {}
        }
        with open('/etc/openvpn/server/openvpn-status.log', 'r') as logfile:
            status = logfile.read().splitlines()
            routing_table_idx = status.index("ROUTING TABLE")
            global_stats_idx = status.index("GLOBAL STATS")

            client_list = status[:routing_table_idx]
            for line in client_list[3:]:
                # line = 'shneorp@flexiwan.com ,192.168.1.1:57662,22206,13194,2021-12-22 11:57:33'
                fields = line.split(',')
                username = fields[0]

                response['clients'][username] = {
                    'Common Name': username,
                    'Real Address': fields[1],
                    'Bytes Received':  fields[2],
                    'Bytes Sent': fields[3],
                    'Connected Since': fields[4],
                }

            routing_table = status[routing_table_idx:global_stats_idx]
            for line in routing_table[2:]:
                # line = '50.50.50.2,shneorp@flexiwan.com ,192.168.1.1:1052,2021-12-22 11:57:33'
                fields = line.split(',')
                username = fields[1]
                if username in response['clients']:
                    response['clients'][username]['Virtual Address'] = fields[0]

        return (True, response)
    except Exception as e:
        return (False, str(e))