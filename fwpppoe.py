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

import os
import psutil
import threading
import time
import traceback

from netaddr import IPNetwork
from sqlitedict import SqliteDict

import fwglobals
import fwnetplan
import fwutils
import fwroutes

from fwobject import FwObject

class FwPppoeConnection(FwObject):
    """The object that represents PPPoE connection.
    It manages connection config files inside /etc/ppp/peers/ folder.
    Also it initiates PPPoE connections using pon/poff scripts.
    """
    def __init__(self, id, dev_id, path, filename):
        FwObject.__init__(self)
        self.id = id
        self.path = path
        self.filename = filename + '-' + str(id)
        self.user = ''
        self.mtu = 0
        self.mru = 0
        self.addr = ''
        self.gw = ''
        self.dev_id = dev_id
        self.metric = 0
        self.usepeerdns = False
        self.tun_if_name = ''
        self.tun_vpp_if_name = ''
        self.tun_vppsb_if_name = ''
        self.opened = False
        self.linux_if_name = fwutils.dev_id_to_linux_if(self.dev_id)
        self.ppp_if_name = f'ppp-{self.linux_if_name}'
        self.if_name = self.linux_if_name

    def __str__(self):
        usepeerdns = 'usepeerdns' if self.usepeerdns else ''
        return f"{self.id}, {self.dev_id},{self.mtu},{self.mru},{self.user},{self.ppp_if_name},{self.addr},{self.gw},{usepeerdns},{self.tun_if_name},{self.opened}"

    def save(self):
        """Create PPPoE connection configuration file.
        """
        self.remove()
        try:
            with open(self.path + self.filename, 'w') as file:
                file.write('noipdefault' + os.linesep)
                file.write('lcp-echo-interval 20' + os.linesep)
                file.write('lcp-echo-failure 3' + os.linesep)
                file.write('hide-password' + os.linesep)
                file.write('connect /bin/true' + os.linesep)
                file.write('noauth' + os.linesep)
                file.write('persist' + os.linesep)
                file.write('noaccomp' + os.linesep)
                file.write('default-asyncmap' + os.linesep)
                file.write('plugin rp-pppoe.so' + os.linesep)
                file.write('mtu %u' % self.mtu + os.linesep)
                file.write('mru %u' % self.mru + os.linesep)
                file.write('nic-%s' % self.if_name + os.linesep)
                file.write('user %s' % self.user + os.linesep)
                file.write('ifname %s' % self.ppp_if_name + os.linesep)
                if self.usepeerdns:
                    file.write('usepeerdns' + os.linesep)

        except Exception as e:
            self.log.error("save: %s" % str(e))

    def scan_and_connect_if_needed(self, is_connected):
        """Check Linux interfaces if PPPoE tunnel (pppX) is created.
        """
        pppd_id = fwutils.pid_of('pppd')
        if not pppd_id and self.opened:
            self.open()

        interfaces = psutil.net_if_addrs()
        if self.ppp_if_name in interfaces:
            connected = True
            self.addr = fwutils.get_interface_address(self.ppp_if_name, log=False)
            self.gw = interfaces[self.ppp_if_name][0].ptp
        else:
            self.addr = ''
            self.gw = ''
            connected = False

        if connected != is_connected:
            if connected:
                self.log.debug(f'pppoe connected: {self}')
                self.add_linux_ip_route()
            else:
                self.log.debug(f'pppoe disconnected: {self}')
                if self.tun_if_name:
                    self.remove_linux_ip_route()

        return connected

    def open(self):
        """Open PPPoE connection.
        """
        sys_cmd = f'ip -4 addr flush label "{self.if_name}"'
        fwutils.os_system(sys_cmd, 'PPPoE open')

        sys_cmd = f'ip link set dev {self.if_name} up'
        fwutils.os_system(sys_cmd, 'PPPoE open')

        sys_cmd = 'pon %s' % self.filename
        fwutils.os_system(sys_cmd, 'PPPoE open')

        self.opened = True

    def close(self):
        """Close PPPoE connection.
        """
        pppd_id = fwutils.pid_of('pppd')
        if not pppd_id:
            return

        sys_cmd = 'poff %s' % self.filename
        fwutils.os_system(sys_cmd, 'PPPoE close')

        self.opened = False

    def remove(self):
        """Remove PPPoE connection configuration file.
        """
        try:
            if os.path.exists(self.path + self.filename):
                os.remove(self.path + self.filename)

        except Exception as e:
            self.log.error("remove: %s" % str(e))

    def create_tun(self):
        """Create TUN interface.
        """
        self.tun_if_name = 'pppoe%u' % self.id
        self.if_name = fwutils.dev_id_to_tap(self.dev_id)

        self.tun_vpp_if_name = fwutils.vpp_cli_execute_one(f'create tap host-if-name {self.tun_if_name} tun', debug=True)
        if not self.tun_vpp_if_name:
            self.log.error("create_tun: tun_vpp_if_name is empty")
            return False

        # Workaround to handle the following output.
        # '_______   _              _   _____  ___
        #  __/ __/ _ \\  (_)__    | | / / _ \\/  \\
        #  _/ _// // / / / _ \\   | |/ / ___/ ___/
        #  /_/ /____(_)_/\\___/   |___/_/  /_/
        #  tun0'
        self.tun_vpp_if_name = self.tun_vpp_if_name.split(' ')[-1]

        self.tun_vppsb_if_name = fwutils.vpp_if_name_to_tap(self.tun_vpp_if_name)
        if not self.tun_vppsb_if_name:
            self.log.error("create_tun: tun_vppsb_if_name is empty")
            return False

        fwglobals.g.cache.dev_id_to_vpp_if_name[self.dev_id] = self.tun_vpp_if_name
        fwglobals.g.cache.vpp_if_name_to_dev_id[self.tun_vpp_if_name] = self.dev_id

        return True

    def remove_tun(self):
        """Remove TUN interface.
        """
        if not self.tun_if_name:
            return

        if self.dev_id in fwglobals.g.cache.dev_id_to_vpp_if_name:
            del fwglobals.g.cache.dev_id_to_vpp_if_name[self.dev_id]
        if self.tun_vpp_if_name in fwglobals.g.cache.vpp_if_name_to_dev_id:
            del fwglobals.g.cache.vpp_if_name_to_dev_id[self.tun_vpp_if_name]

        fwutils.vpp_cli_execute([f'delete tap {self.tun_vpp_if_name}'], debug=True)
        self.tun_if_name = ''
        self.tun_vpp_if_name = ''
        self.tun_vppsb_if_name = ''
        self.if_name = self.linux_if_name

    def add_linux_ip_route(self):
        """Assign TUN interface with ip address.
           Create default route.
           Setup TC mirroring.
           Modify agent cache for dev_id to/from TUN conversion.
        """
        if self.tun_if_name:
            sys_cmd = f'ip link set dev {self.tun_vppsb_if_name} up'
            fwutils.os_system(sys_cmd, 'PPPoE add_linux_ip_route')

            self.create_tc_mirror()

            sys_cmd = f'ip addr add {self.addr} dev {self.tun_vppsb_if_name}'
            fwutils.os_system(sys_cmd, 'PPPoE add_linux_ip_route')

            address = IPNetwork(self.addr)
            success, err_str = fwroutes.add_remove_route('0.0.0.0/0', str(address.ip), self.metric, False, self.dev_id, 'static', self.tun_vppsb_if_name, False)
        else:
            success, err_str = fwroutes.add_remove_route('0.0.0.0/0', self.gw, self.metric, False, self.dev_id, 'static', self.ppp_if_name, False)
            if not success:
                self.log.error(f"add_linux_ip_route: failed to add route: {err_str}")

    def remove_linux_ip_route(self):
        """Remove ip address from TUN interface.
           Remove default route.
           Remove TC mirroring.
           Revert changes to agent cache.
        """
        self.remove_tc_mirror()

        success, err_str = fwroutes.add_remove_route('0.0.0.0/0', None, None, True, self.dev_id, 'static', self.tun_vppsb_if_name, False)
        if not success:
            self.log.error(f"remove_linux_ip_route: failed to remove route: {err_str}")

        sys_cmd = f'ip -4 addr flush label "{self.tun_vppsb_if_name}"'
        fwutils.os_system(sys_cmd, 'PPPoE remove_linux_ip_route')

        sys_cmd = f'ip link set dev {self.tun_vppsb_if_name} down'
        fwutils.os_system(sys_cmd, 'PPPoE remove_linux_ip_route')

    def _tc_mirror_set(self, ifname_1=None, ifname_2=None, op='add'):
        if ifname_1:
            sys_cmd = 'tc qdisc %s dev %s handle ffff: ingress' % (op, ifname_1)
            fwutils.os_system(sys_cmd, 'PPPoE _tc_mirror_set')

        if ifname_1 and ifname_2:
            sys_cmd = 'tc filter %s dev %s parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev %s pipe action drop' % (op, ifname_1, ifname_2)
            fwutils.os_system(sys_cmd, 'PPPoE _tc_mirror_set')

    def create_tc_mirror(self):
        """Setup TC mirroring.
        """
        self._tc_mirror_set(self.tun_if_name, self.ppp_if_name, 'add')
        self._tc_mirror_set(self.ppp_if_name, self.tun_if_name, 'add')

    def remove_tc_mirror(self):
        """Remove TC mirroring.
        """
        self._tc_mirror_set(self.tun_if_name, None, 'del')

class FwPppoeSecretsConfig(FwObject):
    """The object that represents PPPoE PAP/CHAP configuration file.
    It manages secrets config files inside /etc/ppp/ folder.
    """
    def __init__(self, path, filename):
        FwObject.__init__(self)
        self.path = path
        self.filename = filename
        self.users = {}

    def __str__(self):
        return f'{self.users}'

    def save(self):
        """Create PPPoE secrets configuration file.
        """
        pppoe_secrets_top =  """
        # Secrets for authentication
        # client	server	secret			IP addresses
        """

        if not self.users:
            return

        try:
            with open(self.path + self.filename, 'w') as file:
                file.write(pppoe_secrets_top)
                for user in self.users.values():
                    file.write(str(user) + os.linesep)

        except Exception as e:
            self.log.error("save: %s" % str(e))

    def _remove(self):
        """Remove PPPoE secrets configuration file.
        """
        try:
            if os.path.exists(self.path + self.filename):
                os.remove(self.path + self.filename)

        except Exception as e:
            self.log.error("remove: %s" % str(e))

    def clear(self):
        """Clean users from internal dictionary.
        """
        self._remove()
        self.users.clear()

    def add_user(self, name, password):
        """Add user to internal dictionary.
        """
        user = self.FwPppoeUser(name, password)
        self.users[user.get_name()] = user

    def remove_user(self, name):
        """Remove user from internal dictionary.
        """
        del self.users[name]

    class FwPppoeUser():
        """The object that represents PPPoE PAP/CHAP user.
        """
        def __init__(self, name='', password='', server='*', ip='XXX.XXX.XXX.XXX'):
            self.name = name
            self.server = server
            self.password = password
            self.ip = ip

        def __str__(self):
            return f'{self.name} {self.server} {self.password} {self.ip}'

        def get_name(self):
            return self.name

class FwPppoeInterface():
    """The object that represents PPPoE interface configuration.
    """
    def __init__(self, user, password, mtu, mru, usepeerdns, metric, enabled, nameservers=[]):
        self.user = user
        self.password = password
        self.mtu = mtu
        self.mru = mru
        self.usepeerdns = usepeerdns
        self.nameservers = nameservers
        self.metric = metric
        self.is_enabled = enabled
        self.is_connected = False
        self.addr = ''
        self.gw = ''
        self.netplan_section = ''
        self.netplan_fname = ''

    def __str__(self):
        return f'user:{self.user}, password:{self.password}, mtu:{self.mtu}, mru:{self.mru}, usepeerdns:{self.usepeerdns}, nameservers: {self.nameservers}, metric:{self.metric}, enabled:{self.is_enabled}, connected:{self.is_connected}, addr:{self.addr}, gw:{self.gw}'

class FwPppoeClient(FwObject):
    """The object that represents PPPoE client.
    It is used as a high level API from Flexiagent and EdgeUI.
    It aggregates all the PPPoE client configuration and management.
    """
    def __init__(self, db_file=None, path=None, filename=None, standalone=True):
        FwObject.__init__(self)
        db_file = db_file if db_file else fwglobals.g.PPPOE_DB_FILE
        self.filename = filename if filename else fwglobals.g.PPPOE_CONFIG_PROVIDER_FILE
        path = path if path else fwglobals.g.PPPOE_CONFIG_PATH
        self.path = path + 'peers/'
        self.standalone = standalone
        self.thread_pppoec = None
        self.interfaces = SqliteDict(db_file, 'interfaces', autocommit=True)
        self.connections = SqliteDict(db_file, 'connections', autocommit=True)
        self.chap_config = FwPppoeSecretsConfig(path, 'chap-secrets')
        self.pap_config = FwPppoeSecretsConfig(path, 'pap-secrets')
        self._populate_users()

    def initialize(self):
        """Start all PPPoE connections and PPPoE thread if not standalone.
        """
        if self.standalone:
            return

        # before the installation make sure that tap and tc modules are enabled
        fwutils.load_linux_tap_modules()
        fwutils.load_linux_tc_modules()
        fwutils.load_linux_modules(['pppoe'])

        self.scan()
        self.start()

        self.thread_pppoec = threading.Thread(target=self.pppoec_thread, name='PPPOE Client Thread')
        self.thread_pppoec.start()
        self.log.debug('PPPoE thread started')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.finalize()

    def finalize(self):
        """Stop all PPPoE connections and PPPoE thread if not standalone.
           Also close SQLDict databases.
        """
        if self.thread_pppoec:
            self.thread_pppoec.join()
            self.thread_pppoec = None

        if not self.standalone:
            self.stop()

        self.interfaces.close()
        self.interfaces = None
        self.connections.close()
        self.connections = None

    def _populate_users(self):
        """Populate PPPoE users
        """
        for pppoe_iface in self.interfaces.values():
            self._add_user(pppoe_iface.user, pppoe_iface.password)

    def _generate_connection_id(self):
        """Generate connection id
        """
        id = 0
        if not self.connections:
            return id

        for conn in self.connections.values():
            if id < conn.id:
                break
            id += 1

        return id

    def _add_connection(self, dev_id, pppoe_iface):
        """Create connection
        """
        conn = self.connections.get(dev_id)
        if not conn:
            id = self._generate_connection_id()
            conn = FwPppoeConnection(id, dev_id, self.path, self.filename)

        conn.user = pppoe_iface.user
        conn.mtu = pppoe_iface.mtu
        conn.mru = pppoe_iface.mru
        conn.metric = pppoe_iface.metric
        conn.usepeerdns = pppoe_iface.usepeerdns
        self.connections[dev_id] = conn

    def _remove_connection(self, dev_id):
        """Remove connection
        """
        self.connections[dev_id].close()
        self.connections[dev_id].remove()
        del self.connections[dev_id]

    def _remove_files(self):
        """Clean up PPPoE connections database and configuration files.
        """
        self.stop()
        self.chap_config.clear()
        self.pap_config.clear()

        for conn in self.connections.values():
            conn.remove()

    def stop(self, timeout = 120):
        """Stop all PPPoE connections.
        """
        pppd_id = fwutils.pid_of('pppd')
        if not pppd_id:
            return

        for dev_id in self.interfaces.keys():
            self.stop_interface(dev_id)

        while timeout >= 0:
            pppd_id = fwutils.pid_of('pppd')
            if not pppd_id:
                self.scan()
                return

            sys_cmd = 'poff -a'
            fwutils.os_system(sys_cmd, 'PPPoE stop')
            timeout-= 1
            time.sleep(1)

        self.log.error(f'pppoe stop: timeout on waiting pppd to stop ({timeout} sec)')

    def _add_user(self, name, password):
        self.chap_config.add_user(name, password)
        self.pap_config.add_user(name, password)

    def _remove_user(self, name):
        self.chap_config.remove_user(name)
        self.pap_config.remove_user(name)

    def _serialize_users_connections(self):
        """Create secrets and connections configuration files.
        """
        self.chap_config.save()
        self.pap_config.save()
        for dev_id, conn in self.connections.items():
            conn.save()
            self.connections[dev_id] = conn

    def _update_resolv_conf(self):
        """Re-creates /etc/resolv.conf
        """
        usepeerdns = False
        nameservers = []

        for pppoe_iface in self.interfaces.values():
            usepeerdns |= pppoe_iface.usepeerdns
            if not pppoe_iface.usepeerdns:
                nameservers.extend(pppoe_iface.nameservers)

        fwutils.restart_service(service='systemd-resolved', timeout=5)

        try:
            with open(fwglobals.g.PPPOE_DNS_CONFIG_PATH, "r") as file:
                ppp_resolv_conf_data = file.read()

            with open(fwglobals.g.DNS_CONFIG_PATH, "r") as file:
                resolv_conf_data = file.read()

            with open(fwglobals.g.DNS_CONFIG_PATH, 'w') as file:
                if usepeerdns:
                    file.write(ppp_resolv_conf_data)

                for nameserver in nameservers:
                    file.write(f'nameserver {nameserver}{os.linesep}')

                file.write(resolv_conf_data)

        except IOError as error:
            self.log.error(f'save: {error.strerror}')

    def _restore_netplan(self):
        """Restore Netplan by adding PPPoE interfaces back.
        """
        for dev_id, pppoe_iface in self.interfaces.items():
            if_name = fwutils.dev_id_to_linux_if(dev_id)
            pppoe_iface = self.interfaces[dev_id]
            if pppoe_iface.netplan_fname and os.path.exists(pppoe_iface.netplan_fname):
                fwnetplan.add_interface(if_name, pppoe_iface.netplan_fname, pppoe_iface.netplan_section)

    def clean(self):
        """Remove PPPoE configuration files and restore Netplan file.
        """
        if not self.is_pppoe_configured():
            return

        self._remove_files()
        self._restore_netplan()
        self.interfaces.clear()
        self.connections.clear()

    def get_interface(self, if_name = None, dev_id = None):
        """Get interface from database.
        """
        if not self.interfaces:
            return None

        if not dev_id:
            if if_name:
                dev_id = fwutils.get_interface_dev_id(if_name)
            else:
                self.log.error(f'get_interface: both dev_id and if_name are missing')
                return None
        return self.interfaces.get(dev_id)

    def is_pppoe_interface(self, if_name = None, dev_id = None):
        """Check if interface is present in database.
        """
        pppoe_if = self.get_interface(if_name, dev_id)
        if pppoe_if:
            return True

        return False

    def add_interface(self, pppoe_iface, if_name = None, dev_id = None):
        """Add interface into database.
        """
        if not dev_id:
            if if_name:
                dev_id = fwutils.get_interface_dev_id(if_name)
            else:
                self.log.error(f'add_interface: both dev_id and if_name are missing')
                return

        if_name = fwutils.dev_id_to_linux_if(dev_id)
        if not if_name:
            self.log.error(f'add_interface: {dev_id} is missing on the device')
            return

        netplan_fname = fwnetplan.check_interface_exist(if_name)
        if netplan_fname:
            fwnetplan.create_baseline_if_not_exist(netplan_fname)

            netplan_fname, netplan_section = fwnetplan.remove_interface(if_name)
            if netplan_fname:
                pppoe_iface.netplan_fname = netplan_fname
                pppoe_iface.netplan_section = netplan_section

        self.interfaces[dev_id] = pppoe_iface
        self._add_connection(dev_id, pppoe_iface)
        self.reset_interfaces()
        self.start()

    def remove_interface(self, if_name = None, dev_id = None):
        """Remove interface from database.
        """
        if not dev_id and if_name:
            dev_id = fwutils.get_interface_dev_id(if_name)

        if_name = fwutils.dev_id_to_linux_if(dev_id)
        if not if_name:
            self.log.error(f'remove_interface: {dev_id} is missing on the device')
            return

        if dev_id in self.interfaces:
            pppoe_iface = self.interfaces[dev_id]
            netplan_fname = pppoe_iface.netplan_fname
            netplan_section = pppoe_iface.netplan_section
            del self.interfaces[dev_id]
            self._remove_connection(dev_id)
            self.reset_interfaces()
            self.start()
            if pppoe_iface.netplan_fname:
                fwnetplan.add_interface(if_name, netplan_fname, netplan_section)

    def reset_interfaces(self):
        """Re-create PPPoE connection files based on interface DB.
        """
        if not self.is_pppoe_configured():
            return

        self._remove_files()
        self._populate_users()
        self._serialize_users_connections()

    def is_pppoe_configured(self):
        """Check if any PPPoE interface is configured.
        """
        return bool(self.interfaces)

    def scan_interface(self, dev_id, conn):
        """Scan one interface for established PPPoE connection.
        """
        pppoe_iface = self.interfaces.get(dev_id)
        if not pppoe_iface:
            return

        connected = conn.scan_and_connect_if_needed(pppoe_iface.is_connected)

        if pppoe_iface.is_connected != connected:
            pppoe_iface.is_connected = connected
            pppoe_iface.addr = conn.addr
            pppoe_iface.gw = conn.gw
            self.interfaces[dev_id] = pppoe_iface
            self.connections[dev_id] = conn

            if fwglobals.g.fwagent:
                fwglobals.g.fwagent.reconnect()

            self._update_resolv_conf()

        return connected

    def scan(self):
        """Scan all interfaces for established PPPoE connection.
        """
        if not self.connections:
            return

        for dev_id, conn in self.connections.items():
            self.scan_interface(dev_id, conn)

    def start(self):
        """Open connections for all PPPoE interfaces.
        """
        for dev_id, conn in self.connections.items():
            pppoe_iface = self.get_interface(dev_id=dev_id)
            if (pppoe_iface and pppoe_iface.is_enabled and not pppoe_iface.is_connected):
                conn.open()
                self.connections[dev_id] = conn

    def restart_interface(self, dev_id, timeout = 60):
        """This API is called on VPP router start.
           Change value from nic-ethX into nic-vppX in PPPoE configuration file.
           Start PPPoE connection and wait until it is established.
        """
        conn = self.connections.get(dev_id)
        rc = conn.create_tun()
        if not rc:
            return (False, f'PPPoE: {dev_id} TUN was not created')
        conn.save()
        conn.open()
        self.connections[dev_id] = conn

        while timeout >= 0:
            connected = self.scan_interface(dev_id, conn)
            if connected:
                return (True, None)

            timeout-= 1
            time.sleep(1)

        return (False, f'PPPoE: {dev_id} is not connected')

    def stop_interface(self, dev_id):
        """Close PPPoE connection.
           Remove TUN interface if VPP is running.
        """
        conn = self.connections.get(dev_id)
        pppoe_iface = self.interfaces.get(dev_id)

        if conn:
            conn.close()
            conn.remove_tun()
            self.connections[dev_id] = conn
            conn.save()
            pppoe_iface.is_connected = False
            self.interfaces[dev_id] = pppoe_iface

        return (True, None)

    def pppoec_thread(self):
        """PPPoE client thread.
        Its function is to monitor state of interfaces with PPPoE.
        """
        while not fwglobals.g.teardown:
            time.sleep(1)

            try:  # Ensure thread doesn't exit on exception
                if not fwglobals.g.router_api.state_is_starting_stopping():
                    self.scan()
            except Exception as e:
                self.log.error("%s: %s (%s)" %
                    (threading.current_thread().getName(), str(e), traceback.format_exc()))
                pass

    def get_dev_id_from_ppp_if_name(self, ppp_if_name):
        if not self.connections:
            return None

        for dev_id, conn in self.connections.items():
            if conn.ppp_if_name == ppp_if_name:
                return dev_id
        return None

    def get_ppp_if_name_from_if_name(self, if_name):
        if not self.connections:
            return ''

        dev_id = fwutils.get_interface_dev_id(if_name)
        conn = self.connections.get(dev_id)
        return conn.ppp_if_name

    def build_dev_id_to_vpp_if_name_map(self):
        dev_id_vpp_if_name = {}

        for dev_id, conn in self.connections.items():
            if conn.addr:
                dev_id_vpp_if_name[dev_id] = conn.tun_vpp_if_name

        return dev_id_vpp_if_name

def pppoe_get_ppp_if_name(if_name):
    if fwglobals.g.pppoe:
        return fwglobals.g.pppoe.get_ppp_if_name_from_if_name(if_name)
    else:
        with FwPppoeClient() as pppoe:
            return pppoe.get_ppp_if_name_from_if_name(if_name)

def pppoe_get_dev_id_from_ppp(ppp_if_name):
    if fwglobals.g.pppoe:
        return fwglobals.g.pppoe.get_dev_id_from_ppp_if_name(ppp_if_name)
    else:
        with FwPppoeClient() as pppoe:
            return pppoe.get_dev_id_from_ppp_if_name(ppp_if_name)

def is_pppoe_interface(if_name = None, dev_id = None):
    """Check if interface has PPPoE configuration.
    """
    if fwglobals.g.pppoe:
        return fwglobals.g.pppoe.is_pppoe_interface(if_name, dev_id)
    else:
        with FwPppoeClient() as pppoe:
            return pppoe.is_pppoe_interface(if_name, dev_id)

def pppoe_remove():
    """Remove PPPoE configuration files and clean internal DB
    """
    with FwPppoeClient() as pppoe_client:
        pppoe_client.clean()

def is_pppoe_configured():
    """Check if PPPoE is configured
    """
    with FwPppoeClient() as pppoe_client:
        return pppoe_client.is_pppoe_configured()

def pppoe_reset():
    """Reset PPPoE configuration files
    """
    with FwPppoeClient() as pppoe_client:
        pppoe_client.reset_interfaces()

def build_dev_id_to_vpp_if_name_map():
    """Get PPPoE connections.
    """
    if fwglobals.g.pppoe:
        return fwglobals.g.pppoe.build_dev_id_to_vpp_if_name_map()
    else:
        with FwPppoeClient() as pppoe:
            return pppoe.build_dev_id_to_vpp_if_name_map()
