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
import psutil
import socket
import threading
import time
import traceback

from sqlitedict import SqliteDict

import fwglobals
import fwnetplan
import fwutils

from fwobject import FwObject

class FwPppoeConnection(FwObject):
    """The object that represents PPPoE connection.
    It manages connection config files inside /etc/ppp/peers/ folder.
    Also it initiates PPPoE connections using pon/poff scripts.
    """
    def __init__(self, id, path, filename):
        FwObject.__init__(self)
        self.id = id
        self.path = path
        self.filename = filename + '-' + str(id)
        self.nic = ''
        self.user = ''
        self.mtu = 0
        self.mru = 0
        self.tun_vpp_if_name = ''
        self.ppp_if_name = 'ppp%u' % id
        self.addr = ''
        self.gw = ''
        self.if_index = -1
        self.dev_id = ''
        self.metric = 0
        self.usepeerdns = False
        self.connected = False
        self.opened = False

    def __str__(self):
        usepeerdns = ',usepeerdns' if self.usepeerdns else ''
        return f"{self.nic},{self.mtu},{self.mru},{self.user},{self.ppp_if_name},{self.addr},{self.gw}{usepeerdns}"

    def save(self):
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
                file.write('nic-%s' % self.nic + os.linesep)
                file.write('user %s' % self.user + os.linesep)
                file.write('ifname %s' % self.ppp_if_name + os.linesep)
                if self.usepeerdns:
                    file.write('usepeerdns' + os.linesep)

        except Exception as e:
            self.log.error("save: %s" % str(e))

    def scan(self):
        interfaces = psutil.net_if_addrs()
        if self.ppp_if_name in interfaces:
            connected = True
            self.addr = fwutils.get_interface_address(self.ppp_if_name, log=False)
            self.gw = interfaces[self.ppp_if_name][0].ptp
        else:
            self.addr = ''
            self.gw = ''
            connected = False

        if connected != self.connected:
            self.connected = connected
            router_started = fwutils.is_router_running()

            if connected:
                self.log.debug(f'pppoe connected: {self}, router_started: {router_started}')
                if router_started:
                    self.create_tun()
                    self.create_tc_mirror()
                self.add_linux_ip_route()
            else:
                self.log.debug(f'pppoe disconnected: {self}, router_started: {router_started}')
                if router_started:
                    self.remove_tun()
                    self.remove_tc_mirror()

        return self.connected

    def open(self):
        if self.opened:
            return

        os.system(f'ifconfig {self.nic} up')
        os.system('pon %s' % self.filename)
        self.opened = True

    def close(self):
        if not self.opened:
            return

        os.system('poff %s' % self.filename)
        self.clean_linux_ip()
        self.connected = False
        self.opened = False

    def remove(self):
            try:
                if os.path.exists(self.path + self.filename):
                    os.remove(self.path + self.filename)

            except Exception as e:
                self.log.error("remove: %s" % str(e))

    def create_tun(self):
        self.tun_vpp_if_name = 'tun%u' % self.id
        self.if_index = socket.if_nametoindex(self.ppp_if_name)
        cmds = []
        cmds.append('create tap id %u tun' % self.id)
        cmds.append('set interface state %s up' % self.tun_vpp_if_name)
        cmds.append('set interface ip address %s %s' % (self.tun_vpp_if_name, self.addr))
        cmds.append('tap-inject map tap %u %s' % (self.if_index, self.tun_vpp_if_name))
        fwutils.vpp_cli_execute(cmds, debug=True)
        fwglobals.g.cache.dev_id_to_vpp_if_name[self.dev_id] = self.tun_vpp_if_name
        fwglobals.g.cache.vpp_if_name_to_dev_id[self.tun_vpp_if_name] = self.dev_id

    def remove_tun(self):
        cmds = []
        cmds.append('tap-inject map tap %u %s del' % (self.if_index, self.tun_vpp_if_name))
        cmds.append('delete tap %s' % self.tun_vpp_if_name)
        fwutils.vpp_cli_execute(cmds, debug=True)
        del fwglobals.g.cache.dev_id_to_vpp_if_name[self.dev_id]
        del fwglobals.g.cache.vpp_if_name_to_dev_id[self.tun_vpp_if_name]
        self.if_index = -1

    def add_linux_ip_route(self):
        os.system(f'ip r add default via {self.gw} metric {self.metric} proto static')

    def clean_linux_ip(self):
        os.system(f'ifconfig {self.nic} down')

    def _tc_mirror_set(self, ifname_1, ifname_2, op):
        os.system('tc qdisc %s dev %s handle ffff: ingress' % (op, ifname_1))
        os.system('tc filter %s dev %s parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev %s' % (op, ifname_1, ifname_2))

    def create_tc_mirror(self):
        self._tc_mirror_set(self.tun_vpp_if_name, self.ppp_if_name, 'add')
        self._tc_mirror_set(self.ppp_if_name, self.tun_vpp_if_name, 'add')

    def remove_tc_mirror(self):
        self._tc_mirror_set(self.tun_vpp_if_name, self.ppp_if_name, 'del')
        self._tc_mirror_set(self.ppp_if_name, self.tun_vpp_if_name, 'del')

class FwPppoeConnections(dict):
    """The object that represents all PPPoE connections.
    """
    def __getitem__(self, item):
        return self[item]

    def __str__(self):
        contents = ''
        for key, item in self.items():
            contents += f'{key}: {item}; '
        return contents

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
        self._remove()

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
        try:
            if os.path.exists(self.path + self.filename):
                os.remove(self.path + self.filename)

        except Exception as e:
            self.log.error("remove: %s" % str(e))

    def clear(self):
        self.users.clear()

    def add_user(self, name, password):
        user = self.FwPppoeUser(name, password)
        self.users[user.get_name()] = user

    def remove_user(self, name):
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
    def __init__(self, user, password, mtu, mru, usepeerdns, metric, enabled):
        self.user = user
        self.password = password
        self.mtu = mtu
        self.mru = mru
        self.usepeerdns = usepeerdns
        self.metric = metric
        self.is_enabled = enabled
        self.is_connected = False
        self.addr = ''
        self.gw = ''
        self.tun_vpp_if_name = ''
        self.ppp_if_name = ''
        self.netplan = ''
        self.fname = ''

    def __str__(self):
        return f'user:{self.user}, password:{self.password}, mtu:{self.mtu}, mru:{self.mru}, usepeerdns:{self.usepeerdns}, metric:{self.metric}, enabled:{self.is_enabled}, connected:{self.is_connected}, addr:{self.addr}, gw:{self.gw}, tun:{self.tun_vpp_if_name}, ppp:{self.ppp_if_name}'

class FwPppoeClient(FwObject):
    """The object that represents PPPoE client.
    It is used as a high level API from Flexiagent and EdgeUI.
    It aggregates all the PPPoE client configuration and management.
    """
    def __init__(self, db_file, path, filename, standalone=True):
        FwObject.__init__(self)
        self.standalone = standalone
        self.thread_pppoec = None
        self.db_filename = db_file
        self.interfaces = SqliteDict(db_file, 'interfaces', autocommit=True)
        self.id = 0
        self.connections = FwPppoeConnections()
        self.path = path + 'peers/'
        self.filename = filename
        self.chap_config = FwPppoeSecretsConfig(path, 'chap-secrets')
        self.pap_config = FwPppoeSecretsConfig(path, 'pap-secrets')
        self._create_files()

    def initialize(self):
        if self.standalone:
            return

        self.stop()
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
        """Destructor method
        """
        self.interfaces.close()

        if self.thread_pppoec:
            self.thread_pppoec.join()
            self.thread_pppoec = None

    def _create_files(self):
        for dev_id, pppoe_iface in self.interfaces.items():
            self._add_user(pppoe_iface.user, pppoe_iface.password)

            if fwutils.is_router_running():
                if_name = fwutils.dev_id_to_tap(dev_id)
            else:
                if_name = fwutils.dev_id_to_linux_if(dev_id)

            conn = FwPppoeConnection(self.id, self.path, self.filename)
            self.id += 1
            conn.nic = if_name
            conn.dev_id = dev_id
            conn.nic = if_name
            conn.user = pppoe_iface.user
            conn.mtu = pppoe_iface.mtu
            conn.mru = pppoe_iface.mru
            conn.metric = pppoe_iface.metric
            conn.usepeerdns = pppoe_iface.usepeerdns
            self.connections[dev_id] = conn

    def _remove_files(self):
        self.stop()
        self.chap_config.clear()
        self.pap_config.clear()
        self.id = 0
        self.connections.clear()
        files = glob.glob(self.path + self.filename + '*')

        for fname in files:
            os.remove(fname)

    def stop(self, timeout = 120):
        for dev_id, conn in self.connections.items():
            conn.close()

        while timeout >= 0:
            pppd_id = fwutils.pid_of('pppd')
            if not pppd_id:
                return

            os.system('poff -a')
            timeout-= 1
            time.sleep(1)

        self.log.error(f'pppoe stop: timeout on waiting pppd to stop ({timeout} sec)')

    def _add_user(self, name, password):
        self.chap_config.add_user(name, password)
        self.pap_config.add_user(name, password)

    def _remove_user(self, name):
        self.chap_config.remove_user(name)
        self.pap_config.remove_user(name)

    def _save(self):
        self.chap_config.save()
        self.pap_config.save()
        for conn in self.connections.values():
            conn.save()

    def _restore_netplan(self):
        for dev_id, pppoe_iface in self.interfaces.items():
            if_name = fwutils.dev_id_to_linux_if(dev_id)
            pppoe_iface = self.interfaces[dev_id]
            if pppoe_iface.fname:
                fwnetplan.add_interface(if_name, pppoe_iface.fname, pppoe_iface.netplan)

    def clean(self):
        self._remove_files()
        self._restore_netplan()
        self.interfaces.clear()

    def get_interface(self, if_name = None, dev_id = None):
        if not dev_id:
            if if_name:
                dev_id = fwutils.get_interface_dev_id(if_name)
            else:
                self.log.error(f'get_interface: both dev_id and if_name are missing')
                return None
        return self.interfaces.get(dev_id)

    def is_pppoe_interface(self, if_name = None, dev_id = None):
        pppoe_if = self.get_interface(if_name, dev_id)
        return bool(pppoe_if)

    def add_interface(self, pppoe_iface, if_name = None, dev_id = None):
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

        fname, netplan = fwnetplan.remove_interface(if_name)
        if fname:
            pppoe_iface.fname = fname
            pppoe_iface.netplan = netplan

        self.interfaces[dev_id] = pppoe_iface
        self.reset_interfaces()

    def remove_interface(self, if_name = None, dev_id = None):
        if not dev_id and if_name:
            dev_id = fwutils.get_interface_dev_id(if_name)

        if_name = fwutils.dev_id_to_linux_if(dev_id)
        if not if_name:
            self.log.error(f'remove_interface: {dev_id} is missing on the device')
            return

        if dev_id in self.interfaces:
            pppoe_iface = self.interfaces[dev_id]
            if pppoe_iface.fname:
                fwnetplan.add_interface(if_name, pppoe_iface.fname, pppoe_iface.netplan)
            del self.interfaces[dev_id]
            self.reset_interfaces()

    def reset_interfaces(self):
        self._remove_files()
        self._create_files()
        self._save()
        self.start()

    def scan(self):
        for dev_id, conn in self.connections.items():
            connected = conn.scan()

            if dev_id not in self.interfaces:
                self.log.error(f'{dev_id} is missing in DB')
                continue

            pppoe_iface = self.interfaces[dev_id]
            pppoe_iface.is_connected = connected
            pppoe_iface.addr = conn.addr
            pppoe_iface.gw = conn.gw
            pppoe_iface.tun_vpp_if_name = conn.tun_vpp_if_name
            pppoe_iface.ppp_if_name = conn.ppp_if_name
            self.interfaces[dev_id] = pppoe_iface

    def start(self):
        for dev_id, conn in self.connections.items():
            pppoe_iface = self.get_interface(dev_id=dev_id)
            if (pppoe_iface.is_enabled):
                conn.open()

    def restart_interface(self, dev_id, timeout = 60):
        conn = self.connections.get(dev_id)
        if_name = fwutils.dev_id_to_tap(dev_id)
        conn.nic = if_name
        conn.save()
        conn.open()

        while timeout >= 0:
            conn.scan()
            if conn.connected:
                return (True, None)

            timeout-= 1
            time.sleep(1)

        return (False, f'PPPoE: {dev_id} is not connected')

    def pppoec_thread(self):
        """PPPoE client thread.
        Its function is to monitor state of interfaces with PPPoE.
        """
        while not fwglobals.g.teardown:
            time.sleep(1)

            try:  # Ensure thread doesn't exit on exception
                self.scan()
            except Exception as e:
                self.log.error("%s: %s (%s)" %
                    (threading.current_thread().getName(), str(e), traceback.format_exc()))
                pass

def pppoe_get_ppp_if_name(if_name):
    if hasattr(fwglobals.g, 'pppoe'):
        pppoe_iface = fwglobals.g.pppoe.get_interface(if_name=if_name)
    else:
        with FwPppoeClient(fwglobals.g.PPPOE_DB_FILE, fwglobals.g.PPPOE_CONFIG_PATH, fwglobals.g.PPPOE_CONFIG_PROVIDER_FILE) as pppoe:
            pppoe_iface = pppoe.get_interface(if_name=if_name)

    if pppoe_iface:
        return pppoe_iface.ppp_if_name
    else:
        return None
