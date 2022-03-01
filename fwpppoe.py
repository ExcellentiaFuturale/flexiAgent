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

from netaddr import IPNetwork
from sqlitedict import SqliteDict

import fwglobals
import fwnetplan
import fwutils

from fwobject import FwObject

class FwPppoePeerFile(FwObject):
    """The object that represents peer configuration file.
    """
    def __init__(self, id, path, filename, dev_id, pppoe_iface):
        FwObject.__init__(self)
        self.id = id
        self.path = path
        self.filename = filename + '-' + str(id)
        self.user = pppoe_iface.user
        self.mtu = pppoe_iface.mtu
        self.mru = pppoe_iface.mru
        self.ppp_if_name = 'ppp%u' % id
        self.dev_id = dev_id
        self.usepeerdns = pppoe_iface.usepeerdns

    def __str__(self):
        usepeerdns = ',usepeerdns' if self.usepeerdns else ''
        return f"{self.dev_id},{self.mtu},{self.mru},{self.user},{self.ppp_if_name},{usepeerdns}"

    def save(self):
        self.remove()
        try:
            ifname = fwutils.dev_id_to_tap(self.dev_id) if fwutils.is_router_running() \
                     else fwutils.dev_id_to_linux_if(self.dev_id)

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
                file.write('nic-%s' % ifname + os.linesep)
                file.write('user %s' % self.user + os.linesep)
                file.write('ifname %s' % self.ppp_if_name + os.linesep)
                if self.usepeerdns:
                    file.write('usepeerdns' + os.linesep)

        except Exception as e:
            self.log.error("save: %s" % str(e))

    def remove(self):
            try:
                if os.path.exists(self.path + self.filename):
                    os.remove(self.path + self.filename)

            except Exception as e:
                self.log.error("remove: %s" % str(e))

class FwPppoeConnection(FwObject):
    """The object that represents PPPoE connection.
    It manages connection config files inside /etc/ppp/peers/ folder.
    Also it initiates PPPoE connections using pon/poff scripts.
    """
    def __init__(self, id, filename, dev_id, metric):
        FwObject.__init__(self)
        self.id = id
        self.filename = filename + '-' + str(id)
        self.tun_vppsb_if_name = ''
        self.tun_vpp_if_name = ''
        self.tun_if_name = ''
        self.ppp_if_name = 'ppp%u' % id
        self.addr = ''
        self.gw = ''
        self.dev_id = dev_id
        self.metric = metric
        self.connected = False
        self.opened = False

    def __str__(self):
        return f"{self.dev_id},{self.ppp_if_name},{self.addr},{self.gw},{self.metric}"

    def scan(self):
        connected = False
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

        ifname = fwutils.dev_id_to_tap(self.dev_id) if fwutils.is_router_running() \
                 else fwutils.dev_id_to_linux_if(self.dev_id)

        sys_cmd = f'ip link set dev {ifname} up'
        fwutils.os_system(sys_cmd, 'PPPoE open')

        sys_cmd = 'pon %s' % self.filename
        fwutils.os_system(sys_cmd, 'PPPoE open')
        self.opened = True

    def close(self):
        if not self.opened:
            return

        sys_cmd = 'poff %s' % self.filename
        fwutils.os_system(sys_cmd, 'PPPoE close')
        self.clean_linux_ip()
        self.connected = False
        self.opened = False

    def create_tun(self):
        self.tun_vpp_if_name = 'tun%u' % self.id
        self.tun_vppsb_if_name = 'vpp_tun%u' % self.id
        self.tun_if_name = 'pppoe%u' % self.id
        fwutils.vpp_cli_execute([f'create tap host-if-name {self.tun_if_name} tun'], debug=True)
        sys_cmd = f'ip addr add {self.addr} dev {self.tun_vppsb_if_name}'
        fwutils.os_system(sys_cmd, 'PPPoE create_tun')
        sys_cmd = f'ip link set dev {self.tun_vppsb_if_name} up'
        fwutils.os_system(sys_cmd, 'PPPoE create_tun')
        fwglobals.g.cache.dev_id_to_vpp_if_name[self.dev_id] = self.tun_vpp_if_name
        fwglobals.g.cache.vpp_if_name_to_dev_id[self.tun_vpp_if_name] = self.dev_id

    def remove_tun(self):
        cmds = []
        cmds.append('delete tap %s' % self.tun_vpp_if_name)
        fwutils.vpp_cli_execute(cmds, debug=True)
        del fwglobals.g.cache.dev_id_to_vpp_if_name[self.dev_id]
        del fwglobals.g.cache.vpp_if_name_to_dev_id[self.tun_vpp_if_name]

    def add_linux_ip_route(self):
        if fwutils.is_router_running():
            address = IPNetwork(self.addr)
            sys_cmd = f'ip r add default via {address.ip} dev {self.tun_vppsb_if_name} metric {self.metric} proto static'
        else:
            sys_cmd = f'ip r add default via {self.gw} metric {self.metric} proto static'
        fwutils.os_system(sys_cmd, 'PPPoE add_linux_ip_route')

    def clean_linux_ip(self):
        ifname = fwutils.dev_id_to_tap(self.dev_id) if fwutils.is_router_running() \
                 else fwutils.dev_id_to_linux_if(self.dev_id)
        sys_cmd = f'ip link set dev {ifname} down'
        fwutils.os_system(sys_cmd, 'PPPoE clean_linux_ip')

    def _tc_mirror_set(self, ifname_1, ifname_2, op):
        sys_cmd = 'tc qdisc %s dev %s handle ffff: ingress' % (op, ifname_1)
        fwutils.os_system(sys_cmd, 'PPPoE _tc_mirror_set')
        sys_cmd = 'tc filter %s dev %s parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev %s pipe action drop' % (op, ifname_1, ifname_2)
        fwutils.os_system(sys_cmd, 'PPPoE _tc_mirror_set')

    def create_tc_mirror(self):
        self._tc_mirror_set(self.tun_if_name, self.ppp_if_name, 'add')
        self._tc_mirror_set(self.ppp_if_name, self.tun_if_name, 'add')

    def remove_tc_mirror(self):
        self._tc_mirror_set(self.tun_if_name, self.ppp_if_name, 'del')
        self._tc_mirror_set(self.ppp_if_name, self.tun_if_name, 'del')

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
        self.netplan = ''
        self.fname = ''
        self.conn = None

    def __str__(self):
        return f'user:{self.user}, password:{self.password}, mtu:{self.mtu}, mru:{self.mru}, usepeerdns:{self.usepeerdns}, metric:{self.metric}, enabled:{self.is_enabled}'

    def scan(self):
        connected = self.conn.scan()
        if connected != self.conn.connected:
            return True
        return False

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
        self.path = path + 'peers/'
        self.filename = filename
        self.chap_config = FwPppoeSecretsConfig(path, 'chap-secrets')
        self.pap_config = FwPppoeSecretsConfig(path, 'pap-secrets')
        self.peers_configs = {}
        self._fill_collections()

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

    def _create_connection(self, dev_id, pppoe_iface):
        conn = FwPppoeConnection(self.id, self.filename, dev_id, pppoe_iface.metric)
        self.id += 1
        pppoe_iface.conn = conn

    def _fill_collections(self):
        for dev_id, pppoe_iface in self.interfaces.items():
            self._add_user(pppoe_iface.user, pppoe_iface.password)
            self.peers_configs[dev_id] = FwPppoePeerFile(self.id, self.path, self.filename, dev_id, pppoe_iface)
            self._create_connection(dev_id, pppoe_iface)
            self.interfaces[dev_id] = pppoe_iface

    def _remove_files(self):
        self.stop()
        self.chap_config.clear()
        self.pap_config.clear()
        self.peers_configs.clear()
        self.id = 0
        files = glob.glob(self.path + self.filename + '*')

        for fname in files:
            os.remove(fname)

    def stop(self, timeout = 120):
        for dev_id, pppoe_iface in self.interfaces.items():
            if pppoe_iface.conn:
                pppoe_iface.conn.close()
                self.interfaces[dev_id] = pppoe_iface

        while timeout >= 0:
            pppd_id = fwutils.pid_of('pppd')
            if not pppd_id:
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

    def _save(self):
        self.chap_config.save()
        self.pap_config.save()
        for dev_id, pppoe_iface in self.interfaces.items():
            self.peers_configs[dev_id].save()

    def _restore_netplan(self):
        for dev_id, pppoe_iface in self.interfaces.items():
            if_name = fwutils.dev_id_to_linux_if(dev_id)
            pppoe_iface = self.interfaces[dev_id]
            if pppoe_iface.fname:
                fwnetplan.add_interface(if_name, pppoe_iface.fname, pppoe_iface.netplan)

    def clean(self):
        if not self.is_pppoe_configured():
            return

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
        self._fill_collections()
        self._save()
        self.start()

    def is_pppoe_configured(self):
        return bool(self.interfaces)

    def scan(self):
        for dev_id, pppoe_iface in self.interfaces.items():
            changed = pppoe_iface.scan()
            if changed:
                self.interfaces[dev_id] = pppoe_iface

    def start(self):
        for dev_id, pppoe_iface in self.interfaces.items():
            if pppoe_iface.is_enabled:
                pppoe_iface.conn.open()
                self.interfaces[dev_id] = pppoe_iface

    def restart_interface(self, dev_id, timeout = 60):
        pppoe_iface = self.interfaces.get(dev_id)
        self.interfaces[dev_id] = pppoe_iface
        self.peers_configs[dev_id].save()
        pppoe_iface.conn.open()
        self.interfaces[dev_id] = pppoe_iface

        while timeout >= 0:
            changed = pppoe_iface.scan()
            if changed:
                self.interfaces[dev_id] = pppoe_iface
            if pppoe_iface.conn.connected:
                return (True, None)

            timeout-= 1
            time.sleep(1)

        return (False, f'PPPoE: {dev_id} is not connected')

    def stop_interface(self, dev_id):
        pppoe_iface = self.interfaces.get(dev_id)
        pppoe_iface.conn.close()
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

    def pppoe_get_dev_id_from_ppp(self, ppp_if_name):
        for dev_id, pppoe_iface in self.interfaces.items():
            if pppoe_iface.conn.ppp_if_name == ppp_if_name:
                return dev_id

def pppoe_get_ppp_if_name(if_name):
    if hasattr(fwglobals.g, 'pppoe'):
        pppoe_iface = fwglobals.g.pppoe.get_interface(if_name=if_name)
    else:
        with FwPppoeClient(fwglobals.g.PPPOE_DB_FILE, fwglobals.g.PPPOE_CONFIG_PATH, fwglobals.g.PPPOE_CONFIG_PROVIDER_FILE) as pppoe:
            pppoe_iface = pppoe.get_interface(if_name=if_name)

    if pppoe_iface:
        return pppoe_iface.conn.ppp_if_name
    else:
        return None

def pppoe_get_dev_id_from_ppp(ppp_if_name):
    if hasattr(fwglobals.g, 'pppoe'):
        return fwglobals.g.pppoe.pppoe_get_dev_id_from_ppp(ppp_if_name)
    else:
        with FwPppoeClient(fwglobals.g.PPPOE_DB_FILE, fwglobals.g.PPPOE_CONFIG_PATH, fwglobals.g.PPPOE_CONFIG_PROVIDER_FILE) as pppoe:
            return pppoe.pppoe_get_dev_id_from_ppp(ppp_if_name)
    return None
