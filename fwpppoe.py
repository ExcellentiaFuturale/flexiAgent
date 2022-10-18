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
import time

from netaddr import IPNetwork
from sqlitedict import SqliteDict

import fwglobals
import fwnetplan
import fwutils
import fwroutes
import fwthread

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
        self.linux_if_name = fwutils.dev_id_to_linux_if(self.dev_id)
        self.ppp_if_name = f'ppp-{self.linux_if_name}'
        self.if_name = self.linux_if_name

    def __str__(self):
        usepeerdns = 'usepeerdns' if self.usepeerdns else ''
        return f"{self.id}, {self.dev_id},{self.mtu},{self.mru},{self.user},{self.ppp_if_name},{self.addr},{self.gw},{usepeerdns},{self.tun_if_name}"

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

    def scan_and_connect_if_needed(self, connect_if_needed):
        """Check Linux interfaces if PPPoE tunnel (pppX) is created.
        """
        if connect_if_needed:
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

        return connected

    def open(self):
        """Open PPPoE connection.
        """
        if self._is_open():
            return

        sys_cmd = f'ip -4 addr flush label "{self.if_name}"'
        rc, _ = fwutils.os_system(sys_cmd, 'PPPoE open')
        if not rc:
            return

        sys_cmd = f'ip link set dev {self.if_name} up'
        rc, _ = fwutils.os_system(sys_cmd, 'PPPoE open')
        if not rc:
            return

        sys_cmd = 'pon %s' % self.filename
        rc, _ = fwutils.os_system(sys_cmd, 'PPPoE open')
        if not rc:
            return

    def _is_open(self):
        """Check if connection is open.
        The information is parsed from the output similar to 'pgrep -a pppd'.
        '14210 /usr/sbin/pppd call flexiwan-dsl-provider-0'
        flexiwan-dsl-provider-X is compared with filename stored in DB.
        """
        for proc in psutil.process_iter(attrs=['name', 'cmdline']):
            if proc.info['name'] != 'pppd':
                continue

            if proc.info['cmdline'][2] == self.filename:
                return True

        return False

    def close(self, timeout = 120):
        """Close PPPoE connection.
        """
        if not self._is_open():
            return

        if self.addr and self.tun_if_name:
            self.remove_linux_ip_route(self.addr)

        sys_cmd = 'poff %s' % self.filename
        rc, _ = fwutils.os_system(sys_cmd, 'PPPoE close')
        if not rc:
            return

        while timeout >= 0:
            if not self._is_open():
                break
            timeout-= 1
            time.sleep(1)

        if timeout == 0:
            self.log.error(f'pppoe close: timeout on waiting pppd to stop')
            return

        self.addr = ''
        self.gw = ''

    def remove(self):
        """Remove PPPoE connection configuration file.
        """
        try:
            if os.path.exists(self.path + self.filename):
                os.remove(self.path + self.filename)

        except Exception as e:
            self.log.error("remove: %s" % str(e))

    def setup_tun_if_params(self):
        """Setup TUN interface params
        """
        self.tun_if_name, self.tun_vpp_if_name = self.get_linux_and_vpp_tun_if_names()
        self.if_name = fwutils.dev_id_to_tap(self.dev_id)

        self.tun_vppsb_if_name = fwutils.vpp_if_name_to_tap(self.tun_vpp_if_name)
        if not self.tun_vppsb_if_name:
            self.log.error("setup_tun_if_params: tun_vppsb_if_name is empty")
            return False

        fwglobals.g.cache.dev_id_to_vpp_if_name[self.dev_id] = self.tun_vpp_if_name
        fwglobals.g.cache.vpp_if_name_to_dev_id[self.tun_vpp_if_name] = self.dev_id

        return True

    def get_linux_and_vpp_tun_if_names(self):
        """Return TUN interface names in Linux and VPP
        """
        return 'pppoe%u' % self.id, 'tun%u' % self.id

    def reset_tun_if_params(self):
        """Reset TUN interface params
        """
        if not self.tun_if_name:
            return

        if self.dev_id in fwglobals.g.cache.dev_id_to_vpp_if_name:
            del fwglobals.g.cache.dev_id_to_vpp_if_name[self.dev_id]
        if self.tun_vpp_if_name in fwglobals.g.cache.vpp_if_name_to_dev_id:
            del fwglobals.g.cache.vpp_if_name_to_dev_id[self.tun_vpp_if_name]

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

    def remove_linux_ip_route(self, addr):
        """Remove ip address from TUN interface.
           Remove default route.
           Remove TC mirroring.
           Revert changes to agent cache.
        """
        self.remove_tc_mirror()

        if not self.tun_vppsb_if_name:
            return

        success, err_str = fwroutes.add_remove_route('0.0.0.0/0', None, None, True, self.dev_id, 'static', self.tun_vppsb_if_name, False)
        if not success:
            self.log.error(f"remove_linux_ip_route: failed to remove route: {err_str}")

        sys_cmd = f'ip addr del {addr} dev {self.tun_vppsb_if_name}'
        fwutils.os_system(sys_cmd, 'PPPoE remove_linux_ip_route')

        sys_cmd = f'ip link set dev {self.tun_vppsb_if_name} down'
        fwutils.os_system(sys_cmd, 'PPPoE remove_linux_ip_route')

    def _tc_mirror_set(self, ifname_1=None, ifname_2=None, ingress=True, op='add'):

        if ifname_1 and ingress:
            sys_cmd = 'tc qdisc %s dev %s handle ffff: ingress' % (op, ifname_1)
            fwutils.os_system(sys_cmd, 'PPPoE _tc_mirror_set')

        if ifname_1 and ifname_2:
            sys_cmd = 'tc filter %s dev %s parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev %s pipe action drop' % (op, ifname_1, ifname_2)
            fwutils.os_system(sys_cmd, 'PPPoE _tc_mirror_set')

    def create_tc_mirror(self):
        """Setup TC mirroring.
        """
        # For the Linux TUN interface (tun_if_name), tc qdisc ingress is already added by VPP DPDK
        self._tc_mirror_set(self.tun_if_name, self.ppp_if_name, False, 'add')
        self._tc_mirror_set(self.ppp_if_name, self.tun_if_name, True, 'add')

    def remove_tc_mirror(self):
        """Remove TC mirroring.
        """
        if not self.tun_if_name:
            return

        self._tc_mirror_set(self.tun_if_name, None, False, 'del')

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
        self.resolv_path = path + 'resolv/'
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

        self.scan()
        self.start()

        self.thread_pppoec = fwthread.FwThread(target=self.pppoec_thread_func, name='PPPOE Client', log=self.log)
        self.thread_pppoec.start()

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
            self.thread_pppoec.stop()
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
        self.stop_interface(dev_id)
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

    def stop(self, reset_tun_if_params=False):
        """Stop all PPPoE connections.
        """
        for dev_id in self.interfaces.keys():
            self.stop_interface(dev_id)
            if reset_tun_if_params:
                self.reset_tun_if_params(dev_id)

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
            conn.addr = ''
            conn.gw = ''
            conn.save()
            self.connections[dev_id] = conn

        for dev_id, pppoe_iface in self.interfaces.items():
            pppoe_iface.is_connected = False
            pppoe_iface.addr = ''
            pppoe_iface.gw = ''
            self.interfaces[dev_id] = pppoe_iface

    def _parse_resolv_conf(self, filename):
        nameservers = []
        try:
            with open(filename, 'r') as resolvconf:
                for line in resolvconf.readlines():
                    line = line.split('#', 1)[0];
                    line = line.rstrip();
                    if 'nameserver' in line:
                        nameservers.append(line.split()[ 1 ])
        except IOError as error:
            self.log.error(f'_parse_resolve_conf: {error.strerror}, filename: {filename}')
        return nameservers

    def _update_resolvd(self, ppp_if_name, nameservers = []):
        cmd = f'systemd-resolve --interface {ppp_if_name}'

        for nameserver in nameservers:
            cmd += f' --set-dns {nameserver}'

        fwutils.os_system(cmd, '_update_resolvd')

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
            self._remove_connection(dev_id)
            del self.interfaces[dev_id]
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

    def scan_interface(self, dev_id, conn, connect_if_needed=False):
        """Scan one interface for established PPPoE connection.
        """
        pppoe_iface = self.interfaces.get(dev_id)
        if not pppoe_iface:
            return

        addr = conn.addr
        connected = conn.scan_and_connect_if_needed(connect_if_needed)

        if pppoe_iface.is_connected != connected:
            pppoe_iface.is_connected = connected
            pppoe_iface.addr = conn.addr
            pppoe_iface.gw = conn.gw
            self.interfaces[dev_id] = pppoe_iface
            self.connections[dev_id] = conn

            if connected:
                self.log.debug(f'pppoe connected: {conn}')
                conn.add_linux_ip_route()
                nameservers = []
                if pppoe_iface.usepeerdns:
                    filename = f'{self.resolv_path}{conn.ppp_if_name}'
                    nameservers = self._parse_resolv_conf(filename)
                else:
                    nameservers = pppoe_iface.nameservers

                self._update_resolvd(conn.ppp_if_name, nameservers)
            else:
                self.log.debug(f'pppoe disconnected: {conn}')
                conn.remove_linux_ip_route(addr)

        return connected

    def scan(self, connect_if_needed=False):
        """Scan all interfaces for established PPPoE connection.
        """
        if not self.connections:
            return

        for dev_id, conn in self.connections.items():
            self.scan_interface(dev_id, conn, connect_if_needed)

    def start(self):
        """Open connections for all PPPoE interfaces.
        """
        for dev_id, conn in self.connections.items():
            pppoe_iface = self.get_interface(dev_id=dev_id)
            if (pppoe_iface and pppoe_iface.is_enabled and not pppoe_iface.is_connected):
                conn.open()
                self.connections[dev_id] = conn

    def setup_tun_if_params(self, dev_id):
        """Create TUN.
        """
        conn = self.connections.get(dev_id)
        rc = conn.setup_tun_if_params()
        if not rc:
            return (False, f'PPPoE: {dev_id} TUN was not created')
        conn.save()
        self.connections[dev_id] = conn

        return (True, None)

    def get_linux_and_vpp_tun_if_names(self, dev_id):
        """Return TUN interface names in Linux and VPP
        """
        conn = self.connections.get(dev_id)
        return conn.get_linux_and_vpp_tun_if_names()

    def reset_tun_if_params(self, dev_id):
        """Reset TUN interface params
        """
        conn = self.connections.get(dev_id)
        conn.reset_tun_if_params()
        conn.save()
        self.connections[dev_id] = conn

        return (True, None)

    def start_interface(self, dev_id, timeout = 20):
        """ Start PPPoE for this interface.
        """
        conn = self.connections.get(dev_id)
        conn.open()

        while timeout >= 0:
            is_connected = self.scan_interface(dev_id, conn)
            if is_connected:
                break
            timeout-= 1
            time.sleep(1)

        return (True, None)

    def stop_interface(self, dev_id):
        """Close PPPoE connection.
           Remove TUN interface if VPP is running.
        """
        conn = self.connections.get(dev_id)
        pppoe_iface = self.interfaces.get(dev_id)

        if conn and pppoe_iface:
            conn.opened = False
            self.connections[dev_id] = conn
            conn.close()
            self.connections[dev_id] = conn
            pppoe_iface.is_connected = False
            pppoe_iface.addr = ''
            pppoe_iface.gw = ''
            self.interfaces[dev_id] = pppoe_iface

        return (True, None)

    def pppoec_thread_func(self, ticks):
        """PPPoE client thread.
        Its function is to monitor state of interfaces with PPPoE.
        """
        if not fwglobals.g.router_api.state_is_starting_stopping():
            self.scan(connect_if_needed=True)


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

        self.scan()

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
    if fwglobals.g.pppoe:
        fwglobals.g.pppoe.clean()
    else:
        with FwPppoeClient() as pppoe:
            pppoe.clean()

def is_pppoe_configured():
    """Check if PPPoE is configured
    """
    if fwglobals.g.pppoe:
        return fwglobals.g.pppoe.is_pppoe_configured()
    else:
        with FwPppoeClient() as pppoe:
            return pppoe.is_pppoe_configured()

def pppoe_reset():
    """Reset PPPoE configuration files
    """
    if fwglobals.g.pppoe:
        fwglobals.g.pppoe.reset_interfaces()
    else:
        with FwPppoeClient() as pppoe:
            pppoe.reset_interfaces()

def build_dev_id_to_vpp_if_name_map():
    """Get PPPoE connections.
    """
    if fwglobals.g.pppoe:
        return fwglobals.g.pppoe.build_dev_id_to_vpp_if_name_map()
    else:
        with FwPppoeClient() as pppoe:
            return pppoe.build_dev_id_to_vpp_if_name_map()
