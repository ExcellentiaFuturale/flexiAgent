################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
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
################################################################################

import copy
import ctypes
import binascii
import datetime
import glob
import hashlib
import inspect
import ipaddress
import json
import os
import time
import platform
import subprocess
import psutil
import socket
import re
import fwglobals
import fwnetplan
import fwpppoe
from fwpppoe import FwPppoeClient
import fwstats
import shutil
import sys
import traceback
import yaml
import ipaddress
import zlib
import base64

from netaddr import IPNetwork, IPAddress

import fwlte
import fwwifi
import fwtranslate_add_switch

from fwapplications_api import FWAPPLICATIONS_API
from fwikev2        import FwIKEv2
from fwmultilink    import FwMultilink
from fwpolicies     import FwPolicies
from fwrouter_cfg   import FwRouterCfg
from fwsystem_cfg   import FwSystemCfg
from fwwan_monitor  import get_wan_failover_metric
from fw_traffic_identification import FwTrafficIdentifications
from tools.common.fw_vpp_startupconf import FwStartupConf

libc = None

proto_map = {'any': 0, 'icmp': 1, 'tcp': 6, 'udp': 17}

dpdk = __import__('dpdk-devbind')

def get_device_logs(file, num_of_lines):
    """Get device logs.

    :param file:            File name.
    :param num_of_lines:    Number of lines.

    :returns: Return list.
    """
    try:
        if not os.path.exists(file):
            return []

        cmd = "tail -{} {}".format(num_of_lines, file)
        res = subprocess.check_output(cmd, shell=True).decode().splitlines()

        # On zero matching, res is a list with a single empty
        # string which we do not want to return to the caller
        return res if res != [''] else []
    except (OSError, subprocess.CalledProcessError) as err:
        raise err

def get_device_packet_traces(num_of_packets, timeout):
    """Get device packet traces.

    :param num_of_packets:    Number of lines.
    :param timeout:           Timeout to wait for trace to complete.

    :returns: Array of traces.
    """
    try:
        cmd = 'sudo vppctl clear trace'
        subprocess.check_call(cmd, shell=True)
        cmd = 'sudo vppctl show vmxnet3'
        shif_vmxnet3 = subprocess.check_output(cmd, shell=True).decode()
        if shif_vmxnet3 is '':
            cmd = 'sudo vppctl trace add dpdk-input %s && sudo vppctl trace add virtio-input %s' % (num_of_packets, num_of_packets)
        else:
            cmd = 'sudo vppctl trace add vmxnet3-input %s && sudo vppctl trace add virtio-input %s' % (num_of_packets, num_of_packets)
        subprocess.check_call(cmd, shell=True)
        time.sleep(int(timeout))
        cmd = 'sudo vppctl show trace max {}'.format(num_of_packets)
        res = subprocess.check_output(cmd, shell=True).decode().splitlines()
        # skip first line (contains unnecessary information header)
        return res[1:] if res != [''] else []
    except (OSError, subprocess.CalledProcessError) as err:
        raise err

def get_device_versions(filename):
    """Get agent version.

    :param filename:           Versions file name.

    :returns: Version value.
    """
    try:
        with open(filename, 'r') as stream:
            versions = yaml.load(stream, Loader=yaml.BaseLoader)
            return versions
    except:
        err = "get_device_versions: failed to get versions: %s" % (format(sys.exc_info()[1]))
        fwglobals.log.error(err)
        return None

def get_machine_id():
    """Get machine id.

    :returns: UUID.
    """
    if fwglobals.g.cfg.UUID:    # If UUID is configured manually, use it
        return fwglobals.g.cfg.UUID

    try:                        # Fetch UUID from machine
        if platform.system()=="Windows":
            machine_id = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
        else:
            machine_id = subprocess.check_output(['cat','/sys/class/dmi/id/product_uuid']).decode().split('\n')[0].strip()
        return machine_id.upper()
    except:
        return None

def get_machine_serial():
    """Get machine serial number.

    :returns: S/N string.
    """
    try:
        serial = subprocess.check_output(['dmidecode', '-s', 'system-serial-number']).decode().split('\n')[0].strip()
        return str(serial)
    except:
        return '0'
def pid_of(proccess_name):
    """Get pid of process.

    :param proccess_name:   Proccess name.

    :returns:           process identifier.
    """
    try:
        pid = subprocess.check_output(['pidof', proccess_name]).decode()
    except:
        pid = None
    return pid

def vpp_pid():
    """Get pid of VPP process.

    :returns:           process identifier.
    """
    try:
        pid = pid_of('vpp')
    except:
        pid = None
    return pid

def vpp_does_run():
    """Check if VPP is running.

    :returns:           Return 'True' if VPP is running.
    """
    runs = True if vpp_pid() else False
    return runs

def get_vpp_tap_interface_mac_addr(dev_id):
    tap = dev_id_to_tap(dev_id)
    return get_interface_mac_addr(tap)

def get_interface_mac_addr(interface_name):
    interfaces = psutil.net_if_addrs()

    if interface_name in interfaces:
        addrs = interfaces[interface_name]
        for addr in addrs:
            if addr.family == psutil.AF_LINK:
                return addr.address

    return None

def af_to_name(af_type):
    """Convert socket type.

    :param af_type:        Socket type.

    :returns: String.
    """
    af_map = {
    	socket.AF_INET: 'IPv4',
    	socket.AF_INET6: 'IPv6',
    	psutil.AF_LINK: 'MAC',
	}
    return af_map.get(af_type, af_type)

def get_default_route(if_name=None):
    """Get default route.

    :param if_name:  name of the interface to return info for.
        if not provided, the route with the lowest metric will return.

    :returns: tuple (<IP of GW>, <name of network interface>, <Dev ID of network interface>, <protocol>).
    """
    (via, dev, metric, proto) = ("", "", 0xffffffff, "")
    try:
        output = os.popen('ip route list match default').read()
        if output:
            routes = output.splitlines()
            for r in routes:
                _dev = ''   if not 'dev '    in r else r.split('dev ')[1].split(' ')[0]
                _via = ''   if not 'via '    in r else r.split('via ')[1].split(' ')[0]
                _metric = 0 if not 'metric ' in r else int(r.split('metric ')[1].split(' ')[0])
                _proto = '' if not 'proto '  in r else r.split('proto ')[1].split(' ')[0]

                if if_name == _dev: # If if_name specified, we return info for that dev even if it has a higher metric
                    dev    = _dev
                    via    = _via
                    metric = _metric
                    proto  = _proto
                    return (via, dev, get_interface_dev_id(dev), proto)

                if _metric < metric:  # The default route among default routes is the one with the lowest metric :)
                    dev    = _dev
                    via    = _via
                    metric = _metric
                    proto = _proto
    except:
        pass

    if not dev:
        return ("", "", "", "")

    dev_id = get_interface_dev_id(dev)
    return (via, dev, dev_id, proto)

def get_interface_gateway(if_name, if_dev_id=None):
    """Get gateway.

    :param if_name:  name of the interface, gateway for which is returned
    :param if_dev_id: Bus address of the interface, gateway for which is returned.
                     If provided, the 'if_name' is ignored. The name is fetched
                     from system by a Bus address.

    :returns: Gateway ip address.
    """
    if if_dev_id:
        if_name = dev_id_to_tap(if_dev_id)

    if fwglobals.g.pppoe.is_pppoe_interface(if_name=if_name):
        pppoe_iface = fwglobals.g.pppoe.get_interface(if_name=if_name)
        return pppoe_iface.gw, str(pppoe_iface.metric)

    try:
        cmd   = "ip route list match default | grep via | grep 'dev %s'" % if_name
        route = os.popen(cmd).read()
        if not route:
            return '', ''
    except:
        return '', ''

    rip    = route.split('via ')[1].split(' ')[0]
    metric = '' if not 'metric ' in route else route.split('metric ')[1].split(' ')[0]
    return rip, metric


def get_tunnel_gateway(dst, dev_id):
    linux_interfaces = get_linux_interfaces()
    if linux_interfaces:
        interface = linux_interfaces.get(dev_id)
        if interface:
            try:
                network = interface['IPv4'] + '/' + interface['IPv4Mask']
                # If src and dst on the same network return an empty gw
                # In this case the system uses default route as a gateway and connect the interfaces directly and not via the GW
                if is_ip_in_subnet(dst,network): return ''
            except Exception as e:
                fwglobals.log.error("get_tunnel_gateway: failed to check networks: dst=%s, dev_id=%s, network=%s, error=%s" % (dst, dev_id, network, str(e)))

    # If src, dst are not on same subnet or any error, use the gateway defined on the device
    gw_ip, _ = get_interface_gateway('', if_dev_id=dev_id)
    return ipaddress.ip_address(gw_ip) if gw_ip else ipaddress.ip_address('0.0.0.0')

def is_interface_assigned_to_vpp(dev_id):
    """ Check if dev_id is assigned to vpp.
    This function could be called even deamon doesn't run.

    :params dev_id: Bus address to check if assigned

    : return : Boolean
    """
    if getattr(fwglobals.g, 'router_cfg', False):
        return len(fwglobals.g.router_cfg.get_interfaces(dev_id=dev_id)) > 0

    with FwRouterCfg(fwglobals.g.ROUTER_CFG_FILE) as router_cfg:
        return len(router_cfg.get_interfaces(dev_id=dev_id)) > 0

    return False

def get_all_interfaces():
    """ Get all interfaces from linux. For dev id with address family of AF_INET,
        also store gateway, if exists.
        : return : Dictionary of dev_id->IP,GW
    """
    dev_id_ip_gw = {}
    interfaces = psutil.net_if_addrs()
    for nic_name, addrs in list(interfaces.items()):
        dev_id = get_interface_dev_id(nic_name)
        if not dev_id:
            continue

        if fwlte.is_lte_interface(nic_name):
            tap_name = dev_id_to_tap(dev_id, check_vpp_state=True)
            if tap_name:
                nic_name = tap_name
                addrs = interfaces.get(nic_name)

        if fwglobals.g.pppoe.is_pppoe_interface(if_name=nic_name):
            pppoe_iface = fwglobals.g.pppoe.get_interface(if_name=nic_name)
            if pppoe_iface.is_connected:
                addrs = interfaces.get(pppoe_iface.ppp_if_name)
            else:
                addrs = []

        dev_id_ip_gw[dev_id] = {}
        dev_id_ip_gw[dev_id]['addr'] = ''
        dev_id_ip_gw[dev_id]['gw']   = ''

        if not addrs:
            addrs = []

        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address.split('%')[0]
                dev_id_ip_gw[dev_id]['addr'] = ip
                gateway, _ = get_interface_gateway(nic_name)
                dev_id_ip_gw[dev_id]['gw'] = gateway if gateway else ''
                break

    return dev_id_ip_gw

def get_interface_address(if_name, log=True, log_on_failure=None):
    """Gets IP address of interface by name found in OS.

    :param if_name:     Interface name.
    :param log:         If True the found/not found address will be logged.
                        Errors or debug info is printed in any case.
    :param log_on_failure: If provided, overrides the 'log' in case of not found address.

    :returns: IP address.
    """
    if log_on_failure == None:
        log_on_failure = log

    ppp_if_name = fwpppoe.pppoe_get_ppp_if_name(if_name)
    if ppp_if_name:
        if_name = ppp_if_name

    interfaces = psutil.net_if_addrs()
    if if_name not in interfaces:
        fwglobals.log.debug("get_interface_address(%s): interfaces: %s" % (if_name, str(interfaces)))
        return None

    addresses = interfaces[if_name]
    for addr in addresses:
        if addr.family == socket.AF_INET:
            ip   = addr.address
            mask = IPAddress(addr.netmask).netmask_bits()
            if log:
                fwglobals.log.debug("get_interface_address(%s): %s" % (if_name, str(addr)))
            return '%s/%s' % (ip, mask)

    if log_on_failure:
        fwglobals.log.debug("get_interface_address(%s): %s" % (if_name, str(addresses)))
    return None

def get_interface_name(ip_no_mask):
    """ Get interface name based on IP address

    : param ip_no_mask: ip address with no mask
    : returns : if_name - interface name
    """
    interfaces = psutil.net_if_addrs()
    for if_name in interfaces:
        addresses = interfaces[if_name]
        for address in addresses:
            if address.family == socket.AF_INET and address.address == ip_no_mask:
                return if_name
    return None

def is_ip_in_subnet(ip, subnet):
    """Check if IP address is in subnet.

    :param ip:            IP address.
    :param subnet:        Subnet address.

    :returns: 'True' if address is in subnet.
    """
    return True if IPAddress(ip) in IPNetwork(subnet) else False

def dev_id_to_full(dev_id):
    """Convert short PCI into full representation.
    the 'dev_id' param could be either a pci or a usb address.
    in case of pci address - the function will convert into a full address

    :param dev_id:      device bus address.

    :returns: full device bus address.
    """
    (addr_type, addr) = dev_id_parse(dev_id)
    if addr_type == 'usb':
        return dev_id

    pc = addr.split('.')
    if len(pc) == 2:
        return dev_id_add_type(pc[0]+'.'+"%02x"%(int(pc[1],16)))
    return dev_id

# Convert 0000:00:08.01 provided by management to 0000:00:08.1 used by Linux
def dev_id_to_short(dev_id):
    """Convert full PCI into short representation.
    the 'dev_id' param could be either a pci or a usb address.
    in case of pci address - convert pci provided by management into a short address used by Linux

    :param dev_id:      Full PCI address.

    :returns: Short PCI address.
    """
    addr_type, addr = dev_id_parse(dev_id)
    if addr_type == 'usb':
        return dev_id

    l = addr.split('.')
    if len(l[1]) == 2 and l[1][0] == '0':
        return dev_id_add_type(l[0] + '.' + l[1][1])
    return dev_id

def dev_id_parse(dev_id):
    """Convert a dev id into a tuple contained address type (pci, usb) and address.

    :param dev_id:     device bus address.

    :returns: Tuple (type, address)
    """
    type_and_addr = dev_id.split(':', 1)
    if type_and_addr and len(type_and_addr) == 2:
        return (type_and_addr[0], type_and_addr[1])

    return ("", "")

def dev_id_add_type(dev_id):
    """Add address type at the begining of the address.

    :param dev_id:      device bus address.

    :returns: device bus address with type.
    """

    if dev_id:
        if dev_id.startswith('pci:') or dev_id.startswith('usb:'):
            return dev_id

        if re.search('usb', dev_id):
            return 'usb:%s' % dev_id

        return 'pci:%s' % dev_id

    return ''

def set_linux_interfaces_stun(dev_id, public_ip, public_port, nat_type):
    with fwglobals.g.cache.lock:
        interface = fwglobals.g.cache.linux_interfaces.get(dev_id)
        if interface:
            interface['public_ip']   = public_ip
            interface['public_port'] = public_port
            interface['nat_type']    = nat_type

def clear_linux_interfaces_cache():
    with fwglobals.g.cache.lock:
        fwglobals.g.cache.linux_interfaces.clear()

def is_bridged_interface(dev_id):
    """Indicates if the interface is bridged.

    :param dev_id: dev_id of the interface to check.

    :return: bridge address if it is, None if not a bridged interface.
    """
    ifc = fwglobals.g.router_cfg.get_interfaces(dev_id=dev_id)
    if not ifc:
        return None

    bridged_addr = ifc[0].get('bridge_addr')
    if bridged_addr:
        return bridged_addr

    return None

def get_linux_interfaces(cached=True):
    """Fetch interfaces from Linux.

    :param cached: if True the data will be fetched from cache.

    :return: Dictionary of interfaces by full form dev id.
    """
    with fwglobals.g.cache.lock:

        interfaces = fwglobals.g.cache.linux_interfaces

        if cached and interfaces:
            return copy.deepcopy(interfaces)

        fwglobals.log.debug("get_linux_interfaces: Start to build Linux interfaces cache")
        interfaces.clear()

        linux_inf = psutil.net_if_addrs()
        for (if_name, addrs) in list(linux_inf.items()):

            dev_id = get_interface_dev_id(if_name)
            if not dev_id:
                continue

            interface = {
                'name':             if_name,
                'devId':            dev_id,
                'driver':           get_interface_driver(if_name, False),
                'MAC':              '',
                'IPv4':             '',
                'IPv4Mask':         '',
                'IPv6':             '',
                'IPv6Mask':         '',
                'dhcp':             '',
                'gateway':          '',
                'metric':           '',
                'internetAccess':   '',
                'public_ip':        '',
                'public_port':      '',
                'nat_type':         '',
                'link':             '',
                'tap_name':         '',
                'mtu':              '',
            }

            interface['link'] = get_interface_link_state(if_name, dev_id)

            interface['dhcp'] = fwnetplan.get_dhcp_netplan_interface(if_name)

            interface['mtu'] = get_linux_interface_mtu(if_name)

            is_pppoe = fwglobals.g.pppoe.is_pppoe_interface(if_name=if_name)
            is_wifi = fwwifi.is_wifi_interface(if_name)
            is_lte = fwlte.is_lte_interface(if_name)

            # Some interfaces need special logic to get their ip
            # For LTE/WiFi/Bridged interfaces - we need to take it from the tap
            if vpp_does_run():
                tap_name = None

                if is_lte or is_wifi:
                    tap_name = dev_id_to_tap(dev_id, check_vpp_state=True)
                    if tap_name:
                        interface['mtu'] = get_linux_interface_mtu(tap_name)

                # bridged interface is only when vpp is running
                bridge_addr = is_bridged_interface(dev_id)
                if bridge_addr:
                    tap_name = bridge_addr_to_bvi_interface_tap(bridge_addr)

                if tap_name:
                    if_name = tap_name
                    addrs = linux_inf[tap_name]
                    interface['tap_name'] = tap_name


            interface['gateway'], interface['metric'] = get_interface_gateway(if_name)

            for addr in addrs:
                addr_af_name = af_to_name(addr.family)
                if not interface[addr_af_name]:
                    interface[addr_af_name] = addr.address.split('%')[0]
                    if addr.netmask != None:
                        interface[addr_af_name + 'Mask'] = (str(IPAddress(addr.netmask).netmask_bits()))

            if is_lte:
                interface['deviceType'] = 'lte'
                interface['dhcp'] = 'yes'
                interface['deviceParams'] = {
                    'initial_pin1_state': fwlte.get_pin_state(dev_id),
                    'default_settings':   fwlte.get_default_settings(dev_id)
                }

            if is_wifi:
                interface['deviceType'] = 'wifi'
                interface['deviceParams'] = fwwifi.wifi_get_capabilities(dev_id)

            if is_pppoe:
                pppoe_iface = fwglobals.g.pppoe.get_interface(if_name=if_name)
                interface['deviceType'] = 'pppoe'
                interface['dhcp'] = 'yes'
                interface['mtu'] = str(pppoe_iface.mtu)
                if pppoe_iface.addr:
                    address = IPNetwork(pppoe_iface.addr)
                    interface['IPv4'] = str(address.ip)
                    interface['IPv4Mask'] = str(address.prefixlen)

            # Add information specific for WAN interfaces
            #
            if interface['gateway']:

                # Fetch public address info from STUN module
                #
                interface['public_ip'], interface['public_port'], interface['nat_type'] = \
                    fwglobals.g.stun_wrapper.find_addr(dev_id)

                # Fetch internet connectivity info from WAN Monitor module.
                # Hide the metric watermarks used for WAN failover from flexiManage.
                #
                metric = 0 if not interface['metric'] else int(interface['metric'])
                if metric >= fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK:
                    interface['metric'] = str(metric - fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK)
                    interface['internetAccess'] = False
                elif not interface['IPv4']:       # If DHCP interface has no IP
                    interface['internetAccess'] = False
                else:
                    interface['internetAccess'] = True
            else:
                interface['internetAccess'] = False  # If interface has no GW

            interfaces[dev_id] = interface

        fwglobals.log.debug("get_linux_interfaces: Finished to build Linux interfaces cache")
        return copy.deepcopy(interfaces)

def get_interface_dev_id(if_name):
    """Convert  interface name into bus address.

    :param if_name:      Linux interface name.

    :returns: dev_id.
    """
    if is_interface_without_dev_id(if_name):
        return ''

    with fwglobals.g.cache.lock:
        interface = fwglobals.g.cache.linux_interfaces_by_name.get(if_name)
        if not interface:
            fwglobals.g.cache.linux_interfaces_by_name[if_name] = {}
            interface = fwglobals.g.cache.linux_interfaces_by_name.get(if_name)

        dev_id = interface.get('dev_id')
        if dev_id != None:
            return dev_id

        # First try to get dev id if interface is under linux control
        dev_id = build_interface_dev_id(if_name)
        if dev_id:
            interface.update({'dev_id': dev_id})
            return dev_id

        if not vpp_does_run() or is_interface_assigned_to_vpp(dev_id) == False:
            # don't update cache
            return ''

        # If not found and vpp is running, try to fetch dev id if interface was created by vppsb, e.g. vpp1
        vpp_if_name = tap_to_vpp_if_name(if_name)
        if not vpp_if_name:
            # don't update cache
            return ''

        if re.match(r'^loop', vpp_if_name): # loopback interfaces have no dev id (bus id)
            interface.update({'dev_id': ''})
            return ''

        dev_id = vpp_if_name_to_dev_id(vpp_if_name)
        if dev_id:
            interface.update({'dev_id': dev_id})
            return dev_id

        fwglobals.log.error(
            'get_interface_dev_id: if_name=%s, vpp_if_name=%s' % (if_name, str(vpp_if_name)))
        # don't update cache
        return ''

def build_interface_dev_id(linux_dev_name, sys_class_net=None):
    """Converts Linux interface name into bus address.
    This function returns dev_id only for physical interfaces controlled by linux.

    :param linux_dev_name:     Linux device name.
    :param sys_class_net:      List of available networking devices formatted as output of the 'ls -l /sys/class/net' command.
                               This parameter is used for tests.

    :returns: dev_id or None if interface was created by vppsb
    """
    if not linux_dev_name:
        return ""

    if sys_class_net is None:
        cmd = "sudo ls -l /sys/class/net"
        try:
            out = subprocess.check_output(cmd, shell=True).decode()
            sys_class_net = out.splitlines()
        except Exception as e:
            fwglobals.log.error('build_interface_dev_id: failed to fetch networking devices: %s' % str(e))
            return ""

    for networking_device in sys_class_net:
        regex = r'\b%s\b' % linux_dev_name
        if not re.search(regex, networking_device):
            continue
        regex = r'[0-9A-Fa-f]{4}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-9A-Fa-f]{1,2}|usb\d+\/.*(?=\/net)'
        if_addr = re.findall(regex, networking_device)
        if if_addr:
            if_addr = if_addr[-1]
            if re.search(r'usb|pci', networking_device):
                dev_id = dev_id_add_type(if_addr)
                dev_id = dev_id_to_full(dev_id)
                return dev_id

    return ""

def dev_id_to_linux_if(dev_id):
    """Convert device bus address into Linux interface name.

    :param dev_id:      device bus address.

    :returns: Linux interface name.
    """
    # igorn@ubuntu-server-1:~$ sudo ls -l /sys/class/net/
    # total 0
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 enp0s3 -> ../../devices/pci0000:00/0000:00:03.0/net/enp0s3
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 enp0s8 -> ../../devices/pci0000:00/0000:00:08.0/net/enp0s8
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 enp0s9 -> ../../devices/pci0000:00/0000:00:09.0/net/enp0s9
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 lo -> ../../devices/virtual/net/lo

    # We get 0000:00:08.01 from management and not 0000:00:08.1, so convert a little bit
    dev_id = dev_id_to_short(dev_id)
    _, addr = dev_id_parse(dev_id)

    try:
        output = subprocess.check_output("sudo ls -l /sys/class/net/ | grep " + addr, shell=True).decode()
    except:
        return None
    if output is None:
        return None
    return output.rstrip().split('/')[-1]

def dev_id_to_linux_if_name(dev_id):
    """Convert device bus address into Linux interface name.
    If vpp runs, the name of tap interface if fetched, otherwise the device name is used.

    :param dev_id: device bus address.

    :returns: interface name in Linux.
    """
    if not fwglobals.g.router_api.state_is_stopped():
        tap_if_name = dev_id_to_tap(dev_id)
        if tap_if_name:
            return tap_if_name
    return dev_id_to_linux_if(dev_id)

def dev_id_is_vmxnet3(dev_id):
    """Check if device bus address is vmxnet3.

    :param dev_id:    device bus address.

    :returns: 'True' if it is vmxnet3, 'False' otherwise.
    """
    # igorn@ubuntu-server-1:~$ sudo ls -l /sys/bus/pci/devices/*/driver
    # lrwxrwxrwx 1 root root 0 Jul 17 22:08 /sys/bus/pci/devices/0000:03:00.0/driver -> ../../../../bus/pci/drivers/vmxnet3
    # lrwxrwxrwx 1 root root 0 Jul 17 23:01 /sys/bus/pci/devices/0000:0b:00.0/driver -> ../../../../bus/pci/drivers/vfio-pci
    # lrwxrwxrwx 1 root root 0 Jul 17 23:01 /sys/bus/pci/devices/0000:13:00.0/driver -> ../../../../bus/pci/drivers/vfio-pci

    # We get pci:0000:00:08.01 from management and not 0000:00:08.1, so convert a little bit
    dev_id = dev_id_to_short(dev_id)
    addr_type, addr = dev_id_parse(dev_id)
    if addr_type == 'usb':
        return False

    try:
        # The 'ls -l /sys/bus/pci/devices/*/driver' approach doesn't work well.
        # When vpp starts, it rebinds device to vfio-pci, so 'ls' doesn't detect it.
        # Therefore we go with dpdk-devbind.py. It should be installed on Linux
        # as a part of flexiwan-router installation.
        # When vpp does not run, we get:
        #   0000:03:00.0 'VMXNET3 Ethernet Controller' if=ens160 drv=vmxnet3 unused=vfio-pci,uio_pci_generic
        # When vpp does run, we get:
        #   0000:03:00.0 'VMXNET3 Ethernet Controller' if=ens160 drv=vfio-pci unused=vmxnet3,uio_pci_generic
        #
        #output = subprocess.check_output("sudo ls -l /sys/bus/pci/devices/%s/driver | grep vmxnet3" % pci, shell=True).decode()
        output = subprocess.check_output("sudo dpdk-devbind -s | grep -E '%s .*vmxnet3'" % addr, shell=True).decode()
    except:
        return False
    if output is None:
        return False
    return True

# 'dev_id_to_vpp_if_name' function maps interface referenced by device bus address - pci or usb - eg. '0000:00:08.00'
# into name of interface in VPP, eg. 'GigabitEthernet0/8/0'.
# We use the interface cache mapping, if doesn't exist we rebuild the cache
def dev_id_to_vpp_if_name(dev_id):
    """Convert interface bus address into VPP interface name.

    :param dev_id:      device bus address.

    :returns: VPP interface name.
    """
    dev_id = dev_id_to_full(dev_id)
    vpp_if_name = fwglobals.g.cache.dev_id_to_vpp_if_name.get(dev_id)
    if vpp_if_name: return vpp_if_name
    else: return _build_dev_id_to_vpp_if_name_maps(dev_id, None)

# 'vpp_if_name_to_dev_id' function maps interface name, eg. 'GigabitEthernet0/8/0'
# into the dev id of that interface, eg. '0000:00:08.00'.
# We use the interface cache mapping, if doesn't exist we rebuild the cache
def vpp_if_name_to_dev_id(vpp_if_name):
    """Convert vpp interface name address into interface bus address.

    :param vpp_if_name:      VPP interface name.

    :returns: Interface bus address.
    """
    dev_id = fwglobals.g.cache.vpp_if_name_to_dev_id.get(vpp_if_name)
    if dev_id: return dev_id
    else: return _build_dev_id_to_vpp_if_name_maps(None, vpp_if_name)

# '_build_dev_id_to_vpp_if_name_maps' function build the local caches of
# device bus address to vpp_if_name and vise vera
# if dev_id provided, return the name found for this dev_id,
# else, if name provided, return the dev_id for this name,
# else, return None
# To do that we dump all hardware interfaces, split the dump into list by empty line,
# and search list for interface that includes the dev_id name.
# The dumps brings following table:
#              Name                Idx    Link  Hardware
# GigabitEthernet0/8/0               1    down  GigabitEthernet0/8/0
#   Link speed: unknown
#   ...
#   pci: device 8086:100e subsystem 8086:001e address 0000:00:08.00 numa 0
#
def _build_dev_id_to_vpp_if_name_maps(dev_id, vpp_if_name):

    # Note, tap interfaces created by "create tap" are handled as follows:
    # the commands "create tap host-if-name tap_wwan0" and "enable tap-inject" create three interfaces:
    # Two on Linux (tap_wwan0, vpp1) and one on vpp (tap1).
    # Note, we use "tap_" prefix in "tap_wwan0" in order to be able to associate the wwan0 physical interface
    # with the tap1 interface. This is done as follows:
    # Then we can substr the dev_name and get back the linux interface name. Then we can get the dev_id of this interface.
    #
    taps = fwglobals.g.router_api.vpp_api.call('sw_interface_tap_v2_dump')
    for tap in taps:
        vpp_tap = tap.dev_name                      # fetch tap0
        linux_tap = tap.host_if_name                # fetch tap_wwan0
        linux_dev_name = linux_tap.split('_')[-1]   # tap_wwan0 - > wwan0

        # if the lte/wifi interface name is long (more than 15 letters),
        # It's not enough to slice tap_wwan0 and get the linux interface name from the last part.
        # So we take it from the /sys/class/net by filter out the tap_wwan0,
        # then we can get the complete name
        #
        cmd =  "ls -l /sys/class/net | grep -v %s | grep %s" % (linux_tap, linux_dev_name)
        linux_dev_name = subprocess.check_output(cmd, shell=True).decode().strip().split('/')[-1]

        bus = build_interface_dev_id(linux_dev_name)            # fetch bus address of wwan0
        if bus:
            fwglobals.g.cache.dev_id_to_vpp_if_name[bus] = vpp_tap
            fwglobals.g.cache.vpp_if_name_to_dev_id[vpp_tap] = bus

    shif = _vppctl_read('show hardware-interfaces')
    if shif == None:
        fwglobals.log.debug("_build_dev_id_to_vpp_if_name_maps: Error reading interface info")
    data = shif.splitlines()
    for interface in _get_group_delimiter(data, r"^\w.*?\d"):
        # Contains data for a given interface
        data = ''.join(interface)
        (k,v) = _parse_vppname_map(data,
            valregex=r"^(\w[^\s]+)\s+\d+\s+(\w+)",
            keyregex=r"\s+pci:.*\saddress\s(.*?)\s")
        if k and v:
            k = dev_id_add_type(k)
            full_addr = dev_id_to_full(k)
            fwglobals.g.cache.dev_id_to_vpp_if_name[full_addr] = v
            fwglobals.g.cache.vpp_if_name_to_dev_id[v] = full_addr

    vmxnet3hw = fwglobals.g.router_api.vpp_api.call('vmxnet3_dump')
    for hw_if in vmxnet3hw:
        vpp_if_name = hw_if.if_name.rstrip(' \t\r\n\0')
        pci_addr = 'pci:%s' % pci_bytes_to_str(hw_if.pci_addr)
        fwglobals.g.cache.dev_id_to_vpp_if_name[pci_addr] = vpp_if_name
        fwglobals.g.cache.vpp_if_name_to_dev_id[vpp_if_name] = pci_addr

    if dev_id:
        vpp_if_name = fwglobals.g.cache.dev_id_to_vpp_if_name.get(dev_id)
        if vpp_if_name: return vpp_if_name
    elif vpp_if_name:
        dev_id = fwglobals.g.cache.vpp_if_name_to_dev_id.get(vpp_if_name)
        if dev_id: return dev_id

    fwglobals.log.debug("_build_dev_id_to_vpp_if_name_maps(%s, %s): not found: sh hard: %s" % (dev_id, vpp_if_name, shif))
    fwglobals.log.debug("_build_dev_id_to_vpp_if_name_maps(%s, %s): not found: sh vmxnet3: %s" % (dev_id, vpp_if_name, vmxnet3hw))
    fwglobals.log.debug("_build_dev_id_to_vpp_if_name_maps(%s, %s): not found: %s" % (dev_id, vpp_if_name, str(traceback.extract_stack())))
    return None

# 'pci_str_to_bytes' converts "0000:0b:00.0" string to bytes to pack following struct:
#    struct
#    {
#      u16 domain;
#      u8 bus;
#      u8 slot: 5;
#      u8 function:3;
#    };
#
def pci_str_to_bytes(pci_str):
    """Convert PCI address into bytes.

    :param pci_str:      PCI address.

    :returns: Bytes array.
    """
    list = re.split(r':|\.', pci_str)
    domain   = int(list[0], 16)
    bus      = int(list[1], 16)
    slot     = int(list[2], 16)
    function = int(list[3], 16)
    bytes = ((domain & 0xffff) << 16) | ((bus & 0xff) << 8) | ((slot & 0x1f) <<3 ) | (function & 0x7)
    return socket.htonl(bytes)   # vl_api_vmxnet3_create_t_handler converts parameters by ntoh for some reason (vpp\src\plugins\vmxnet3\vmxnet3_api.c)

# 'pci_str_to_bytes' converts pci bytes into full string "0000:0b:00.0"
def pci_bytes_to_str(pci_bytes):
    """Converts PCI bytes to PCI full string.

    :param pci_str:      PCI bytes.

    :returns: PCI full string.
    """
    bytes = socket.ntohl(pci_bytes)
    domain   = (bytes >> 16)
    bus      = (bytes >> 8) & 0xff
    slot     = (bytes >> 3) & 0x1f
    function = (bytes) & 0x7
    return "%04x:%02x:%02x.%02x" % (domain, bus, slot, function)

# 'dev_id_to_vpp_sw_if_index' function maps interface referenced by device bus address, e.g pci - '0000:00:08.00'
# into index of this interface in VPP, eg. 1.
# To do that we convert firstly the device bus address into name of interface in VPP,
# e.g. 'GigabitEthernet0/8/0', than we dump all VPP interfaces and search for interface
# with this name. If found - return interface index.


def dev_id_to_vpp_sw_if_index(dev_id):
    """Convert device bus address into VPP sw_if_index.

    :param dev_id:      device bus address.

    :returns: sw_if_index.
    """
    vpp_if_name = dev_id_to_vpp_if_name(dev_id)

    fwglobals.log.debug("dev_id_to_vpp_sw_if_index(%s): vpp_if_name: %s" % (dev_id, str(vpp_if_name)))
    if vpp_if_name is None:
        return None

    sw_ifs = fwglobals.g.router_api.vpp_api.call('sw_interface_dump')
    for sw_if in sw_ifs:
        if re.match(vpp_if_name, sw_if.interface_name):    # Use regex, as sw_if.interface_name might include trailing whitespaces
            return sw_if.sw_if_index
    fwglobals.log.debug("dev_id_to_vpp_sw_if_index(%s): vpp_if_name: %s" % (dev_id, yaml.dump(sw_ifs, canonical=True)))

    return None

# 'bridge_addr_to_bvi_interface_tap' function get the addr of the interface in a bridge
# and return the tap interface of the BVI interface
def bridge_addr_to_bvi_interface_tap(bridge_addr):
    if not vpp_does_run():
        return None

    # check if interface indeed in a bridge
    bd_id = fwtranslate_add_switch.get_bridge_id(bridge_addr)
    if not bd_id:
        fwglobals.log.error('bridge_addr_to_bvi_interface_tap: failed to fetch bridge id for address: %s' % str(bridge_addr))
        return None

    vpp_bridges_det = fwglobals.g.router_api.vpp_api.call('bridge_domain_dump', bd_id=bd_id)
    if not vpp_bridges_det:
        fwglobals.log.error('bridge_addr_to_bvi_interface_tap: failed to fetch vpp bridges for bd_id %s' % str(bd_id))
        return None

    bvi_sw_if_index = vpp_bridges_det[0].bvi_sw_if_index
    return vpp_sw_if_index_to_tap(bvi_sw_if_index)

# 'dev_id_to_tap' function maps interface referenced by dev_id, e.g '0000:00:08.00'
# into interface in Linux created by 'vppctl enable tap-inject' command, e.g. vpp1.
# To do that we convert firstly the dev_id into name of interface in VPP,
# e.g. 'GigabitEthernet0/8/0' and than we grep output of 'vppctl sh tap-inject'
# command by this name:
#   root@ubuntu-server-1:/# vppctl sh tap-inject
#       GigabitEthernet0/8/0 -> vpp0
#       GigabitEthernet0/9/0 -> vpp1
def dev_id_to_tap(dev_id, check_vpp_state=False, print_log=True):
    """Convert Bus address into TAP name.

    :param dev_id:          Bus address.
    :param check_vpp_state: If True ensure that vpp runs so taps are available.
    :returns: Linux TAP interface name.
    """
    dev_id_full = dev_id_to_full(dev_id)

    if check_vpp_state:
        is_assigned = is_interface_assigned_to_vpp(dev_id_full)
        vpp_runs    = vpp_does_run()
        if not (is_assigned and vpp_runs):
            if print_log:
                fwglobals.log.debug('dev_id_to_tap(%s): is_assigned=%s, vpp_runs=%s' %
                    (dev_id, str(is_assigned), str(vpp_runs)))
            return None

    cache = fwglobals.g.cache.dev_id_to_vpp_tap_name
    tap = cache.get(dev_id_full)
    if tap:
        return tap

    vpp_if_name = dev_id_to_vpp_if_name(dev_id_full)
    if vpp_if_name is None:
        return None
    tap = vpp_if_name_to_tap(vpp_if_name)
    if tap:
        cache[dev_id_full] = tap
    return tap

def set_dev_id_to_tap(dev_id, tap):
    """Update cache.

    :param dev_id:          Bus address.
    :param tap:             TAP name
    """
    if not dev_id:
        return

    dev_id_full = dev_id_to_full(dev_id)
    cache = fwglobals.g.cache.dev_id_to_vpp_tap_name
    cache[dev_id_full] = tap

def tunnel_to_vpp_if_name(params):
    """Finds the name of the tunnel loopback interface in vpp.
    We exploit vpp internals to do it in simple way.

    :param params: parameters of tunnel taken from the router configuration database.
                   It is 'params' field of the 'add-tunnel' request.
    :returns: name of the tunnel loopback interface in vpp.
    """
    vpp_if_name = 'loop%d' % (params['tunnel-id']*2)
    return vpp_if_name

def peer_tunnel_to_vpp_if_name(params):
    """Finds the name of the peer tunnel ipip interface in vpp.
    We exploit vpp internals to do it in simple way.

    :param params: parameters of tunnel taken from the router configuration database.
                   It is 'params' field of the 'add-tunnel' request.
    :returns: name of the tunnel loopback interface in vpp.
    """
    # The peer tunnel uses two vpp interfaces - the loopback interface to
    # provide access to peer tunnel from Linux, and the ip-ip tunnel interface.
    # The first one has 'loopX' name, the other one - 'ipipX' name, where
    # X is (tunnel-id * 2).
    #
    vpp_if_name = 'ipip%d' % (params['tunnel-id']*2)
    return vpp_if_name

def tunnel_to_tap(params):
    """Retrieves TAP name of the tunnel loopback interface that is exposed to Linux.

    :param params: parameters of tunnel taken from the router configuration database.
                   It is 'params' field of the 'add-tunnel' request.
    :returns: name of the tunnel loopback interface in Linux.
    """
    vpp_if_name = tunnel_to_vpp_if_name(params)
    return vpp_if_name_to_tap(vpp_if_name)

def vpp_enable_tap_inject():
    """Enable tap-inject plugin
     """
    out = _vppctl_read("enable tap-inject").strip()
    if out == None:
        return (False, "'vppctl enable tap-inject' failed")

    if not vpp_does_run():
        return (False, "VPP is not running")

    taps = _vppctl_read("show tap-inject").strip()

    # check if tap-inject is configured and enabled
    if taps and 'not enabled' in taps:
        return (False, "%s" % taps)

    return (True, None)

# 'vpp_get_tap_info' returns mappings between TAPs and VPP interfaces.
# To do that it greps output of 'vppctl sh tap-inject' by the tap interface name:
#   root@ubuntu-server-1:/# vppctl sh tap-inject
#       GigabitEthernet0/8/0 -> vpp0
#       GigabitEthernet0/9/0 -> vpp1
def vpp_get_tap_info(vpp_if_name=None, vpp_sw_if_index=None, tap_if_name=None):
    """Get tap information

     :returns: tap info in list
     """
    if not vpp_does_run():
        fwglobals.log.debug("vpp_get_tap_info: VPP is not running")
        return ({}, {}, 'None')

    if vpp_if_name:
        vppctl_cmd = f"show tap-inject {vpp_if_name}"
    elif vpp_sw_if_index:
        vppctl_cmd = f"show tap-inject sw_if_index {vpp_sw_if_index}"
    elif tap_if_name:
        vppctl_cmd = f"show tap-inject tap_name {tap_if_name}"
    else:
        fwglobals.log.debug("vpp_get_tap_info: no arguments provided")
        return (None, None)

    taps = _vppctl_read(vppctl_cmd).strip()
    if not taps:
        fwglobals.log.debug(f"vpp_get_tap_info: '{vppctl_cmd}' returned nothing")
        return (None, None)

    # check if tap-inject is configured and enabled
    if 'not enabled' in taps:
        fwglobals.log.debug("vpp_get_tap_info: tap-inject disabled")
        return (None, None)

    tap_lines = taps.splitlines()

    # the output of "show tap-inject" might be messy,
    # Here are some examples we dealt with during the time:
    # [
    # '_______    _        _   _____  ___ ',
    # ' __/ __/ _ \\  (_)__    | | / / _ \\/ _ \\',
    # ' _/ _// // / / / _ \\   | |/ / ___/ ___/',
    # ' /_/ /____(_)_/\\___/   |___/_/  /_/    ',
    # '',
    # 'vpp# loop16300 -> vpp3',
    # 'vmxnet3-0/3/0/0 -> vpp0',
    # 'GigabitEthernet4/0/1 -> vpp0',
    # 'tapcli-0 -> vpp5',
    # 'tap0 -> vpp3'
    # ]
    # we use a regex check to get the closest words before and after the arrow
    for line in tap_lines:
        tap_info = re.search(r'([/\w-]+) -> ([\S]+)', line)
        if tap_info:
            vpp_if_name = tap_info.group(1)
            tap = tap_info.group(2)
            return (vpp_if_name, tap)

    fwglobals.log.debug("vpp_get_tap_info(vpp_if_name=%s, vpp_sw_if_index=%s, tap_if_name=%s): interface not found: %s" % \
        (str(vpp_if_name), str(vpp_sw_if_index), str(tap_if_name), str(taps)))
    return (None, None)

def vpp_get_tap_mapping():
    """Get tap mapping

     :returns: tap info in list
     """
    vpp_loopback_name_to_tunnel_name = {}
    if not vpp_does_run():
        fwglobals.log.debug("vpp_get_tap_mapping: VPP is not running")
        return {}

    taps = _vppctl_read("show tap-inject map interface").strip()
    if not taps:
        fwglobals.log.debug("vpp_get_tap_mapping: no TAPs configured")
        return {}

    taps = taps.splitlines()

    for line in taps:
        tap_info = re.search("([/\w-]+) -> ([\S]+)", line)
        if tap_info:
            vpp_if_name_dst = tap_info.group(1)
            vpp_if_name_src = tap_info.group(2)
            vpp_loopback_name_to_tunnel_name[vpp_if_name_dst] = vpp_if_name_src

    return vpp_loopback_name_to_tunnel_name

# 'tap_to_vpp_if_name' function maps name of vpp tap interface in Linux, e.g. vpp0,
# into name of the vpp interface.
def tap_to_vpp_if_name(tap):
    """Convert Linux interface created by tap-inject into VPP interface name.

     :param tap:  Interface created in linux by tap-inject.

     :returns: Vpp interface name.
     """
    vpp_if_name, _ = vpp_get_tap_info(tap_if_name=tap)
    return vpp_if_name

# 'vpp_if_name_to_tap' function maps name of interface in VPP, e.g. loop0,
# into name of correspondent tap interface in Linux.
def vpp_if_name_to_tap(vpp_if_name):
    """Convert VPP interface name into Linux TAP interface name.

     :param vpp_if_name:  interface name.

     :returns: Linux TAP interface name.
     """
    # Try to fetch name from cache firstly.
    #
    tap_if_name = fwglobals.g.db.get('router_api', {}).get('vpp_if_name_to_tap_if_name', {}).get(vpp_if_name)
    if tap_if_name:
        return tap_if_name

    # Now go to the heavy route.
    #
    _, tap_if_name = vpp_get_tap_info(vpp_if_name=vpp_if_name)
    return tap_if_name

def generate_linux_interface_short_name(prefix, linux_if_name, max_length=15):
    """
    The interface name in Linux cannot be more than 15 letters.
    So, we calculate the length of the prefix plus the interface name.
    If they are more the 15 letters, we cutting the needed letters from the beginning of the Linux interface name.
    We cut from the begging because the start of the interface name might be the same as other interfaces (eth1, eth2),
    They usually different by the end of the name

    :param prefix: prefix to add to the interface name

    :param linux_if_name: name of the linux interface to create interface for

    :returns: interface name to use.
    """
    new_name = '%s_%s' % (prefix, linux_if_name)
    if len(new_name) > max_length:
        letters_to_cat = len(new_name) - 15
        new_name = '%s_%s' % (prefix, linux_if_name[letters_to_cat:])
    return new_name

def linux_tap_by_interface_name(linux_if_name):
    try:
        lines = subprocess.check_output("sudo ip link | grep %s" % generate_linux_interface_short_name("tap", linux_if_name), shell=True).decode().splitlines()
        for line in lines:
            words = line.split(': ')
            return words[1]
    except:
        return None

def vpp_tap_connect(linux_tap_if_name):
    """Run vpp tap connect command.
      This command will create a linux tap interface and also tapcli interface in vpp.
     :param linux_tap_if_name: name to be assigned to linux tap device

     :returns: VPP tap interface name.
     """

    vppctl_cmd = "tap connect %s" % linux_tap_if_name
    fwglobals.log.debug("vppctl " + vppctl_cmd)
    subprocess.check_call("sudo vppctl %s" % vppctl_cmd, shell=True)

def vpp_sw_if_index_to_name(sw_if_index):
    """Convert VPP sw_if_index into VPP interface name.

     :param sw_if_index:      VPP sw_if_index.

     :returns: VPP interface name.
     """
    # Try to fetch name from cache firstly.
    #
    vpp_if_name = fwglobals.g.db.get('router_api', {}).get('sw_if_index_to_vpp_if_name', {}).get(sw_if_index)
    if vpp_if_name:
        return vpp_if_name

    # Now go to the heavy route.
    #
    sw_interfaces = fwglobals.g.router_api.vpp_api.call('sw_interface_dump', sw_if_index=sw_if_index)
    if not sw_interfaces:
        fwglobals.log.debug(f"vpp_sw_if_index_to_name({sw_if_index}): not found")
        return None
    return sw_interfaces[0].interface_name.rstrip(' \t\r\n\0')

def vpp_if_name_to_sw_if_index(vpp_if_name, type):
    """Convert VPP interface name into VPP sw_if_index.

     :param vpp_if_name:      VPP interface name.
     :param type:             Interface type.

     :returns: VPP sw_if_index.
     """
    router_api_db  = fwglobals.g.db['router_api']
    cache_by_name  = router_api_db['vpp_if_name_to_sw_if_index'][type]
    sw_if_index  = cache_by_name[vpp_if_name]
    return sw_if_index

def vpp_sw_if_index_to_tap(sw_if_index):
    """Convert VPP sw_if_index into Linux TAP interface name created by 'vppctl enable tap-inject' command.

     :param sw_if_index:      VPP sw_if_index.

     :returns: Linux TAP interface name.
     """
    # Try to fetch name from cache firstly.
    #
    tap_if_name = fwglobals.g.db.get('router_api', {}).get('sw_if_index_to_tap_if_name', {}).get(sw_if_index)
    if tap_if_name:
        return tap_if_name

    # Now go to the heavy route.
    #
    _, tap_if_name = vpp_get_tap_info(vpp_sw_if_index=sw_if_index)
    return tap_if_name

def vpp_get_interface_status(sw_if_index):
    """Get VPP interface state.

     :param sw_if_index:      VPP sw_if_index.

     :returns: Status.
     """
    flags = 0
    status = 'down'

    try:
        interfaces = fwglobals.g.router_api.vpp_api.call('sw_interface_dump', sw_if_index=sw_if_index)
        if len(interfaces) == 1:
            flags = interfaces[0].flags
            # flags are equal to IF_STATUS_API_FLAG_LINK_UP|IF_STATUS_API_FLAG_ADMIN_UP when interface is up
            # and flags is equal to 0 when interface is down
            status = 'down' if flags == 0 else 'up'
    except Exception as e:
        fwglobals.log.debug("vpp_get_interface_state: %s" % str(e))

    return status

def _vppctl_read(cmd, wait=True):
    """Read command from VPP.

    :param cmd:       Command to execute (not including vppctl).
    :param wait:      Whether to wait until command succeeds.

    :returns: Output returned bu vppctl.
    """

    # Give one optimistic shot before going into cycles
    try:
        output = subprocess.check_output("vppctl " + cmd, shell=True).decode()
        return output
    except Exception as e:
        fwglobals.log.debug(f"'vppctl {cmd}' failed: {str(e)}, start retrials")
        pass

    retries = 200
    retries_sleep = 1
    if wait == False:
        retries = 1
        retries_sleep = 0
    # make sure socket exists
    for _ in range(retries):
        if os.path.exists("/run/vpp/cli.sock"):
            break
        time.sleep(retries_sleep)
    if not os.path.exists("/run/vpp/cli.sock"):
        return None
    # make sure command succeeded, try up to 200 iterations
    for _ in range(retries):
        try:
            _ = open(os.devnull, 'r+b', 0)
            handle = os.popen('sudo vppctl ' + cmd + ' 2>/dev/null')
            data = handle.read()
            retcode = handle.close()
            if retcode == None or retcode == 0:  # Exit OK
                break
        except:
            return None
        time.sleep(retries_sleep)
    if retcode: # not succeeded after 200 retries
        return None
    return data

def _parse_vppname_map(s, valregex, keyregex):
    """Find key and value in a string using regex.

    :param s:               String.
    :param valregex:        Value.
    :param keyregex:        Key.

    :returns: Error message and status code.
    """
    # get value
    r = re.search(valregex,s)
    if r!=None: val_data = r.group(1)
    else: return (None, None)   # val not found, don't add and return
    # get key
    r = re.search(keyregex,s)
    if r!=None: key_data = r.group(1)
    else: return (None, None)   # key not found, don't add and return
    # Return values
    return (key_data, val_data)

def stop_vpp():
    """Stop VPP and rebind Linux interfaces.

     :returns: Error message and status code.
     """

    call_applications_hook('router_is_being_to_stop')

    dpdk_ifs = []
    dpdk.devices = {}
    dpdk.dpdk_drivers = ["igb_uio", "vfio-pci", "uio_pci_generic"]
    dpdk.check_modules()
    dpdk.get_nic_details()
    os.system('sudo systemctl stop vpp')
    os.system('sudo systemctl stop frr')
    for d,v in list(dpdk.devices.items()):
        if "Driver_str" in v:
            if v["Driver_str"] in dpdk.dpdk_drivers:
                dpdk.unbind_one(v["Slot"], False)
                dpdk_ifs.append(d)
        elif "Module_str" != "":
            dpdk_ifs.append(d)
    # refresh nic_details
    dpdk.get_nic_details()
    for d in dpdk_ifs:
        drivers_unused = dpdk.devices[d]["Module_str"].split(',')
        #print ("Drivers unused=" + str(drivers_unused))
        for drv in drivers_unused:
            #print ("Driver=" + str(drv))
            if drv not in dpdk.dpdk_drivers:
                dpdk.bind_one(dpdk.devices[d]["Slot"], drv, False)
                break
    fwstats.update_state(False)
    netplan_apply('stop_vpp')

    call_applications_hook('router_is_stopped')

    with FwIKEv2() as ike:
        ike.clean()
    with FwPppoeClient(fwglobals.g.PPPOE_DB_FILE, fwglobals.g.PPPOE_CONFIG_PATH, fwglobals.g.PPPOE_CONFIG_PROVIDER_FILE) as pppoe:
        pppoe.reset_interfaces()

def reset_device_config():
    """Reset router config by cleaning DB and removing config files.

     :returns: None.
     """
    with FwRouterCfg(fwglobals.g.ROUTER_CFG_FILE) as router_cfg:
        router_cfg.clean()
    with FwSystemCfg(fwglobals.g.SYSTEM_CFG_FILE) as system_cfg:
        system_cfg.clean()
    if os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
        os.remove(fwglobals.g.ROUTER_STATE_FILE)
    if os.path.exists(fwglobals.g.FRR_CONFIG_FILE):
        os.remove(fwglobals.g.FRR_CONFIG_FILE)
    if os.path.exists(fwglobals.g.FRR_OSPFD_FILE):
        os.remove(fwglobals.g.FRR_OSPFD_FILE)
    if os.path.exists(fwglobals.g.VPP_CONFIG_FILE_BACKUP):
        shutil.copyfile(fwglobals.g.VPP_CONFIG_FILE_BACKUP, fwglobals.g.VPP_CONFIG_FILE)
    elif os.path.exists(fwglobals.g.VPP_CONFIG_FILE_RESTORE):
        shutil.copyfile(fwglobals.g.VPP_CONFIG_FILE_RESTORE, fwglobals.g.VPP_CONFIG_FILE)
    if os.path.exists(fwglobals.g.CONN_FAILURE_FILE):
        os.remove(fwglobals.g.CONN_FAILURE_FILE)
    with FwMultilink(fwglobals.g.MULTILINK_DB_FILE) as db_multilink:
        db_multilink.clean()
    with FwPolicies(fwglobals.g.POLICY_REC_DB_FILE) as db_policies:
        db_policies.clean()

    with FwTrafficIdentifications(fwglobals.g.TRAFFIC_ID_DB_FILE) as traffic_db:
        traffic_db.clean()
    fwnetplan.restore_linux_netplan_files()
    with FwIKEv2() as ike:
        ike.clean()

    with FwPppoeClient(fwglobals.g.PPPOE_DB_FILE, fwglobals.g.PPPOE_CONFIG_PATH, fwglobals.g.PPPOE_CONFIG_PROVIDER_FILE) as pppoe:
        pppoe.reset_interfaces()

    if 'lte' in fwglobals.g.db:
        fwglobals.g.db['lte'] = {}

    reset_router_api_db_sa_id() # sa_id-s are used in translations of router configuration, so clean them too.
    reset_router_api_db(enforce=True)

    restore_dhcpd_files()

    fwglobals.g.applications_db.clear()

def reset_router_api_db_sa_id():
    router_api_db = fwglobals.g.db['router_api'] # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
    router_api_db['sa_id'] = 0
    fwglobals.g.db['router_api'] = router_api_db

def reset_router_api_db(enforce=False):

    if not 'router_api' in fwglobals.g.db:
        fwglobals.g.db['router_api'] = {}
    router_api_db = fwglobals.g.db['router_api'] # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict

    if not 'sa_id' in fwglobals.g.db['router_api'] or enforce:
        router_api_db['sa_id'] = 0
    if not 'bridges' in fwglobals.g.db['router_api'] or enforce:
        #
        # Bridge domain id in VPP is up to 24 bits (see #define L2_BD_ID_MAX ((1<<24)-1))
        # In addition, we use bridge domain id as id for loopback BVI interface set on this bridge.
        # BVI interface is the only interface on the bridge that might have IP address.
        # As loopback interface id is limitied by 16,384 in vpp\src\vnet\ethernet\interface.c:
        #   #define LOOPBACK_MAX_INSTANCE		(16 * 1024),
        # we choose range for bridge id to be 16300-16384.
        # Note vppsb creates taps for even names only e.g. loop10010
        # (due to flexiWAN specific logic, see tap_inject_interface_add_del()),
        # hence step of '2' in the range.
        #
        min_id, max_id = fwglobals.g.LOOPBACK_ID_SWITCHES
        router_api_db['bridges'] = {
            'vacant_ids': list(range(min_id, max_id, 2))
        }
    if not 'sw_if_index_to_vpp_if_name' in router_api_db or enforce:
        router_api_db['sw_if_index_to_vpp_if_name'] = {}
    if not 'vpp_if_name_to_sw_if_index' in router_api_db or enforce:
        router_api_db['vpp_if_name_to_sw_if_index'] = {}
    vpp_if_name_to_sw_if_index_keys = ['tunnel', 'peer-tunnel', 'lan', 'switch-lan', 'wan', 'switch']
    for key in vpp_if_name_to_sw_if_index_keys:
        if not key in router_api_db['vpp_if_name_to_sw_if_index'] or enforce:
            router_api_db['vpp_if_name_to_sw_if_index'][key] = {}
    if not 'vpp_if_name_to_tap_if_name' in router_api_db or enforce:
        router_api_db['vpp_if_name_to_tap_if_name'] = {}
    if not 'sw_if_index_to_tap_if_name' in router_api_db or enforce:
        router_api_db['sw_if_index_to_tap_if_name'] = {}
    fwglobals.g.db['router_api'] = router_api_db

def print_system_config(full=False):
    """Print router configuration.

     :returns: None.
     """
    with FwSystemCfg(fwglobals.g.SYSTEM_CFG_FILE) as system_cfg:
        cfg = system_cfg.dumps(full=full)
        print(cfg)

def print_device_config_signature():
    cfg = get_device_config_signature()
    print(cfg)

def print_applications_db():
    out = []
    try:
        for key in sorted(list(fwglobals.g.applications_db.keys())):
            obj = {}
            obj[key] = fwglobals.g.applications_db[key]
            out.append(obj)
        cfg = json.dumps(out, indent=2, sort_keys=True)
        print(cfg)
    except Exception as e:
        fwglobals.log.error(str(e))
        pass

def print_router_config(basic=True, full=False, multilink=False):
    """Print router configuration.

     :returns: None.
     """
    with FwRouterCfg(fwglobals.g.ROUTER_CFG_FILE) as router_cfg:
        if basic:
            cfg = router_cfg.dumps(full=full, escape=['add-application','add-multilink-policy'])
        elif multilink:
            cfg = router_cfg.dumps(full=full, types=['add-application','add-multilink-policy'])
        else:
            cfg = ''
        print(cfg)

def print_general_database():
    out = []
    try:
        for key in sorted(list(fwglobals.g.db.keys())):
            obj = {}
            obj[key] = fwglobals.g.db[key]
            out.append(obj)
        cfg = json.dumps(out, indent=2, sort_keys=True)
        print(cfg)
    except Exception as e:
        fwglobals.log.error(str(e))
        pass
    
def update_device_config_signature(request):
    """Updates the database signature.
    This function assists the database synchronization feature that keeps
    the configuration set by user on the flexiManage in sync with the one
    stored on the flexiEdge device.
        The initial signature of the database is empty string. Than on every
    successfully handled request it is updated according following formula:
            signature = sha1(signature + request)
    where both signature and delta are strings.

    :param request: the last successfully handled router configuration
                    request, e.g. add-interface, remove-tunnel, etc.
                    As configuration database signature should reflect
                    the latest configuration, it should be updated with this
                    request.
    """
    current     = fwglobals.g.db['signature']
    delta       = json.dumps(request, separators=(',', ':'), sort_keys=True)
    update      = current + delta
    hash_object = hashlib.sha1(update.encode())
    new         = hash_object.hexdigest()

    fwglobals.g.db['signature'] = new

    log_line = "sha1: new=%s, current=%s, delta=%s" % (str(new), str(current), str(delta))
    fwglobals.log.debug(log_line)
    logger = fwglobals.g.get_logger(request)
    if logger:
        logger.debug(log_line)

def get_device_config_signature():
    if not 'signature' in fwglobals.g.db:
        reset_device_config_signature()
    return fwglobals.g.db['signature']

def reset_device_config_signature(new_signature=None, log=True):
    """Resets configuration signature to the empty sting.

    :param new_signature: string to be used as a signature of the configuration.
            If not provided, the empty string will be used.
            When flexiManage detects discrepancy between this signature
            and between signature that it calculated, it sends
            the 'sync-device' request in order to apply the user
            configuration onto device. On successfull sync the signature
            is reset to the empty string on both sides.
    :param log: if False the reset will be not logged.
    """
    old_signature = fwglobals.g.db.get('signature', '<none>')
    new_signature = "" if new_signature == None else new_signature
    fwglobals.g.db['signature'] = new_signature
    if log:
        fwglobals.log.debug("reset signature: '%s' -> '%s'" % \
                            (old_signature, new_signature))

def dump_router_config(full=False):
    """Dumps router configuration into list of requests that look exactly
    as they would look if were received from server.

    :param full: return requests together with translated commands.

    :returns: list of 'add-X' requests.
    """
    cfg = []
    with FwRouterCfg(fwglobals.g.ROUTER_CFG_FILE) as router_cfg:
        cfg = router_cfg.dump(full)
    return cfg

def dump_system_config(full=False):
    """Dumps system configuration into list of requests that look exactly
    as they would look if were received from server.

    :param full: return requests together with translated commands.

    :returns: list of 'add-X' requests.
    """
    cfg = []
    with FwSystemCfg(fwglobals.g.SYSTEM_CFG_FILE) as system_cfg:
        cfg = system_cfg.dump(full)
    return cfg

def get_router_status():
    """Check if VPP is running.

     :returns: VPP state.
     """
    reason = ''
    if os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
        state = 'failed'
        with open(fwglobals.g.ROUTER_STATE_FILE, 'r') as f:
            reason = f.read()
    elif vpp_pid():
        state = 'running'
    else:
        state = 'stopped'
    return (state, reason)

def is_router_running():
    """Check if VPP is running.

     :returns: True/False.
    """
    if hasattr(fwglobals.g, 'router_api'):
        return fwglobals.g.router_api.state_is_started() or fwglobals.g.router_api.state_is_starting_stopping()
    return False

def _get_group_delimiter(lines, delimiter):
    """Helper function to iterate through a group lines by delimiter.

    :param lines:       List of text lines.
    :param delimiter:   Regex to group lines by.

    :returns: None.
    """
    data = []
    for line in lines:
        if re.match(delimiter,line)!=None:
            if data:
                yield data
                data = []
        data.append(line)
    if data:
        yield data

def _parse_add_if(s, res):
    """Helper function that parse fields from a given interface data and add to res.

    :param s:       String with interface data.
    :param res:     Dict to store the result in.

    :returns: None.
    """
    # get interface name
    r = re.search(r"^(\w[^\s]+)\s+\d+\s+(\w+)",s)
    if r!=None and r.group(2)=="up": if_name = r.group(1)
    else: return    # Interface not found, don't add and return
    # rx packets
    r = re.search(r" rx packets\s+(\d+)?",s)
    if r!=None: rx_packets = r.group(1)
    else: rx_packets = 0
    # tx packets
    r = re.search(r" tx packets\s+(\d+)?",s)
    if r!=None: tx_packets = r.group(1)
    else: tx_packets = 0
    # rx bytes
    r = re.search(r" rx bytes\s+(\d+)?",s)
    if r!=None: rx_bytes = r.group(1)
    else: rx_bytes = 0
    # tx bytes
    r = re.search(r" tx bytes\s+(\d+)?",s)
    if r!=None: tx_bytes = r.group(1)
    else: tx_bytes = 0
    # Add data to res
    res[if_name] = {'rx_pkts':int(rx_packets), 'tx_pkts':int(tx_packets), 'rx_bytes':int(rx_bytes), 'tx_bytes':int(tx_bytes)}

def get_vpp_if_count():
    """Get number of VPP interfaces.

     :returns: Dictionary with results.
     """
    shif = _vppctl_read('sh int', wait=False)
    if shif == None:  # Exit with an error
        return None
    data = shif.splitlines()
    res = {}
    for interface in _get_group_delimiter(data, r"^\w.*?\s"):
        # Contains data for a given interface
        data = ''.join(interface)
        _parse_add_if(data, res)
    return res

def ip_str_to_bytes(ip_str):
    """Convert IP address string into bytes.

     :param ip_str:         IP address string.

     :returns: IP address in bytes representation.
     """
    # take care of possible netmask, like in 192.168.56.107/24
    addr_ip = ip_str.split('/')[0]
    addr_len = int(ip_str.split('/')[1]) if len(ip_str.split('/')) > 1 else 32
    return socket.inet_pton(socket.AF_INET, addr_ip), addr_len

def ports_str_to_range(ports_str):
    """Convert Ports string range into ports_from and ports_to

     :param ports_str:         Ports range string.

     :returns: port_from and port_to
     """
    ports_range = ports_str.split('-')
    port_from = port_to = int(ports_range[0])
    if len(ports_range) > 1:
        port_to = int(ports_range[1])
    return port_from, port_to

def mac_str_to_bytes(mac_str):      # "08:00:27:fd:12:01" -> bytes
    """Convert MAC address string into bytes.

     :param mac_str:        MAC address string.

     :returns: MAC address in bytes representation.
     """
    return binascii.a2b_hex(mac_str.replace(':', ''))

def is_python2():
    """Checks if it is Python 2 version.

     :returns: 'True' if Python2 and 'False' otherwise.
     """
    ret = True if sys.version_info < (3, 0) else False
    return ret

def hex_str_to_bytes(hex_str):
    """Convert HEX string into bytes.

     :param hex_str:        HEX string.

     :returns: Bytes array.
     """
    if is_python2():
        return hex_str.decode("hex")
    else:
        return bytes.fromhex(hex_str)

def yaml_dump(var):
    """Convert object into YAML string.

    :param var:        Object.

    :returns: YAML string.
    """
    str = yaml.dump(var, canonical=True)
    str = re.sub(r"\n[ ]+: ", ' : ', str)
    return str

#
def valid_message_string(str):
    """Ensure that string contains only allowed by management characters.
    To mitigate security risks management limits text that might be received
    within responses to the management-to-device requests.
    This function ensure the compliance of string to the management requirements.

    :param str:        String.

    :returns: 'True' if valid and 'False' otherwise.
    """
    if len(str) > 200:
        fwglobals.log.excep("valid_message_string: string is too long")
        return False
    # Enable following characters only: [0-9],[a-z],[A-Z],'-','_',' ','.',':',',', etc.
    tmp_str = re.sub(r'[-_.,:0-9a-zA-Z_" \']', '', str)
    if len(tmp_str) > 0:
        fwglobals.log.excep("valid_message_string: string has not allowed characters")
        return False
    return True

def obj_dump(obj, print_obj_dir=False):
    """Print object fields and values. Used for debugging.

     :param obj:                Object.
     :param print_obj_dir:      Print list of attributes and methods.

     :returns: None.
     """
    callers_local_vars = list(inspect.currentframe().f_back.f_locals.items())
    obj_name = [var_name for var_name, var_val in callers_local_vars if var_val is obj][0]
    print('========================== obj_dump start ==========================')
    print("obj=%s" % obj_name)
    print("str(%s): %s" % (obj_name, str(obj)))
    if print_obj_dir:
        print("dir(%s): %s" % (obj_name, str(dir(obj))))
    obj_dump_attributes(obj)
    print('========================== obj_dump end ==========================')

def obj_dump_attributes(obj, level=1):
    """Print object attributes.

    :param obj:          Object.
    :param level:        How many levels to print.

    :returns: None.
    """
    for a in dir(obj):
        if re.match('__.+__', a):   # Escape all special attributes, like __abstractmethods__, for which val = getattr(obj, a) might fail
            continue
        val = getattr(obj, a)
        if isinstance(val, (int, float, str, list, dict, set, tuple)):
            print(level*' ' + a + '(%s): ' % str(type(val)) + str(val))
        else:
            print(level*' ' + a + ':')
            obj_dump_attributes(val, level=level+1)

def vpp_startup_conf_remove_param(filename, path):
    with FwStartupConf(filename) as conf:
        conf.del_simple_param(path)

def vpp_startup_conf_add_nopci(vpp_config_filename):
    p = FwStartupConf(vpp_config_filename)
    config = p.get_root_element()

    if config['dpdk'] == None:
        tup = p.create_element('dpdk')
        config.append(tup)
    if p.get_element(config['dpdk'], 'no-pci') == None:
        config['dpdk'].append(p.create_element('no-pci'))
        p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_startup_conf_remove_nopci(vpp_config_filename):
    p = FwStartupConf(vpp_config_filename)
    config = p.get_root_element()

    if config['dpdk'] == None:
       return (True, None)
    if p.get_element(config['dpdk'], 'no-pci') == None:
        return (True, None)
    p.remove_element(config['dpdk'], 'no-pci')
    p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_startup_conf_add_devices(vpp_config_filename, devices):
    p = FwStartupConf(vpp_config_filename)
    config = p.get_root_element()

    if config['dpdk'] == None:
        tup = p.create_element('dpdk')
        config.append(tup)

    for dev in devices:
        dev_short = dev_id_to_short(dev)
        dev_full = dev_id_to_full(dev)
        addr_type, addr_short = dev_id_parse(dev_short)
        addr_type, addr_full = dev_id_parse(dev_full)
        if addr_type == "pci":
            old_config_param = 'dev %s' % addr_full
            new_config_param = 'dev %s' % addr_short
            if p.get_element(config['dpdk'],old_config_param) != None:
                p.remove_element(config['dpdk'], old_config_param)
            if p.get_element(config['dpdk'],new_config_param) == None:
                tup = p.create_element(new_config_param)
                config['dpdk'].append(tup)

    p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_startup_conf_remove_devices(vpp_config_filename, devices):
    p = FwStartupConf(vpp_config_filename)
    config = p.get_root_element()

    if config['dpdk'] == None:
        return
    for dev in devices:
        dev = dev_id_to_short(dev)
        _, addr = dev_id_parse(dev)
        config_param = 'dev %s' % addr
        key = p.get_element(config['dpdk'],config_param)
        if key:
            p.remove_element(config['dpdk'], key)

    p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def is_interface_without_dev_id(if_name):
    """Check if the given interface is expected to have no dev_id

    :param if_name:  Interface name tpo check.

    :returns: Boolean indicates if expected to have no dev_id
    """
    if not if_name:
        return True

    if if_name == 'lo':
        return True

    # tap interface that created for LTE interface has no dev_id
    if if_name.startswith('tap_'):
        return True

    # bridge interface that created for WiFi has no dev_id
    if if_name.startswith('br_'):
        return True

    # PPPoE interface has no dev_id
    if if_name.startswith('ppp'):
        return True

    return False

def get_lte_interfaces_names():
    names = []
    interfaces = psutil.net_if_addrs()

    for nic_name, _ in list(interfaces.items()):
        dev_id = get_interface_dev_id(nic_name)
        if dev_id and fwlte.is_lte_interface(nic_name):
            names.append(nic_name)

    return names

def traffic_control_add_del_dev_ingress(dev_name, is_add):
    try:
        subprocess.check_call('sudo tc -force qdisc %s dev %s ingress handle ffff:' % ('add' if is_add else 'delete', dev_name), shell=True)
        return (True, None)
    except Exception:
        return (True, None)

def traffic_control_replace_dev_root(dev_name):
    try:
        subprocess.check_call('sudo tc -force qdisc replace dev %s root handle 1: htb' % dev_name, shell=True)
        return (True, None)
    except Exception:
        return (True, None)

def traffic_control_remove_dev_root(dev_name):
    try:
        subprocess.check_call('sudo tc -force qdisc del dev %s root' % dev_name, shell=True)
        return (True, None)
    except Exception:
        return (True, None)

def reset_traffic_control():
    fwglobals.log.debug('clean Linux traffic control settings')
    search = []
    lte_interfaces = get_lte_interfaces_names()

    if lte_interfaces:
        search.extend(lte_interfaces)

    for term in search:
        try:
            subprocess.check_call('sudo tc -force qdisc del dev %s root 2>/dev/null' % term, shell=True)
        except:
            pass

        try:
            subprocess.check_call('sudo tc -force qdisc del dev %s ingress handle ffff: 2>/dev/null' % term, shell=True)
        except:
            pass

    return True

def remove_linux_bridges():
    try:
        lines = subprocess.check_output('ls -l /sys/class/net/ | grep br_', shell=True).decode().splitlines()
        for line in lines:
            bridge_name = line.rstrip().split('/')[-1]
            try:
                subprocess.check_call("sudo ip link set %s down " % bridge_name, shell=True)
            except:
                pass
            try:
                subprocess.check_call('sudo brctl delbr %s' % bridge_name, shell=True)
            except:
                pass
        return True
    except:
        return True

def backup_dhcpd_files():
    try:
        cmd = 'systemctl stop isc-dhcp-server'
        fwglobals.log.debug(cmd)
        subprocess.check_call(cmd, shell=True)

        if not os.path.exists(fwglobals.g.DHCPD_CONFIG_FILE_BACKUP):
            shutil.copyfile(fwglobals.g.DHCPD_CONFIG_FILE, fwglobals.g.DHCPD_CONFIG_FILE_BACKUP)
            open(fwglobals.g.DHCPD_CONFIG_FILE, 'w').close()

        if not os.path.exists(fwglobals.g.ISC_DHCP_CONFIG_FILE_BACKUP):
            shutil.copyfile(fwglobals.g.ISC_DHCP_CONFIG_FILE, fwglobals.g.ISC_DHCP_CONFIG_FILE_BACKUP)
            open(fwglobals.g.ISC_DHCP_CONFIG_FILE, 'w').close()

    except Exception as e:
        fwglobals.log.error("backup_dhcpd_files: %s" % str(e))

def restore_dhcpd_files():
    try:
        if os.path.exists(fwglobals.g.DHCPD_CONFIG_FILE_BACKUP):
            shutil.copyfile(fwglobals.g.DHCPD_CONFIG_FILE_BACKUP, fwglobals.g.DHCPD_CONFIG_FILE)
            os.remove(fwglobals.g.DHCPD_CONFIG_FILE_BACKUP)

        if os.path.exists(fwglobals.g.ISC_DHCP_CONFIG_FILE_BACKUP):
            shutil.copyfile(fwglobals.g.ISC_DHCP_CONFIG_FILE_BACKUP, fwglobals.g.ISC_DHCP_CONFIG_FILE)
            os.remove(fwglobals.g.ISC_DHCP_CONFIG_FILE_BACKUP)

        cmd = 'systemctl restart isc-dhcp-server'
        fwglobals.log.debug(cmd)
        subprocess.check_call(cmd, shell=True)

    except Exception as e:
        fwglobals.log.error("restore_dhcpd_files: %s" % str(e))

def modify_dhcpd(is_add, params):
    """Modify /etc/dhcp/dhcpd configuration file.

    :param params:   Parameters from flexiManage.

    :returns: String with sed commands.
    """
    dev_id      = params['interface']
    range_start = params.get('range_start', '')
    range_end   = params.get('range_end', '')
    dns         = params.get('dns', {})
    mac_assign  = params.get('mac_assign', {})

    interfaces = fwglobals.g.router_cfg.get_interfaces(dev_id=dev_id)
    if not interfaces:
        return (False, "modify_dhcpd: %s was not found" % (dev_id))

    address = IPNetwork(interfaces[0]['addr'])
    router = str(address.ip)
    subnet = str(address.network)
    netmask = str(address.netmask)

    config_file = fwglobals.g.DHCPD_CONFIG_FILE

    remove_string = 'sudo sed -e "/subnet %s netmask %s {/,/}/d" ' \
                    '-i %s; ' % (subnet, netmask, config_file)

    range_string = ''
    if range_start:
        range_string = 'range %s %s;\n' % (range_start, range_end)

    if dns:
        dns_string = 'option domain-name-servers'
        for d in dns[:-1]:
            dns_string += ' %s,' % d
        dns_string += ' %s;\n' % dns[-1]
    else:
        dns_string = ''

    subnet_string = 'subnet %s netmask %s' % (subnet, netmask)
    routers_string = 'option routers %s;\n' % (router)
    dhcp_string = 'echo "' + subnet_string + ' {\n' + range_string + \
                 routers_string + dns_string + '}"' + ' | sudo tee -a %s;' % config_file

    if is_add == 1:
        exec_string = remove_string + dhcp_string
    else:
        exec_string = remove_string

    for mac in mac_assign:
        remove_string_2 = 'sudo sed -e "/host %s {/,/}/d" ' \
                          '-i %s; ' % (mac['host'], config_file)

        host_string = 'host %s {\n' % (mac['host'])
        ethernet_string = 'hardware ethernet %s;\n' % (mac['mac'])
        ip_address_string = 'fixed-address %s;\n' % (mac['ipv4'])
        mac_assign_string = 'echo "' + host_string + ethernet_string + ip_address_string + \
                            '}"' + ' | sudo tee -a %s;' % config_file

        if is_add == 1:
            exec_string += remove_string_2 + mac_assign_string
        else:
            exec_string += remove_string_2

    try:
        output = subprocess.check_output(exec_string, shell=True).decode()
    except Exception as e:
        return (False, str(e))

    return True

def vpp_multilink_update_labels(labels, remove, next_hop=None, dev_id=None, sw_if_index=None, result_cache=None):
    """Updates VPP with flexiwan multilink labels.
    These labels are used for Multi-Link feature: user can mark interfaces
    or tunnels with labels and than add policy to choose interface/tunnel by
    label where to forward packets to.

        REMARK: this function is temporary solution as it uses VPP CLI to
    configure lables. Remove it, when correspondent Python API will be added.
    In last case the API should be called directly from translation.

    :param labels:      python list of labels
    :param is_dia:      type of labels (DIA - Direct Internet Access)
    :param remove:      True to remove labels, False to add.
    :param dev_id:      Interface bus address if device to apply labels to.
    :param next_hop:    IP address of next hop.
    :param result_cache: cache, key and variable, that this function should store in the cache:
                            {'result_attr': 'next_hop', 'cache': <dict>, 'key': <key>}

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """

    ids_list = fwglobals.g.router_api.multilink.get_label_ids_by_names(labels, remove)
    ids = ','.join(map(str, ids_list))

    if dev_id:
        vpp_if_name = dev_id_to_vpp_if_name(dev_id)
    elif sw_if_index:
        vpp_if_name = vpp_sw_if_index_to_name(sw_if_index)
    else:
        return (False, "Neither 'dev_id' nor 'sw_if_index' was found in params")

    if not vpp_if_name:
        return (False, "'vpp_if_name' was not found for %s" % dev_id)

    if not next_hop:
        tap = vpp_if_name_to_tap(vpp_if_name)
        next_hop, _ = get_interface_gateway(tap)
    if not next_hop:
        return (False, "'next_hop' was not provided and there is no default gateway")

    op = 'del' if remove else 'add'

    vppctl_cmd = 'fwabf link %s label %s via %s %s' % (op, ids, next_hop, vpp_if_name)
    fwglobals.log.debug(vppctl_cmd)

    out = _vppctl_read(vppctl_cmd, wait=False)
    if out is None:
        return (False, "failed vppctl_cmd=%s" % vppctl_cmd)

    # Store 'next_hope' in cache if provided by caller.
    #
    if result_cache and result_cache['result_attr'] == 'next_hop':
        key = result_cache['key']
        result_cache['cache'][key] = next_hop

    return (True, None)


def vpp_multilink_update_policy_rule(add, links, policy_id, fallback, order,
                                     acl_id=None, priority=None, override_default_route=False,
                                     attach_to_wan=False):
    """Updates VPP with flexiwan policy rules.
    In general, policy rules instruct VPP to route packets to specific interface,
    which is marked with multilink label that noted in policy rule.

    :param params: params - rule parameters:
                        policy-id - the policy id (two byte integer)
                        labels    - labels of interfaces to be used for packet forwarding
                        remove    - True to remove rule, False to add.
                        override_default_route - If True, the policy links will be enforced,
                                    even if FIB lookup brings default route and this route
                                    does not use one of policy links.
                                    This logic is needed for the so called Branch-to-HQ topology,
                                    (another name - Internet Gateway use case), where all internet
                                    designated traffic on Branch device is pushed into tunnels
                                    that go to the Head Quarters (HQ) machine, and there it goes
                                    out to internet. On branch machine we have to ignore routes
                                    for default route packets - Internet designated packets,
                                    and to push it into tunnels to HQ machine.
                        attach_to_wan - If True the policy will be attached to the WAN
                                    interfaces. This is addition to the attachment to the LAN
                                    and the Tunnel loopback interfaces that are always performed.
                                    This logic is needed for the Branch-to-HQ topology,
                                    see explanation above. We need attachment to WAN in order
                                    to choose proper tunnel on the HQ machine for the downstream
                                    packets - packets received from internet.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    op = 'add' if add else 'del'

    bvi_vpp_name_list      = list(fwglobals.g.db['router_api']['vpp_if_name_to_sw_if_index']['switch'].keys())
    lan_vpp_name_list      = list(fwglobals.g.db['router_api']['vpp_if_name_to_sw_if_index']['lan'].keys())
    loopback_vpp_name_list = list(fwglobals.g.db['router_api']['vpp_if_name_to_sw_if_index']['tunnel'].keys())
    vpp_if_names = bvi_vpp_name_list + lan_vpp_name_list + loopback_vpp_name_list

    if attach_to_wan:
        wan_vpp_name_list  = list(fwglobals.g.db['router_api']['vpp_if_name_to_sw_if_index']['wan'].keys())
        vpp_if_names += wan_vpp_name_list


    if not add:
        for vpp_if_name in vpp_if_names:
            vppctl_cmd = 'fwabf attach ip4 del policy %d priority %d %s' % (int(policy_id), priority, vpp_if_name)
            vpp_cli_execute([vppctl_cmd])
        fwglobals.g.policies.remove_policy(policy_id)

    fallback = 'fallback drop' if re.match(fallback, 'drop') else ''
    order    = 'select_group random' if re.match(order, 'load-balancing') else ''
    override_dr = 'override_default_route' if override_default_route else ''

    if acl_id is None:
        vppctl_cmd = 'fwabf policy %s id %d %s action %s %s' % (op, policy_id, override_dr, fallback, order)
    else:
        vppctl_cmd = 'fwabf policy %s id %d acl %d %s action %s %s' % (op, policy_id, acl_id, override_dr, fallback, order)

    group_id = 1
    for link in links:
        order = {
            'priority': '',
            'load-balancing': 'random',
            'link-quality': 'quality'
        }.get(link.get('order', 'None'), '')
        labels = link['pathlabels']
        ids_list = fwglobals.g.router_api.multilink.get_label_ids_by_names(labels)
        ids = ','.join(map(str, ids_list))

        vppctl_cmd += ' group %u %s labels %s' % (group_id, order, ids)
        group_id = group_id + 1

    out = _vppctl_read(vppctl_cmd, wait=False)
    if out is None or re.search('unknown|failed|ret=-', out):
        return (False, "failed vppctl_cmd=%s: %s" % (vppctl_cmd, out))

    if add:
        fwglobals.g.policies.add_policy(policy_id, priority)
        for vpp_if_name in vpp_if_names:
            vppctl_cmd = 'fwabf attach ip4 add policy %d priority %d %s' % (int(policy_id), priority, vpp_if_name)
            vpp_cli_execute([vppctl_cmd])

    return (True, None)

def vpp_cli_execute(cmds, debug = False):
    """Map interfaces inside tap-inject plugin.

    :param cmds:     List of VPP CLI commands
    :param debug:    Print command to be executed

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """

    if not isinstance(cmds, list):
        fwglobals.log.error("vpp_cli_execute: expect list of commands")
        return (False, "Expect list of commands")

    for cmd in cmds:
        if debug:
            fwglobals.log.debug(cmd)

        out = _vppctl_read(cmd, wait=False)
        if out is None or re.search('unknown|failed|ret=-', out):
            return (False, "failed vppctl_cmd=%s" % cmd)

    return (True, None)

def vpp_set_dhcp_detect(dev_id, remove):
    """Enable/disable DHCP detect feature.

    :param params: params:
                        dev_id -  Interface device bus address.
                        remove  - True to remove rule, False to add.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    addr_type, _ = dev_id_parse(dev_id)

    if addr_type != "pci":
        return (False, "addr type needs to be a pci address")

    op = 'del' if remove else ''

    sw_if_index = dev_id_to_vpp_sw_if_index(dev_id)
    int_name = vpp_sw_if_index_to_name(sw_if_index)


    vppctl_cmd = 'set dhcp detect intfc %s %s' % (int_name, op)

    out = _vppctl_read(vppctl_cmd, wait=False)
    if out is None:
        return (False, "failed vppctl_cmd=%s" % vppctl_cmd)

    return True


def tunnel_change_postprocess(remove, vpp_if_name):
    """Tunnel add/remove postprocessing

    :param remove:      True if tunnel is removed, False if added
    :param vpp_if_name: name of the vpp software interface, e.g. "loop4"
    """
    policies = fwglobals.g.policies.policies_get()
    if len(policies) == 0:
        return

    op = 'del' if remove else 'add'

    for policy_id, priority in list(policies.items()):
        vppctl_cmd = 'fwabf attach ip4 %s policy %d priority %d %s' % (op, int(policy_id), priority, vpp_if_name)
        vpp_cli_execute([vppctl_cmd])


# The messages received from flexiManage are not perfect :)
# Some of them should be not sent at all, some of them include modifications
# that are not importants, some of them do not comply with expected format.
# Below you can find list of problems fixed by this function:
#
# 1. May-2019 - message aggregation is not well defined in protocol between
# device and server. It uses several types of aggregations:
#   1. 'start-router' aggregation: requests are embedded into 'params' field on some request
#   2. 'add-interface' aggregation: 'params' field is list of 'interface params'
#   3. 'list' aggregation: the high level message is a list of requests
# As protocol is not well defined on this matter, for now we assume
# that 'list' is used for FWROUTER_API requests only (add-/remove-/modify-),
# so it should be handled as atomic operation and should be reverted in case of
# failure of one of the requests in opposite order - from the last succeeded
# request to the first, when the whole operation is considered to be failed.
# Convert both type of aggregations into same format:
# {
#   'message': 'aggregated',
#   'params' : {
#                'requests':     <list of aggregated requests>,
#                'original_msg': <original message>
#              }
# }
# The 'original_msg' is needed for configuration hash feature - every received
# message is used for signing router configuration to enable database sync
# between device and server. Once the protocol is fixed, there will be no more
# need in this proprietary format.
#
# 2. Nov-2020 - the 'add-/modify-interface' message might include both 'dhcp': 'yes'
# and 'ip' and 'gw' fields. These IP and GW are not used by the agent, but
# change in their values causes unnecessary removal and adding back interface
# and, as a result of this,  restart of network daemon and reconnection to
# flexiManage. To avoid this we fix the received message by cleaning 'ip' and
# 'gw' fields if 'dhcp' is 'yes'. Than if the fixed message includes no other
# modified parameters, it will be ignored by the agent.
#
def fix_received_message(msg):

    def _fix_aggregation_format(msg):
        requests = []

        # 'list' aggregation
        if type(msg) == list:
            return  \
                {
                    'message': 'aggregated',
                    'params' : { 'requests': copy.deepcopy(msg) }
                }

        # 'start-router' aggregation
        # 'start-router' might include interfaces and routes. Move them into list.
        if msg['message'] == 'start-router' and 'params' in msg:

            start_router_params = copy.deepcopy(msg['params'])  # We are going to modify params, so preserve original message
            if 'interfaces' in start_router_params:
                for iface_params in start_router_params['interfaces']:
                    requests.append(
                        {
                            'message': 'add-interface',
                            'params' : iface_params
                        })
                del start_router_params['interfaces']
            if 'routes' in start_router_params:
                for route_params in start_router_params['routes']:
                    requests.append(
                        {
                            'message': 'add-route',
                            'params' : route_params
                        })
                del start_router_params['routes']

            if len(requests) > 0:
                if bool(start_router_params):  # If there are params after deletions above - use them
                    requests.append(
                        {
                            'message': 'start-router',
                            'params' : start_router_params
                        })
                else:
                    requests.append(
                        {
                            'message': 'start-router'
                        })
                return \
                    {
                        'message': 'aggregated',
                        'params' : { 'requests': requests }
                    }

        # 'add-X' aggregation
        # 'add-interface'/'remove-interface' can have actually a list of interfaces.
        # This is done by setting 'params' as a list of interface params, where
        # every element represents parameters of some interface.
        if re.match('add-|remove-', msg['message']) and type(msg['params']) is list:

            for params in msg['params']:
                requests.append(
                    {
                        'message': msg['message'],
                        'params' : copy.deepcopy(params)
                    })

            return \
                {
                    'message': 'aggregated',
                    'params' : { 'requests': requests }
                }

        # Remove NULL elements from aggregated requests, if sent by bogus flexiManage
        #
        if msg['message'] == 'aggregated':
            requests = [copy.deepcopy(r) for r in msg['params']['requests'] if r]
            return \
                {
                    'message': 'aggregated',
                    'params' : { 'requests': requests }
                }

        # No conversion is needed here.
        # We return copy of object in order to be consistent with previous 'return'-s
        # which return new object. The caller function might rely on this,
        # e.g. see the fwglobals.g.handle_request() assumes
        #
        return copy.deepcopy(msg)


    def _fix_dhcp(msg):

        def _fix_dhcp_params(params):
            if params.get('dhcp') == 'yes':
                params['addr']    = ''
                params['addr6']   = ''
                params['gateway'] = ''

        if re.match('(add|modify)-interface', msg['message']):
            _fix_dhcp_params(msg['params'])
            return msg
        if re.match('aggregated|sync-device', msg['message']):
            for request in msg['params']['requests']:
                if re.match('(add|modify)-interface', request['message']):
                    _fix_dhcp_params(request['params'])
            return msg
        return msg

    def _fix_application(msg):

        def _fix_application_compression(params):
            # Check if applications are compressed - type is string. If yes, decompress first
            if (isinstance(params['applications'], str)):
                params['applications'] = decompress_params(params['applications'])

        if msg['message'] == 'add-application':
            _fix_application_compression(msg['params'])
            return msg
        if re.match('aggregated|sync-device', msg['message']):
            for request in msg['params']['requests']:
                if request['message'] == 'add-application':
                    _fix_application_compression(request['params'])
            return msg

        return msg

    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # Order of functions is important, as the first one (_fix_aggregation_format())
    # creates clone of the received message, so the rest functions can simply
    # modify it as they wish!
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    msg = _fix_aggregation_format(msg)
    msg = _fix_dhcp(msg)
    msg = _fix_application(msg)
    return msg

def decompress_params(params):
    """ Decompress parmas from base64 to object

    :param params: base64 params

    :return: object after decompression

    """
    return json.loads(zlib.decompress(base64.b64decode(params)))

def wifi_get_available_networks(dev_id):
    """Get WIFI available access points.

    :param dev_id: Bus address of interface to get for.

    :returns: string array of essids
    """
    linux_if = dev_id_to_linux_if(dev_id)

    networks = []
    if linux_if:
        def clean(n):
            n = n.replace('"', '')
            n = n.strip()
            n = n.split(':')[-1]
            return n

        # make sure the interface is up
        cmd = 'ip link set dev %s up' % linux_if
        subprocess.check_call(cmd, shell=True)

        try:
            cmd = 'iwlist %s scan | grep ESSID' % linux_if
            networks = subprocess.check_output(cmd, shell=True).decode().splitlines()
            networks = list(map(clean, networks))
            return networks
        except subprocess.CalledProcessError:
            return networks

    return networks

def connect_to_wifi(params):
    interface_name = dev_id_to_linux_if(params['dev_id'])

    if interface_name:
        essid = params['essid']
        password = params['password']

        wpaIsRun = True if pid_of('wpa_supplicant') else False
        if wpaIsRun:
            os.system('sudo killall wpa_supplicant')
            time.sleep(3)

        # create config file
        subprocess.check_call('wpa_passphrase %s %s | sudo tee /etc/wpa_supplicant.conf' % (essid, password), shell=True)

        try:
            subprocess.check_call('wpa_supplicant -i %s -c /etc/wpa_supplicant.conf -D wext -B -C /var/run/wpa_supplicant' % interface_name, shell=True)
            time.sleep(3)

            output = subprocess.check_output('wpa_cli  status | grep wpa_state | cut -d"=" -f2', shell=True).decode().strip()
            if output == 'COMPLETED':
                if params['useDHCP']:
                    subprocess.check_call('dhclient %s' % interface_name, shell=True)
                return True
            else:
                return False
        except subprocess.CalledProcessError:
            return False

    return False

def get_inet6_by_linux_name(inf_name):
    interfaces = psutil.net_if_addrs()
    if inf_name in interfaces:
        for addr in interfaces[inf_name]:
            if addr.family == socket.AF_INET6:
                inet6 = addr.address.split('%')[0]
                if addr.netmask != None:
                    inet6 += "/" + (str(IPAddress(addr.netmask).netmask_bits()))
                return inet6

    return None

def get_ethtool_value(if_name, ethtool_key):
    """Gets requested value from ethtool command output

    :param if_name: linux interface name (e.g. enp0s3).
    :param ethtool_key: a key to retrieve the value from.

    :returns: string.
    """
    cmd = f'ethtool -i {if_name}' \
          if ethtool_key == 'driver' \
          else f'ethtool {if_name}'
    val = ''
    try:
        lines = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode().splitlines()
        for line in lines:
            if ethtool_key in line:
                val = line.split("%s: " % ethtool_key, 1)[-1]
                break
    except subprocess.CalledProcessError:
        pass

    return val

def get_interface_link_state(if_name, dev_id):
    """Gets interface link state.

    :param if_name: interface name (e.g enp0s3).
    :param dev_id:  interface bus address (e.g '0000:00:16.0').

    :returns: up if link is detected, down if not detected.
    """
    if not if_name:
        fwglobals.log.error('get_interface_link_state: if_name is empty')
        return ''
    # First, check if interface is managed by vpp (vppctl).
    # Otherwise, check as linux interface (ethtool).
    if fwglobals.g.router_api.state_is_started() and is_interface_assigned_to_vpp(dev_id):
        vpp_if_name = tap_to_vpp_if_name(if_name)
        if vpp_if_name:
            state = ''
            try:
                cmd = 'show hardware-interfaces brief'
                vppctl_read_response = _vppctl_read(cmd, False)
                if vppctl_read_response:
                    lines = vppctl_read_response.splitlines()
                    for line in lines:
                        if vpp_if_name in line:
                            # Here is an example response from the command. We are interested in the
                            # Link column, hence using index 2 after the split
                            #               Name                Idx   Link  Hardware
                            # GigabitEthernet0/3/0               1     up   GigabitEthernet0/3/0
                            #   Link speed: 1 Gbps
                            # GigabitEthernet0/8/0               2     up   GigabitEthernet0/8/0
                            #   Link speed: 1 Gbps
                            # local0                             0    down  local0
                            #   Link speed: unknown
                            state = line.split(None, 4)[2]
                            break
            except subprocess.CalledProcessError:
                pass

            if state:
                return state

    state = get_ethtool_value(if_name, 'Link detected')
    # 'Link detected' field has yes/no values, so conversion is needed
    return 'up' if state == 'yes' else 'down' if state == 'no' else ''

def get_interface_driver_by_dev_id(dev_id):
    if_name = dev_id_to_linux_if(dev_id)
    return get_interface_driver(if_name)

def get_interface_driver(if_name, cache=True):
    """Get Linux interface driver.

    :param if_name: interface name in Linux.

    :returns: driver name.
    """
    if not if_name:
        fwglobals.log.error('get_interface_driver: if_name is empty')
        return ''

    with fwglobals.g.cache.lock:
        interface = fwglobals.g.cache.linux_interfaces_by_name.get(if_name)
        if not interface or cache == False:
            fwglobals.g.cache.linux_interfaces_by_name[if_name] = {}
            interface = fwglobals.g.cache.linux_interfaces_by_name.get(if_name)

        driver = interface.get('driver')
        if driver:
            return driver

        driver = get_ethtool_value(if_name, 'driver')

        interface.update({'driver': driver})
        return driver

def is_dpdk_interface(dev_id):
    return not is_non_dpdk_interface(dev_id)

def is_non_dpdk_interface(dev_id):
    """Check if interface is not supported by dpdk.

    :param dev_id: Bus address of interface to check.

    :returns: boolean.
    """

    # 0000:06:00.00 'I210 Gigabit Network Connection' if=eth0 drv=igb unused= 192.168.1.11
    # 0000:0a:00.00 'Ethernet Connection X553 1GbE' if=eth4 drv=ixgbe unused= 10.0.0.1
    # 0000:07:00.00 'I210 Gigabit Network Connection' if=eth2 drv=igb unused=vfio-pci,uio_pci_generic =192.168.0.1

    if fwwifi.is_wifi_interface_by_dev_id(dev_id):
        return True
    if fwlte.is_lte_interface_by_dev_id(dev_id):
        return True

    return False

def frr_vtysh_run(commands, restart_frr=False, wait_after=None):
    '''Run vtysh command to configure router

    :param commands:    array of frr commands
    :param restart_frr: some OSPF configurations require restarting the service in order to apply them
    :param wait_after:  seconds to wait after successfull command execution.
                        It might be needed to give a systemt/vpp time to get updates as a result of frr update.
    '''
    try:
        shell_commands = ' -c '.join(map(lambda x: '"%s"' % x, commands))
        vtysh_cmd = f'sudo /usr/bin/vtysh -c "configure" -c {shell_commands}'

        # If frr restart is needed or if router was already started, flush down
        # the frr configuration into file, next frr restart will load it from the file.
        # If router is being started, we don't want to dump the configuration
        # on every 'add-tunnel', 'add-interface', etc in order to reduce bootup time.
        # Instead we will do that only once from within _on_start_router_after().
        #
        if restart_frr or fwglobals.g.router_api.state_is_started() == True:
            vtysh_cmd += (' ; sudo /usr/bin/vtysh -c "write" > /dev/null')

        output = os.popen(vtysh_cmd).read().splitlines()

        # in output, the first line might contains error. So we print only the first line
        fwglobals.log.debug("frr_vtysh_run: vtysh_cmd=%s, wait_after=%s, output=%s" %
                            (vtysh_cmd, str(wait_after), output[0] if output else ''))

        if restart_frr:
            os.system('systemctl restart frr')

        if wait_after:
            time.sleep(wait_after)

        return (True, None)
    except Exception as e:
        return (False, str(e))

def frr_flush_config_into_file():
    '''Dumps frr configuration into file, so if frr is crashed or is restarted
    for some reason, it could restore the state out of this file.
    '''
    try:
        write_cmd = 'sudo /usr/bin/vtysh -c "write" > /dev/null'
        output = os.popen(write_cmd).read().splitlines()
        fwglobals.log.debug(f"frr_flush_config_into_file: {str(output) if output else 'OK'}")
        return None
    except Exception as e:
        return str(e)

def frr_setup_config():
    '''Setup the /etc/frr/frr.conf file, initializes it and
    ensures that ospf is switched on in the frr configuration'''

    # Ensure that ospfd is switched on in /etc/frr/daemons.
    subprocess.check_call('if [ -n "$(grep ospfd=no %s)" ]; then sudo sed -i -E "s/ospfd=no/ospfd=yes/" %s; sudo systemctl restart frr; fi'
            % (fwglobals.g.FRR_DAEMONS_FILE,fwglobals.g.FRR_DAEMONS_FILE), shell=True)

    # Ensure that integrated-vtysh-config is disabled in /etc/frr/vtysh.conf.
    subprocess.check_call('sudo sed -i -E "s/^service integrated-vtysh-config/no service integrated-vtysh-config/" %s' % (fwglobals.g.FRR_VTYSH_FILE), shell=True)

    # Setup basics on frr.conf.
    frr_commands = [
        "password zebra",
        f"log file {fwglobals.g.OSPF_LOG_FILE} notifications",
        "log stdout notifications",
        "log syslog notifications"
    ]

    # Setup route redistribution, so the static routes configured by 'add-route'
    # requests will be propagated over tunnels to other flexiEdges.
    #
    # When we add a static route, OSPF sees it as a kernel route, not a static one.
    # That is why we are forced to set in OSPF/BGP - redistribution of *kernel* routes.
    # But, of course, we don't want to redistribute them all, so we create a filter.
    # This is content in OSPF file after the filter settings (bgp is similar):
    # router ospf
    #   redistribute kernel route-map fw-redist-ospf-rm
    # !
    # route-map fw-redist-ospf-rm permit 1
    #   match ip address fw-redist-ospf-acl
    # !
    #
    frr_commands.extend([
        f"route-map {fwglobals.g.FRR_OSPF_ROUTE_MAP} permit 1",
        f"match ip address {fwglobals.g.FRR_OSPF_ACL}",
        "router ospf", f"redistribute kernel route-map {fwglobals.g.FRR_OSPF_ROUTE_MAP}"
    ])
    frr_vtysh_run(frr_commands)

def file_write_and_flush(f, data):
    '''Wrapper over the f.write() method that flushes wrote content
    into the disk immediately

    :param f:       the python file object
    :param data:    the data to write into file
    '''
    f.write(data)
    f.flush()
    os.fsync(f.fileno())

def netplan_apply(caller_name=None):
    '''Wrapper over the f.write() method that flushes wrote content
    into the disk immediately

    :param f:       the python file object
    :param data:    the data to write into file
    '''
    try:
        # Before netplan apply go and note the default route.
        # If it will be changed as a result of netplan apply, we return True.
        #
        if fwglobals.g.fwagent:
            (_, _, dr_pci_before, _) = get_default_route()

        cmd = 'netplan apply'
        log_str = caller_name + ': ' + cmd if caller_name else cmd
        fwglobals.log.debug(log_str)
        os.system(cmd)
        time.sleep(1)  				# Give a second to Linux to configure interfaces

        # Netplan might change interface names, e.g. enp0s3 -> vpp0, or other parameters so reset cache
        #
        fwglobals.g.cache.linux_interfaces_by_name.clear()
        clear_linux_interfaces_cache()

        # IPv6 might be renable if interface name is changed using set-name
        disable_ipv6()

        # Find out if the default route was changed. If it was - reconnect agent.
        #
        if fwglobals.g.fwagent:
            (_, _, dr_pci_after, _) = get_default_route()
            if dr_pci_before != dr_pci_after:
                fwglobals.log.debug(
                    "%s: netplan_apply: default route changed (%s->%s) - reconnect" % \
                    (caller_name, dr_pci_before, dr_pci_after))
                fwglobals.g.fwagent.reconnect()

    except Exception as e:
        fwglobals.log.debug("%s: netplan_apply failed: %s" % (caller_name, str(e)))
        return False

def compare_request_params(params1, params2):
    """ Compares two dictionaries while normalizing them for comparison
    and ignoring orphan keys that have None or empty string value.
        The orphans keys are keys that present in one dict and don't
    present in the other dict, thanks to Scooter Software Co. for the term :)
        We need this function to pay for bugs in flexiManage code, where
    is provides add-/modify-/remove-X requests for same configuration
    item with inconsistent letter case, None/empty string,
    missing parameters, etc.
        Note! The normalization is done for top level keys only!
    """
    if not params1 or not params2:
        fwglobals.log.debug("compare_request_params: either params1 or params2 is None/''/[]")
        return False
    if type(params1) != type(params2):
        fwglobals.log.debug(f"compare_request_params: type(params1)={str(type(params1))} != type(params2)={str(type(params2))}")
        return False
    if type(params1) != dict:
        same = (params1 == params2)
        if not same:
            fwglobals.log.debug(f"compare_request_params: params1 != params2: param1={format(params1)}, params2={format(params2)}")
        return same

    set_keys1   = set(params1.keys())
    set_keys2   = set(params2.keys())
    keys1_only  = list(set_keys1 - set_keys2)
    keys2_only  = list(set_keys2 - set_keys1)
    keys_common = set_keys1.intersection(set_keys2)

    for key in keys1_only:
        if type(params1[key]) == bool or params1[key]:
            # params1 has non-empty string/value that does not present in params2
            fwglobals.log.debug(f"compare_request_params: params1['{key}'] does not present in params2")
            return False

    for key in keys2_only:
        if type(params2[key]) == bool or params2[key]:
            # params2 has non-empty string/value that does not present in params1
            fwglobals.log.debug(f"compare_request_params: params2['{key}'] does not present in params1")
            return False

    for key in keys_common:
        val1 = params1[key]
        val2 = params2[key]

        # If both values are neither None-s nor empty strings.
        # False booleans will be handled by next 'elif'.
        #
        if val1 and val2:
            if (type(val1) == str) and (type(val2) == str):
                if val1.lower() != val2.lower():
                    fwglobals.log.debug(f"compare_request_params: '{key}': '{val1}' != '{val2}'")
                    return False    # Strings are not equal
            elif type(val1) != type(val2):
                fwglobals.log.debug(f"compare_request_params: '{key}': {str(type(val1))} != {str(type(val2))}")
                return False        # Types are not equal
            elif val1 != val2:
                fwglobals.log.debug(f"compare_request_params: '{key}': '{format(val1)}' != '{format(val2)}'")
                return False        # Values are not equal

        # If False booleans or if one of values not exists or empty string.
        #
        elif (val1 and not val2) or (not val1 and val2):
            fwglobals.log.debug(f"compare_request_params: '{key}': '{format(val1)}' != '{format(val2)}'")
            return False

    return True

def check_if_virtual_environment():
    virt_exist = os.popen('dmesg |grep -i hypervisor| grep -i detected').read()
    if virt_exist =='':
        return False
    else:
        return True

def check_root_access():
    if os.geteuid() == 0: return True
    print("Error: requires root privileges, try to run 'sudo'")
    return False

def disable_ipv6():
    """ disable default and all ipv6
    """
    sys_cmd = 'sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null'
    rc = os.system(sys_cmd)
    if rc:
        fwglobals.log.error("Disable IPv6 all command failed : %s" % (sys_cmd))
    else:
        fwglobals.log.debug("Disable IPv6 all command successfully executed: %s" % (sys_cmd))

    sys_cmd = 'sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null'
    rc = os.system(sys_cmd)
    if rc:
        fwglobals.log.error("Disable IPv6 default command failed : %s" % (sys_cmd))
    else:
        fwglobals.log.debug("Disable IPv6 default command successfully executed: %s" % (sys_cmd))

def set_default_linux_reverse_path_filter(rpf_value):

    """ set default and all (current) rp_filter value of Linux

    : param rpf_value: RPF value to be set using the sysctl command
    """
    sys_cmd = 'sysctl -w net.ipv4.conf.all.rp_filter=%d > /dev/null' % (rpf_value)
    rc = os.system(sys_cmd)
    if rc:
        fwglobals.log.error("RPF set command failed : %s" % (sys_cmd))
    else:
        fwglobals.log.debug("RPF set command successfully executed: %s" % (sys_cmd))

    sys_cmd = 'sysctl -w net.ipv4.conf.default.rp_filter=%d > /dev/null' % (rpf_value)
    rc = os.system(sys_cmd)
    if rc:
        fwglobals.log.error("RPF set command failed : %s" % (sys_cmd))
    else:
        fwglobals.log.debug("RPF set command successfully executed: %s" % (sys_cmd))
    return rc

def set_linux_igmp_max_memberships(value = 4096):
    """ Set limit to allowed simultaneous multicast group membership (linux default is 20)
    """
    sys_cmd = 'sysctl -w net.ipv4.igmp_max_memberships=%d > /dev/null' % (value)
    rc = os.system(sys_cmd)
    if rc:
        fwglobals.log.error("Set limit of multicast group membership command failed : %s" % (sys_cmd))
    else:
        fwglobals.log.debug("Set limit of multicast group membership command successfully executed: %s" % (sys_cmd))

def set_linux_socket_max_receive_buffer_size(value = 1024000):
    """ Set maximum socket receive buffer size which may be set by using the SO_RCVBUF socket option
    """
    sys_cmd = 'sysctl -w net.core.rmem_max=%d > /dev/null' % (value)
    rc = os.system(sys_cmd)
    if rc:
        fwglobals.log.error("Set maximum socket receive buffer size command failed : %s" % (sys_cmd))
    else:
        fwglobals.log.debug("Set maximum socket receive buffer size command successfully executed: %s" % (sys_cmd))

def remove_linux_default_route(dev):
    """ Invokes 'ip route del' command to remove default route.
    """
    try:
        cmd = "ip route del default dev %s" % dev
        fwglobals.log.debug(cmd)
        ok = not subprocess.call(cmd, shell=True)
        if not ok:
            raise Exception("'%s' failed" % cmd)
        return (True, None)
    except Exception as e:
        fwglobals.log.error(str(e))
        return (False, str(e))

def vmxnet3_unassigned_interfaces_up():
    """This function finds vmxnet3 interfaces that should NOT be controlled by
    VPP and brings them up. We call these interfaces 'unassigned'.
    This hack is needed to prevent disappearing of unassigned interfaces from
    Linux, as VPP captures all down interfaces on start.

    Note for non vmxnet3 interfaces we solve this problem in elegant way - we
    just add assigned interfaces to the white list in the VPP startup.conf,
    so VPP captures only them, while ignoring the unassigned interfaces, either
    down or up. In case of vmxnet3 we can't use the startup.conf white list,
    as placing them there causes VPP to bind them to vfio-pci driver on start,
    so trial to bind them later to the vmxnet3 driver by call to the VPP
    vmxnet3_create() API fails. Hence we go with the dirty workaround of UP state.
    """
    try:
        linux_interfaces = get_linux_interfaces()
        assigned_list    = fwglobals.g.router_cfg.get_interfaces()
        assigned_dev_ids    = [params['dev_id'] for params in assigned_list]

        for dev_id in linux_interfaces:
            if not dev_id in assigned_dev_ids:
                if dev_id_is_vmxnet3(dev_id):
                    os.system("ip link set dev %s up" % linux_interfaces[dev_id]['name'])

    except Exception as e:
        fwglobals.log.debug('vmxnet3_unassigned_interfaces_up: %s (%s)' % (str(e),traceback.format_exc()))
        pass

def get_reconfig_hash():
    """ This function creates a string that holds all the information added to the reconfig
    data, and then create a hash string from it.

    : return : md5 hash result of all the data collected or empty string.
    """
    res = ''

    linux_interfaces = get_linux_interfaces()
    for dev_id in linux_interfaces:
        name = linux_interfaces[dev_id]['name']

        tap_name = linux_interfaces[dev_id].get('tap_name')
        if tap_name:
            name = tap_name

        addr = get_interface_address(name, log=False)
        gw, metric = get_interface_gateway(name)

        addr = addr.split('/')[0] if addr else ''

        mtu = str(linux_interfaces[dev_id]['mtu'])

        res += 'addr:'    + addr + ','
        res += 'gateway:' + gw + ','
        res += 'metric:'  + metric + ','
        res += 'mtu:'  + mtu + ','
        if gw and addr:
            res += 'public_ip:'   + linux_interfaces[dev_id]['public_ip'] + ','
            res += 'public_port:' + str(linux_interfaces[dev_id]['public_port']) + ','

    hash = hashlib.md5(res.encode()).hexdigest()
    fwglobals.log.debug("get_reconfig_hash: %s: %s" % (hash, res))
    return hash

def vpp_nat_interface_add(dev_id, remove):

    vpp_if_name = dev_id_to_vpp_if_name(dev_id)
    fwglobals.log.debug("NAT Interface Address - (%s is_delete: %s)" % (vpp_if_name, remove))
    if remove:
        vppctl_cmd = 'nat44 add interface address %s del' % vpp_if_name
    else:
        vppctl_cmd = 'nat44 add interface address %s' % vpp_if_name
    out = _vppctl_read(vppctl_cmd, wait=False)
    if out is None:
        fwglobals.log.debug("failed vppctl_cmd=%s" % vppctl_cmd)
        return False

def vpp_wan_tap_inject_configure(dev_id, remove):

    vpp_if_name = dev_id_to_vpp_if_name(dev_id)
    fwglobals.log.debug("Forward tap-inject WAN packets to ip4-output - \
        (%s is_delete: %s)" % (vpp_if_name, remove))
    if remove:
        vppctl_cmd = 'tap-inject enable-ip4-output interface %s \
            del' % (vpp_if_name)
    else:
        vppctl_cmd = 'tap-inject enable-ip4-output interface %s' % vpp_if_name
    out = _vppctl_read(vppctl_cmd, wait=False)
    if out is None:
        fwglobals.log.debug("failed vppctl_cmd=%s" % vppctl_cmd)
        return False

def get_min_metric_device(skip_dev_id):

    metric_min_dev_id = None
    metric_min = sys.maxsize

    wan_list = fwglobals.g.router_cfg.get_interfaces(type='wan')
    for wan in wan_list:
        if skip_dev_id and skip_dev_id == wan['dev_id']:
            fwglobals.log.trace("Min Metric Check - Skip dev_id: %s" % (skip_dev_id))
            continue

        metric_iter_str = wan.get('metric')
        fwglobals.log.trace("Min Metric Check (Device: %s) Metric: %s" %
            (wan['dev_id'], metric_iter_str))
        metric_iter = int(metric_iter_str or 0)
        metric_iter = get_wan_failover_metric(wan['dev_id'], metric_iter)
        fwglobals.log.trace("Min Metric Check (Device: %s) FO Metric: %d" %
            (wan['dev_id'], metric_iter))
        if metric_iter < metric_min:
            metric_min = metric_iter
            metric_min_dev_id = wan['dev_id']

    return (metric_min_dev_id, metric_min)

def dump(filename=None, path=None, clean_log=False):
    '''This function invokes 'fwdump' utility while ensuring no DoS on disk space.

    :param filename:  the name of the final file where to dump will be tar.gz-ed
    :param clean_log: if True, agent log files will be cleaned
    '''
    try:
        cmd = 'fwdump'
        if filename:
            cmd += ' --zip_file ' + filename
        if not path:
            path = fwglobals.g.DUMP_FOLDER
        cmd += ' --dest_folder ' + path

        # Ensure no more than last 5 dumps are saved to avoid disk out of space
        #
        files = glob.glob("%s/*.tar.gz" % path)
        if len(files) > 5:
            files.sort()
            os.remove(files[0])

        subprocess.check_call(cmd + ' > /dev/null 2>&1', shell=True)

        if clean_log:
            os.system("echo '' > %s" % fwglobals.g.ROUTER_LOG_FILE)
            os.system("echo '' > %s" % fwglobals.g.APPLICATION_IDS_LOG_FILE)
    except Exception as e:
        fwglobals.log.error("failed to dump: %s" % (str(e)))

def linux_check_gateway_exist(gw):
    interfaces = psutil.net_if_addrs()
    net_if_stats = psutil.net_if_stats()
    for if_name in interfaces:
        addresses = interfaces[if_name]
        for address in addresses:
            if address.family == socket.AF_INET:
                network = IPNetwork(address.address + '/' + address.netmask)
                if net_if_stats[if_name].isup and is_ip_in_subnet(gw, str(network)):
                    return True

    return False

def exec_with_timeout(cmd, timeout=60):
    """Run bash command with timeout option

    :param cmd:         Bash command
    :param timeout:     kill process after timeout, default=60sec

    :returns: Command execution result
    """
    state = {'proc':None, 'output':'', 'error':'', 'returncode':0}
    try:
        state['proc'] = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        (state['output'], state['error']) = state['proc'].communicate(timeout=timeout)
    except OSError as err:
        state['error'] = str(err)
        fwglobals.log.error("Error executing command '%s', error: %s" % (str(cmd), str(err)))
    except Exception as err:
        state['error'] = "Error executing command '%s', error: %s" % (str(cmd), str(err))
        fwglobals.log.error("Error executing command '%s', error: %s" % (str(cmd), str(err)))
    state['returncode'] = state['proc'].returncode

    return {'output':state['output'], 'error':state['error'], 'returncode':state['returncode']}

def get_template_data_by_hw(template_fname):
    system_info = subprocess.check_output('lshw -c system', shell=True).decode().strip()
    match = re.findall('(?<=vendor: ).*?\\n|(?<=product: ).*?\\n', system_info)
    if len(match) > 0:
        product = match[0].strip()
        vendor = match[1].strip()
        vendor_product = '%s__%s' % (vendor, product.replace(" ", "_"))

    with open(template_fname, 'r') as stream:
        info = yaml.load(stream, Loader=yaml.BaseLoader)
        shared = info['devices']['globals']
        # firstly, we will try to search for specific variables for the vendor and specific model
        # if it does not exist, we will try to get variables for the vendor
        vendor_product = '%s__%s' % (vendor, product.replace(" ", "_"))
        if vendor_product and vendor_product in info['devices']:
            data = info['devices'][vendor_product]
        elif vendor and vendor in info['devices']:
            data = info['devices'][vendor]
        elif product and product in info['devices']:
            data = info['devices'][product]
        else:
            data = shared

        # loop on global fields and override them with specific device values
        for k, v in shared.items():
            if k in data:
                v.update(data[k])
        data.update(shared)

        return data

def replace_file_variables(template_fname, replace_fname):
    """Replace variables in the json file with the data from the template file.

    For example, assuming we are in Virtualbox, the data from the template file looks:
        VirtualBox:
            __INTERFACE_1__:
            dev_id:       pci:0000:00:08.0
            name:         enp0s8
            __INTERFACE_2__:
            dev_id:       pci:0000:00:09.0
            name:         enp0s9
            __INTERFACE_3__:
            dev_id:       pci:0000:00:03.0
            name:         enp0s3

    The file to replace looks:
        [
            {
                "entity": "agent",
                "message": "start-router",
                "params": {
                    "interfaces": [
                        "__INTERFACE_1__",
                        {
                            "dev_id":"__INTERFACE_2__dev_id",
                            "addr":"__INTERFACE_2__addr",
                            "gateway": "192.168.56.1",
                            "type":"wan",
                            "routing":"ospf"
                        }
                    ]
                }
            }
        ]
    
    The function loops on the requests and replaces the variables.
    There are two types of variables. template and specific field.
    If we want to use all the data for a given interface (addr, gateway, dev_id etc.), we can use __INTERFACE_1__ only.
    If we want to get specifc value from a given interface, we can use __INTERFACE_1__{field_name} (__INTERFACE_1__addr)
    In the example above, we use template variable for interface 1, and specific interfaces values for interface 2.

    :param template_fname:    Path to template file
    :param replace_fname:     Path to json file to replace

    :returns: replaced json file
    """
    data = get_template_data_by_hw(template_fname)
    def replace(input):
        if type(input) == list:
            for idx, value in enumerate(input):
                input[idx] = replace(value)

        elif type(input) == dict:
            for key in input:
                value = input[key]
                input[key] = replace(value)

        elif type(input) == str:
            match = re.search('(__.*__)(.*)', str(input))
            if match:
                interface, field = match.groups()
                if field:
                    new_input = re.sub('__.*__.*', data[interface][field], input)
                    return new_input

                # replace with the template, but remove unused keys, They break the expected JSON files
                template = copy.deepcopy(data[interface])
                del template['addr_no_mask']
                if 'name' in template:
                    del template['name']
                return template
        return input

    # loop on the requests and replace the variables
    with open(replace_fname, 'r') as f:
        requests = json.loads(f.read())

        # cli requests
        if type(requests) == list:
            for req in requests:
                if not 'params' in req:
                    continue
                req['params'] = replace(req['params'])

        # json expected files
        elif type(requests) == dict:
            for req in requests:
                requests[req] = replace(requests[req])

    return requests

def is_need_to_reload_lte_drivers():
    # 2c7c:0125 is the vendor Id and product Id of quectel EC25 card.
    ec25_card_exists = os.popen('lsusb | grep 2c7c:0125').read()
    if not ec25_card_exists:
        return False

    # check if driver is associated with the modem. (see the problematic output "Driver=").
    # venko@PCENGINE2:~$ lsusb -t
    # /:  Bus 02.Port 1: Dev 1, Class=root_hub, Driver=ehci-pci/2p, 480M
    #     |__ Port 1: Dev 2, If 0, Class=Hub, Driver=hub/4p, 480M
    #         |__ Port 3: Dev 3, If 0, Class=Vendor Specific Class, Driver=option, 480M
    #         |__ Port 3: Dev 3, If 1, Class=Vendor Specific Class, Driver=option, 480M
    #         |__ Port 3: Dev 3, If 2, Class=Vendor Specific Class, Driver=option, 480M
    #         |__ Port 3: Dev 3, If 3, Class=Vendor Specific Class, Driver=option, 480M
    #         |__ Port 3: Dev 3, If 4, Class=Communications, Driver=, 480M
    #         |__ Port 3: Dev 3, If 5, Class=CDC Data, Driver=option, 480M
    cmd = 'lsusb -t | grep "Class=Communications" | awk -F "Driver=" {\'print $2\'} | awk -F "," {\'print $1\'}'
    driver = os.popen(cmd).read().strip()
    if not driver:
        return True
    return False

def send_udp_packet(src_ip, src_port, dst_ip, dst_port, dev_name, msg):
    """
    This function sends a UDP packet with provided source/destination parameters and payload.
    : param src_ip     : packet source IP
    : param src_port   : packet source port
    : param dst_ip     : packet destination IP
    : param dst_port   : packet destination port
    : param dev_name   : device name to bind() to
    : param msg        : packet payload

    """

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        if dev_name != None:
            s.setsockopt(socket.SOL_SOCKET, 25, dev_name.encode())
        s.bind((src_ip, src_port))
    except Exception as e:
        fwglobals.log.error("send_udp_packet: bind: %s" % str(e))
        s.close()
        return

    data = binascii.a2b_hex(msg)
    #fwglobals.log.debug("Packet: sendto: (%s,%d) data %s" %(dst_ip, dst_port, data))
    try:
        s.sendto(data, (dst_ip, dst_port))
    except Exception as e:
        fwglobals.log.error("send_udp_packet: sendto(%s:%d) failed: %s" % (dst_ip, dst_port, str(e)))
        s.close()
        return

    s.close()

def map_keys_to_acl_ids(acl_ids, arg):
    # arg carries command cache
    keys = acl_ids['keys']
    i = 0
    while i < len(keys):
        keys[i] = arg[keys[i]]
        i += 1
    return keys


def build_timestamped_filename(filename, ext='', separator='_'):
    '''Incorporates date and time into the filename in format "%Y%M%d_%H%M%S".
    Example:
        build_timestamped_filename("fwdump_EdgeDevice01_", ext='.tar.gz')
        ->
        fwdump_EdgeDevice01_20210510_131900.tar.gz
    '''
    return filename + separator + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ext

def is_ip(str_to_check):
    try:
        ipaddress.ip_address(str_to_check)
        return True
    except:
        return False

def build_tunnel_remote_loopback_ip(addr):
    network = IPNetwork(addr)     # 10.100.0.4 / 10.100.0.5
    network.value  ^= IPAddress('0.0.0.1').value        # 10.100.0.4 -> 10.100.0.5 / 10.100.0.5 -> 10.100.0.4
    return str(network.ip)

def build_tunnel_second_loopback_ip(addr):
    network = IPNetwork(addr)     # 10.100.0.4/31
    network.value  += IPAddress('0.1.0.0').value        # 10.100.0.4/31 -> 10.101.0.4/31
    return str(network)

def set_ip_on_bridge_bvi_interface(bridge_addr, dev_id, is_add):
    """Configure IP address on the BVI tap inerface if needed

    :param bridge_addr: bridge address
    :param is_add:      indiciate if need to add or remote the IP

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    try:
        tap = bridge_addr_to_bvi_interface_tap(bridge_addr)
        if not tap:
            return (False, 'tap is not found for bvi interface')

        if is_add:
            # check if IP already configured for this tap
            ip_addr = get_interface_address(tap)
            if not ip_addr:
                subprocess.check_call(f'sudo ip addr add {bridge_addr} dev {tap}', shell=True)
                subprocess.check_call(f'sudo ip link set dev {tap} up', shell=True)
        else:
            # check if there are other interefaces in the bridge.
            # if so, don't remove the bridge ip
            bridged_interfaces = fwglobals.g.router_cfg.get_interfaces(ip=bridge_addr)

            # if bridged_interfaces containes only one interface at this remove process
            # it means that this interface is the last in the bridge and we need to remove the ip
            if len(bridged_interfaces) == 1:
                subprocess.check_call(f'sudo ip link set dev {tap} down', shell=True)
                subprocess.check_call(f'sudo ip addr del {bridge_addr} dev {tap}', shell=True)
        return (True, None)
    except Exception as e:
        return (False, str(e))

class SlidingWindow(list):
    def __init__(self, window_size=30):
        """ Initialize sliding window
        : param window_size : number of points to keep in the window
        : return : None
        """
        self.window_size = window_size
        list.__init__(self)

    def add_datapoint(self, datapoint):
        """ Add data point to the sliding window, remove old entries to maintain size
        :param datapoint: new data point
        """
        self.append(datapoint)
        if len(self) > self.window_size:
            del self[0]

    def get_average(self):
        """ If list items support number arithmetic, returns sum/num.
        : return : arithmetic average of list items.
        """
        if len(self) == 0:
            return 0
        return float(sum(self)) / float(len(self))

def restart_service(service, timeout=0):
    '''Restart service

    :param service:     Service name.
    :param timeout:     Number of retrials.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    '''
    try:
        while timeout >= 0:
            cmd = 'systemctl restart %s.service > /dev/null 2>&1;' % service
            os.system(cmd)

            cmd = 'systemctl is-active --quiet %s' % service
            rc = os.system(cmd)
            if rc == 0:
                return (True, None)

            timeout-= 1
            time.sleep(1)

    except Exception as e:
        fwglobals.log.error(f'restart_service({service}): {str(e)}')
        return (False, str(e))

    fwglobals.log.error(f'restart_service({service}): failed on timeout ({timeout} seconds)')
    return (False, "Service is not running")

def load_linux_module(module):
    '''
    Sometimes, due to a problem in the machine boot process, some of the modules do not load properly for the first time.
    The 'modprobe' command falls with the error "Key was rejected by service".
    Surprisingly, when you run this command several times - in about 85% of the problems it is solved.
    So this function is a workaround to this problem but doesn't solve the root cause of the problem that is not up to us.
    '''
    tries = 5
    err = None
    for _ in range(tries):
        try:
            subprocess.check_call(f'modprobe {module}', shell=True)
            return (True, None)
        except Exception as e:
            err = str(e)
            time.sleep(0.5)
            pass
    return (False, err)

def load_linux_modules(modules):
    for module in modules:
        _, err = load_linux_module(module)
        if err:
            return (False, err)
    return (True, None)

def get_thread_tid():
    '''Returns OS thread id'''
    try:
        global libc
        if not libc:
            libc = ctypes.cdll.LoadLibrary('libc.so.6')
        tid = str(libc.syscall(186)) # gettid defined in /usr/include/x86_64-linux-gnu/asm/unistd_64.h
    except Exception as e:
        tid = f'<str({e})>'
    return tid


def dict_deep_update(dst, src):
    '''Implements recursive dict::update() method - the sub-dictionaries are
    not replaced but updated with sub-dicts from 'src'. Eventually, this function
    never removes keys from 'dst', but adds / updates them only.
    '''
    for key, value in src.items():
        if isinstance(value, dict):
            if not key in dst:
                dst[key] = {}
            dict_deep_update(dst[key], value)
        else:
            dst[key] = value

def call_applications_hook(hook):
    with FWAPPLICATIONS_API() as applications_api:
        applications_api.call_hook(hook)

def get_linux_interface_mtu(if_name):
    net_if_stats = psutil.net_if_stats()
    if if_name not in net_if_stats:
        return ''

    return str(net_if_stats[if_name].mtu)
