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
import shutil
import sys
import traceback
import yaml
import zlib
import base64

from netaddr import IPNetwork, IPAddress

import fwlte
import fwwifi
import fwqos
import fwtranslate_add_switch
import fwutils
import fw_os_utils

from fwapplications_api import call_applications_hook, FWAPPLICATIONS_API
from fwfrr          import FwFrr
from fwikev2        import FwIKEv2
from fwmultilink    import FwMultilink
from fwpolicies     import FwPolicies
from fwrouter_cfg   import FwRouterCfg
from fwsystem_cfg   import FwSystemCfg
from fwroutes       import FwLinuxRoutes
from fwjobs         import FwJobs
from fwapplications_cfg import FwApplicationsCfg
from fwwan_monitor  import get_wan_failover_metric
from fw_traffic_identification import FwTrafficIdentifications
from tools.common.fw_vpp_startupconf import FwStartupConf
from fwcfg_request_handler import FwCfgMultiOpsWithRevert

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
        if shif_vmxnet3 == '':
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

def get_linux_distro():
    """Get Linux Distribution

    :returns: (Ubuntu Release, Ubuntu CodeName)
    """
    try:
        cmd = 'lsb_release -rscs'
        distro = subprocess.check_output(cmd, shell=True).decode().strip().split('\n')
        return (str(distro[0]), str(distro[1]))
    except:
        return ('','')

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

    :returns: tuple (<IP of GW>, <name of network interface>, <Dev ID of network interface>, <protocol>, <metric>).
    """
    dev = ""
    metric = None

    try:
        output = os.popen('ip route list match default').read()
    except:
        return ("", "", "", "", None)

    if not output:
        return ("", "", "", "", None)

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
            return (via, dev, get_interface_dev_id(dev), proto, metric)

        if not metric or _metric < metric:  # The default route among default routes is the one with the lowest metric :)
            dev    = _dev
            via    = _via
            metric = _metric
            proto = _proto

    if not dev:
        return ("", "", "", "", None)

    # If no route for a specified interface was found
    if if_name and if_name != dev:
        return ("", "", "", "", None)

    dev_id = get_interface_dev_id(dev)
    return (via, dev, dev_id, proto, metric)

def get_gateway_arp_entries(gw):
    try:
        out = subprocess.check_output(f'ip neigh show to {gw}', shell=True).decode()
        return out.splitlines()
    except Exception as e:
        fwglobals.log.error(f'get_gateway_arp({gw}): failed to fetch arp for gateway. {str(e)}')
        return []

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

    if fwpppoe.is_pppoe_interface(if_name=if_name):
        pppoe_iface = fwglobals.g.pppoe.get_interface(if_name=if_name)
        return pppoe_iface.gw, str(pppoe_iface.metric)

    routes_linux = FwLinuxRoutes(prefix='0.0.0.0/0')
    for route in routes_linux.values():
        if route.dev == if_name:
            return route.via, str(route.metric)

    return '', ''

def get_tunnel_gateway(dst, dev_id):
    interface = get_linux_interfaces(if_dev_id=dev_id)
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
    dev_id_ip_gw, wan_ips = {}, []

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

        if fwpppoe.is_pppoe_interface(if_name=nic_name):
            ppp_if_name = fwpppoe.pppoe_get_ppp_if_name(nic_name)
            if not ppp_if_name:
                continue
            addrs = interfaces.get(ppp_if_name)

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

        if dev_id_ip_gw[dev_id]['addr'] and dev_id_ip_gw[dev_id]['gw']:
            wan_ips.append(dev_id_ip_gw[dev_id]['addr'])

    return dev_id_ip_gw, wan_ips

def get_interface_address(if_name, if_dev_id=None, log=True, log_on_failure=None):
    """Gets IP address of interface by name found in OS.

    :param if_name:     Interface name.
    :param if_dev_id:   Bus address of the interface, address for which is returned.
                        If provided, the 'if_name' is ignored. The name is fetched
                        from system by a Bus address.
    :param log:         If True the found/not found address will be logged.
                        Errors or debug info is printed in any case.
    :param log_on_failure: If provided, overrides the 'log' in case of not found address.

    :returns: IP address.
    """
    if if_dev_id:
        if_name = dev_id_to_tap(if_dev_id)

    if log_on_failure == None:
        log_on_failure = log

    if fwpppoe.is_pppoe_interface(if_name=if_name):
        ppp_if_name = fwpppoe.pppoe_get_ppp_if_name(if_name)
        if ppp_if_name:
            if_name = ppp_if_name

    interfaces = psutil.net_if_addrs()

    addresses = interfaces.get(if_name, [])
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

def get_interface_name(ip_no_mask, by_subnet=False):
    """ Get interface name based on IP address

    : param ip_no_mask: ip address with no mask
    : param by_subnet:  if True, the function retrieves the first interface
                        with IP in the same sub network as 'ip'.
    : returns : if_name - interface name
    """
    interfaces = psutil.net_if_addrs()
    for if_name in interfaces:
        addresses = interfaces[if_name]
        for address in addresses:
            if address.family != socket.AF_INET:
                continue
            if by_subnet:
                addr_with_mask = '%s/%s' % (address.address, IPAddress(address.netmask).netmask_bits())
                if is_ip_in_subnet(ip_no_mask, addr_with_mask):
                    return if_name
            elif address.address == ip_no_mask:
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
        return dev_id_add_type(pc[0]+'.'+"%02x"%(int(pc[1],16)), addr_type)

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

def dev_id_add_type(dev_id, addr_type=None):
    """Add address type at the beginning of the address.

    :param dev_id:      device bus address.
    :param addr_type:   device address type.

    :returns: device bus address with type.
    """

    if dev_id:
        if dev_id.startswith('pci:') or dev_id.startswith('usb:'):
            return dev_id

        if re.search('usb', dev_id):
            return 'usb:%s' % dev_id

        if addr_type:
            return '%s:%s' % (addr_type, dev_id)

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

def get_interface_is_dhcp(if_name):
    is_dhcp_in_netplan = fwnetplan.is_interface_dhcp(if_name)
    if is_dhcp_in_netplan == 'yes':
        return is_dhcp_in_netplan

    dhclient_running_for_if_name = os.popen(f'ps -aux | grep "dhclient {if_name}" | grep -v grep').read()
    if dhclient_running_for_if_name:
        return 'yes'

    if fwglobals.g.is_gcp_vm:
        # all Google Cloud Platform interfaces are configured by their agent as dhcp
        return 'yes'

    return 'no'

def get_linux_interfaces(cached=True, if_dev_id=None):
    """Fetch interfaces from Linux.

    :param cached: if True the data will be fetched from cache.
    :param if_dev_id: ID of interface to be fetched from cache.

    :return: Dictionary of interfaces by full form dev id, or specific interface if 'dev_id' was provided.
    """
    with fwglobals.g.cache.lock:

        interfaces = fwglobals.g.cache.linux_interfaces

        if cached and interfaces:
            if if_dev_id:
                return copy.deepcopy(interfaces.get(if_dev_id))
            return copy.deepcopy(interfaces)

        fwglobals.log.debug("get_linux_interfaces: Start to build Linux interfaces cache")
        interfaces.clear()

        linux_inf = psutil.net_if_addrs()
        for (if_name, addrs) in list(linux_inf.items()):

            if if_name.startswith('ppp'):
                continue

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

            interface['dhcp'] = get_interface_is_dhcp(if_name)

            interface['mtu'] = get_linux_interface_mtu(if_name)

            is_pppoe = fwpppoe.is_pppoe_interface(if_name=if_name)
            is_wifi = fwwifi.is_wifi_interface(if_name)
            is_lte = fwlte.is_lte_interface(if_name)
            is_vlan = is_vlan_interface(dev_id=dev_id)

            if is_lte:
                interface['deviceType'] = 'lte'
            elif is_wifi:
                interface['deviceType'] = 'wifi'
            elif is_pppoe:
                interface['deviceType'] = 'pppoe'
            elif is_vlan:
                interface['deviceType'] = 'vlan'
                interface['driver'] = 'vlan'
            else:
                interface['deviceType'] = 'dpdk'

            interface['link'] = get_interface_link_state(if_name, dev_id, device_type=interface['deviceType'])

            # Some interfaces need special logic to get their ip
            # For LTE/WiFi/Bridged interfaces - we need to take it from the tap
            if fw_os_utils.vpp_does_run():
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
                interface['dhcp'] = 'yes'
                interface['deviceParams'] = {
                    'initial_pin1_state': fwlte.get_pin_state(dev_id),
                    'default_settings':   fwlte.get_default_settings(dev_id)
                }

            elif is_wifi:
                interface['deviceParams'] = fwwifi.wifi_get_capabilities(dev_id)

            elif is_pppoe:
                pppoe_iface = fwglobals.g.pppoe.get_interface(if_name=if_name)
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
        if if_dev_id:
            return copy.deepcopy(interfaces.get(if_dev_id))
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

        if not fw_os_utils.vpp_does_run() or is_interface_assigned_to_vpp(dev_id) == False:
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
    vlan_id = None
    if not linux_dev_name:
        return ""

    if is_vlan_interface(if_name=linux_dev_name):
        linux_dev_name, vlan_id = if_name_parse_vlan(linux_dev_name)

    if linux_dev_name.startswith('ppp'):
        return fwpppoe.pppoe_get_dev_id_from_ppp(linux_dev_name)

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

                if vlan_id:
                    dev_id = build_vlan_dev_id(vlan_id, dev_id)
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

def dev_id_to_linux_if_name_safe(dev_id):
    if getattr(fwglobals.g, 'router_api', False): # don't fail if agent is not running
        return dev_id_to_linux_if_name(dev_id)
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

    # For tap interfaces we don't use 'vpp_if_name', but fetch Linux name of interface from vpp.
    # Tap interfaces are created as follows:
    # The commands "create tap host-if-name tap_wwan0" and "enable tap-inject" create three interfaces:
    # Two on Linux (tap_wwan0, vpp1) and one on vpp (tap0).
    # We compose name of tap interface (tap_wwan0) of two parts: "tap_" and "wwan0", so we can
    # fetch name of Linux interface (wwan0) out of the tap name by a simple string split.
    #
    taps = fwglobals.g.router_api.vpp_api.vpp.call('sw_interface_tap_v2_dump')
    for tap in taps:
        if not re.match("tap_", tap.host_if_name):
            continue   # pppoe interfaces don't follow "tap_" convention

        vpp_tap = tap.dev_name                      # fetch tap0
        linux_tap = tap.host_if_name                # fetch tap_wwan0
        linux_dev_name = linux_tap.split('_')[-1]   # tap_wwan0 - > wwan0

        # 'linux_dev_name' might include truncated name of linux interface.
        # This is because Linux limits length of interface names to be no more than 15 characters.
        # So, when we create tap interface for linux interface with long name, e.g. wwp0s21u1i12m,
        # we can get "tap_wwp0s21u1i12" that exceeds the limit. So we have to short it.
        # We chop the beginning of the name as the end of the name is unique for interfaces.
        # So the final version of tap will be "tap_wp0s21u1i12". Note missing the first "w".
        #   To get Linux interface name out of truncated 'linux_dev_name' we use the '/sys/class/net'.
        # 'grep -v {linux_tap}' is used to filter out "tap_wp0s21u1i12",
        # 'grep {linux_dev_name}' is used to find full name (wwp0s21u1i12) based on truncated name (wp0s21u1i12).
        #
        cmd =  f"ls -l /sys/class/net | grep -v {linux_tap} | grep {linux_dev_name}"
        linux_dev_name = subprocess.check_output(cmd, shell=True).decode().strip().split('/')[-1]

        bus = build_interface_dev_id(linux_dev_name)            # fetch bus address of wwan0
        if bus:
            fwglobals.g.cache.dev_id_to_vpp_if_name[bus] = vpp_tap
            fwglobals.g.cache.vpp_if_name_to_dev_id[vpp_tap] = bus

    lte_dev_id_dict = None
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
        else:
            # Non PCI cases - LTE tap interfaces initialized by DPDK
            lte_vpp_if_name = data.split(' ', 1)[0]
            if 'dpdk-tap' in lte_vpp_if_name: #VPP LTE tap name starts with dpdk-tap
                if lte_dev_id_dict is None:
                    lte_dev_id_dict = fwlte.get_lte_interfaces_dev_ids()
                for _, linux_dev_name in lte_dev_id_dict.items():
                    # For LTE tap interfaces, data would have device args as 'iface=tap_wwan0'
                    lte_dev_args = 'iface=' + generate_linux_interface_short_name("tap", linux_dev_name)
                    if lte_dev_args in data:
                        lte_dev_bus = build_interface_dev_id(linux_dev_name)
                        fwglobals.g.cache.dev_id_to_vpp_if_name[lte_dev_bus] = lte_vpp_if_name
                        fwglobals.g.cache.vpp_if_name_to_dev_id[lte_vpp_if_name] = lte_dev_bus

    vmxnet3hw = fwglobals.g.router_api.vpp_api.vpp.call('vmxnet3_dump')
    for hw_if in vmxnet3hw:
        vpp_if_name = hw_if.if_name.rstrip(' \t\r\n\0')
        pci_addr = 'pci:%s' % pci_bytes_to_str(hw_if.pci_addr)
        fwglobals.g.cache.dev_id_to_vpp_if_name[pci_addr] = vpp_if_name
        fwglobals.g.cache.vpp_if_name_to_dev_id[vpp_if_name] = pci_addr

    # IMPORTANT! PPPoE should be consulted at last, as it might override values found so far!
    #
    pppoe_dev_id_vpp_if_name = fwpppoe.build_dev_id_to_vpp_if_name_map()
    for pppoe_dev_id, pppoe_vpp_if_name in pppoe_dev_id_vpp_if_name.items():
        if pppoe_vpp_if_name:
            fwglobals.g.cache.dev_id_to_vpp_if_name[pppoe_dev_id] = pppoe_vpp_if_name
            fwglobals.g.cache.vpp_if_name_to_dev_id[pppoe_vpp_if_name] = pppoe_dev_id

    sw_ifs = fwglobals.g.router_api.vpp_api.vpp.call('sw_interface_dump')
    for sw_if in sw_ifs:
        if sw_if.type == 1: # IF_API_TYPE_SUB
            parent_vpp_if_name = vpp_sw_if_index_to_name(sw_if.sup_sw_if_index)
            parent_dev_id = fwglobals.g.cache.vpp_if_name_to_dev_id[parent_vpp_if_name]
            pci_addr = build_vlan_dev_id(sw_if.sub_outer_vlan_id, parent_dev_id)
            vpp_if_name = sw_if.interface_name.rstrip(' \t\r\n\0')
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

def dev_ids_to_vpp_sw_if_indexes(dev_ids):
    res = []
    for dev_id in dev_ids:
        res.append(dev_id_to_vpp_sw_if_index(dev_id))
    return res

def dev_id_to_switch_sw_if_index(dev_id):
    bridge_addr = fwutils.is_bridged_interface(dev_id)
    if not bridge_addr:
        return None

    return bridge_addr_to_bvi_sw_if_index(bridge_addr)

def dev_id_to_vpp_sw_if_index(dev_id, verbose=True):
    """Convert device bus address into VPP sw_if_index.

    This function maps interface referenced by device bus address, e.g pci - '0000:00:08.00'
    into index of this interface in VPP, eg. 1.
    To do that we convert firstly the device bus address into name of interface in VPP,
    e.g. 'GigabitEthernet0/8/0', than we dump all VPP interfaces and search for interface
    with this name.

    :param dev_id:      device bus address.

    :returns: sw_if_index.
    """
    # Try to fetch name from cache firstly.
    #
    sw_if_index = fwglobals.g.db.get('router_api', {}).get('dev_id_to_sw_if_index', {}).get(dev_id)
    if sw_if_index:
        return sw_if_index

    # Now go to the heavy route.
    #
    vpp_if_name = dev_id_to_vpp_if_name(dev_id)
    if verbose or not vpp_if_name:
        fwglobals.log.debug("dev_id_to_vpp_sw_if_index(%s): vpp_if_name: %s" % (dev_id, str(vpp_if_name)))
    return vpp_if_name_to_sw_if_index(vpp_if_name)

def vpp_if_name_to_cached_sw_if_index(vpp_if_name, type):
    """Convert VPP interface name into the cached VPP sw_if_index.

     :param vpp_if_name:      VPP interface name.
     :param type:             Interface type.

     :returns: VPP sw_if_index.
     """
    router_api_db  = fwglobals.g.db['router_api']
    cache_by_name  = router_api_db['vpp_if_name_to_sw_if_index'][type]
    sw_if_index  = cache_by_name[vpp_if_name]
    return sw_if_index

def vpp_if_name_to_sw_if_index(vpp_if_name):
    """Convert VPP interface name into VPP sw_if_index.

    This function maps interface referenced by vpp interface name, e.g tun0
    into index of this interface in VPP, eg. 1.

    :param vpp_if_name:      VPP interface name

    :returns: sw_if_index.
    """
    if vpp_if_name is None:
        return None

    sw_ifs = fwglobals.g.router_api.vpp_api.vpp.call('sw_interface_dump')
    for sw_if in sw_ifs:
        if re.match(vpp_if_name, sw_if.interface_name):    # Use regex, as sw_if.interface_name might include trailing whitespaces
            return sw_if.sw_if_index
    fwglobals.log.debug("vpp_if_name_to_sw_if_index(%s): vpp_if_name: %s" % (vpp_if_name, yaml.dump(sw_ifs, canonical=True)))

    return None

def bridge_addr_to_bvi_sw_if_index(bridge_addr):
    if not fw_os_utils.vpp_does_run():
        return None

    # check if interface indeed in a bridge
    bd_id = fwtranslate_add_switch.get_bridge_id(bridge_addr)
    if not bd_id:
        fwglobals.log.error('bridge_addr_to_bvi_interface_tap: failed to fetch bridge id for address: %s' % str(bridge_addr))
        return None

    vpp_bridges_det = fwglobals.g.router_api.vpp_api.vpp.call('bridge_domain_dump', bd_id=bd_id)
    if not vpp_bridges_det:
        fwglobals.log.error('bridge_addr_to_bvi_interface_tap: failed to fetch vpp bridges for bd_id %s' % str(bd_id))
        return None

    return vpp_bridges_det[0].bvi_sw_if_index

# 'bridge_addr_to_bvi_interface_tap' function get the addr of the interface in a bridge
# and return the tap interface of the BVI interface
def bridge_addr_to_bvi_interface_tap(bridge_addr):
    bvi_sw_if_index = bridge_addr_to_bvi_sw_if_index(bridge_addr)
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
        vpp_runs    = fw_os_utils.vpp_does_run()
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

def unset_dev_id_to_tap(dev_id):
    """Remove entry from cache.

    :param dev_id:          Bus address.
    """
    if not dev_id:
        return

    dev_id_full = dev_id_to_full(dev_id)
    cache = fwglobals.g.cache.dev_id_to_vpp_tap_name
    del cache[dev_id_full]

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

    if not fw_os_utils.vpp_does_run():
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
    if not fw_os_utils.vpp_does_run():
        fwglobals.log.debug("vpp_get_tap_info: VPP is not running")
        return (None, None)

    if vpp_if_name:
        vppctl_cmd = f"show tap-inject {vpp_if_name}"
    elif vpp_sw_if_index:
        vppctl_cmd = f"show tap-inject sw_if_index {vpp_sw_if_index}"
    elif tap_if_name:
        vppctl_cmd = f"show tap-inject tap_name {tap_if_name}"
    else:
        fwglobals.log.debug("vpp_get_tap_info: no arguments provided")
        return (None, None)

    taps = _vppctl_read(vppctl_cmd)
    if not taps:
        fwglobals.log.debug(f"vpp_get_tap_info: '{vppctl_cmd}' returned nothing")
        return (None, None)

    taps = taps.strip()

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
        tap_info = re.search(r'([/.\w-]+) -> ([\S]+)', line)
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
    if not fw_os_utils.vpp_does_run():
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
    sw_interfaces = fwglobals.g.router_api.vpp_api.vpp.call('sw_interface_dump', sw_if_index=sw_if_index)
    if not sw_interfaces:
        fwglobals.log.debug(f"vpp_sw_if_index_to_name({sw_if_index}): not found")
        return None
    return sw_interfaces[0].interface_name.rstrip(' \t\r\n\0')

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

def vpp_get_interface_status(sw_if_index=None, dev_id=None):
    """Get VPP interface state.

     :param sw_if_index:      VPP sw_if_index.
	 :param dev_id:           dev_id of interface as received from flexiManage

     :returns: dict with admin and link statuses.
     """
    try:
        if not sw_if_index:
            sw_if_index = dev_id_to_vpp_sw_if_index(dev_id, verbose=False)
        if not sw_if_index:
            raise Exception(f"sw_if_index was not provided, dev_id={dev_id} was not resolved")

        interfaces = fwglobals.g.router_api.vpp_api.vpp.call('sw_interface_dump', sw_if_index=sw_if_index)
        if len(interfaces) == 1:
            flags = interfaces[0].flags

            # vnet\interface_types_api.h
            #     enum if_status_flags
            #     {
            #       IF_STATUS_API_FLAG_ADMIN_UP = 1,
            #       IF_STATUS_API_FLAG_LINK_UP = 2,
            #     };
            #
            admin_state = "up" if (flags & 1) else "down"
            link_status = "up" if (flags & 2) else "down"
            return {'admin': admin_state , 'link': link_status}
        else:
            raise Exception(f"sw_if_index={sw_if_index} retrieved no interface")

    except Exception as e:
        fwglobals.log.debug("vpp_get_interface_state: %s" % str(e))
        return {}


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
        if not fw_os_utils.vpp_does_run():  # No need to retry if vpp crashed
            fwglobals.log.debug("stop retrials: vpp process not found")
            return None
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

    call_applications_hook('on_router_is_stopping')

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
    if fwglobals.g.statistics:
        fwglobals.g.statistics.update_vpp_state(running=False)

    reset_traffic_control()                     # Release LTE operations
    remove_linux_bridges()                      # Release bridges for wifi
    fwwifi.stop_hostapd()                       # Stop access point service

    # Restore original netplan files.
    # If no files were restored, run 'netplan apply' to be on safe side
    #
    restored_files = fwnetplan.restore_linux_netplan_files()
    if not restored_files:
        netplan_apply('stop_vpp')

    call_applications_hook('on_router_is_stopped')

    with FwIKEv2() as ike:
        ike.clean()
    fwpppoe.pppoe_reset()

def reset_device_config(pppoe=False):
    """Reset router config by cleaning DB and removing config files.

     :returns: None.
     """
    reset_agent_cfg()
    reset_router_cfg()
    reset_system_cfg()
    reset_device_config_signature("empty_cfg")
    if pppoe:
        fwpppoe.pppoe_remove()

def reset_agent_cfg():
    if os.path.exists(fwglobals.g.CONN_FAILURE_FILE):
        os.remove(fwglobals.g.CONN_FAILURE_FILE)

def reset_router_cfg():
    with FwFrr(fwglobals.g.FRR_DB_FILE) as db_frr:
        db_frr.clean()
    with FwRouterCfg(fwglobals.g.ROUTER_CFG_FILE) as router_cfg:
        router_cfg.clean()
    with FwRouterCfg(fwglobals.g.ROUTER_PENDING_CFG_FILE) as router_pending_cfg:
        router_pending_cfg.clean()
    with FwMultilink(fwglobals.g.MULTILINK_DB_FILE) as db_multilink:
        db_multilink.clean()
    with FwPolicies(fwglobals.g.POLICY_REC_DB_FILE) as db_policies:
        db_policies.clean()
    with FwTrafficIdentifications(fwglobals.g.TRAFFIC_ID_DB_FILE) as traffic_db:
        traffic_db.clean()
    fwnetplan.restore_linux_netplan_files()
    with FwIKEv2() as ike:
        ike.clean()
    with FwApplicationsCfg() as applications_cfg:
        applications_cfg.clean()

    if os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
        os.remove(fwglobals.g.ROUTER_STATE_FILE)
    if os.path.exists(fwglobals.g.VPP_CONFIG_FILE_BACKUP):
        shutil.copyfile(fwglobals.g.VPP_CONFIG_FILE_BACKUP, fwglobals.g.VPP_CONFIG_FILE)
    elif os.path.exists(fwglobals.g.VPP_CONFIG_FILE_RESTORE):
        shutil.copyfile(fwglobals.g.VPP_CONFIG_FILE_RESTORE, fwglobals.g.VPP_CONFIG_FILE)

    frr_clean_files()
    reset_router_api_db_sa_id() # sa_id-s are used in translations of router configuration, so clean them too.
    reset_router_api_db(enforce=True)
    restore_dhcpd_files()
    reset_device_config_signature("empty_router_cfg")

def reset_system_cfg(reset_lte_db=True):
    with FwSystemCfg(fwglobals.g.SYSTEM_CFG_FILE) as system_cfg:
        system_cfg.clean()
    if 'lte' in fwglobals.g.db and reset_lte_db:
        fwglobals.g.db['lte'] = {}
    reset_device_config_signature("empty_system_cfg")

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
    if not 'dev_id_to_sw_if_index' in router_api_db or enforce:
        router_api_db['dev_id_to_sw_if_index'] = {}
    vpp_if_name_to_sw_if_index_keys = ['tunnel', 'peer-tunnel', 'lan', 'switch-lan', 'wan', 'switch', 'trunk']
    for key in vpp_if_name_to_sw_if_index_keys:
        if not key in router_api_db['vpp_if_name_to_sw_if_index'] or enforce:
            router_api_db['vpp_if_name_to_sw_if_index'][key] = {}
    if not 'vpp_if_name_to_tap_if_name' in router_api_db or enforce:
        router_api_db['vpp_if_name_to_tap_if_name'] = {}
    if not 'sw_if_index_to_tap_if_name' in router_api_db or enforce:
        router_api_db['sw_if_index_to_tap_if_name'] = {}
    if not 'dhcpd' in router_api_db or enforce:
        router_api_db['dhcpd'] = {}
    if not 'interfaces' in router_api_db['dhcpd'] or enforce:
        router_api_db['dhcpd']['interfaces'] = {}
    fwglobals.g.db['router_api'] = router_api_db

def print_system_config(full=False):
    """Print router configuration.

     :returns: None.
     """
    with FwSystemCfg(fwglobals.g.SYSTEM_CFG_FILE) as system_cfg:
        cfg = system_cfg.dumps(full=full)
        print(cfg)

def print_jobs():
    with FwJobs(fwglobals.g.JOBS_FILE) as jobs:
        cfg = jobs.dumps()
        print(cfg)

def print_device_config_signature():
    cfg = get_device_config_signature()
    print(cfg)

def print_applications_db(full=False):
    with FwApplicationsCfg() as applications_cfg:
        cfg = applications_cfg.dumps(full=full)
        print(cfg)

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

def print_router_pending_config():
    """Print router pending configuration - the configuration items that were
    requested to be configured, but the configuration of that is not possible
    at the moment. E.g. tunnels for interfaces without IP.

     :returns: None.
     """
    with FwRouterCfg(fwglobals.g.ROUTER_PENDING_CFG_FILE) as router_pending_cfg:
        cfg = router_pending_cfg.dumps()
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

def reset_device_config_signature(new_signature=None, log=None):
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
    if log and old_signature != new_signature:
        log.debug(f"reset signature: {old_signature} -> {new_signature}")

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

def dump_applications_config(full=False):
    """Dumps applications configuration into list of requests that look exactly
    as they would look if were received from server.

    :param full: return requests together with translated commands.

    :returns: list of 'add-X' requests.
    """
    cfg = []
    with FwApplicationsCfg() as applications_cfg:
        cfg = applications_cfg.dump(full)
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
    elif fw_os_utils.vpp_pid():
        state = 'running'
    else:
        state = 'stopped'
    return (state, reason)

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

def _vmxnet3_align_to_pow2_and_max_value(x):
    """
    vmxnet3 driver supports RX queues only values pow of 2 and the max value is 16
    So we need to map configured value to supported as following:

    1        -> 1
    2,3      -> 2
    4-7      -> 4
    8-15     -> 8
    >= 16    -> 16

    :returns: Aligned value to closest which is supported.
    """

    if x//16:
        pw = 16
    elif x//8:
        pw = 8
    elif x//4:
        pw = 4
    elif x//2:
        pw = 2
    else:
        pw = 1
    return pw


def vpp_startup_conf_add_dpdk_config (vpp_config_filename, devices):
    """
    Function for setting up of startup-conf's dpdk config on VPP start
    """
    p = FwStartupConf(vpp_config_filename)
    hqos_capable = True if (p.get_cpu_hqos_workers() > 0) else False
    tap_count = 0
    tun_count = 0
    num_workers = p.get_cpu_workers()
    config = p.get_root_element()

    p.remove_element(config, 'dpdk')
    tup = p.create_element('dpdk')
    config.append(tup)

    if len(devices) == 0:
        # When the list of devices in the startup.conf file is empty, the vpp attempts
        # to manage all the down linux interfaces.
        # If all interfaces are non-dpdk interfaces (like WiFi) then this list could be empty.
        # In order to prevent vpp from doing so, we need to add the "no-pci" flag.
        config['dpdk'].append(p.create_element('no-pci'))
        p.dump(config, vpp_config_filename)
        return (True, None)

    for dev in devices:
        qos_on_dev_id = True if (fwqos.has_qos_policy(dev, True)) else False
        dev_short = dev_id_to_short(dev)
        addr_type, addr_short = dev_id_parse(dev_short)
        pppoe_if = fwpppoe.is_pppoe_interface(dev_id=dev)

        if (hqos_capable and qos_on_dev_id):
            max_subports, max_pipes = fwglobals.g.qos.get_max_subports_and_pipes ()
            hqos_config_param = 'hqos { num-subports %d num-pipes %d } ' % (max_subports, max_pipes)
        else:
            hqos_config_param = ''

        if addr_type == "pci":

            custom_config_param = ''
            # For PPPoE interface, QoS is enabled on the corresponding tun interface
            if hqos_capable and qos_on_dev_id and not pppoe_if:
                custom_config_param += hqos_config_param
            if dev_id_is_vmxnet3(dev):
                #for vmxnet3 we need to align value to supported numbers (pow of 2 and max is 16)
                rx_queues = _vmxnet3_align_to_pow2_and_max_value(num_workers)
                custom_config_param += ' num-rx-queues %s' % (rx_queues)

            if custom_config_param:
                new_config_param = "dev %s { %s }" % (addr_short, custom_config_param)
            else:
                new_config_param = "dev %s" % (addr_short)

            tup = p.create_element(new_config_param)
            config['dpdk'].append(tup)
        elif addr_type == "usb":
            iface_name = dev_id_to_linux_if(dev)
            tap_linux_iface_name = generate_linux_interface_short_name("tap", iface_name)
            tap_config_param = "vdev net_tap%d,iface=%s" % (tap_count, tap_linux_iface_name)
            tap_config_param += ' { %s num-rx-queues 1 num-tx-queues 1 }' %  hqos_config_param
            tup = p.create_element(tap_config_param)
            config['dpdk'].append(tup)
            tap_count += 1

        if pppoe_if:
            tun_linux_if_name,_ = fwglobals.g.pppoe.get_linux_and_vpp_tun_if_names(dev_id=dev)
            tunnel_config_param = 'vdev net_tun%d,iface=%s' % (tun_count, tun_linux_if_name)
            # If queues are not specified, DPDK tun interface init looks to be dynamically
            # setting up queue numbers. Working compatibly with this dynamic queue setup may likely
            # need corresponding changes from other configs (like tc) made in setting up PPPoE
            tunnel_config_param += ' { %s num-rx-queues 1 num-tx-queues 1 }' %  hqos_config_param
            tup = p.create_element(tunnel_config_param)
            config['dpdk'].append(tup)
            tun_count += 1

    if num_workers > 1:
        p.set_simple_param('dpdk.dev default.num-rx-queues', num_workers)
    p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_startup_conf_remove_dpdk_config (vpp_config_filename):
    """
    Function for removing of startup-conf's dpdk config on VPP stop
    """
    p = FwStartupConf(vpp_config_filename)
    config = p.get_root_element()
    p.remove_element(config, 'dpdk')
    p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_setup_hqos (vpp_config_filename, is_add, num_interfaces):
    """
    - Add/Remove HQoS Worker thread if QoS policy is applied
    - Update QoS context with the system parameters like memory, thread

    :param vpp_config_filename: Filename of VPP startup configuration
    :type vpp_config_filename: String
    :param is_add: Flag indicating if HQoS worker thread need to be added/removed
    :type is_add: bool
    """
    with FwStartupConf(vpp_config_filename) as startup_conf:
        num_worker_cores = startup_conf.get_cpu_workers()
        num_worker_cores += startup_conf.get_cpu_hqos_workers()
        hqos_enabled = False
        if fwqos.has_qos_policy() is True:
            hqos_enabled = True if ((num_worker_cores > 1) and (is_add is True)) else False
        startup_conf.set_cpu_workers(num_worker_cores, num_interfaces=num_interfaces, hqos_enabled=hqos_enabled)
        fwglobals.g.qos.setup_hqos \
            (hqos_enabled, num_worker_cores, startup_conf.get_vpp_heap_size_in_GB())


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

    return False

def get_lte_interfaces_names():
    names = []
    interfaces = psutil.net_if_addrs()

    for nic_name, _ in list(interfaces.items()):
        dev_id = get_interface_dev_id(nic_name)
        if dev_id and fwlte.is_lte_interface(nic_name):
            names.append(nic_name)

    return names

def traffic_control_add_del_qdisc(is_add, dev_name, class_name='ingress'):
    add_delete = 'add' if is_add else 'del'
    try:
        subprocess.check_call(f'sudo tc qdisc {add_delete} dev {dev_name} handle ffff: {class_name}', stderr=subprocess.STDOUT, shell=True)
    except Exception as e:
        fwglobals.log.error(f"traffic_control_add_del_qdisc({is_add}, {dev_name}, {class_name}): {str(e)}")
        raise e

def traffic_control_add_del_mirror_policy(is_add, from_ifc, to_ifc, set_dst_mac=None):
    try:
        cmd = f"tc filter {'add' if is_add  else 'del'} dev {from_ifc} parent ffff: \
                protocol all prio 2 u32 \
                match u32 0 0 flowid 1:1 \
                {f'action pedit ex munge eth dst set {set_dst_mac}' if set_dst_mac else ''} \
                pipe action mirred egress mirror dev {to_ifc} \
                pipe action drop"
        subprocess.check_call(cmd, stderr=subprocess.STDOUT, shell=True)
    except Exception as e:
        fwglobals.log.error(f"traffic_control_add_del_mirror_policy({is_add}, {from_ifc}, {to_ifc}, {set_dst_mac}): {str(e)}")
        raise e

def reset_traffic_control():
    fwglobals.log.debug('clean Linux traffic control settings')
    lte_interface_names = get_lte_interfaces_names()
    for dev_name in lte_interface_names:
        try:
            subprocess.check_call(f'sudo tc -force qdisc del dev {dev_name} ingress handle ffff: 2>/dev/null', shell=True)
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
    options     = params.get('options', [])

    interfaces = fwglobals.g.router_cfg.get_interfaces(dev_id=dev_id)
    if not interfaces:
        return (False, "modify_dhcpd: %s was not found" % (dev_id))

    address = IPNetwork(interfaces[0]['addr'])
    ifc_ip = str(address.ip)
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

    routers_option_found = False
    options_str = ''
    for option in options:
        name = option['option']
        value = option['value']
        options_str += f'option {name} {value};\n'
        if name == 'routers':
            routers_option_found = True
    
    # if user didn't provide a gateway, we put the interface ip
    if not routers_option_found: 
        options_str += f'option routers {ifc_ip};\n'

    subnet_string = 'subnet %s netmask %s' % (subnet, netmask)
    dhcp_string = 'echo "' + subnet_string + ' {\n' + range_string + \
                 options_str + dns_string + '}"' + ' | sudo tee -a %s;' % config_file

    if is_add == 1:
        exec_string = remove_string + dhcp_string
    else:
        exec_string = remove_string

    for mac in mac_assign:
        host = mac.get('host')
        remove_string_2 = 'sudo sed -e "/host %s {/,/}/d" ' \
                          '-i %s; ' % (host, config_file)

        host_string = 'host %s {\n' % (host)
        ethernet_string = 'hardware ethernet %s;\n' % (mac['mac'])
        ip_address_string = 'fixed-address %s;\n' % (mac['ipv4'])
        
        host_name_string = ''
        use_host_name_as_dhcp_option = mac.get('useHostNameAsDhcpOption')
        if use_host_name_as_dhcp_option:
            host_name_string = f'option host-name {host};\n'

        mac_assign_string = 'echo "' + host_string + ethernet_string + ip_address_string + host_name_string + \
                            '}"' + ' | sudo tee -a %s;' % config_file

        if is_add == 1:
            exec_string += remove_string_2 + mac_assign_string
        else:
            exec_string += remove_string_2

    try:
        output = subprocess.check_output(exec_string, shell=True).decode()
    except Exception as e:
        return (False, str(e))

    # Update persistent cache with DHCPD interface
    #
    router_api_db = fwglobals.g.db['router_api'] # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
    if is_add:
        router_api_db['dhcpd']['interfaces'].update({dev_id: None})
    elif dev_id in router_api_db['dhcpd']['interfaces']:
        del router_api_db['dhcpd']['interfaces'][dev_id]
    fwglobals.g.db['router_api'] = router_api_db

    return True

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

    # Get LAN interfaces managed by installed applications.
    # The function below returns dictionary, where keys are application identifiers,
    # and values are lists of vpp interface names, e.g.
    #      { 'com.flexiwan.vpn': ['tun0'] }
    app_lans = fwglobals.g.applications_api.get_interfaces(type="lan", vpp_interfaces=True, linux_interfaces=False)
    app_lans_list = [vpp_if_name for vpp_if_names in app_lans.values() for vpp_if_name in vpp_if_names]

    vpp_if_names = bvi_vpp_name_list + lan_vpp_name_list + loopback_vpp_name_list + app_lans_list

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

def vpp_cli_execute_one(cmd, debug = False):
    """Execute one VPP CLI command.

    :param cmd:      VPP CLI command
    :param debug:    Print command to be executed

    :returns: Output from VPP.
    """
    if debug:
        fwglobals.log.debug(cmd)
    out = _vppctl_read(cmd, wait=False)
    out = out.strip() if out else out
    if debug and out:
        fwglobals.log.debug(str(out))
    return out

def vpp_cli_execute(cmds, debug = False, log_prefix=None, raise_exception_on_error=False):
    """Execute list of VPP CLI commands.

    :param cmds:     List of VPP CLI commands
    :param debug:    Print command to be executed

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """

    if not isinstance(cmds, list):
        fwglobals.log.error("vpp_cli_execute: expect list of commands")
        return (False, "Expect list of commands")

    for cmd in cmds:
        out = vpp_cli_execute_one(cmd, debug)
        if out is None or re.search('unknown|failed|ret=-', out):
            err_str = f"failed vpp_cli_execute_one({cmd}): out={str(out)}"
            if log_prefix:
                err_str = log_prefix + ": " + err_str
            if raise_exception_on_error:
                raise Exception(err_str)
            return (False, err_str)

    return (True, None)

def vpp_set_dhcp_detect(dev_id, remove):
    """Enable/disable DHCP detect feature.

    :param params: params:
                        dev_id -  Interface device bus address.
                        remove  - True to remove rule, False to add.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    addr_type, _ = dev_id_parse(dev_id)

    if  "pci" not in addr_type:
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
    fwglobals.g.policies.vpp_attach_detach_policies(False if remove else True, vpp_if_name)


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

    try:
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        # Order of functions is important, as the first one (_fix_aggregation_format())
        # creates clone of the received message, so the rest functions can simply
        # modify it as they wish!
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        msg = _fix_aggregation_format(msg)
        msg = _fix_dhcp(msg)
        msg = _fix_application(msg)
        return msg
    except Exception as e:
        fwglobals.log.error(f"fix_received_message failed: {str(e)} {traceback.format_exc()}")
        return None

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

        wpaIsRun = True if fw_os_utils.pid_of('wpa_supplicant') else False
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

def get_interface_link_state(if_name, dev_id, device_type=None):
    """Gets interface link state.

    :param if_name: interface name (e.g enp0s3).
    :param dev_id:  interface bus address (e.g '0000:00:16.0').

    :returns: up if link is detected, down if not detected.
    """
    if not if_name:
        fwglobals.log.error('get_interface_link_state: if_name is empty')
        return ''

    def _return_ethtool_value(if_name):
        state = get_ethtool_value(if_name, 'Link detected')
        # 'Link detected' field has yes/no values, so conversion is needed
        return 'up' if state == 'yes' else 'down' if state == 'no' else ''

    if device_type == 'vlan':
        # VLAN link status is the same as its parent
        if_name, _ = if_name_parse_vlan(if_name)

    if device_type == 'lte' or device_type == 'wifi':
        # no need to check for tap interface in case of LTE or WiFi
        return _return_ethtool_value(if_name)

    if not fwglobals.g.router_api.state_is_started():
        # no need to check for tap if router is not running
        return _return_ethtool_value(if_name)

    if not is_interface_assigned_to_vpp(dev_id):
        # no need to check for tap if interface is not assigned to vpp
        return _return_ethtool_value(if_name)

    # Check if interface is managed by vpp (vppctl).
    vpp_if_name = tap_to_vpp_if_name(if_name)
    if vpp_if_name:
        return vpp_get_interface_status(dev_id=dev_id).get('link')

    return _return_ethtool_value(if_name)

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
    if fwutils.is_vlan_interface(dev_id=dev_id):
        return True

    return False

def get_ipaddress_ip_network(ip_str):
    try:
        return ipaddress.ip_network(ip_str, strict=False)
    except Exception as e:
        fwglobals.log.warning(f"_get_ip_network_from_str: {ip_str} is not ip address. err={str(e)}")
        return None

def frr_add_remove_interface_routes_if_needed(is_add, routing, dev_id):
    """Check if need to advertise in FRR some built-in routes automatically along with the given interface.

    For example, if an interface has an address with /32 netmask,
        the DHCP server pushes routes to the client to reach the whole network via the gateway.
        Once we call "netplan apply" for this interface, new routes are installed with the "DHCP" protocol.
            root@VB1:/etc/frr# ip a
            vpp1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 1000
                link/ether 08:00:27:96:18:0e brd ff:ff:ff:ff:ff:ff
                inet 155.155.155.10/32 scope global dynamic vpp1
                valid_lft 455sec preferred_lft 455sec

            root@VB1:/etc/frr# ip route
            155.155.155.0/24 via 155.155.155.1 dev vpp1 proto dhcp src 155.155.155.10
            155.155.155.1 dev vpp1 proto dhcp scope link src 155.155.155.10

        In order to advertised the whole network to OSPF/BGP neighbors, and not only the interface ip and mask,
        We need to specify them in our frr access lists.

    :param is_add: Indicate if to add the routes or removed them (add-X or remove-X process).
    :param routing: Routing protocol to add routes for ("ospf" or "bgp").
    :param dev_id: Bus address of interface to check.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    try:
        if_addr_str = get_interface_address(None, dev_id)
        if not if_addr_str:
            fwglobals.log.warning(f"frr_add_remove_interface_routes_if_needed: no ip found for dev_id {dev_id}")
            return (True, None) # We do not fail add-interface if there is no IP

        if_addr = get_ipaddress_ip_network(if_addr_str)
        if not if_addr:
            return (False, f'failed to convert {if_addr_str} to ip_network object')

        routes_to_advertise = []

        # get linux ip routes
        routes_linux = FwLinuxRoutes(proto='dhcp')
        for route in routes_linux.values():
            if route.prefix == '0.0.0.0/0':
                continue

            # make sure first word is a network
            dest_network = get_ipaddress_ip_network(route.prefix)
            if not dest_network:
                continue

            # /32 routes are not relevant here
            if dest_network.prefixlen == 32:
                continue

            # get linux ip routes
            if dest_network.overlaps(if_addr):
                routes_to_advertise.append(str(dest_network))

        if routing == 'ospf':
            frr_acl_name = fwglobals.g.FRR_OSPF_ACL
        elif routing == 'bgp':
            frr_acl_name = fwglobals.g.FRR_BGP_ACL
        else:
            return (False, f'frr_add_remove_interface_routes_if_needed(): unsupported routing protocol ({routing}) provided')

        revert_succeeded_vtysh_commands = []
        for route in routes_to_advertise:
            if is_add:
                cmd = f"access-list {frr_acl_name} permit {route}"
                revert_cmd = f"no {cmd}"
            else:
                cmd = f"no access-list {frr_acl_name} permit {route}"
                revert_cmd = cmd.split(maxsplit=1)[1] # take out the "no" by splitting by first space and take the rest.

            success, err = frr_vtysh_run([cmd])
            if success:
                revert_succeeded_vtysh_commands.append(revert_cmd)
            else:
                # first revert the succeeded commands, then throw exception.
                # don't catch exception of revert because it has no end. In any case exception will be thrown
                frr_vtysh_run(revert_succeeded_vtysh_commands)
                raise Exception(err)

        return (True, None)
    except Exception as e:
        return (False, f'frr_add_remove_interface_routes_if_needed({is_add}, {routing}, {dev_id}): failed. error={str(e)}')

# A list of allowed outputs from vtysh that should not fail the job
allowed_vtysh_outputs = [
    'For this router-id change to take effect, save config and restart ospfd\n'
]
def frr_vtysh_run(commands, restart_frr=False, wait_after=None, on_error_commands=[]):
    '''Run vtysh command to configure router

    :param commands:          array of frr commands
    :param restart_frr:       some OSPF configurations require restarting the service in order to apply them
    :param wait_after:        seconds to wait after successful command execution.
                              It might be needed to give a system/vpp time to get updates as a result of frr update.
    :param on_error_commands: array of frr commands to run if one of the "commands" fails.
    '''
    def _revert():
        if on_error_commands:
            str_error_commands = "\n".join(on_error_commands)
            fwglobals.log.debug(f"frr_vtysh_run: revert starting. on_error_commands={str_error_commands}")
            frr_vtysh_run(on_error_commands, restart_frr, on_error_commands=[]) # on_error_commands= empty list to prevent infinite loop
            fwglobals.log.debug(f"frr_vtysh_run: revert finished")
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

        p = subprocess.Popen(vtysh_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        (out, err) = p.communicate()
        # Note, vtysh cli prints errors/warnings to STDOUT.
        # If no errors/warnings, "out" is empty string.
        if out:
            if out in allowed_vtysh_outputs:
                fwglobals.log.warning(f"frr_vtysh_run: allowed warning received when executed FRR commands. vtysh_cmd={vtysh_cmd} out={out}.. ignore")
            else:
                raise Exception(f"(vtysh_cmd failed: vtysh_cmd={vtysh_cmd}, out={out}, err={err})")

        if restart_frr:
            os.system('systemctl restart frr')

        if wait_after:
            time.sleep(wait_after)

        return (True, None)
    except Exception as e:
        fwglobals.log.error(f"frr_vtysh_run: exception occurred. commands={commands} err={str(e)}. reverting..")
        _revert()
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

def frr_clean_files():
    if os.path.exists(fwglobals.g.FRR_CONFIG_FILE):
        os.remove(fwglobals.g.FRR_CONFIG_FILE)

    if os.path.exists(fwglobals.g.FRR_OSPFD_FILE):
        os.remove(fwglobals.g.FRR_OSPFD_FILE)
    if os.path.exists(fwglobals.g.FRR_OSPFD_FILE + '.sav'): # frr cache file
        os.remove(fwglobals.g.FRR_OSPFD_FILE + '.sav')

    if os.path.exists(fwglobals.g.FRR_BGPD_FILE):
        os.remove(fwglobals.g.FRR_BGPD_FILE)
    if os.path.exists(fwglobals.g.FRR_BGPD_FILE + '.sav'): # frr cache file
        os.remove(fwglobals.g.FRR_BGPD_FILE + '.sav')

    if os.path.exists(fwglobals.g.FRR_ZEBRA_FILE):
        os.remove(fwglobals.g.FRR_ZEBRA_FILE)
    if os.path.exists(fwglobals.g.FRR_ZEBRA_FILE + '.sav'): # frr cache file
        os.remove(fwglobals.g.FRR_ZEBRA_FILE + '.sav')

def frr_setup_config():
    '''Setup the /etc/frr/frr.conf file, initializes it and
    ensures that ospf is switched on in the frr configuration'''

    # Ensure that ospfd is switched on in /etc/frr/daemons.
    subprocess.check_call('if [ -n "$(grep ospfd=no %s)" ]; then sudo sed -i -E "s/ospfd=no/ospfd=yes/" %s; sudo systemctl restart frr; fi'
            % (fwglobals.g.FRR_DAEMONS_FILE,fwglobals.g.FRR_DAEMONS_FILE), shell=True)

    # Ensure that bgpd is switched on in /etc/frr/daemons.
    # Important! We have to enable it always in order that access-lists and route-maps
    # will be recognized by bgpd daemon
    subprocess.check_call('if [ -n "$(grep bgpd=no %s)" ]; then sudo sed -i -E "s/bgpd=no/bgpd=yes/" %s; sudo systemctl restart frr; fi'
            % (fwglobals.g.FRR_DAEMONS_FILE, fwglobals.g.FRR_DAEMONS_FILE), shell=True)

    # Ensure that integrated-vtysh-config is disabled in /etc/frr/vtysh.conf.
    subprocess.check_call('sudo sed -i -E "s/^service integrated-vtysh-config/no service integrated-vtysh-config/" %s' % (fwglobals.g.FRR_VTYSH_FILE), shell=True)

    # Setup basics on frr.conf.
    frr_commands = [
        "password zebra",
        f"log file {fwglobals.g.FRR_LOG_FILE} notifications",
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
        cmd = 'netplan apply'
        log_str = caller_name + ': ' + cmd if caller_name else cmd
        fwglobals.log.debug(log_str)
        os.system(cmd)
        time.sleep(1)  				# Give a second to Linux to configure interfaces

        if fwglobals.g.is_gcp_vm:
            # Google Guest Agent has an issue when starting it without IP on the primary interface.
            # This service may also depend on 'systemd-networkd'.
            # (See 'WantedBy' attribute in Google Guest Agent service fi
            # In the process of start-router or modify-interface, we call 'netplan apply' a few times
            # even when the interface is not fully configured.
            # The 'netplan apply' causes the stop and start of 'systemd-networkd'
            # and 'systemd-networkd' causes Google Guest Agent to be restarted too.
            # This leads to the issue that Google Guest Agent is stuck when starting with no IP.
            # We saw that 'systemctl restart systemd-networkd' solves the issue.
            # Hence, After each netplan apply we call restart of systemd-networkd to make it work.
            os_system('systemctl restart systemd-networkd')
            time.sleep(1)  				# Give a second to Linux to configure interfaces

        # Netplan might change interface names, e.g. enp0s3 -> vpp0, or other parameters so reset cache
        #
        fwglobals.g.cache.linux_interfaces_by_name.clear()
        clear_linux_interfaces_cache()

        # IPv6 might be renable if interface name is changed using set-name
        disable_ipv6()


    except Exception as e:
        fwglobals.log.debug("%s: netplan_apply failed: %s" % (caller_name, str(e)))
        return False

def compare_request_params(params1, params2):
    """ Compares two dictionaries while normalizing them for comparison
    and ignoring orphan keys that have None or empty string value.
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
                    fwglobals.log.debug(f"compare_request_params: string values of key '{key}' are different: '{val1}' != '{val2}'")
                    return False    # Strings are not equal
            elif type(val1) != type(val2):
                fwglobals.log.debug(f"compare_request_params: '{key}': {str(type(val1))} != {str(type(val2))}")
                return False        # Types are not equal
            elif val1 != val2:
                fwglobals.log.debug(f"compare_request_params: values of key '{key}' are different: '{format(val1)}' != '{format(val2)}'")
                return False        # Values are not equal

        # If False booleans or if one of values not exists or empty string.
        #
        elif (val1 and not val2) or (not val1 and val2):
            fwglobals.log.debug(f"compare_request_params: either val1 or val2 of '{key}' does not exist: '{format(val1)}' != '{format(val2)}'")
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

def get_reconfig_hash():
    """ This function creates a string that holds all the information added to the reconfig
    data, and then create a hash string from it.

    : return : md5 hash result of all the data collected or empty string.
    """
    res = ''

    linux_interfaces = get_linux_interfaces()
    for dev_id in linux_interfaces:
        name = linux_interfaces[dev_id]['name']
        device_type = linux_interfaces[dev_id].get('deviceType')

        # Link state has to be retrieved first. Otherwise code below will.
        # change the interface name to be used. And this can create an issue.
        # For example, in case of bridge interface we need state of member interface
        # and not the state of bridge itself.
        link = get_interface_link_state(name, dev_id, device_type=device_type)

        # Some interfaces need special logic to get their ip
        # For LTE/WiFi/Bridged interfaces - we need to take it from the tap name
        tap_name = linux_interfaces[dev_id].get('tap_name')
        if tap_name:
            name = tap_name

        addr = get_interface_address(name, log=False)
        gw, metric = get_interface_gateway(name)

        addr = addr.split('/')[0] if addr else ''

        mtu = str(linux_interfaces[dev_id]['mtu'])

        res += 'deviceType:'  + linux_interfaces[dev_id].get('deviceType') + ','
        res += 'addr:'    + addr + ','
        res += 'gateway:' + gw + ','
        res += 'metric:'  + metric + ','
        res += 'mtu:'  + mtu + ','
        if gw and addr:
            res += 'public_ip:'   + linux_interfaces[dev_id]['public_ip'] + ','
            res += 'public_port:' + str(linux_interfaces[dev_id]['public_port']) + ','
        res += 'link:'  + link + ','

    hash = hashlib.md5(res.encode()).hexdigest()
    fwglobals.log.debug("get_reconfig_hash: %s: %s" % (hash, res))
    return hash

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

def fwdump(filename=None, path=None, clean_log=False):
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

    interfaces.pop("lo", None)  # Light optimization - 'lo' is out of our interest

    for if_name in interfaces:
        addresses = interfaces[if_name]
        for address in addresses:
            if address.family == socket.AF_INET:
                network = IPNetwork(address.address + '/' + address.netmask)
                if net_if_stats[if_name].isup and is_ip_in_subnet(gw, str(network)):
                    return True
    return False

def exec(cmd, timeout=60):
    """Runs bash command and return result in format suitable for
    fwcfg_request_handler (see _parse_result() function for details).

    :param cmd: bash command

    :returns: tuple of (<boolean success>, <output/error string>)
    """
    success = False
    try:
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        (out, err) = p.communicate(timeout=timeout)
        if p.returncode != 0:
            return (False, err)
        return (True, out)
    except subprocess.TimeoutExpired:
        p.kill()
        return (False, f"timeout ({timeout} seconds) on waiting for command to return")
    except Exception as err:
        return (False, str(err))

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
    out_keys = []
    for key in keys:
        out_keys.append(arg[key])
    return out_keys


def build_timestamped_filename(filename, ext='', separator='_'):
    '''Incorporates date and time into the filename in format "%Y%M%d_%H%M%S".
    Example:
        build_timestamped_filename("fwdump_EdgeDevice01_", ext='.tar.gz')
        ->
        fwdump_EdgeDevice01_20210510_131900.tar.gz
    '''
    return filename + separator + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ext

def is_ipv4(str_to_check):
    try:
        ipaddress.ip_network(str_to_check, strict=False)
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

def load_linux_tap_modules():
    return load_linux_modules(['tap', 'vhost', 'vhost-net'])

def load_linux_tc_modules():
    return load_linux_modules(['act_gact', 'act_mirred', 'act_pedit', 'cls_u32', 'sch_htb', 'sch_ingress', 'uio'])

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

def get_linux_interface_mtu(if_name):
    net_if_stats = psutil.net_if_stats()
    if if_name not in net_if_stats:
        return ''

    return str(net_if_stats[if_name].mtu)

def os_system(cmd, log_prefix="", log=True, print_error=True, raise_exception_on_error=False):
    error = None
    if log:
        fwglobals.log.debug(cmd)

    rc = os.system(cmd)
    if rc:
        prefix = f'{log_prefix}: ' if log_prefix else ''
        error = f'{prefix}command failed: {cmd}'

        if print_error:
            fwglobals.log.error(error)

        if raise_exception_on_error:
            raise Exception(error)

    return (not bool(rc), error)

def detect_gcp_vm():
    '''Detect if the machine is a VM of Google Cloud Platform.
    '''
    cmd = 'sudo dmidecode -s system-product-name | grep "Google Compute Engine"'
    output = os.popen(cmd).read().strip()
    return output == "Google Compute Engine"

def list_to_dict_by_key(list, key_name):
    ''' Creates an object that composed of keys generated from the results of running an each item of the given list.

    Currently, the function returns the element only if the "key" exists in the nested object.
    '''
    res = {}
    for item in list:
        if type(item) == dict:
            key = item.get(key_name)
            if key:
                res[key] = item
    return res

def get_device_networks_json(type=None):
    networks = set() # prevent duplication of bridged interfaces

    interfaces = fwglobals.g.router_cfg.get_interfaces(type=type)
    for interface in interfaces:
        if interface['dhcp'] == 'yes':
            # take from interface itself
            linux_if_name = dev_id_to_linux_if_name_safe(interface['dev_id'])
            network = get_interface_address(linux_if_name, log=False, log_on_failure=False)
            if network:
                networks.add(network)
        else:
            networks.add(interface['addr'])

    return json.dumps(list(networks), indent=2, sort_keys=True)

def shutdown_activate_bgp_peer_if_exists(neighbor_ip, shutdown):
    try:
        bgp_config = fwglobals.g.router_cfg.get_bgp()
        if not bgp_config:
            return (True, None)

        neighbors = bgp_config.get('neighbors', [])

        exists = False
        for neighbor in neighbors:
            ip = neighbor.get('ip')
            if ip and ip == neighbor_ip:
                exists = True
                break

        if not exists:
            return (True, None)

        vtysh_cmd = ['router bgp']
        if shutdown:
            vtysh_cmd.append(f'neighbor {neighbor_ip} shutdown')
        else:
            vtysh_cmd.append(f'no neighbor {neighbor_ip} shutdown')

        return frr_vtysh_run(vtysh_cmd)
    except Exception as e:
        return (False, str(e))

def exec_with_retrials(cmd, retrials = 30, expected_to_fail=False):
    for _ in range(retrials):
        try:
            subprocess.check_output(cmd, shell=True).decode()
            if not expected_to_fail:
                return True
        except:
            if expected_to_fail:
                return True
        time.sleep(1)
    return False

def exec_to_file(cmd, file_name):
    with open(file_name, 'w') as f:
        try:
            subprocess.call(cmd, stdout=f, shell=True)
        except Exception as e:
            fwglobals.log.excep(f"exec_to_file({cmd}, {file_name}) failed. error={str(e)}")
            pass

def build_tunnel_bgp_neighbor(tunnel):
    loop0_ip         = tunnel['loopback-iface']['addr']
    remote_loop0_ip  = build_tunnel_remote_loopback_ip(loop0_ip)
    bgp_remote_asn   = tunnel['loopback-iface'].get('bgp-remote-asn')
    return {
        'ip': remote_loop0_ip,
        'remoteAsn': bgp_remote_asn
    }

def create_tun_in_vpp(addr, host_if_name, recreate_if_exists=False, no_vppsb=False):
    # ensure that tun is not exists in case of down-script failed
    tun_exists = os.popen(f'sudo vppctl show tun | grep -B 1 "{host_if_name}"').read().strip()
    if tun_exists:
        if not recreate_if_exists:
            raise Exception(f'The tun "{host_if_name}" already exists in VPP. tun_exists={str(tun_exists)}')

        # root@flexiwan-zn1:/home/shneorp# sudo vppctl show tun | grep -B 1 "vpp_remotevpn"
        # Interface: tun0 (ifindex 7)
        #   name "vpp_remotevpn"
        tun_name = tun_exists.splitlines()[0].split(' ')[1]
        os.system(f'sudo vppctl delete tap {tun_name}')

    # configure the vpp interface
    cmd = f'create tap host-if-name {host_if_name} tun'
    if no_vppsb:
        cmd += ' no-vppsb'
    tun_vpp_if_name = vpp_cli_execute_one(cmd)
    if not tun_vpp_if_name:
        raise Exception('Cannot create tun device in vpp')

    fwglobals.log.info(f'create_tun_in_vpp(): TUN created in vpp. vpp_if_name={tun_vpp_if_name}')

    vpp_cmds = [
        f'set interface ip address {tun_vpp_if_name} {addr}',
        f'set interface state {tun_vpp_if_name} up'
    ]

    vpp_cli_execute(vpp_cmds)

    return tun_vpp_if_name

def delete_tun_tap_from_vpp(vpp_if_name, ignore_errors):
    vpp_cli_execute([f'delete tap {vpp_if_name}'], raise_exception_on_error=(not ignore_errors))

def vpp_add_remove_nat_identity_mapping_from_wan_interfaces(is_add, port, protocol):
    """
    Configure VPP NAT identity mapping for all WAN interfaces.

    :param is_add:    True to set, False to remove.
    :param port:      Port number.
    :param protocol:  Protocol name (not number). Valid names are listed in "proto_map".

    :returns: Return list.
    """
    wan_interfaces = fwglobals.g.router_cfg.get_interfaces(type='wan')
    for wan_interface in wan_interfaces:
        dev_id = wan_interface.get('dev_id')
        sw_if_index = dev_id_to_vpp_sw_if_index(dev_id)
        fwglobals.log.info(f'vpp_add_remove_nat_identity_mapping_from_wan_interfaces(): applying on {dev_id}. sw_if_index={sw_if_index}')
        fwglobals.g.router_api.vpp_api.vpp.call(
            'nat44_add_del_identity_mapping',
            sw_if_index=sw_if_index,
            port=port,
            protocol=proto_map[protocol],
            is_add=is_add,
        )

def get_vxlan_port():
    """
    Returns integer of vxlan source port.
    """
    vxlan_config = fwglobals.g.router_cfg.get_vxlan_config()
    if not vxlan_config:
        return fwglobals.g.default_vxlan_port
    return int(vxlan_config.get('port', fwglobals.g.default_vxlan_port))

def get_version(version_str):
    source_version = version_str.split('-')[0].split('.')
    return (int(source_version[0]), int(source_version[1]))

def version_less_than(source_version_str, target_version_str):
    source_major_version, source_minor_version = get_version(source_version_str)
    target_major_version, target_minor_version = get_version(target_version_str) 
    return source_major_version < target_major_version or \
        (source_major_version == target_major_version and source_minor_version < target_minor_version)

class FwJsonEncoder(json.JSONEncoder):
    '''Customization of the JSON encoder that is able to serialize simple
    Python objects, e.g. FwMultilinkLink. This encoder should be used within
    json.dump/json.dumps calls.
    '''
    def default(self, o):
        try:
            serialized = str(o)      # Firstly, probe the existence of __str__()
        except:
            serialized = o.__dict__  # As a last resort, assume complex object
        return serialized

def is_vlan_interface(dev_id=None, if_name=None):
    '''Check if dev_id/if_name stands for VLAN interface.
    '''
    if dev_id:
        return 'vlan' in dev_id
    else:
        return '.' in if_name

def build_vlan_dev_id(vlan_id, dev_id):
    '''Build vlan dev_id.
    '''
    return f'vlan.{vlan_id}.{dev_id}'

def dev_id_parse_vlan(dev_id):
    '''Parse parent dev_id and vlan id.
    '''
    if not 'pci' in dev_id:
        # lte dev_id does not have 'pci'
        return None, None
    parts = dev_id.split("pci")
    parent_dev_id = "pci" + parts[1]
    vlan_id = int(parts[0].split(".")[1]) if parts[0] else None
    return parent_dev_id, vlan_id

def if_name_parse_vlan(if_name):
    '''Parse parent if_name and vlan id.
    '''
    parts = if_name.split('.')
    if len(parts) != 2:
        return (None, 0)
    parent_if_name = parts[0]
    vlan_id = int(parts[1])
    return parent_if_name, vlan_id

def dev_id_get_parent (dev_id):
    if (is_vlan_interface (dev_id)):
        parent_dev_id, _ = dev_id_parse_vlan (dev_id)
    else:
        parent_dev_id = dev_id
    return parent_dev_id

def vpp_loopback_get_mac_address(sw_if_index):
    mac = "de:ad:00:00:%0.4x" % sw_if_index
    mac = mac[:-2] + ':' + mac[-2:]
    return mac

def vpp_vrrp_get_mac_address(vr_id):
    mac = "00:00:5e:00:01%0.2x" % vr_id
    mac = mac[:-2] + ':' + mac[-2:]
    return mac

def vrrp_add_del_vr(params, is_add, result_cache=None):
    virtual_router_id = params.get('virtualRouterId')
    virtual_router_ip = params.get('virtualIp')
    priority = params.get('priority')
    dev_id = params.get('devId')
    interval = params.get('interval', 100)

    preemption = params.get('preemption')
    accept_mode = params.get('acceptMode')
    preemption_flag  = 0x1 if preemption else 0  # see VRRP_API_VR_PREEMPT = 1 in vrrp_api.json
    accept_mode_flag = 0x2 if accept_mode else 0 # see VRRP_API_VR_ACCEPT = 2 in vrrp_api.json

    is_switch = False
    sw_if_index = dev_id_to_switch_sw_if_index(dev_id)
    if sw_if_index:
       is_switch = True
    else:
       sw_if_index = dev_id_to_vpp_sw_if_index(dev_id)


    with FwCfgMultiOpsWithRevert() as handler:
        try:
            handler.exec(
                func=fwglobals.g.router_api.vpp_api.vpp.call,
                params={
                    'api_name': 'vrrp_vr_add_del',
                    'is_add': is_add,
                    'vr_id': virtual_router_id,
                    'priority': priority,
                    'flags': (preemption_flag|accept_mode_flag),
                    'addrs': [ipaddress.ip_address(virtual_router_ip)],
                    'n_addrs': 1,
                    'interval': interval,
                    'sw_if_index': sw_if_index
                },
                revert_func=fwglobals.g.router_api.vpp_api.vpp.call,
                revert_params={
                    'api_name': 'vrrp_vr_add_del',
                    'is_add': 0 if is_add else 1,
                    'vr_id': virtual_router_id,
                    'priority': priority,
                    'flags': (preemption_flag|accept_mode_flag),
                    'addrs': [ipaddress.ip_address(virtual_router_ip)],
                    'n_addrs': 1,
                    'interval': interval,
                    'sw_if_index': sw_if_index
                }
            )

            if not is_switch:
                return

            if is_add:
                set_mac_address = vpp_vrrp_get_mac_address(virtual_router_id)
                revert_mac_address = vpp_loopback_get_mac_address(sw_if_index)
            else:
                set_mac_address = vpp_loopback_get_mac_address(sw_if_index)
                revert_mac_address = vpp_vrrp_get_mac_address(virtual_router_id)

            handler.exec(
                func=fwglobals.g.router_api.vpp_api.vpp.call,
                params={
                    'api_name': 'sw_interface_set_mac_address',
                    'sw_if_index': sw_if_index,
                    'mac_address': mac_str_to_bytes(set_mac_address)
                },
                revert_func=fwglobals.g.router_api.vpp_api.vpp.call,
                revert_params={
                    'api_name': 'sw_interface_set_mac_address',
                    'sw_if_index': sw_if_index,
                    'mac_address': mac_str_to_bytes(revert_mac_address)
                }
            )

        except Exception as e:
            fwglobals.log.error(f"vrrp_add_del_vr({str(params), is_add, str(result_cache)}) failed: {str(e)}")
            handler.revert(e)

    # Store 'bridge_id' in cache if provided by caller.
    #
    if result_cache and result_cache['result_attr'] == 'sw_if_index':
        key = result_cache['key']
        result_cache['cache'][key] = sw_if_index


def vrrp_add_del_track_interfaces(track_interfaces, is_add, vr_id, sw_if_index, track_ifc_priority):
    interfaces = []
    for track_interface in track_interfaces:
        track_ifc_dev_id = track_interface.get('devId')
        track_sw_if_index = dev_id_to_vpp_sw_if_index(track_ifc_dev_id)
        interfaces.append({ 'sw_if_index': track_sw_if_index, 'priority': track_ifc_priority })

    if not interfaces:
        return (True, None)

    fwglobals.g.router_api.vpp_api.vpp.call(
        'vrrp_vr_track_if_add_del',
        is_add=is_add,
        vr_id=vr_id,
        n_ifs=len(interfaces),
        ifs=interfaces,
        sw_if_index=sw_if_index
    )

class DYNAMIC_INTERVAL():
    def __init__(self, value, max_value_on_failure):
        self.default  = value
        self.current  = value
        self.max      = max_value_on_failure
        self.failures = 0

    def update(self, failure):
        if failure:
            self.failures += 1
            if self.failures % 3 == 0:   # forgive 3 failure before increasing interval
                self.current = min(self.max, self.current * 2)
        else:
            self.current  = self.default
            self.failures = 0

def normalize_for_json_dumps(input_value):
    """Modifies the input dictionary, list or other basic python type to have
    only these values that are eatable by the json.dumps:
        - replaces bytearrays with strings
    """
    normilized = False

    def _normalize_for_json_dumps(input):
        """Recursive function for dict deep search and replace bytearray.
        """
        nonlocal normilized
        if type(input) == dict:
            for key, val in input.items():
                input[key] = _normalize_for_json_dumps(val)
            return input
        elif type(input) == list:
            return [_normalize_for_json_dumps(value) for value in input]
        elif isinstance(input, (bytes, bytearray)):
            normilized = True
            return str(input)
        else:
            return input

    try:
        new = copy.deepcopy(input_value) # avoid in-place modification of original
        new = _normalize_for_json_dumps(new)
    except Exception as e:
        input_value_str = json.dumps(input_value, indent=2, sort_keys=True, cls=fwutils.FwJsonEncoder)
        fwglobals.log.excep(f'normalize_for_json_dumps: {str(e)}: {input_value_str}')
        return input_value

    return new if normilized else input_value
