#! /usr/bin/python3

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
import glob
import os
import re
import subprocess
import time
import yaml

import fwglobals
import fwlte
import fwutils
import fwpppoe
import fwroutes

from fwwan_monitor import get_wan_failover_metric

def _copyfile(source_name, dest_name, buffer_size=1024*1024):
    with open(source_name, 'r') as source, open(dest_name, 'w') as dest:
        while True:
            copy_buffer = source.read(buffer_size)
            if not copy_buffer:
                break
            fwutils.file_write_and_flush(dest, copy_buffer)

def backup_linux_netplan_files():
    for values in list(fwglobals.g.NETPLAN_FILES.values()):
        fname = values.get('fname')
        fname_backup = fname + '.fw_run_orig'
        fname_run = fname.replace('yaml', 'fwrun.yaml')

        fwglobals.log.debug('_backup_netplan_files: doing backup of %s' % fname)
        if not os.path.exists(fname_backup):
            _copyfile(fname, fname_backup)
        if not os.path.exists(fname_run):
            _copyfile(fname, fname_run)
        if os.path.exists(fname):
            os.remove(fname)

def restore_linux_netplan_files():
    files = glob.glob("/etc/netplan/*.fwrun.yaml") + \
            glob.glob("/lib/netplan/*.fwrun.yaml") + \
            glob.glob("/run/netplan/*.fwrun.yaml")

    for fname in files:
        fname_run = fname
        fname = fname_run.replace('fwrun.yaml', 'yaml')
        fname_backup = fname + '.fw_run_orig'

        if os.path.exists(fname_run):
            os.remove(fname_run)

        if os.path.exists(fname_backup):
            _copyfile(fname_backup, fname)
            os.remove(fname_backup)

    if files:
        fwutils.netplan_apply('restore_linux_netplan_files')


def netplan_get_filepaths():

    return glob.glob("/etc/netplan/*.yaml") + \
           glob.glob("/lib/netplan/*.yaml") + \
           glob.glob("/run/netplan/*.yaml")


def netplan_unload_vpp_assigned_ports(assigned_linux_interfaces):
    '''
    The function is called after taking backup of original netplan file and
    before adding VPP tap interfaces to netplan. The function modifies the system
    netplan files (Common example: Modifies 50-cloud-init.yaml) i.e removes the
    ports assigned to VPP from it and applies the updated config. Doing this is
    needed to prevent, VPP tap-inject interfaces from getting renamed immediately
    after create (due to set-name) by linux system network service.

    params assigned_linux_interfaces: List of Linux interface names assigned to VPP
    '''
    files = netplan_get_filepaths()
    netplan_apply = False

    for fname in files:

        changed = False
        config = None
        with open(fname, 'r') as stream:
            config = yaml.safe_load(stream)
            if config is None:
                continue
            if 'network' in config:
                network = config['network']
                if 'ethernets' in network:
                    ethernets = network['ethernets']
                    ethernets_updates = copy.deepcopy(ethernets)
                    for dev in ethernets:
                        set_name = ethernets[dev].get('set-name', dev)
                        if set_name in assigned_linux_interfaces:
                            del ethernets_updates[dev]
                            changed = True
                            fwglobals.log.debug("netplan_unload_vpp_assigned_ports: Device: %s \
                                File: %s" % (set_name, fname))
        if changed:
            config['network']['ethernets'] = ethernets_updates
            with open(fname, 'w') as file_stream:
                yaml.dump(config, file_stream)
            netplan_apply = True

    if netplan_apply:
        fwutils.netplan_apply('netplan_unload_vpp_assigned_ports')


def load_netplan_filenames(read_from_disk=False, get_only=False):
    '''Parses currently active netplan yaml files into dict of device info by
    interface name, where device info is represented by tuple:
    (<netplan filename>, <interface name>, <gw>, <dev_id>, <set-name name>).
    Than the parsed info is loaded into fwglobals.g.NETPLAN_FILES cache.

    :param read_from_disk: if True it means that we need to fill the cache with the data that stored on the disk.
    :param get_only: if True the parsed info is not loaded into cache.
    '''

    if read_from_disk:
        netplan_filenames = fwglobals.g.db.get('netplan', {}).get('filenames')
        if netplan_filenames:
            fwglobals.log.debug("load_netplan_filenames: loading from disk. %s" % str(netplan_filenames))
            fwglobals.g.NETPLAN_FILES = dict(netplan_filenames)
            return fwglobals.g.NETPLAN_FILES

    devices = {}
    routes_linux = fwroutes.FwLinuxRoutes(prefix='0.0.0.0/0')
    for route in routes_linux.values():
        devices[route.dev] = route.via

    files = glob.glob("/etc/netplan/*.fw_run_orig") + \
            glob.glob("/lib/netplan/*.fw_run_orig") + \
            glob.glob("/run/netplan/*.fw_run_orig")

    if not files:
        files = glob.glob("/etc/netplan/*.yaml") + \
                glob.glob("/lib/netplan/*.yaml") + \
                glob.glob("/run/netplan/*.yaml")

    fwglobals.log.debug("load_netplan_filenames: %s" % files)

    our_files = {}
    for fname in files:
        with open(fname, 'r') as stream:
            if re.search('fw_run_orig', fname):
                fname = fname.replace('yaml.fw_run_orig', 'yaml')
            config = yaml.safe_load(stream)
            if config is None:
                continue
            if 'network' in config:
                network = config['network']
                if 'ethernets' in network:
                    ethernets = network['ethernets']
                    for dev in ethernets:
                        name = ethernets[dev].get('set-name', '')
                        if name:
                            gateway = devices.get(name)
                            dev_id = fwutils.get_interface_dev_id(name)
                        else:
                            gateway = devices.get(dev)
                            dev_id = fwutils.get_interface_dev_id(dev)
                        if fname in our_files:
                            our_files[fname].append({'ifname': dev, 'gateway': gateway, 'dev_id': dev_id, 'set-name': name})
                        else:
                            our_files[fname] = [{'ifname': dev, 'gateway': gateway, 'dev_id': dev_id, 'set-name': name}]

    if get_only:
        return our_files

    for fname, devices in list(our_files.items()):
        for dev in devices:
            dev_id = dev.get('dev_id')
            ifname = dev.get('ifname')
            set_name = dev.get('set-name')
            if dev_id:
                fwglobals.g.NETPLAN_FILES[dev_id] = {'fname': fname, 'ifname': ifname, 'set-name': set_name}
                fwglobals.log.debug('load_netplan_filenames: %s(%s) uses %s' % (ifname, dev_id, fname))

    # Save the disk cache for use when needed
    netplan = fwglobals.g.db.get('netplan')
    if not netplan:
        fwglobals.g.db['netplan'] = {}
    netplan_db = fwglobals.g.db['netplan']  # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
    netplan_db['filenames'] = fwglobals.g.NETPLAN_FILES
    fwglobals.g.db['netplan'] = netplan_db

def _write_to_netplan_file(fname, config, **args):
    with open(fname, 'w') as stream:
        yaml.safe_dump(config, stream, **args)
        stream.flush()
        os.fsync(stream.fileno())

def _add_netplan_file(fname):
    if os.path.exists(fname):
        return

    config = dict()
    config['network'] = {'version': 2, 'renderer': 'networkd'}
    _write_to_netplan_file(fname, config, default_flow_style=False)

def _dump_netplan_file(fname):
    if fname:
        try:
            with open(fname, 'r') as f:
                fwglobals.log.error("NETPLAN file contents: " + f.read())
        except Exception as e:
            err_str = "_dump_netplan_file failed: file: %s, error: %s"\
              % (fname, str(e))
            fwglobals.log.error(err_str)

def _set_netplan_section_dhcp(config_section, dhcp, type, metric, ip, gw, dnsServers=None, dnsDomains=None):
    if 'dhcp6' in config_section:
        del config_section['dhcp6']

    nameservers = config_section.get('nameservers', {})
    if dnsServers:
        nameservers['addresses'] = dnsServers
        config_section['nameservers'] = nameservers

    if dnsDomains:
        nameservers['search'] = dnsDomains
        config_section['nameservers'] = nameservers

    if type == 'LAN' and 'gateway4' in config_section :
        del config_section['gateway4']

    if re.match('yes', dhcp):
        if 'addresses' in config_section:
            del config_section['addresses']
        if 'routes' in config_section:
            del config_section['routes']
        if 'gateway4' in config_section:
            del config_section['gateway4']

        config_section['dhcp4'] = True
        config_section['dhcp4-overrides'] = {'route-metric': metric}

        # If a user doesn't specify static DNS servers and domains, use DNS that received from DHCP
        if not dnsServers and not dnsDomains and 'nameservers' in config_section:
            del config_section['nameservers']

        # Override DNS info received from DHCP server with those configured by the user
        if dnsServers:
            config_section['dhcp4-overrides']['use-dns'] = False
        elif config_section.get('nameservers', {}).get('addresses'):
            del config_section['nameservers']['addresses']

        if dnsDomains:
            config_section['dhcp4-overrides']['use-domains'] = False
        elif config_section.get('nameservers', {}).get('search'):
            del config_section['nameservers']['search']

        return config_section

    # Static IP
    config_section['dhcp4'] = False
    if 'dhcp4-overrides' in config_section:
        del config_section['dhcp4-overrides']

    if ip:
        config_section['addresses'] = [ip]
    elif 'addresses' in config_section:
        del config_section['addresses']

    if not gw or type != 'WAN':
        return config_section

    # WAN interface configuration
    default_route_found = False
    routes = config_section.get('routes', [])
    for route in routes:
        if route['to'] == '0.0.0.0/0':
            default_route_found = True
            route['metric']     = metric
            route['via']        = gw
            break
    if not default_route_found:
        routes.append({'to': '0.0.0.0/0', 'via': gw, 'metric': metric})
        config_section['routes'] = routes   # Handle case where there is no 'routes' section
    if 'gateway4' in config_section:
        del config_section['gateway4']

    return config_section

def add_remove_netplan_interface(is_add, dev_id, ip, gw, metric, dhcp, type, dnsServers, dnsDomains, mtu=None, if_name=None, netplan_apply=True):
    '''
    :param metric:  integer (whole number)
    '''

    old_ethernets = {}

    if fwpppoe.is_pppoe_interface(dev_id=dev_id):
        err_str = "add_remove_netplan_interface: PPPoE interface %s is not supported" % dev_id
        fwglobals.log.error(err_str)
        return (False, err_str)

    fwglobals.log.debug(
        "add_remove_netplan_interface: is_add=%d, dev_id=%s, ip=%s, gw=%s, metric=%d, dhcp=%s, type=%s, \
         dnsServers=%s, dnsDomains=%s, mtu=%s, if_name=%s" %
        (is_add, dev_id, ip, gw, metric, dhcp, type, dnsServers, dnsDomains, str(mtu), if_name))

    fo_metric = get_wan_failover_metric(dev_id, metric)
    if fo_metric != metric:
        fwglobals.log.debug(
            "add_remove_netplan_interface: dev_id=%s, use wan failover metric %d" % (dev_id, fo_metric))
        metric = fo_metric

    set_name = ''
    old_ifname = ''
    ifname = if_name if if_name else fwutils.dev_id_to_tap(dev_id)
    if not ifname:
        err_str = "add_remove_netplan_interface: %s was not found" % dev_id
        fwglobals.log.error(err_str)
        return (False, err_str)

    dev_id = fwutils.dev_id_to_full(dev_id)
    if dev_id in fwglobals.g.NETPLAN_FILES:
        fname = fwglobals.g.NETPLAN_FILES[dev_id].get('fname')
        fname_run = fname.replace('yaml', 'fwrun.yaml')
        _add_netplan_file(fname_run)

        fname_backup = fname + '.fw_run_orig'

        old_ifname = fwglobals.g.NETPLAN_FILES[dev_id].get('ifname')
        set_name   = fwglobals.g.NETPLAN_FILES[dev_id].get('set-name', '')

        with open(fname_backup, 'r') as stream:
            old_config = yaml.safe_load(stream)
            old_network = old_config['network']
            old_ethernets = old_network['ethernets']
    else:
        fname_run = fwglobals.g.NETPLAN_FILE
        _add_netplan_file(fname_run)

    try:
        with open(fname_run, 'r') as stream:
            config = yaml.safe_load(stream)
            network = config['network']
            network['renderer'] = 'networkd'

        if 'ethernets' not in network:
            network['ethernets'] = {}

        ethernets = network['ethernets']

        config_section = {}
        if old_ethernets:
            if old_ifname in old_ethernets:
                config_section = dict(old_ethernets[old_ifname])

        if mtu:
            config_section['mtu'] = mtu

        # Configure DHCP related logic
        config_section = _set_netplan_section_dhcp(config_section, dhcp, type, metric, ip, gw, dnsServers, dnsDomains)

        # Note, for the LTE interface we have two interfaces.
        # The physical interface (wwan0) and the vppsb(vppX) interface.
        # Both of them have the same dev_id, so we return True from `is_lte_interface()` for both of them.
        # We set the IP configuration only on the vppsb.
        # But if the user has configured in the netplan file also the LTE with set-name option,
        # we need to make sure that in any action, of any kind, that set-name will apply to the physical interface.
        # Note the comments below in the appropriate places.
        is_lte = fwlte.is_lte_interface_by_dev_id(dev_id)

        if is_add == 1:
            '''
            With 'set-name' attribute or not, the main name shall not be changed. Example below:
            enp0s3:
                 set-name: wan3
            After VPP start, Changed as:
            vpp<x>:
                 set-name: wan3
            '''
            if old_ifname in ethernets:
                del ethernets[old_ifname]

            if set_name and is_lte:
                # For LTE interface with set-name we need to keep the `set-name` on the physical interface and not for the vppsb (see explanation above).
                # The part of LTE in netplan should look like this
                # vpp3 (vppsb interface):
                #   addresses: [100.96.96.225/30]
                #   dhcp4: false
                #   mtu: 1500
                #   nameservers:
                #     addresses: [91.205.152.174, 91.205.152.204]
                #   routes:
                #   - {metric: 0, to: 0.0.0.0/0, via: 100.96.96.226}
                # wwan0 (physical interface)::
                #   match: {macaddress: '1e:10:c7:a5:5a:c7'}
                #   set-name: WANLTE
                del config_section['set-name']
                del config_section['match'] # set-name requires 'match' property
                ethernets[ifname] = config_section

                # Keep the old_ifname for LTE (wwan0 e.g) in order to apply the set-name for this interface.
                # So for lte with set-name both interfaces should be listed in netplan files.
                # The physical interface with set-name, and the vppsb (vppX) with IP configuration.
                if old_ethernets and old_ifname in old_ethernets:
                    ethernets[old_ifname] = old_ethernets[old_ifname]

                    # When vpp runs, we don't need the nameservers on the physical interface but the vppsb
                    if 'nameservers' in ethernets[old_ifname]:
                        del ethernets[old_ifname]['nameservers']
            else:
                ethernets[ifname] = config_section
        else:
            # This part of the function is executed when the VPP is running, and we will not stop it.
            # This means that the interface will remain under VPP control and will not be released to Linux control.
            # Hence, when we come to remove an interface, the intention is only to clear its configuration.
            if ifname in ethernets:
                ethernets[ifname] = {}
                ethernets[ifname]['dhcp4'] = False

                # Explanation about LTE with set-name:
                # when we want to remove it from netplan, we have here three variables:
                #    'set_name' which is the new name for the physical interface(WANLTE)
                #    'ifname' which is the vppsb interface name (vpp1).
                #    'old_ifname' which is the original lte interface name (wwan0)
                #
                # 'ethernets' at this point looks:
                # {
                #   'eno1': ...,
                #   'eno2': ...,
                #   'vpp1': {
                #       'addresses': ['10.95.246.39/28'],
                #       'dhcp4': False,
                #       'mtu': 1500,
                #       'nameservers': {'addresses': ['91.135.104.8', '91.135.102.8']},
                #       'routes': [{'metric': 150, 'to': '0.0.0.0/0', 'via': '10.95.246.40'}]},
                #    'wwan0': {'match': {'macaddress': 'ba:2a:be:44:38:e8'}, 'set-name': 'WANLTE'}
                # }
                # So we need to clear the ip configuration for vpp1, and keep the the set-name on the wwan0

        _write_to_netplan_file(fname_run, config)

        # Remove default route from ip table because Netplan is not doing it.
        if not is_add and type == 'WAN':
            fwutils.remove_linux_default_route(ifname)

        if netplan_apply:
            fwutils.netplan_apply('add_remove_netplan_interface')

        if is_add and set_name and set_name is not ifname and not is_lte:
            # To understand the following code, it is necessary to understand the following two principles:
            #
            # 1. To apply the set-name,
            #   the interface name in netplan must be the *current* interface name in Linux.
            #   The "match" section is not enough for changing the interface name.
            #
            #   Assuming we have vpp0 in Linux and we want to change it to eth2 -
            #     The following netplan config will work:
            #       vpp0:
            #         addresses: [172.16.55.1/24]
            #         dhcp4: false
            #         match: {macaddress: '00:e0:ed:8f:73:94'}
            #         mtu: 1400
            #         set-name: eth2
            #
            #     The following netplan config will not work:
            #       eth2:
            #         addresses: [172.16.55.1/24]
            #         dhcp4: false
            #         match: {macaddress: '00:e0:ed:8f:73:94'}
            #         mtu: 1400
            #         set-name: eth2
            #
            # 2. When the agent enables tap-inject in the start-router process, the vppsb creates the interface with the vppX name.
            #   The vppsb doesn't know at this point about the set-name.
            #
            # Following the example above, when the router starts -
            #   the "ifname" (taken from fwutils.dev_id_to_tap(dev_id)) is vpp0 and the set-name is eth2.
            #
            # The following netplan file is created:
            #   vpp0:
            #     addresses: [172.16.55.1/24]
            #     dhcp4: false
            #     match: {macaddress: '00:e0:ed:8f:73:94'}
            #     mtu: 1400
            #     set-name: eth2
            #
            # At this point, after "netplan apply", the interface name is changed to eth2, and vpp0 is no longer exists.
            # So, the generated netplan config for this interface is under non-exists interface name.
            #
            # This situation causes a future problem:
            # Once `modify-interface` arrives, the `dev_id_to_tap()` will return `eth2` and not `vpp0`.
            # This function will add the config under `eth2` interface, without removing the `vpp0` which no longer exists.
            # As a result, the netplan file contains the same interface twice:
            #   vpp0:
            #     addresses: [172.16.55.1/24]
            #     dhcp4: false
            #     match: {macaddress: '00:e0:ed:8f:73:94'}
            #     mtu: 1400
            #     set-name: eth2
            #   eth2:
            #     addresses: [172.16.55.1/24]
            #     dhcp4: false
            #     match: {macaddress: '00:e0:ed:8f:73:94'}
            #     mtu: 1400
            #     set-name: eth2
            #
            # Hence, immediately after the set-name applied,
            # we are changing the default vppsb name (vpp0) with the applied set-name interface (eth2) name.
            # No need to call netplan apply now.
            #
            config['network']['ethernets'][set_name] = config['network']['ethernets'].pop(ifname)
            _write_to_netplan_file(fname_run, config)

            ifname = set_name

        # For DHCP interfaces wait a bit - give a chance to system get IP
        #
        if dhcp == 'yes' and is_add:
            for _ in range(10):
                time.sleep(1)
                if_addr = fwutils.get_interface_address(ifname, log=False)
                if if_addr:
                    fwglobals.log.debug("Interface address from DHCP server is %s, dev_id %s" % (if_addr, dev_id))
                    break

        # On interface adding or removal update caches interface related caches.
        #
        if dev_id:
            dev_id_full = fwutils.dev_id_to_full(dev_id)

            # Remove dev-id-to-vpp-if-name and vpp-if-name-to-dev-id cached
            # values for this dev id if the interface is removed from system.
            #
            if is_add == False:
                vpp_if_name = fwglobals.g.cache.dev_id_to_vpp_if_name.get(dev_id_full)
                if vpp_if_name:
                    del fwglobals.g.cache.dev_id_to_vpp_if_name[dev_id_full]
                    del fwglobals.g.cache.vpp_if_name_to_dev_id[vpp_if_name]

            # Remove dev-id-to-tap cached value for this dev id, as netplan might change
            # interface name (see 'set-name' netplan option).
            # As well re-initialize the interface name by dev id.
            # Note 'dev_id' is None for tap-inject (vppX) of tapcli-X interfaces used for LTE/WiFi devices.
            #
            fwutils.set_dev_id_to_tap(dev_id, ifname)
            fwglobals.log.debug("Interface name in cache is %s, dev_id %s" % (ifname, dev_id_full))

    except Exception as e:
        err_str = "add_remove_netplan_interface failed: dev_id: %s, file: %s, error: %s"\
              % (dev_id, fname_run, str(e))
        fwglobals.log.error(err_str)
        _dump_netplan_file(fname_run)
        return (False, err_str)

    return (True, None)

def get_dhcp_netplan_interface(if_name):
    files = glob.glob("/etc/netplan/*.yaml") + \
            glob.glob("/lib/netplan/*.yaml") + \
            glob.glob("/run/netplan/*.yaml")

    for fname in files:
        with open(fname, 'r') as stream:
            config = yaml.safe_load(stream)

        if config is None:
            continue

        if 'network' in config:
            network = config['network']

            if 'ethernets' in network:
                ethernets = network['ethernets']

                if if_name in ethernets:
                    interface = ethernets[if_name]
                    if 'dhcp4' in interface:
                        if interface['dhcp4'] == True:
                            return 'yes'
    return 'no'

def check_interface_exist(if_name):
    files = netplan_get_filepaths()

    for fname in files:
        config = None
        with open(fname, 'r') as stream:
            config = yaml.safe_load(stream)
            if not config:
                continue
            interface = config.get('network',{}).get('ethernets',{}).get(if_name)
            if interface:
                return fname

    return None

def remove_interface(if_name):
    files = netplan_get_filepaths()

    for fname in files:
        config = None
        with open(fname, 'r') as stream:
            config = yaml.safe_load(stream)
            if config is None:
                continue
            if 'network' in config:
                network = config['network']
                if 'ethernets' in network:
                    ethernets = network['ethernets']
                    if if_name in ethernets:
                        removed_section = copy.deepcopy(ethernets[if_name])
                        del ethernets[if_name]
                        with open(fname, 'w') as file_stream:
                            yaml.dump(config, file_stream)
                        fwutils.netplan_apply('remove_interface_netplan')
                        return (fname, removed_section)
    return ('', '')

def add_interface(if_name, fname, netplan_section):
    config = None
    with open(fname, 'r') as stream:
        config = yaml.safe_load(stream)
        if 'network' in config:
            network = config['network']
            if 'ethernets' in network:
                ethernets = network['ethernets']
                ethernets[if_name] = netplan_section
                with open(fname, 'w') as file_stream:
                    yaml.dump(config, file_stream)
                fwutils.netplan_apply('add_interface_netplan')

def create_baseline_if_not_exist(fname):
    if 'baseline' in fname:
        return fname

    fname_baseline = fname.replace('yaml', 'baseline.yaml')
    os.system('cp %s %s.fworig' % (fname, fname))
    os.system('mv %s %s' % (fname, fname_baseline))
    return fname_baseline

def netplan_unload_vlans():
    files = netplan_get_filepaths()
    netplan_apply = False

    for fname in files:
        changed = False
        config = None
        with open(fname, 'r') as stream:
            config = yaml.safe_load(stream)
            if config is None:
                continue
            if 'network' in config:
                network = config['network']
                if 'vlans' in network:
                    del network['vlans']
                    changed = True
        if changed:
            config['network'] = network
            with open(fname, 'w') as file_stream:
                yaml.dump(config, file_stream)
            netplan_apply = True

    if netplan_apply:
        fwutils.netplan_apply('netplan_unload_vlans')

def _set_netplan_section_vlan(config_section, vlan_id, parent_dev_id):
    ifname = fwutils.dev_id_to_tap(parent_dev_id)
    config_section['id'] = vlan_id
    config_section['link'] = ifname
    return config_section

def add_remove_netplan_vlan(is_add, dev_id, ip, gw, metric, dhcp, type, netplan_apply=True):

    fwglobals.log.debug(
        "add_remove_netplan_vlan: is_add=%d, dev_id=%s, ip=%s, gw=%s, metric=%d, dhcp=%s, type=%s" % \
        (is_add, dev_id, ip, gw, metric, dhcp, type))

    ifname = fwutils.dev_id_to_tap(dev_id)
    if not ifname:
        err_str = "add_remove_netplan_vlan: %s was not found" % dev_id
        fwglobals.log.error(err_str)
        return (False, err_str)

    parts = dev_id.split("pci")
    parent_dev_id = "pci" + parts[1]
    vlan_id = parts[0].split(".")[1]

    fname_run = fwglobals.g.NETPLAN_FILE
    _add_netplan_file(fname_run)

    try:
        with open(fname_run, 'r') as stream:
            config = yaml.safe_load(stream)
            network = config['network']
            network['renderer'] = 'networkd'

        if 'vlans' not in network:
            network['vlans'] = {}

        vlans = network['vlans']

        config_section = {}
        config_section = _set_netplan_section_vlan(config_section, vlan_id, parent_dev_id)
        config_section = _set_netplan_section_dhcp(config_section, dhcp, type, metric, ip, gw)

        if is_add == 1:
            vlans[ifname] = config_section
        else:
            # This part of the function is executed when the VPP is running, and we will not stop it.
            # This means that the interface will remain under VPP control and will not be released to Linux control.
            # Hence, when we come to remove an interface, the intention is only to clear its configuration.
            if ifname in vlans:
                del vlans[ifname]

        _write_to_netplan_file(fname_run, config)

        # Remove default route from ip table because Netplan is not doing it.
        if not is_add and type == 'WAN':
            fwutils.remove_linux_default_route(ifname)

        if netplan_apply:
            fwutils.netplan_apply('add_remove_netplan_interface')

        # On interface adding or removal update caches interface related caches.
        #
        if dev_id:
            dev_id_full = fwutils.dev_id_to_full(dev_id)

            # Remove dev-id-to-vpp-if-name and vpp-if-name-to-dev-id cached
            # values for this dev id if the interface is removed from system.
            #
            if is_add == False:
                vpp_if_name = fwglobals.g.cache.dev_id_to_vpp_if_name.get(dev_id_full)
                if vpp_if_name:
                    del fwglobals.g.cache.dev_id_to_vpp_if_name[dev_id_full]
                    del fwglobals.g.cache.vpp_if_name_to_dev_id[vpp_if_name]

            # Remove dev-id-to-tap cached value for this dev id, as netplan might change
            # interface name (see 'set-name' netplan option).
            # As well re-initialize the interface name by dev id.
            # Note 'dev_id' is None for tap-inject (vppX) of tapcli-X interfaces used for LTE/WiFi devices.
            #
            fwutils.set_dev_id_to_tap(dev_id, ifname)
            fwglobals.log.debug("Interface name in cache is %s, dev_id %s" % (ifname, dev_id_full))

    except Exception as e:
        err_str = "add_remove_netplan_vlan failed: dev_id: %s, file: %s, error: %s"\
              % (dev_id, fname_run, str(e))
        fwglobals.log.error(err_str)
        _dump_netplan_file(fname_run)
        return (False, err_str)

    return (True, None)
