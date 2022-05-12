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

import fwglobals
import fwlte
import fwpppoe
import fwutils
import fwwifi
import fw_nat_command_helpers

# add_interface
# --------------------------------------
# Translates request:
#
#    {
#      "message": "add-interface",
#      "params": {
#           "dev_id":"0000:00:08.00",
#           "addr":"10.0.0.4/24",
#           "routing":"ospf"
#      }
#    }
#
# into list of commands:
#
#    1.vpp.cfg
#    ------------------------------------------------------------
#    01. sudo vppctl set int state 0000:00:08.00 up
#    02. sudo vppctl set int ip address 0000:00:08.00 192.168.56.107/24
#
#    2.Netplan config
#    ------------------------------------------------------------
#    03. add interface section into configuration file
#
#    3. Add interface address to ospfd.conf for FRR
#    04. add 'network 192.168.56.107/24 area 0.0.0.0' line:
#    ------------------------------------------------------------
#    hostname ospfd
#    password zebra
#    ------------------------------------------------------------
#    log file /var/log/frr/ospfd.log informational
#    log stdout
#    !
#    router ospf
#      ospf router-id 192.168.56.107
#      network 192.168.56.107/24 area 0.0.0.0
#
#
def add_interface(params):
    """Generate commands to configure interface in Linux and VPP

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    dev_id  = params['dev_id']
    iface_addr = params.get('addr', '')
    iface_name = fwutils.dev_id_to_linux_if(dev_id)

    ######################################################################
    #  NO NEED TO SET IP AND UP/DOWN STATE IN VPP !
    #  WE DO THAT IN LINUX, TAP-INJECT REFLECTS THESE CHANGES TO VPP
    #  (as well we avoid various errors like 'duplicated address' on add
    #   or 'illegal addess' on delete ;))
    #  Note, as on Nov-2019 the opposite direction doesn't work,
    #  delete address in VPP doesn't delete it in Linux ?)
    ######################################################################

    # Add interface section into Netplan configuration file
    gw        = params.get('gateway', None)
    metric    = 0 if not params.get('metric', '') else int(params.get('metric', '0'))
    dhcp      = params.get('dhcp', 'no')
    int_type  = params.get('type', None)

    dnsServers  = params.get('dnsServers', [])
    # If for any reason, static IP interface comes without static dns servers, we set the default automatically
    if int_type == 'wan' and dhcp == 'no' and len(dnsServers) == 0:
        dnsServers = fwglobals.g.DEFAULT_DNS_SERVERS
    dnsDomains  = params.get('dnsDomains')

    mtu       = params.get('mtu', None)

    # To enable multiple LAN interfaces on the same subnet, we put them all into a bridge in VPP.
    # if interface needs to be inside a bridge, we indicate it with a 'bridge_addr' field of the 'add-interface' request.
    # In this case, we create in VPP a bridge (see fwtranslate_add_switch) with a loopback BVI interface.
    # Then, we put the IP address on the BVI interface. Therefore the physical interface should have no IP.
    # Then, we will also add this interface to the L2 bridge.
    bridge_addr   = params.get('bridge_addr')
    if bridge_addr:
        iface_addr = bridge_addr

    is_wifi = fwwifi.is_wifi_interface_by_dev_id(dev_id)
    is_lte = fwlte.is_lte_interface_by_dev_id(dev_id) if not is_wifi else False
    is_pppoe = fwpppoe.is_pppoe_interface(dev_id=dev_id)
    if is_pppoe:
        dhcp = 'no'

    if is_wifi or is_lte:
        # Create tap interface in linux and vpp.
        # This command will create three interfaces:
        #   1. linux tap interface.
        #   2. vpp tap interface in vpp.
        #   3. linux interface for tap-inject.
        #
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "exec"
        cmd['cmd']['module']  = "fwutils"
        cmd['cmd']['descr']   = "create tap interface in vpp and linux"
        cmd['cmd']['params']  = {
                        'cmd': "sudo vppctl create tap host-if-name %s" %
                               fwutils.generate_linux_interface_short_name("tap", iface_name)
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "exec"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['params'] = {
                        'cmd':    "sudo vppctl delete tap sw_if_index DEV-TAP",
                        'substs': [ {'replace':'DEV-TAP', 'key': 'cmd', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ]
        }
        cmd['revert']['descr']  = "delete tap interface in vpp and linux"
        cmd_list.append(cmd)

        if is_wifi:
            # Configure hostapd with saved configuration
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['func']   = "configure_hostapd"
            cmd['cmd']['module'] = "fwwifi"
            cmd['cmd']['params'] = {
                            'dev_id': dev_id,
                            'configuration': params.get('configuration', None)
            }
            cmd_list.append(cmd)

            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['func']   = "start_hostapd"
            cmd['cmd']['module'] = "fwwifi"
            cmd['cmd']['descr']  = "start hostpad"
            cmd['revert'] = {}
            cmd['revert']['func']   = "stop_hostapd"
            cmd['revert']['module'] = "fwwifi"
            cmd['revert']['descr']  = "stop hostpad"
            cmd_list.append(cmd)

            bridge_name = fwutils.generate_linux_interface_short_name("br", iface_name)
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['func']   = "exec"
            cmd['cmd']['module'] = "fwutils"
            cmd['cmd']['params'] = { 'cmd': f"sudo brctl addbr {bridge_name} || true" }
            cmd['cmd']['descr']  = "create linux bridge %s for interface %s" % (bridge_name, iface_name)

            cmd['revert'] = {}
            cmd['revert']['func']   = "exec"
            cmd['revert']['module'] = "fwutils"
            cmd['revert']['params'] = { 'cmd': f"sudo ip link set dev {bridge_name} down && sudo brctl delbr {bridge_name}" }
            cmd['revert']['descr']  = "remove linux bridge %s for interface %s" % (bridge_name, iface_name)
            cmd_list.append(cmd)

            # add tap into a bridge.
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['func']   = "exec"
            cmd['cmd']['module'] = "fwutils"
            cmd['cmd']['params'] =  {
                            'cmd':    f"sudo brctl addif {bridge_name} DEV-TAP || true",
                            'substs': [ {'replace':'DEV-TAP', 'key': 'cmd', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name } ]
            }
            cmd['cmd']['descr']  = "add tap interface of %s into the appropriate bridge %s" % (iface_name, bridge_name)

            cmd['revert'] = {}
            cmd['revert']['func']   = "exec"
            cmd['revert']['module'] = "fwutils"
            cmd['revert']['params'] = {
                            'cmd':    f"sudo brctl delif {bridge_name} DEV-TAP",
                            'substs': [ {'replace':'DEV-TAP', 'key': 'cmd', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name } ]
            }
            cmd['revert']['descr']  = "remove tap from a bridge %s" % bridge_name
            cmd_list.append(cmd)

            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['func']   = "exec"
            cmd['cmd']['module'] = "fwutils"
            cmd['cmd']['params'] =  { 'cmd': f"sudo brctl addif {bridge_name} {iface_name} || true" }
            cmd['cmd']['descr']  = "add wifi interface %s into the bridge %s" % (iface_name, bridge_name)

            cmd['revert'] = {}
            cmd['revert']['func']   = "exec"
            cmd['revert']['module'] = "fwutils"
            cmd['revert']['params'] = { 'cmd': f"sudo brctl delif {bridge_name} {iface_name}" }
            cmd['revert']['descr']  = "remove wifi interface %s from the bridge %s" %  (iface_name, bridge_name)
            cmd_list.append(cmd)

            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['func']      = "exec"
            cmd['cmd']['module']    = "fwutils"
            cmd['cmd']['descr']     = "UP bridge %s in Linux" % bridge_name
            cmd['cmd']['params']    = { 'cmd': f"sudo ip link set dev {bridge_name} up" }
            cmd_list.append(cmd)
        elif is_lte:
            # dhcp for LTE interface has special meaning.
            # Although that flexiManage looks at it as DHCP because the user can't set static IP
            # but the agent looks at it as static IP from the modem.
            # We take the IP from the modem via the mbimcli command.
            # That's why we override the the 'dhcp' to 'no'
            #
            dhcp = 'no'

            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['func']      = "exec"
            cmd['cmd']['module']    = "fwutils"
            cmd['cmd']['descr']     = "UP interface %s in Linux" % iface_name
            cmd['cmd']['params']    = { 'cmd': f"sudo ip link set dev {iface_name} up" }
            cmd['revert'] = {}
            cmd['revert']['func']   = "exec"
            cmd['revert']['module'] = "fwutils"
            cmd['revert']['descr']  = "Down interface %s in Linux" % iface_name
            cmd['revert']['params'] = { 'cmd': f"sudo ip link set dev {iface_name} down && sudo ip addr flush dev {iface_name}" }
            cmd_list.append(cmd)

            # connect the modem to the cellular provider
            configs = copy.deepcopy(params['configuration'])
            configs['dev_id'] = dev_id
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['func']   = "connect"
            cmd['cmd']['module'] = "fwlte"
            cmd['cmd']['params'] = { 'params': configs }
            cmd['cmd']['descr'] = "connect modem to lte cellular network provider"
            cmd_list.append(cmd)

    # enable DHCP packets detection in VPP
    if dhcp == 'yes':
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "vpp_set_dhcp_detect"
        cmd['cmd']['module'] = "fwutils"
        cmd['cmd']['descr']  = "Enable DHCP detect"
        cmd['cmd']['params'] = { 'dev_id': dev_id, 'remove': False }
        cmd['revert'] = {}
        cmd['revert']['func']   = "vpp_set_dhcp_detect"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['descr']  = "Disable DHCP detect"
        cmd['revert']['params'] = { 'dev_id': dev_id, 'remove': True }
        cmd_list.append(cmd)

    # add interface into netplan configuration
    netplan_params = {
                    'is_add'   : 1,
                    'dev_id'   : dev_id,
                    'ip'       : iface_addr,
                    'gw'       : gw,
                    'metric'   : metric,
                    'dhcp'     : dhcp,
                    'type'     : int_type,
                    'mtu'      : mtu,
                    'dnsServers': dnsServers,
                    'dnsDomains': dnsDomains
    }

    if is_lte:
        netplan_params['substs'] = [
            { 'add_param':'ip', 'val_by_func':'fwlte.get_ip_configuration', 'arg': [dev_id, 'ip'] },
            { 'add_param':'gw', 'val_by_func':'fwlte.get_ip_configuration', 'arg': [dev_id, 'gateway'] },
        ]

        # If a user doesn't configure static dns servers, we use the servers received from ISP
        if len(dnsServers) == 0:
            netplan_params['substs'].append({ 'add_param':'dnsServers', 'val_by_func':'fwlte.get_ip_configuration', 'arg': [dev_id, 'dns_servers'] })

    if bridge_addr:
        netplan_params['ip'] = ''
        netplan_params['validate_ip'] = False

    if is_pppoe:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "exec"
        cmd['cmd']['module']    = "fwutils"
        cmd['cmd']['descr']     = "UP interface %s in Linux"
        cmd['cmd']['params']    = {
                        'cmd':    "sudo ip link set dev DEV-STUB up",
                        'substs': [ {'replace':'DEV-STUB', 'key': 'cmd', 'val_by_func':'dev_id_to_tap', 'arg':dev_id} ],
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "exec"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['descr']  = "DOWN interface %s in Linux"
        cmd['revert']['params'] = {
                        'cmd':    "sudo ip link set dev DEV-STUB down",
                        'substs': [ {'replace':'DEV-STUB', 'key': 'cmd', 'val_by_func':'dev_id_to_tap', 'arg':dev_id} ]
        }
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "restart_interface"
        cmd['cmd']['object']    = "fwglobals.g.pppoe"
        cmd['cmd']['descr']     = "Restart PPPoE interface"
        cmd['cmd']['params']    = { 'dev_id': dev_id }
        cmd['revert'] = {}
        cmd['revert']['func']   = "stop_interface"
        cmd['revert']['object'] = "fwglobals.g.pppoe"
        cmd['revert']['descr']  = "Stop PPPoE interface"
        cmd['revert']['params'] = { 'dev_id': dev_id }
        cmd_list.append(cmd)
    else:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "add_remove_netplan_interface"
        cmd['cmd']['module'] = "fwnetplan"
        cmd['cmd']['params'] = netplan_params
        cmd['cmd']['descr'] = "add interface into netplan config file"
        cmd['revert'] = {}
        cmd['revert']['func']   = "add_remove_netplan_interface"
        cmd['revert']['module'] = "fwnetplan"
        cmd['revert']['params'] = copy.deepcopy(netplan_params)
        cmd['revert']['params']['is_add'] = 0
        cmd['revert']['descr'] = "remove interface from netplan config file"
        cmd_list.append(cmd)

    if bridge_addr:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "call_vpp_api"
        cmd['cmd']['object']  = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']   = "add interface %s to bridge" % iface_name
        cmd['cmd']['params']  = {
            'api': 'sw_interface_set_l2_bridge',
            'args': {
                'enable':   1,
                'port_type':0,
                'substs':   [
                    { 'add_param':'rx_sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id },
                    { 'add_param':'bd_id', 'val_by_func': 'fwtranslate_add_switch.get_bridge_id', 'arg': bridge_addr }
                ]
            },
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "call_vpp_api"
        cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr']  = "remove interface %s from bridge" % iface_name
        cmd['revert']['params'] = {
            'api':  'sw_interface_set_l2_bridge',
            'args': {
                'enable': 0,
                'substs': [
                    { 'add_param':'rx_sw_if_index', 'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg':dev_id },
                    { 'add_param':'bd_id', 'val_by_func': 'fwtranslate_add_switch.get_bridge_id', 'arg': bridge_addr }
                ]
            },
        }
        cmd_list.append(cmd)

        # set the bridge IP address here.
        # If the bridged interface exists in original netplan with set-name it might cause issues,
        # So we configure the IP address for the BVI interface here
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "set_ip_on_bridge_bvi_interface"
        cmd['cmd']['module']  = "fwutils"
        cmd['cmd']['descr']   = "set %s to BVI loopback interface in Linux" % bridge_addr
        cmd['cmd']['params']  = {
                        'bridge_addr': bridge_addr,
                        'dev_id':      dev_id,
                        'is_add':      True,
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "set_ip_on_bridge_bvi_interface"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['descr']  = "unset %s to BVI loopback interface in Linux" % bridge_addr
        cmd['revert']['params']  = {
                        'bridge_addr': bridge_addr,
                        'dev_id':      dev_id,
                        'is_add':      False,
        }
        cmd_list.append(cmd)

    if mtu:
        # interface.api.json: sw_interface_set_mtu (..., sw_if_index, mtu, ...)
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "call_vpp_api"
        cmd['cmd']['object']  = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']   = "set mtu=%s to interface" % (mtu)
        cmd['cmd']['params']  = {
                        'api':  "sw_interface_set_mtu",
                        'args': {
                            'mtu': [ mtu , 0, 0, 0 ],
                            'substs': [
                                { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id }
                            ],
                        },
        }
        cmd_list.append(cmd)

    # interface.api.json: sw_interface_flexiwan_label_add_del (..., sw_if_index, n_labels, labels, ...)
    if not is_wifi and 'multilink' in params and 'labels' in params['multilink']:
        labels = params['multilink']['labels']
        if len(labels) > 0:
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['func']    = "vpp_multilink_update_labels"
            cmd['cmd']['module']  = "fwutils"
            cmd['cmd']['descr']   = "add multilink labels into interface %s %s: %s" % (iface_addr, dev_id, labels)
            cmd['cmd']['params']  = {
                                        'labels':   labels,
                                        'next_hop': gw,
                                        'dev_id':   dev_id,
                                        'remove':   False
            }
            # Cache 'next_hop' resolved by vpp_multilink_update_labels on 'add-interface',
            # to be used on 'remove-interface'. This is needed for DHCP interfaces,
            # where GW can be changed/removed under our legs
            #
            cache_key = 'next_hop-%s' % dev_id
            cmd['cmd']['cache_ret_val'] = ('next_hop', cache_key)

            cmd['revert'] = {}
            cmd['revert']['func']   = "vpp_multilink_update_labels"
            cmd['revert']['module'] = "fwutils"
            cmd['revert']['descr']  = "remove multilink labels from interface %s %s: %s" % (iface_addr, dev_id, labels)
            cmd['revert']['params'] = {
                            'labels':   labels,
                            'dev_id':   dev_id,
                            'remove':   True,
                            'substs': [ { 'add_param':'next_hop', 'val_by_key':cache_key} ],
            }
            cmd_list.append(cmd)

    # Setup NAT config on WAN interface
    if 'type' not in params or params['type'].lower() == 'wan':
        cmd_list.extend(fw_nat_command_helpers.get_nat_wan_setup_config(dev_id))

    # Update ospfd configuration.
    routing = params.get('routing', [])
    if 'OSPF' in routing:
        ospf = params.get('ospf', {})
        area = ospf.get('area', '0.0.0.0')
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "frr_vtysh_run"
        cmd['cmd']['module']  = "fwutils"
        cmd['cmd']['descr']   =  f"add interface {dev_id} to OSPF"
        cmd['cmd']['params'] = {
                        'commands': ["router ospf", f"network DEV-NETWORK area {area}"],
                        'substs': [ {'replace':'DEV-NETWORK', 'key': 'commands', 'val_by_func': 'get_interface_address_by_dev_id', 'arg': dev_id} ]
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "frr_vtysh_run"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['params'] = {
                        'commands': ["router ospf", f"no network DEV-NETWORK area {area}"],
                        'substs': [ {'replace':'DEV-NETWORK', 'key': 'commands', 'val_by_func': 'get_interface_address_by_dev_id', 'arg': dev_id} ]
        }
        cmd['revert']['descr']   =  f"remove interface {dev_id} from OSPF"
        cmd_list.append(cmd)

        # OSPF per interface configuration
        frr_cmd = []
        restart_frr = False
        hello_interval = ospf.get('helloInterval')
        if hello_interval:
            frr_cmd.append(f'ip ospf hello-interval {hello_interval}')

        dead_interval = ospf.get('deadInterval')
        if dead_interval:
            frr_cmd.append(f'ip ospf dead-interval {dead_interval}')

        cost = ospf.get('cost')
        if cost:
            frr_cmd.append('ip ospf cost {cost}')

        key_id = ospf.get('keyId')
        key = ospf.get('key')
        if key_id and key:
            restart_frr = True
            frr_cmd.append(f'ip ospf message-digest-key {key_id} md5 {key}')
            frr_cmd.append('ip ospf authentication message-digest')

        if frr_cmd:
            frr_cmd_revert = list(map(lambda x: f'no {x}', frr_cmd))

            # if interface is inside a bridge, we need to put the ospf on the bvi loop interface
            func = 'dev_id_to_tap'
            arg = dev_id
            if bridge_addr:
                func = 'bridge_addr_to_bvi_interface_tap'
                arg = bridge_addr

            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['func']    = "frr_vtysh_run"
            cmd['cmd']['module']  = "fwutils"
            cmd['cmd']['params'] = {
                        'commands'   : ["interface DEV-STUB"] + frr_cmd,
                        'restart_frr': restart_frr,
                        'substs': [ {'replace':'DEV-STUB', 'key': 'commands', 'val_by_func': func, 'arg': arg} ]
            }
            cmd['cmd']['descr']   =  "add OSPF per link configuration of interface %s" % dev_id
            cmd['revert'] = {}
            cmd['revert']['func']    = "frr_vtysh_run"
            cmd['revert']['module']  = "fwutils"
            cmd['revert']['params'] = {
                        'commands'   : ["interface DEV-STUB"] + frr_cmd_revert,
                        'restart_frr': restart_frr,
                        'substs': [ {'replace':'DEV-STUB', 'key': 'commands', 'val_by_func': func, 'arg': arg} ]
            }
            cmd['revert']['descr']   =  "remove OSPF per link configuration of interface %s" % dev_id
            cmd_list.append(cmd)

    if is_lte:
        substs = [ {'replace':'DEV-STUB', 'key': 'cmds', 'val_by_func':'dev_id_to_vpp_if_name', 'arg': dev_id},
                   {'replace':'LTE-GW', 'key': 'cmds', 'val_by_func':'fwlte.get_ip_configuration', 'arg':[dev_id, 'gateway']} ]

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "vpp_cli_execute"
        cmd['cmd']['module']  = "fwutils"
        cmd['cmd']['descr']   = f"add arp static entry to vpp for LTE device {dev_id}"
        cmd['cmd']['params']  = {
                        'substs': substs,
                        'cmds':   ['set ip neighbor static DEV-STUB LTE-GW ff:ff:ff:ff:ff:ff']
        }
        cmd['revert'] = {}
        cmd['revert']['func']    = "vpp_cli_execute"
        cmd['revert']['module']  = "fwutils"
        cmd['revert']['descr']   = f"remove arp static entry from vpp for LTE device {dev_id}"
        cmd['revert']['params']  = {
                        'substs': substs,
                        'cmds':   ['set ip neighbor del static DEV-STUB LTE-GW ff:ff:ff:ff:ff:ff']
        }
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "exec"
        cmd['cmd']['module']    = "fwutils"
        cmd['cmd']['params'] = {
                        'cmd':    "sudo arp -s DEV-STUB 00:00:00:00:00:00",
                        'substs': [ {'replace':'DEV-STUB', 'key': 'cmd', 'val_by_func':'fwlte.get_ip_configuration', 'arg': [dev_id, 'gateway']} ]
        }
        cmd['cmd']['descr'] = "set arp entry on linux for lte interface"
        cmd['revert'] = {}
        cmd['revert']['func']   = "exec"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['descr']  = "remove arp entry on linux for lte interface"
        cmd['revert']['params'] = {
                        'cmd':    "sudo arp -d DEV-STUB || true",
                        'substs': [ {'replace':'DEV-STUB', 'key': 'cmd', 'val_by_func':'fwlte.get_ip_configuration', 'arg': [dev_id, 'gateway'] } ]
        }
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "traffic_control_add_del_dev_ingress"
        cmd['cmd']['module'] = "fwutils"
        cmd['cmd']['params'] = {
                    'dev_name': '',
                    'is_add': 1,
                    'substs': [ { 'add_param':'dev_name', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name } ]
        }
        cmd['cmd']['descr'] = "add traffic control command for linux tap interface"
        cmd['revert'] = {}
        cmd['revert']['func']   = "traffic_control_add_del_dev_ingress"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['params'] = {
                    'is_add': 0,
                    'substs': [ { 'add_param':'dev_name', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name } ]
        }
        cmd['revert']['descr']  = "remove traffic control command for linux tap interface"
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "traffic_control_replace_dev_root"
        cmd['cmd']['module'] = "fwutils"
        cmd['cmd']['params'] = {
                    'substs': [ { 'add_param':'dev_name', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name } ]
        }
        cmd['cmd']['descr'] = "replace traffic control command for linux tap interface"
        cmd['revert'] = {}
        cmd['revert']['func']   = "traffic_control_remove_dev_root"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['params'] = {
                    'substs': [ { 'add_param':'dev_name', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name } ]
        }
        cmd['revert']['descr']  = "remove replaced tc command for linux tap interface"
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "traffic_control_add_del_dev_ingress"
        cmd['cmd']['module'] = "fwutils"
        cmd['cmd']['params'] = { 'dev_name'  : iface_name, 'is_add': 1 }
        cmd['cmd']['descr'] = "add traffic control command for lte interface"
        cmd['revert'] = {}
        cmd['revert']['func']   = "traffic_control_add_del_dev_ingress"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['params'] = { 'dev_name'  : iface_name, 'is_add': 0 }
        cmd['revert']['descr']  = "remove traffic control command for lte interface"
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "traffic_control_replace_dev_root"
        cmd['cmd']['module'] = "fwutils"
        cmd['cmd']['params'] = { 'dev_name'  : iface_name }
        cmd['cmd']['descr'] = "replace traffic control command for lte interface"
        cmd['revert'] = {}
        cmd['revert']['func']   = "traffic_control_remove_dev_root"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['params'] = { 'dev_name'  : iface_name }
        cmd['revert']['descr']  = "remove replaced tc command for lte interface"
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "exec"
        cmd['cmd']['module'] = "fwutils"
        cmd['cmd']['params'] = {
            'cmd':
                f"tc filter add dev DEV-STUB parent ffff: \
                protocol all prio 2 u32 \
                match u32 0 0 flowid 1:1 \
                action pedit ex munge eth dst set LTE-MAC \
                pipe action mirred egress mirror dev {iface_name} \
                pipe action drop",
            'substs': [
                {'replace':'DEV-STUB', 'key':'cmd', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name },
                {'replace':'LTE-MAC',  'key':'cmd', 'val_by_func':'get_interface_mac_addr', 'arg':iface_name }
            ]
        }
        cmd['cmd']['descr'] = "add filter traffic control command for tap and wwan interfaces"
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "exec"
        cmd['cmd']['module'] = "fwutils"
        cmd['cmd']['params'] = {
            'cmd':
                f"tc filter add dev {iface_name} parent ffff: \
                protocol all prio 2 u32 \
                match u32 0 0 flowid 1:1 \
                action pedit ex munge eth dst set VPP-MAC \
                pipe action mirred egress mirror dev DEV-STUB \
                pipe action drop",
            'substs': [
                {'replace':'VPP-MAC',  'key':'cmd', 'val_by_func':'get_vpp_tap_interface_mac_addr', 'arg':dev_id },
                {'replace':'DEV-STUB', 'key':'cmd', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name }
            ]
        }
        cmd['cmd']['descr'] = "add filter traffic control command for tap and wwan interfaces"
        cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "_on_add_interface_after"
    cmd['cmd']['object']  = "fwglobals.g.router_api"
    cmd['cmd']['descr']   = "postprocess add-interface"
    cmd['cmd']['params']  = {
                    'type': 'switch-lan' if bridge_addr else str(int_type).lower(),
                    'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ]
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "_on_remove_interface_before"
    cmd['revert']['object'] = "fwglobals.g.router_api"
    cmd['revert']['descr']  = "preprocess remove-interface"
    cmd['revert']['params'] = {
                    'type': 'switch-lan' if bridge_addr else str(int_type).lower(),
                    'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ]
    }
    cmd_list.append(cmd)

    return cmd_list

# The modify_X_ignored_params variable represents set of parameters
# that can be received from flexiManage within the 'modify-X' request
# and that have no impact on device configuration. If the request includes
# only such parameters, it should not be executed, we just update the configuration
# database, so it will be in sync with device configuration on flexiManage.
#
modify_interface_ignored_params = {
    'PublicIP': None,
    'PublicPort': None,
    'useStun': None,
}


def get_request_key(params):
    """Get add interface command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-interface:%s' % params['dev_id']
