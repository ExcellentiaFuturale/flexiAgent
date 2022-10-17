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

import os
import re

import fwnetplan
import fwglobals
import fwikev2
import fwutils
import fw_nat_command_helpers

# start_router
# --------------------------------------
# Translates request:
#
#    {
#      "entity": "agent",
#      "message": "start-router",
#      "params": {
#        "dev_id": [
#           "0000:00:08.00",
#           "0000:00:09.00"
#        ]
#      }
#    }
#|
# into list of commands:
#
#    1. generates ospfd.conf for FRR
#    01. print CONTENT > ospfd.conf
#    ------------------------------------------------------------
#    hostname ospfd
#    password zebra
#    ------------------------------------------------------------
#    log file /var/log/frr/ospfd.log informational
#    log stdout
#    !
#    router ospf
#      ospf router-id 192.168.56.107
#
#    2.Linux_sh1.sh
#    ------------------------------------------------------------
#    02. sudo ip link set dev enp0s8 down &&
#        sudo ip addr flush dev enp0s8
#    03. sudo ip link set dev enp0s9 down &&
#        sudo ip addr flush dev enp0s9
#
#    3.vpp.cfg
#    ------------------------------------------------------------
#    04. sudo systemtctl start vpp
#    05. sudo vppctl enable tap-inject
#
#
def start_router(params=None):
    """Generate commands to start VPP.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    # Initialize some stuff before router start
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "_on_start_router_before"
    cmd['cmd']['object']  = "fwglobals.g.router_api"
    cmd['cmd']['descr']   = "fwrouter_api._on_start_router_before()"
    cmd['revert'] = {}
    cmd['revert']['func']   = "_on_stop_router_after"
    cmd['revert']['object'] = "fwglobals.g.router_api"
    cmd['revert']['descr']  = "fwrouter_api._on_stop_router_after()"
    cmd_list.append(cmd)

    dev_id_list         = []
    pci_list_vmxnet3 = []
    assigned_linux_interfaces = []

    # Remove interfaces from Linux.
    #   sudo ip link set dev enp0s8 down
    #   sudo ip addr flush dev enp0s8
    # The interfaces to be removed are stored within 'add-interface' requests
    # in the configuration database.
    interfaces = fwglobals.g.router_cfg.get_interfaces()
    for params in interfaces:
        linux_if  = fwutils.dev_id_to_linux_if(params['dev_id'])
        if linux_if:

            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['func']    = "exec"
            cmd['cmd']['module']  = "fwutils"
            cmd['cmd']['params']  = { 'cmd': "sudo ip link set dev %s down && sudo ip addr flush dev %s" % (linux_if,linux_if ) }
            cmd['cmd']['descr']   = "shutdown dev %s in Linux" % linux_if
            cmd_list.append(cmd)

            # Non-dpdk interface should not appear in /etc/vpp/startup.conf because they don't have a pci address.
            # Additional spacial logic for these interfaces is at add_interface translator
            if fwutils.is_non_dpdk_interface(params['dev_id']):
                continue
            assigned_linux_interfaces.append(linux_if)

            # Mark 'vmxnet3' interfaces as they need special care:
            #   They require additional VPP call vmxnet3_create on start
            #      and complement vmxnet3_delete on stop
            if fwutils.dev_id_is_vmxnet3(params['dev_id']):
                pci_list_vmxnet3.append(params['dev_id'])

            dev_id_list.append(params['dev_id'])

    vpp_filename = fwglobals.g.VPP_CONFIG_FILE

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "vpp_coredump_setup_startup_conf"
    cmd['cmd']['module']  = "fw_vpp_coredump_utils"
    cmd['cmd']['descr']   = "enable coredump to %s" % vpp_filename
    cmd['cmd']['params']  = { 'vpp_config_filename' : vpp_filename, 'enable': 1 }
    cmd_list.append(cmd)

    # The 'no-pci' parameter in /etc/vpp/startup.conf is too dangerous - it
    # causes vpp to boot up without interfaces. The stale 'no-pci' might cause
    # constant start-router failure. To avoid this we just remove it now and
    # will add it back a bit later if needed.
    #
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "vpp_startup_conf_remove_nopci"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   = "clean no-pci flag from %s" % vpp_filename
    cmd['cmd']['params']  = { 'vpp_config_filename' : vpp_filename }
    cmd_list.append(cmd)

    # Enable HQoS worker to startup conf if QoS Policy if enabled
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "Enable hqos to %s" % vpp_filename
    cmd['cmd']['module']  = 'fwutils'
    cmd['cmd']['func']    = 'vpp_startup_conf_hqos'
    cmd['cmd']['params']  = {
        'vpp_config_filename' : vpp_filename,
        'is_add'              : True
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "Disable hqos from %s" % vpp_filename
    cmd['revert']['module'] = 'fwutils'
    cmd['revert']['func']   = 'vpp_startup_conf_hqos'
    cmd['revert']['params'] = {
        'vpp_config_filename' : vpp_filename,
        'is_add'              : False
    }
    cmd_list.append(cmd)

    # Add interfaces to the vpp configuration file, thus creating whitelist.
    # If whitelist exists, on bootup vpp captures only whitelisted interfaces.
    # Other interfaces will be not captured by vpp even if they are DOWN.
    if len(dev_id_list) > 0:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "vpp_startup_conf_add_devices"
        cmd['cmd']['module']  = "fwutils"
        cmd['cmd']['descr']   = "add devices to %s" % vpp_filename
        cmd['cmd']['params']  = { 'vpp_config_filename' : vpp_filename, 'devices': dev_id_list }
        cmd['revert'] = {}
        cmd['revert']['func']   = "vpp_startup_conf_remove_devices"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['descr']  = "remove devices from %s" % vpp_filename
        cmd['revert']['params'] = { 'vpp_config_filename' : vpp_filename, 'devices': dev_id_list }
        cmd_list.append(cmd)
    else:
        # When the list of devices in the startup.conf file is empty, the vpp attempts
        # to manage all the down linux interfaces.
        # Since we allow non-dpdk interfaces (LTE, WiFi), this list could be empty.
        # In order to prevent vpp from doing so, we need to add the "no-pci" flag.
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "vpp_startup_conf_add_nopci"
        cmd['cmd']['module']  = "fwutils"
        cmd['cmd']['descr']   = "add no-pci flag to %s" % vpp_filename
        cmd['cmd']['params']  = { 'vpp_config_filename' : vpp_filename }
        cmd['revert'] = {}
        cmd['revert']['func']   = "vpp_startup_conf_remove_nopci"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['descr']  = "remove no-pci flag to %s" % vpp_filename
        cmd['revert']['params'] = { 'vpp_config_filename' : vpp_filename }
        cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "backup_linux_netplan_files"
    cmd['cmd']['module']  = "fwnetplan"
    cmd['cmd']['descr'] = "backup Linux netplan files"
    cmd['revert'] = {}
    cmd['revert']['func']    = "restore_linux_netplan_files"
    cmd['revert']['module']  = "fwnetplan"
    cmd['revert']['descr'] = "restore linux netplan files"
    cmd_list.append(cmd)

    if assigned_linux_interfaces:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "netplan_unload_vpp_assigned_ports"
        cmd['cmd']['module']  = "fwnetplan"
        cmd['cmd']['descr']   = "Unload to-be-VPP interfaces from linux networkd"
        cmd['cmd']['params']  = { 'assigned_linux_interfaces' : assigned_linux_interfaces }
        cmd_list.append(cmd)

    #  Create commands that start vpp and configure it with addresses
    #  sudo systemtctl start vpp
    #  <connect to python bindings of vpp and than run the rest>
    #  sudo vppctl enable tap-inject
    cmd = {}
    cmd['cmd'] = {}                     # vfio-pci related stuff is needed for vmxnet3 interfaces
    cmd['cmd']['func']    = "exec"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['params']  = { 'cmd': 'sudo modprobe vfio-pci  &&  (echo Y | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode)' }
    cmd['cmd']['descr']   = "enable vfio-pci driver in Linux"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "exec"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['params']  = { 'cmd': 'sudo systemctl start vpp' }
    cmd['cmd']['descr']   = "start vpp"
    cmd['revert'] = {}
    cmd['revert']['func']   = "stop_vpp"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['descr']  = "stop vpp"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "connect_to_vpp"
    cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr']     = "connect to vpp papi"
    cmd['revert'] = {}
    cmd['revert']['func']   = "disconnect_from_vpp"
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['descr']  = "disconnect from vpp papi"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "vpp_enable_tap_inject"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   = "enable tap-inject"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "call_vpp_api"
    cmd['cmd']['object']  = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr']   = "enable NAT pluging and configure it"
    cmd['cmd']['params']  = {
                    'api':  "nat44_plugin_enable_disable",
                    'args': {
                        'enable':   1,
                        'flags':    1,      # nat.h: _(0x01, IS_ENDPOINT_DEPENDENT)
                        'sessions': 100000  # Defaults: users=1024, sessions=10x1024, in multicore these parameters are per worker thread
                    }
    }
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "exec"
    cmd['cmd']['module'] = "fwutils"
    cmd['cmd']['params'] = { 'cmd': "sudo vppctl ip route add 255.255.255.255/32 via punt" }
    cmd['cmd']['descr'] = "punt ip broadcast"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "backup_dhcpd_files"
    cmd['cmd']['module'] = "fwutils"
    cmd['cmd']['descr'] = "backup DHCP server files"
    cmd['revert'] = {}
    cmd['revert']['func']   = "restore_dhcpd_files"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['descr'] = "restore DHCP server files"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "exec"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['params']  = { 'cmd': 'sudo systemctl start frr; if [ -z "$(pgrep frr)" ]; then exit 1; fi' }
    cmd['cmd']['descr']   = "start frr"
    cmd['revert'] = {}
    cmd['revert']['func']   = "exec"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['descr']  = "stop frr"
    cmd['revert']['params'] = { 'cmd': 'sudo systemctl stop frr' }
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "frr_setup_config"
    cmd['cmd']['module'] = "fwutils"
    cmd['cmd']['descr'] = "Setup FRR configuration"
    cmd_list.append(cmd)

    # Setup Global VPP NAT parameters
    # Post VPP NAT/Firewall changes - The param need to be false
    cmd_list.append(fw_nat_command_helpers.get_nat_forwarding_config(False))

    # vmxnet3 interfaces are not created by VPP on bootup, so create it explicitly
    # vmxnet3.api.json: vmxnet3_create (..., pci_addr, enable_elog, rxq_size, txq_size, ...)
    # Note we do it here and not on 'add-interface' as 'modify-interface' is translated
    # into 'remove-interface' and 'add-interface', so we want to avoid deletion
    # and creation interface on every 'modify-interface'. There is no sense to do
    # that and it causes problems in FIB, when default route interface is deleted.
    for dev_id in pci_list_vmxnet3:
        _, pci = fwutils.dev_id_parse(dev_id)
        pci_bytes = fwutils.pci_str_to_bytes(pci)
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "call_vpp_api"
        cmd['cmd']['object']  = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']   = "create vmxnet3 interface for %s" % pci
        cmd['cmd']['params']  = {
                        'api':  "vmxnet3_create",
                        'args': {'pci_addr':pci_bytes}
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "call_vpp_api"
        cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr']  = "delete vmxnet3 interface for %s" % pci
        cmd['revert']['params'] = {
                        'api':    "vmxnet3_delete",
                        'args':   {
                            'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ]
                        }
        }
        cmd_list.append(cmd)

    # Once VPP started, apply configuration to it.
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "_on_apply_router_config"
    cmd['cmd']['object']  = "fwglobals.g.router_api"
    cmd['cmd']['descr']   = "FWROUTER_API::_on_apply_router_config()"
    cmd_list.append(cmd)

    # Finalize some stuff after VPP start / before VPP stops.
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "_on_start_router_after"
    cmd['cmd']['object']  = "fwglobals.g.router_api"
    cmd['cmd']['descr']   = "fwrouter_api._on_start_router_after()"
    cmd['revert'] = {}
    cmd['revert']['func']   = "_on_stop_router_before"
    cmd['revert']['object'] = "fwglobals.g.router_api"
    cmd['revert']['descr']  = "fwrouter_api._on_stop_router_before()"
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(*params):
    """Get start router command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'start-router'
