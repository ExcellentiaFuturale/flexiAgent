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

import fwutils
import fwglobals
from fwobject import FwObject

class FwFirewall(FwObject):
    """
    Flexiwan Firewall class:
    The class encapsulates all the ACL attachment contexts and the context of
    global Identity NATs (edge access rules). It maintains context of per
    interface ACLs data. The maintained contexts aid in handling attachments
    during dynamic interfaces creation and deletion.

    :param FwObject: Flexiwan object that has common contexts like logger
    :type FwObject: Object
    """

    def __init__(self):
        """
        Inits all local contexts
        """
        FwObject.__init__(self)
        self.reset()

    def reset(self):
        """
        Resets all local contexts
        """
        self.interfaces = {}
        self.lan_global_acls = {}
        self.wan_global_acls = {}
        self.wan_global_identity_nat = []

    def set_lan_global_acls(self, ingress_acls, egress_acls):
        """
        Set global LAN ACLs i.e. ACLs corresponding to outbound firewall rules
        in which specific interface is not provided

        :param ingress_acls: ACLs to be attached in the interface ingress
        :type ingress_acls: List
        :param egress_acls: ACLs to be attached in the interface egress
        :type egress_acls: List
        """
        self.lan_global_acls['ingress'] = ingress_acls
        self.lan_global_acls['egress'] = egress_acls

    def set_wan_global_acls(self, ingress_acls, egress_acls):
        """
        Set global WAN ACLs i.e. ACLs corresponding to inbound firewall rules
        in which specific interface is not provided

        :param ingress_acls: ACLs to be attached in the interface ingress
        :type ingress_acls: List
        :param egress_acls: ACLs to be attached in the interface egress
        :type egress_acls: List
        """
        self.wan_global_acls['ingress'] = ingress_acls
        self.wan_global_acls['egress'] = egress_acls

    def set_interface_acls(self, dev_id, ingress_acls, egress_acls, sw_if_index):
        """
        Setup per interface context and attach ACLs to the interface context

        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param ingress_acls: ACLs to be attached in the interface ingress
        :type ingress_acls: List
        :param egress_acls: ACLs to be attached in the interface egress
        :type egress_acls: List
        :param sw_if_index: VPP identifier of the interface
        :type sw_if_index: Integer
        """
        if self.interfaces.get(dev_id) is None:
            self.interfaces[dev_id] = { 'ingress': None, 'egress': None }
        self.interfaces[dev_id]['ingress'] = ingress_acls
        self.interfaces[dev_id]['egress'] = egress_acls
        self.interfaces[dev_id]['sw_if_index'] = sw_if_index


    def add_wan_global_identity_nat(self, protocols, ports):
        """
        Add a global Edge Access rule to the global identity nat context

        :param protocols: Protocols for which the edge access is to be enabled
        :type protocols: List
        :param ports: Ports for which the edge access is to be enabled
        :type ports: List
        """
        self.wan_global_identity_nat.append({
            'protocols': protocols,
            'ports'    : ports
        })

    def map_acl_keys_to_index (self):
        """
        Map the ACL keys to the ACL Index.
        While adding ACLs, the returned acl index value is cached in the command
        cache. This functions transforms the ACL-key list to the corresponding
        ACL-index list
        """
        # Map ACL keys of per interface context
        for dev_id in self.interfaces.keys():
            if self.interfaces[dev_id].get('ingress'):
                self.interfaces[dev_id]['ingress'] =\
                    fwutils.map_keys_to_acl_ids(self.interfaces[dev_id]['ingress'],
                                                fwglobals.g.router_api.cmd_cache)
            if self.interfaces[dev_id].get('egress'):
                self.interfaces[dev_id]['egress'] =\
                    fwutils.map_keys_to_acl_ids(self.interfaces[dev_id]['egress'],
                                                fwglobals.g.router_api.cmd_cache)
        # Map ACL keys of global LAN context
        if self.lan_global_acls.get('ingress'):
            self.lan_global_acls['ingress'] =\
                fwutils.map_keys_to_acl_ids(self.lan_global_acls['ingress'],
                                            fwglobals.g.router_api.cmd_cache)
        if self.lan_global_acls.get('egress'):
            self.lan_global_acls['egress'] =\
                fwutils.map_keys_to_acl_ids(self.lan_global_acls['egress'],
                                            fwglobals.g.router_api.cmd_cache)
        # Map ACL keys of global WAN context
        if self.wan_global_acls.get('ingress'):
            self.wan_global_acls['ingress'] =\
                fwutils.map_keys_to_acl_ids(self.wan_global_acls['ingress'],
                                            fwglobals.g.router_api.cmd_cache)
        if self.wan_global_acls.get('egress'):
            self.wan_global_acls['egress'] =\
                fwutils.map_keys_to_acl_ids(self.wan_global_acls['egress'],
                                            fwglobals.g.router_api.cmd_cache)

    def __exec_vpp_set_interface_acls(self, dev_id, sw_if_index,
                                      ingress_acls=None, egress_acls=None):
        """
        Attach ACLs to the interface identified by the device identifier.
        The ACLs to be attached are taken from the object context if the passed
        ACL arguments are empty.

        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param sw_if_index: VPP identifier of the interface
        :type sw_if_index: Integer, optional
        :param ingress_acls: ACLs to be attached in the interface ingress
        :type ingress_acls: List, optional
        :param egress_acls: ACLs to be attached in the interface egress
        :type egress_acls: List, optional
        :raises Exception: Raises exception if the VPP API call fails
        """
        acls = []
        if ingress_acls:
            acls.extend(ingress_acls)
        elif self.interfaces[dev_id]['ingress']:
            acls.extend(self.interfaces[dev_id]['ingress'])
        ingress_acls_count = len(acls)
        if egress_acls:
            acls.extend(egress_acls)
        elif self.interfaces[dev_id]['egress']:
            acls.extend(self.interfaces[dev_id]['egress'])
        count = len(acls)

        rv = fwglobals.g.router_api.vpp_api.vpp.call('acl_interface_set_acl_list',
        count=count, sw_if_index=sw_if_index, n_input=ingress_acls_count, acls=acls)
        if rv is None:
            raise Exception("Firewall Attach acl_interface_set_acl_list failed")


    def __exec_vpp_clear_interface_acls(self, sw_if_index):
        """
        Clear ACL attachment on the interface identified by the
        device identifier

        :param sw_if_index: VPP identifier of the interface
        :type sw_if_index: Integer
        :raises Exception: Raises exception if the VPP API call fails
        """
        rv = fwglobals.g.router_api.vpp_api.vpp.call\
            ('acl_interface_set_acl_list', count=0, sw_if_index=sw_if_index, n_input=0, acls=[])
        if rv is None:
            raise Exception("Firewall Detach acl_interface_set_acl_list failed")


    def __exec_vpp_interface_identity_nat (self, is_add, dev_id, identity_nat):
        """
        Program (In VPP) the given Identity NAT config on the interface
        identified by the device identifier

        :param is_add: Flag to indicate add or delete of the config
        :type is_add: Bool
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param identity_nat: Config that represent a identity NAT rule
        :type identity_nat: dict
        :raises Exception: Raised exception if the protocol value of the
        identity nat config is wrong
        :raises Exception: Raises exception if the VPP API call fails
        """
        port_from, port_to = fwutils.ports_str_to_range(identity_nat['ports'])
        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)
        for port in range(port_from, (port_to + 1)):

            protocols = identity_nat['protocols']
            if not protocols:
                protocols = ['tcp', 'udp']
            for proto in protocols:
                if (fwutils.proto_map[proto] != fwutils.proto_map['tcp'] and
                        fwutils.proto_map[proto] != fwutils.proto_map['udp']):
                    raise Exception('Firewall Set identity NAT failed - Protocol \
                                    input is wrong %s' % (proto))
                rv = fwglobals.g.router_api.vpp_api.vpp.call\
                    ('nat44_add_del_identity_mapping', is_add=is_add, sw_if_index=sw_if_index,
                    protocol=fwutils.proto_map[proto], port=port)
                if rv is None:
                    raise Exception("Firewall Set identity NAT failed")


    def setup_interface_acls(self, dev_id=None, if_type=None, sw_if_index=None):
        """
        Assign the global firewall rules to all the LAN/WAN devices. And
        attach the ACL rules on the interfaces using VPP API call.
        If the device identifier is given, only the specific interface is setup,
        this is the flow used to setup rules on dynamic interfaces. If the
        device identifier is None, all the device identifiers maintained in the
        object are programmed using VPP API calls.

        :param dev_id: Unique identifier of the device
        :type dev_id: String, optional
        :param if_type: Value indicating if the given interface is LAN or WAN
        :type if_type: String, optional
        :param sw_if_index: VPP identifier of the interface
        :type sw_if_index: Integer, optional
        """
        if dev_id:
            # With dev_id input, if_type and sw_if_index are required input parameters
            if if_type == 'lan':
                if dev_id.startswith('app_'):
                    dev_id = get_firewall_interface_key_for_app(dev_id, sw_if_index)
                self.set_interface_acls (dev_id, self.lan_global_acls.get('ingress'),
                                        self.lan_global_acls.get('egress'), sw_if_index)
                self.__exec_vpp_set_interface_acls (dev_id,  self.interfaces[dev_id]['sw_if_index'])
            elif if_type == 'wan':
                self.set_interface_acls (dev_id, self.wan_global_acls.get('ingress'),
                                         self.wan_global_acls.get('egress'), sw_if_index)
                self.__exec_vpp_set_interface_acls (dev_id,  self.interfaces[dev_id]['sw_if_index'])
            else:
                self.log.warning('Firewall - Invalid Interface type input: %s' % if_type)

        else:
            for dev_id in self.interfaces.keys():
                self.__exec_vpp_set_interface_acls (dev_id, self.interfaces[dev_id]['sw_if_index'])
            lan_interfaces = fwglobals.g.router_cfg.get_interfaces(type='lan')
            # Attach global outbound rules on all LAN interfaces
            for lan_interface in lan_interfaces:
                dev_id = lan_interface['dev_id']
                if not self.interfaces.get(dev_id):
                    self.set_interface_acls (dev_id, self.lan_global_acls.get('ingress'),
                                             self.lan_global_acls.get('egress'),
                                             fwutils.dev_id_to_vpp_sw_if_index(dev_id))
                    self.__exec_vpp_set_interface_acls (dev_id, self.interfaces[dev_id]['sw_if_index'],
                                                        self.lan_global_acls.get('ingress'),
                                                        self.lan_global_acls.get('egress'))
            # Attach global inbound rules on all WAN interfaces
            wan_interfaces = fwglobals.g.router_cfg.get_interfaces(type='wan')
            for wan_interface in wan_interfaces:
                dev_id = wan_interface['dev_id']
                if not self.interfaces.get(dev_id):
                    self.set_interface_acls (dev_id, self.wan_global_acls.get('ingress'),
                                             self.wan_global_acls.get('egress'),
                                             fwutils.dev_id_to_vpp_sw_if_index(dev_id))
                    self.__exec_vpp_set_interface_acls (dev_id,
                                                        self.interfaces[dev_id]['sw_if_index'],
                                                        self.wan_global_acls.get('ingress'),
                                                        self.wan_global_acls.get('egress'))

            # Update firewall rules on app interfaces whenever there is a firewall config change
            sw_if_index_list, app_id_list = get_app_sw_if_index_list()
            for idx, sw_if_index in enumerate(sw_if_index_list):
                app_dev_id = get_firewall_interface_key_for_app(app_id_list[idx], sw_if_index)
                if not app_dev_id in self.interfaces:
                    self.set_interface_acls (app_dev_id, self.lan_global_acls.get('ingress'),
                                                self.lan_global_acls.get('egress'), sw_if_index)
                    self.__exec_vpp_set_interface_acls (app_dev_id, sw_if_index,
                                                        self.lan_global_acls.get('ingress'),
                                                        self.lan_global_acls.get('egress'))
        return


    def clear_interface_acls(self, dev_id=None, sw_if_index=None):
        """
        Clear ACL attachment on the interfaces. if the device identifier is
        None, attachments on all interfaces are cleared using VPP API.

        :param dev_id: Unique identifier of the device
        :type dev_id: String, optional
        :param sw_if_index: VPP identifier of the interface
        :type sw_if_index: Integer, optional
        """
        if dev_id:
            # if dev_id is provided, sw_if_index is also a required input parameter
            if dev_id.startswith('app_'):
                dev_id = get_firewall_interface_key_for_app(dev_id, sw_if_index)
            self.__exec_vpp_clear_interface_acls (self.interfaces[dev_id]['sw_if_index'])
            del self.interfaces[dev_id]
        else:
            for dev_id in self.interfaces.keys():
                self.__exec_vpp_clear_interface_acls (self.interfaces[dev_id]['sw_if_index'])
            self.interfaces = {}
            self.lan_global_acls = {}
            self.wan_global_acls = {}
        return


    def process_wan_global_identity_nat(self, is_add, dev_id=None):
        """
        Create/Delete the global identity nat rules to all the WAN devices.
        Program the identity NAT on the interfaces using corresponding VPP API.
        If the device identifier is given, only the specific interface is setup,
        this is the flow used to setup config on dynamic interfaces. If the
        device identifier is None, all the WAN device identifiers are programmed
        using VPP API.

        :param is_add: Flag to indicate setup or delete config
        :type is_add: Boolean
        :param dev_id: Unique identifier of the device
        :type dev_id: String, optional
        """
        if dev_id:
            for identity_nat in self.wan_global_identity_nat:
                self.__exec_vpp_interface_identity_nat(is_add, dev_id, identity_nat)
        else:
            interfaces = fwglobals.g.router_cfg.get_interfaces(type='wan')
            for interface in interfaces:
                dev_id = interface['dev_id']
                for identity_nat in self.wan_global_identity_nat:
                    self.__exec_vpp_interface_identity_nat(is_add, dev_id, identity_nat)
            if not is_add:
                self.wan_global_identity_nat = {}
        return


def setup_firewall_acls (is_add, dev_id, if_type, sw_if_index):
    """
    Setup / Clear ACLs on the given device identifier. This API is the entry
    call for firewall post creation or deletion of dynamic interfaces.

    :param is_add: Flag to indicate setup or delete config
    :type is_add: Boolean
    :param dev_id: Unique identifier of the device
    :type dev_id: String
    :param if_type: Value indicating if the given interface is LAN or WAN
    :type if_type: String
    :param sw_if_index: VPP identifier of the interface
    :type sw_if_index: Integer
    """
    if is_add:
        fwglobals.g.firewall.setup_interface_acls(dev_id, if_type, sw_if_index)
    else:
        fwglobals.g.firewall.clear_interface_acls(dev_id, sw_if_index)


def setup_nat_global_identity_nat (is_add, dev_id):
    """
    Setup / Clear Identity nat on the given device identifier. This API is the
    entry call for firewall post creation or deletion of dynamic interfaces.

    :param is_add: Flag to indicate setup or delete config
    :type is_add: Boolean
    :param dev_id: Unique identifier of the device
    :type dev_id: String
    """
    fwglobals.g.firewall.process_wan_global_identity_nat(is_add, dev_id)


def get_firewall_interface_key_for_app (app_id, sw_if_index):
    """
    Generate a unique interface identifier using the given application identifier
    and sw_if_index

    :param app_id: Unique identifier that represents the application type
    :type app_id: String
    :param sw_if_index: VPP identifier of the interface
    :type sw_if_index: String
    :return: Unique interface identifier for the given application and the
    interface associated with it
    :rtype: String
    """
    return 'fw app %d %s' % (sw_if_index, app_id)


def get_app_sw_if_index_list (app_id=None, type='lan'):
    """
    Return the list of sw_if_index associated with the given application identifier and
    interface type

    :param type: Application name to be matched
    :type type: String, optional
    :param type: Value indicating the type of interface
    :type type: String, optional
    :return: List of sw_if_index and application identifier matching the given interface type
    :rtype: List, List
    """
    sw_if_index_list = []
    app_id_list = []
    app_interfaces = fwglobals.g.applications_api.get_interfaces\
        (type=type, vpp_interfaces=True, linux_interfaces=False)
    for app_identifier, vpp_if_names in app_interfaces.items():
        if app_id and (app_id != f'app_{app_identifier}'):
            continue
        for vpp_if_name in vpp_if_names:
            sw_if_index = fwutils.vpp_if_name_to_sw_if_index (vpp_if_name)
            if sw_if_index is not None:
                sw_if_index_list.append(sw_if_index)
                app_id_list.append(f'app_{app_identifier}')
            else:
                fwglobals.g.log.error('Failed to get sw_if_index from vpp_if_name : %s(app_id: %s)'\
                                      % (vpp_if_names, app_identifier))
    return sw_if_index_list, app_id_list
