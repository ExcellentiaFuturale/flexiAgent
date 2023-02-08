#! /usr/bin/python3

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

import json

from sqlitedict import SqliteDict

import fwutils
from fwobject import FwObject


class FwFrr(FwObject):
    """This is object that encapsulates configuration of FRR.
    """
    def __init__(self, db_file, fill_if_empty=True):
        FwObject.__init__(self)

        self.db_filename = db_file
        # The DB contains:
        # db['ospf']       - the OSPF configuration

        self.db = SqliteDict(db_file, autocommit=True)

        if not fill_if_empty:
            return

        if not 'ospf' in self.db:
            self.db['ospf'] = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.finalize()

    def finalize(self):
        """Destructor
        """
        self.db.close()

    def clean(self):
        """Clean DB
        """
        self.db['ospf'] = {}

    def dumps(self):
        """Prints content of database into string
        """
        db_keys = sorted(self.db.keys())                    # The key order might be affected by dictionary content, so sort it
        dump = [ { key: self.db[key] } for key in db_keys ] # We can't json.dumps(self.db) directly as it is SqlDict and not dict
        return json.dumps(dump, indent=2, sort_keys=True)

    def ospf_network_add(self, dev_id, address=None, area='0.0.0.0'):
        """Adds network to configuration of FRR, which should be published by OSPF.
        We use addresses of LAN interfaces to describe such networks. As a result,
        the branch networks are exchanged between flexiEdge devices by OSPF over
        tunnels, so two or more company branches become to be visible one to each other.

        :param dev_id:  The DEV-ID of the interface, network of which should be added to FRR OSPF.
        :param address: The address of network to be added. It will appear as "network {address} area {area}" record in ospfd.conf.
        :param area:    The area, which the added network belongs to.

        :returns: True on success, (False, err_str) tuple otherwise
        """
        ospf         = self.db['ospf']
        ospf_network = ospf.get(dev_id, {}).get('network')
        if ospf_network:
            self.log.error(f"ospf_network_add({dev_id}): network for '{dev_id}' exists: {str(ospf_network)}")
            return (False, f"failed to add OSPF network for {dev_id}")

        if not address:
             address = fwutils.get_interface_address(None, dev_id)

        if address:     # update FRR only if interface has IP (DHCP/cable is plugged/etc)
            ret, err_str =  self.run_ospf_add(address, area)
            if not ret:
                self.log.error(f"ospf_network_add({dev_id}): failed to update frr: {err_str}")
                return (False, f"failed to add OSPF network for {dev_id}")

        if not dev_id in ospf:
            ospf[dev_id] = {}
        ospf_network = { 'address': address, 'area': area }
        ospf[dev_id].update({'network': ospf_network})
        self.db['ospf'] = ospf    # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
        self.log.debug(f"ospf_network_add({dev_id}): {str(ospf_network)}")
        return True

    def ospf_network_remove(self, dev_id):
        """Removes network to be published by OSPF from the FRR configuration.

        :param dev_id:  The DEV-ID of the interface, network of which should be removed.

        :returns: None
        """
        ospf         = self.db['ospf']
        ospf_network = ospf.get(dev_id, {}).get('network')
        if not ospf_network:
            self.log.debug(f"ospf_network_remove({dev_id}): there is no existing network for '{dev_id}'")
            return

        if ospf_network['address']:  # update FRR only if interface has IP
            ret, err_str = self.run_ospf_remove(ospf_network['address'], ospf_network['area'])
            if not ret:
                self.log.excep(f"ospf_network_remove({dev_id}): failed to update frr: {err_str}")

        self.log.debug(f"ospf_network_remove({dev_id}): {str(ospf_network)}")
        del ospf[dev_id]['network']
        self.db['ospf'] = ospf    # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict

    def ospf_network_update(self, dev_id, new_address):
        """Updates network to be published by OSPF. The network is identified by
        the interface attached to this network. In turn, the interface is identified
        by dev-id.
            Note the update might remove network from FRR, if the new value
        of network is None.
            To remove network completely, i.e. from both FRR and from the self.db,
        you should call the ospf_network_remove().

        :param dev_id:      The DEV-ID of the interface, network of which should be updated.
        :param new_address: The new address of the network.

        :returns: True on success, False otherwise
        """
        ospf         = self.db['ospf']
        ospf_network = ospf.get(dev_id, {}).get('network')
        if not ospf_network:
            self.log.error(f"ospf_network_update({dev_id}): there is no existing network for '{dev_id}'")
            return False

        # Firstly remove the old network if exists
        #
        area        = ospf_network['area']
        old_address = ospf_network['address']
        if old_address:
            ret, err_str = self.run_ospf_remove(old_address, area)
            if not ret:
                self.log.excep(f"ospf_network_update({dev_id}): failed to remove old network '{old_address}' from frr: {err_str}")

        # Now update new address.
        # If new address was provided, update FRR. Otherwise update database only.
        #
        if new_address:
            ret, err_str = self.run_ospf_add(new_address, area)
            if not ret:
                self.log.excep(f"ospf_network_update({dev_id}): failed to add new network '{new_address}' to frr: {err_str}")
                new_network = None

        ospf_network['address'] = new_address
        self.db['ospf'] = ospf    # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
        self.log.debug(f"ospf_network_update({dev_id}): '{old_address}' -> '{new_address}'")

    def translate_bgp_neighbor_to_vtysh_commands(self, neighbor):
        ip = neighbor.get('ip')
        remote_asn = neighbor.get('remoteAsn')
        password = neighbor.get('password')
        keepalive_interval = neighbor.get('keepaliveInterval')
        hold_interval = neighbor.get('holdInterval')

        commands = [
            f'neighbor {ip} remote-as {remote_asn}',

            # Allow peering between directly connected eBGP peers using loopback addresses.
            f'neighbor {ip} disable-connected-check',
        ]

        if password:
            commands.append(f'neighbor {ip} password {password}')

        if keepalive_interval and hold_interval:
            commands.append(f'neighbor {ip} timers {keepalive_interval} {hold_interval}')

        return commands

    def run_ospf_remove(self, address, area):
        ret, err_str = fwutils.frr_vtysh_run(["router ospf", f"no network {address} area {area}"])
        return ret, err_str

    def run_ospf_add(self, address, area):
        ret, err_str = fwutils.frr_vtysh_run(["router ospf", f"network {address} area {area}"])
        return ret, err_str

    def run_bgp_remove_network(self, address):
        ret, err_str = fwutils.frr_vtysh_run(["router bgp", 'address-family ipv4 unicast', f"no network {address}"])
        return ret, err_str

    def run_bgp_add_network(self, address):
        ret, err_str = fwutils.frr_vtysh_run(["router bgp", 'address-family ipv4 unicast', f"network {address}"])
        return ret, err_str

