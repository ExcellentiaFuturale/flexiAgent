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

import fwglobals
import fwutils
import json
from sqlitedict import SqliteDict

from fwobject import FwObject

class FwMultilinkLink():
    """Abstraction of link. Actually this object is no more than the container
    of arguments for the the VPP API "fwabf link add/del".
    """
    def __init__(self, link_id, labels, next_hop, vpp_if_name):
        """
        :param link_id:     string that represents link unique identifier
        :param labels:      list of label strings received from flexiManage
        :param next_hop:    IP address of next hop
        :param vpp_if_name: name of the interface in VPP that represents link.
                            It may be either a WAN physical interface if label
                            is used for Direct Internet Access (DIA), or loopback
                            interface, if label is used for flexiEdge tunnel.
        """
        self.labels      = labels
        self.link_id     = link_id
        self.next_hop    = next_hop
        self.vpp_if_name = vpp_if_name

class FwMultilink(FwObject):
    """This is object that encapsulates data used by multi-link feature.
    """
    def __init__(self, db_file, fill_if_empty=True):
        FwObject.__init__(self)

        self.db_filename = db_file
        # The DB contains:
        # db['labels']     - map of label strings (aka names) into integers (aka id-s) used by VPP.
        # db['links']      - hash of FwMultilinkLink objects by dev-id/sw_if_index
        # db['vacant_ids'] - pool of available id-s.

        self.db = SqliteDict(db_file, autocommit=True)

        if not fill_if_empty:
            return

        if not 'labels' in self.db:
            self.db['labels'] = {}
        if not 'links' in self.db:
            self.db['links'] = {}
        if not 'vacant_ids' in self.db:
            self.db['vacant_ids'] = list(range(256))  # VPP uses u8 to keep ID, hence limitation of 0-255
        else:
            self.db['vacant_ids'] = sorted(self.db['vacant_ids'])  # Reduce chaos a bit :)

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
        self.db['labels'] = {}
        self.db['vacant_ids'] = list(range(256))

    def dumps(self):
        """Prints content of database into string
        """
        # We can't json.dumps(self.db) directly as it is SqlDict and not dict.
        # So we have to export it's elements before serialization by JSON.
        # On the way, sort the keys, as alphabetical order of elements in dict
        # is not guaranteed.
        # Note we have to use customized JSON encoder to make json.dumps()
        # to be able to digest Python objects, like FwMultilinkLink-s.
        #
        db_keys = sorted(self.db.keys())
        dump = [ { key: self.db[key] } for key in db_keys]
        return json.dumps(dump, indent=2, sort_keys=True, cls=fwutils.FwJsonEncoder)

    def get_label_ids_by_names(self, names, remove=False):
        """Maps label names into label id-s.
        Label ID is two bytes integer.

        :param names:   list of strings that represent label names.
        :param remove:  True if label refCounter should be decremented and
                        label should be removed from database if no more
                        refCounter exist. False if refCounter should be incremented.

        :returns: list of id-s.
        """
        # Note we can't modify self.db subelements, as SqlDict can't detect
        # modifications in the object memory, so we have to replace whole
        # root element. That is why we use temporary copies of root elements.
        #
        labels     = self.db['labels']
        vacant_ids = self.db['vacant_ids']

        gc_before = len(labels)

        ids = []
        for name in names:
            if name in labels:
                if remove:
                    labels[name]['refCounter'] -= 1
                else:
                    labels[name]['refCounter'] += 1
                ids.append(labels[name]['id'])
            else:
                if remove:
                    raise Exception("FwMultilink: remove not existing label '%s'" % name)

                if len(vacant_ids) == 0:
                    self.db['labels']     = labels
                    self.db['vacant_ids'] = vacant_ids
                    raise Exception("FwMultilink: 1-byte limit for label ID is reached, can't store label '%s'" % name)

                new_id = vacant_ids.pop(0)
                labels[name] = {}
                labels[name]['id'] = new_id
                labels[name]['refCounter'] = 1
                ids.append(new_id)

        # Clean id-s with no refCounter
        if remove:
            for name in names:
                if name in labels:
                    if labels[name]['refCounter'] == 0:
                        vacant_ids.insert(0, labels[name]['id'])
                        del labels[name]

        self.db['labels']     = labels
        self.db['vacant_ids'] = vacant_ids

        gc_after = len(labels)

        self.log.debug("get_label_ids_by_names: input=%s, remove=%s, output=%s, gc: %d -> %d" % \
            (names, str(remove), ','.join(map(str, ids)), gc_before, gc_after))
        return ids

    def vpp_update_labels(self, remove, labels=None, next_hop=None, dev_id=None, sw_if_index=None):
        """Updates VPP with flexiwan path labels.
        These labels are used for Multi-Link feature: user can mark interfaces
        or tunnels with labels and than add policy to choose interface/tunnel by
        label where to forward packets to.

            REMARK: this function is temporary solution as it uses VPP CLI to
        configure labels. Remove it, when correspondent Python API will be added.
        In last case the API should be called directly from translation.

        :param labels:      python list of labels
        :param remove:      True to remove labels, False to add.
        :param dev_id:      Interface bus address if device to apply labels to.
        :param next_hop:    IP address of next hop.

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        # Find link in database
        #
        if not dev_id and not sw_if_index:
            return (False, "neither 'dev_id' nor 'sw_if_index' was provided")
        link_id = dev_id if dev_id else sw_if_index
        link = self.db['links'].get(link_id)

        # Remove link
        if remove:
            if not link:
                self.log.error(f"no link to be removed was found: dev_id={dev_id}, sw_if_index={sw_if_index}")
                return (False, "failed to update multilink label for dev_id={dev_id}")
            err_str = self._remove_link(link)
            if err_str:
                return (False, err_str)
            return True

        # Add link.
        # It can be link modification, if link exists in database, or it can be
        # link addition, if link does not exists.
        # In the former case we have to remove existing link firstly.

        # Resolve next_hop if not provided
        #
        if link:
            vpp_if_name = link.vpp_if_name
        else:
            vpp_if_name = fwutils.dev_id_to_vpp_if_name(dev_id) if dev_id else \
                          fwutils.vpp_sw_if_index_to_name(sw_if_index)
            if not vpp_if_name:
                return (False, "'vpp_if_name' was not found for {link_id}")
        if not next_hop:
            tap = fwutils.vpp_if_name_to_tap(vpp_if_name)
            next_hop, _ = fwutils.get_interface_gateway(tap)
        if not next_hop:
            next_hop = "0.0.0.0"
            fwglobals.log.warning(f"vpp_update_labels: no 'next_hop' was provided, use black hole {next_hop}")

        if link:
            err_str = self._remove_link(link)
            if err_str:
                return (False, err_str)

            # Now update link object with new data.
            #
            link.labels     = labels
            link.next_hop   = next_hop
        else:
            link = FwMultilinkLink(link_id, labels, next_hop, vpp_if_name)

        err_str = self._add_link(link)
        if err_str:
            return (False, err_str)
        return True

    def _add_link(self, link):
        # Allocate ID-s for labels and convert them into string
        #
        ids = self.get_label_ids_by_names(link.labels)
        label_ids = ','.join(map(str, ids))

        # Add link to  VPP
        #
        vppctl_cmd = 'fwabf link add label %s via %s %s' % (label_ids, link.next_hop, link.vpp_if_name)
        out = fwutils.vpp_cli_execute_one(vppctl_cmd, debug=True)
        if out is None:
            return "_add_link: failed vppctl_cmd=%s" % vppctl_cmd

        # Store link in database.
        # We do it in so strange way, as self.db is SqliteDict object,
        # and the last does not support in-memory modifications.
        #
        links = self.db['links']
        links[link.link_id] = link
        self.db['links'] = links

    def _remove_link(self, link):
        # Deallocate label ID-s from database and convert them into string
        #
        ids = self.get_label_ids_by_names(link.labels, remove=True)
        label_ids = ','.join(map(str, ids))

        # Remove link from VPP
        #
        vppctl_cmd = 'fwabf link del label %s via %s %s' % (label_ids, link.next_hop, link.vpp_if_name)
        out = fwutils.vpp_cli_execute_one(vppctl_cmd, debug=True)
        if out is None:
            return "_remove_link: failed vppctl_cmd=%s" % vppctl_cmd

        # Remove link from database.
        # We do it in so strange way, as self.db is SqliteDict object,
        # and the last does not support in-memory modifications.
        #
        links = self.db['links']
        del links[link.link_id]
        self.db['links'] = links

    def get_link(self, dev_id):
        return self.db['links'].get(dev_id)
