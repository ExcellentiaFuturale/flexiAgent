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

from sqlitedict import SqliteDict

import fwglobals
import fwutils
from fwobject import FwObject
from fwcfg_request_handler import FwCfgMultiOpsWithRevert

class FwPolicies(FwObject):
    """Policies class representation.
    This is a persistent storage of VPP policies identifiers that are used on
    tunnel add/remove to reattach policies to the loopback interfaces.
    """

    def __init__(self, db_file):
        """Constructor method.
        """
        self.db_filename = db_file
        self.policies = SqliteDict(db_file, 'policies', autocommit=True)

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
        self.policies.close()

    def clean(self):
        """Clean DB

        :returns: None.
        """
        self.policies.clear()

    def add_policy(self, policy_id, priority):
        """Stores policy into database.

        :returns: None.
        """
        self.policies[policy_id] = priority

    def remove_policy(self, policy_id):
        """Removes policy from database.

        :returns: None.
        """
        del self.policies[policy_id]

    def policies_get(self):
        """Get policies dictionary.

        :returns: Dictionary.
        """
        return self.policies

    def vpp_attach_detach_policies(self, attach, vpp_if_name, if_type=None):
        """Attach interface to policy policies dictionary.

        :param attach: A boolean indicates if to attach or detach.
        :param vpp_if_name: VPP interface name to attach to policies on.
        :param if_type: LAN or WAN.

        """
        policies = self.policies_get()
        if len(policies) == 0:
            return

        if if_type == 'wan':
            policy = fwglobals.g.router_cfg.get_multilink_policy()
            rules = policy.get('rules', [])
            attach_to_wan = rules[0].get('apply-on-wan-rx', False) if len(rules) > 0 else False
            if not attach_to_wan:
                return

        op         = 'add' if attach else 'del'
        revert_op  = 'del' if attach else 'add'

        with FwCfgMultiOpsWithRevert() as handler:
            try:
                for policy_id, priority in list(policies.items()):
                    vppctl_cmd        = f'fwabf attach ip4 {op} policy {int(policy_id)} priority {priority} {vpp_if_name}'
                    revert_vppctl_cmd = f'fwabf attach ip4 {revert_op} policy {int(policy_id)} priority {priority} {vpp_if_name}'
                    handler.exec(
                        func=fwutils.vpp_cli_execute,
                        params={ 'cmds': [vppctl_cmd], 'raise_exception_on_error': True },
                        revert_func=fwutils.vpp_cli_execute if attach else None,
                        revert_params={ 'cmds': [revert_vppctl_cmd] } if attach else None
                    )
            except Exception as e:
                fwglobals.log.error(f"vpp_attach_detach_policies({attach, vpp_if_name, if_type}) failed: {str(e)}")
                handler.revert(e)
