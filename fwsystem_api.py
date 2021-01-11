#! /usr/bin/python

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
from fwrequest_executor import FwRequestExecutor
import traceback

fwsystem_modules = {
    'fwtranslate_revert':       __import__('fwtranslate_revert') ,
    'fwtranslate_add_lte':      __import__('fwtranslate_add_lte'),
}

fwsystem_translators = {
    'add-lte':               {'module':'fwtranslate_add_lte',    'api':'add_lte'},
    'remove-lte':            {'module':'fwtranslate_revert',     'api':'revert'},    
}

class FWSYSTEM_API:
    """This is System API class representation.
        These APIs are used to handle system configuration requests regardless of the vpp state.
        e.g to enable lte connection even if the vpp is not running.
        They are invoked by the flexiManage over secure WebSocket
        connection using JSON requests.
        For list of available APIs see the 'fwsystem_translators' variable.
    """
    def __init__(self, cfg):
        """Constructor method
        """
        self.cfg = cfg
        self.request_executor = FwRequestExecutor(fwsystem_modules, fwsystem_translators, fwglobals.g.system_cfg)

    def call(self, request):
        try:             
            self.request_executor.execute(request)
        except Exception as e:
            err_str = "FWSYSTEM_API::call: %s" % str(traceback.format_exc())
            fwglobals.log.error(err_str)
            raise e

        return {'ok':1}

    def restore_system_configuration(self):
        """Restore system configuration.
        Run all system configuration translated commands.
        """
        self.request_executor.restore_configuration()