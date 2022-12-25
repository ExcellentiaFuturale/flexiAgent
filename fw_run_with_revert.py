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

from functools import partial

import fwglobals

class FwRunWithRevert():
    """This class implements an helper to a function that should do multiple configurations.
       In case of failure in one function, the helper knows to revert succeeded configurations.
    """
    def __init__(self):
        """Constructor.
        """
        self.revert_functions = []

    def run(self, success, success_params=None, revert=None, revert_params=None):
        try:
            ret = success(**success_params) if success_params else success()
            self.append_revert(revert, revert_params)
            return ret
        except Exception as e:
            fwglobals.log.error(f"FwRunWithRevert(): func {success.__name__}({success_params}) failed. err: {str(e)}")
            self.revert(e)

    def append_revert(self, revert=None, revert_params=None):
        if revert and revert_params:
            self.revert_functions.append(partial(revert, **revert_params))
        elif revert:
            self.revert_functions.append(partial(revert))

    def revert(self, error):
        if not self.revert_functions:
            raise error

        self.revert_functions.reverse()
        for revert_function in self.revert_functions:
            try:
                revert_function()
            except Exception as revert_e: # on revert, don't raise exceptions to prevent infinite loop of failure -> revert failure -> revert of revert failure and so on (:
                fwglobals.log.excep(f"FwRunWithRevert(): revert func {str(revert_function)} failed. err: {str(revert_e)}")
                pass

        self.revert_functions = []
        raise error
