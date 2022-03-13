#! /usr/bin/python

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
import os
import sys
from abc import ABC

this_dir = os.path.dirname(os.path.realpath(__file__))
up_dir   = os.path.dirname(this_dir)
sys.path.append(up_dir)

from fwobject import FwObject

class FwApplicationInterface(ABC, FwObject):
    def __init__(self):
        FwObject.__init__(self, self.identifier)

    @property
    def identifier(self):
        return self.__module__.replace('_', '.')

    def install(self):
        raise NotImplementedError

    def configure(self):
        raise NotImplementedError

    def uninstall(self):
        raise NotImplementedError

    def start(self):
        pass

    def is_app_running(self):
        raise NotImplementedError

    # hooks
    def on_watchdog(self, params):
        pass

    def on_router_is_started(self):
        pass

    def on_router_is_stopped(self):
        pass

    def on_router_is_stopping(self):
        pass

    # getters
    def get_log_file(self, params) -> str:
        return None

    def get_statistics(self) -> dict:
        return {}

    def get_interfaces(self, params) -> list:
        return []