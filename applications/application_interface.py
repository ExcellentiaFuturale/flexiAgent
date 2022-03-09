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
from abc import ABC, abstractmethod

# getting the name of the directory
# where the this file is present.
current = os.path.dirname(os.path.realpath(__file__))

# Getting the parent directory name
# where the current directory is present.
parent = os.path.dirname(current)

# adding the parent directory to
# the sys.path.
sys.path.append(parent)

from fwobject import FwObject

class IApplication(ABC, FwObject):
    def __init__(self):
        FwObject.__init__(self, f'application "{self.identifier}"')

    @property
    @abstractmethod
    def identifier(self):
        pass

    def install(self):
        raise NotImplementedError

    def configure(self):
        raise NotImplementedError

    def uninstall(self):
        raise NotImplementedError

    def get_status(self):
        raise NotImplementedError

    def get_log_file(self, params) -> str:
        return None

    def get_statistics(self):
        pass

    def start(self):
        pass

    def get_interfaces(self, params) -> list:
        return []

    # hooks
    def on_apps_watchdog(self, params):
        pass

    def on_router_is_started(self):
        pass

    def on_router_is_stopped(self):
        pass

    def on_router_stopping(self):
        pass

