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

    def install(self, params):
        """Install functionality for application.

        :param params - A dictionary that contains the application configuration that received from flexiManage

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        raise NotImplementedError

    def uninstall(self):
        """Uninstall functionality for application.

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        raise NotImplementedError

    def configure(self, params):
        """Configuration functionality for application.

        :param params: params - open vpn parameters received from flexiManage

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        raise NotImplementedError

    # hooks
    def on_watchdog(self):
        """A function the agent calls every few seconds and allows control and monitoring on the application

        :returns: None
        """
        pass

    def on_router_is_started(self):
        """A function the agent calls when the router has successfully started.

        :returns: None
        """
        pass

    def on_router_is_stopped(self):
        """A function the agent calls when the router has successfully stopped

        :returns: None
        """
        pass

    def on_router_is_stopping(self):
        """A function the agent calls when the router starts stopping

        :returns: None
        """
        pass

    # getters
    def get_log_filename(self) -> str:
        """A function that returns the application's log filename.
        It is used for retrieving and displaying logs in flexiManage

        :returns: Log filename
        """
        return None

    def get_statistics(self) -> dict:
        """A function that returns the statistics of the application

        :returns: Dictionary
        """
        return {}

    def get_interfaces(self, type='lan', vpp_interfaces=False) -> list:
        """A function that returns the application's interfaces.

        :param type: Specifies the type of interface to return, LAN or WAN. Leave None for all types.
        :param vpp: Specifies whether to return VPP or Linux interfaces. Leave None for all the interfaces.

        :returns: List
        """
        return []

    def is_app_running(self) -> bool:
        """A function that returns a boolean that indicates whether the application is currently running or not

        :returns: Boolean
        """
        raise NotImplementedError