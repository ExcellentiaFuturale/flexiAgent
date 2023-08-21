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

from fwlog import FwObjectLogger

class FwObject():
    """This is FlexiWAN version of the Python 'object' class.
    It provides functionality which is common for all FlexiWAN objects.
    This object allows to initialize a separate FwObject instance per
    class/object with data that is specific for that class/object.
    This is different than fwglobals module which contains one instance
    of the FwGlobals class for the entire project.
        The main purpose for the FwObject is to provide seamless logging
    for objects by calling self.log(), while prepending log line with name
    of the specific object that called the self.log().
    """
    def __init__(self, name=None, log=None):
        self.name = name if name else self.__class__.__name__
        self.log = FwObjectLogger(object_name=self.name, log=log)
        self.loggers = [self.log] # Stack of loggers, where the last in list is used for logging
        self.initialized = False

    def initialize(self):
        self.initialized = True

    def finalize(self):
        self.initialized = False

    def push_logger(self, log):
        self.loggers.append(log)
        if self.log != log:
            self.log.debug(f"{self.name}: logging switched from {str(self.log)} to {str(log)}")
        self.log = log

    def pop_logger(self):
        self.loggers.pop()
        prev_log = self.loggers[-1]
        if self.log != prev_log:
            self.log.debug(f"{self.name}: logging switched back to {prev_log}")
        self.log = prev_log
