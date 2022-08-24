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

import pickle
import sqlite3

from sqlitedict import SqliteDict
from fwlog import FwObjectLogger


def _decode(obj):
    """Deserialize objects retrieved from SQLite."""
    return pickle.loads(bytes(obj), encoding="latin1")


def _encode(obj):
    """Serialize objects to binary format."""
    return sqlite3.Binary(pickle.dumps(obj, protocol=2))


class FwSqliteDict(SqliteDict):
    """This is base DB class implementation, based on SqliteDict."""

    def __init__(self, db_file):
        """Constructor method

        :param db_file:      SQLite database file name.
        """
        super().__init__(filename=db_file, flag='c', autocommit=True, encode=_encode, decode=_decode)

        name = self.__class__.__name__
        self.log = FwObjectLogger(object_name=name)

    def finalize(self):
        """Close DB

        :returns: None.
        """
        self.close()

    def clean(self):
        """Clean DB

        :returns: None.
        """
        for req_key in self:
            del self[req_key]
