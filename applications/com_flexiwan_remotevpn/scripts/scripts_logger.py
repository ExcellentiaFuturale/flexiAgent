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

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

this_dir = os.path.dirname(os.path.realpath(__file__))
up_dir   = os.path.dirname(this_dir)
sys.path.append(up_dir)

from application_cfg import config
openvpn_scripts_log_file = config["openvpn_scripts_log_file"]

logging.basicConfig(
    filename=openvpn_scripts_log_file,
    level=logging.DEBUG,
    format='%(asctime)s %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p' # 12/12/2010 11:46:36 AM,
)

# Save the files, up to 5 files of 5MB each
handler = RotatingFileHandler(openvpn_scripts_log_file, mode='a', maxBytes=5*1024*1024,
                                 backupCount=5, encoding=None, delay=0)

logger = logging.getLogger('applications')
if not logger.handlers:
    logger.addHandler(handler)

class Logger():
    def error(self, str):
        logging.error(str)

    def debug(self, str):
        logging.debug(str)

    def info(self, str):
        logging.info(str)
