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

import argparse
import os
import sys

agent_root_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(agent_root_dir)

import fwglobals
from fwjobs import FwJobs

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description="fwjobs command line interface",
        formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(help='Jobs commands', dest='jobs_commands')
    subparsers.required = True

    parser_show = subparsers.add_parser('show', help='Prints job information to stdout')

    parser_update = subparsers.add_parser('update', help='Updates job information')
    parser_update.add_argument('-j', '--job_id', dest='job_id', default=None,
                        help="job id")
    parser_update.add_argument('-r', '--request', dest='request', default=None,
                        help="job request")
    parser_update.add_argument('-c', '--command', dest='command', default=None,
                        help="failed job command")
    parser_update.add_argument('-e', '--job_error', dest='job_error', default=None,
                        help="job error")
    args = parser.parse_args()

    g = fwglobals.Fwglobals()
    fwglobals.initialize()

    with FwJobs(g.JOBS_FILE) as jobs:
        command_functions = {
                        'show': lambda _: print(jobs.dumps()),
                        'update': lambda args: jobs.update_record(args.job_id, {'request': args.request, 'command': args.command, 'error': args.job_error}) }
        command_functions[args.jobs_commands](args)