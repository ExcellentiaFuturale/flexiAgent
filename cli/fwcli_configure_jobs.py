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
agent_root_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..')
sys.path.append(agent_root_dir)

from fwjobs import FwJobs

def argparse(configure_subparsers):
    configure_jobs_parser = configure_subparsers.add_parser('jobs', help='Configure jobs')
    configure_jobs_subparsers = configure_jobs_parser.add_subparsers(dest='jobs')

    update_jobs_cli = configure_jobs_subparsers.add_parser('update', help='Update job')
    update_jobs_cli.add_argument('--job_id', dest='params.job_id', help="Job id", required=True)
    update_jobs_cli.add_argument('--request', dest='params.request', help="Job request", required=True)
    update_jobs_cli.add_argument('--command', dest='params.command', help="Failed job command", required=True)
    update_jobs_cli.add_argument('--job_error', dest='params.job_error', help="Job error", required=True)

def update(job_id, request, command, job_error):
    with FwJobs('/etc/flexiwan/agent/.jobs.sqlite') as jobs:
        jobs.update_record(job_id, {'request': request, 'command': command, 'error': job_error})