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
from fwagent import daemon_rpc

def argparse(configure_subparsers):
    configure_fwjobs_parser = configure_subparsers.add_parser('fwjobs', help='Configure fwjobs')
    configure_fwjobs_subparsers = configure_fwjobs_parser.add_subparsers(dest='fwjobs')

    job_parser = configure_fwjobs_subparsers.add_parser('job', help='Configure job')
    fwjobs_job_subparsers = job_parser.add_subparsers(dest='job')

    update_fwjobs_cli = fwjobs_job_subparsers.add_parser('update', help='Update fwjob')
    update_fwjobs_cli.add_argument('--job_id', dest='params.job_id', help="Job id", required=True)
    update_fwjobs_cli.add_argument('--request', dest='params.request', help="Job request", required=True)
    update_fwjobs_cli.add_argument('--command', dest='params.command', help="Failed job command", required=True)
    update_fwjobs_cli.add_argument('--job_error', dest='params.job_error', help="Job error", required=True)

def job_update(job_id, request, command, job_error):

    daemon_rpc(
        'api',
        api_object='fwglobals.g.jobs',
        api_name='update_record',
        job_id=job_id, error={'request': request, 'command': command, 'error': job_error})
