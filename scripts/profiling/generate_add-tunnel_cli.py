#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2021  flexiWAN Ltd.
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

###############################################################################
# This script generates CLI file that can be injected into fwagent using
# 'cli' command:
#       python fwagent.py cli -f add-tunnel.200.cli -t ${workspaceFolder}/tests/fwtemplates.yaml"
#
# Note, the fwtemplates.yaml file is required!
###############################################################################

import glob
import os
import pstats
import sys

def main(args):

    num_tunnels  = int(args.num_of_tunnels) if args.num_of_tunnels else 200
    out_filename = args.out_filename if args.out_filename else f'add-tunnel.{num_tunnels}.cli'
    out_stream   = open(out_filename, 'w')

    out_stream.write("[\n")

    start_router = \
        '{\n'\
        '  "entity":  "agent",\n'\
        '  "message": "start-router",\n'\
        '  "params": {\n'\
        '    "interfaces": [\n'\
        '      "__INTERFACE_1__",\n'\
        '      "__INTERFACE_2__"\n'\
        '    ]\n'\
        '  }\n'\
        '}\n'\
        ',\n'
    out_stream.write(start_router)

    for i in range(1, num_tunnels+1):
        add_tunnel = \
            '{\n'\
            '    "entity": "agent",\n'\
            '    "message": "add-tunnel",\n'\
            '    "params": {\n'\
            '        "encryption-mode": "psk",\n'\
            '        "src": "__INTERFACE_1__addr_no_mask",\n'\
            '        "dev_id": "__INTERFACE_1__dev_id",\n'\
            '        "dst": "192.168.1.110",\n'\
            '        "dstPort": "4789",\n'\
            f'        "tunnel-id": {i},\n'\
            '        "loopback-iface": {\n'\
            f'            "addr": "10.100.{int((i*2)/256)}.{(i*2)%256}/31",\n'\
            f'            "mac": "02:00:27:fd:{int((i*2)/256):02x}:{((i*2)%256):02x}",\n'\
            '            "mtu": 1500,\n'\
            '            "routing": "ospf",\n'\
            '            "multilink": {\n'\
            '                "labels": [\n'\
            '                    "5e98748a622b106749e653a9"\n'\
            '                ]\n'\
            '            }\n'\
            '        },\n'\
            '        "ipsec": {\n'\
            '            "local-sa": {\n'\
            f'                "spi": {i*2},\n'\
            '                "crypto-key": "370f461cc84fa8a0f3aeffb5871b69c0",\n'\
            '                "integr-key": "72314ca9ae26c7fe3869ccbc42e8dfe6",\n'\
            '                "crypto-alg": "aes-cbc-128",\n'\
            '                "integr-alg": "sha-256-128"\n'\
            '            },\n'\
            '            "remote-sa": {\n'\
            f'                "spi": {i*2+1},\n'\
            '                "crypto-key": "1302a5188a2761732194eb783c2325f3",\n'\
            '                "integr-key": "542e6b528cd10edc9f31da28dd6f784f",\n'\
            '                "crypto-alg": "aes-cbc-128",\n'\
            '                "integr-alg": "sha-256-128"\n'\
            '            }\n'\
            '        }\n'\
            '    }\n'\
            '}\n'\
            ',\n'
        out_stream.write(add_tunnel)


    stop_router = \
        '{\n'\
        '  "entity":  "agent",\n'\
        '  "message": "stop-router"\n'\
        '}\n'
    out_stream.write(stop_router)

    out_stream.write("]\n")
    out_stream.close()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='generator of add-tunnel cli for many tunnels')
    parser.add_argument('-n', dest='num_of_tunnels', default=200,
                        help="number of add-tunnel requests in resulted CLI")
    parser.add_argument('-o', '--out', dest='out_filename', nargs='?', const='default',
                        help="name of the output file. The default is 'add-tunnel.200.cli'")
    args = parser.parse_args()

    main(args)
