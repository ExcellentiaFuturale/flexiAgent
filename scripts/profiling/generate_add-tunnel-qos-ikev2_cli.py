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

    num_tunnels = int(args.num_of_tunnels) if args.num_of_tunnels else 200
    out_filename = args.out_filename if args.out_filename else f'add-tunnel.{num_tunnels}.cli'
    out_stream = open(out_filename, 'w')
    certificate = '"-----BEGIN CERTIFICATE-----\\nMIIFPzCCAyegAwIBAgIUaqvpDeCkWHtBZuYCx+VtlsSe6J0wDQYJKoZIhvcNAQEL\\nBQAwLzEtMCsGA1UEAwwkNEM2QkU4Q0EtQjE0Qy00RDFDLUJCODItQTc2RDMyQjc5\\nMDY1MB4XDTIzMDIxNTE3NTQ0MloXDTI0MDIxMDE3NTQ0MlowLzEtMCsGA1UEAwwk\\nNEM2QkU4Q0EtQjE0Qy00RDFDLUJCODItQTc2RDMyQjc5MDY1MIICIjANBgkqhkiG\\n9w0BAQEFAAOCAg8AMIICCgKCAgEA1UPAvaX7L/X46/LzvW3eOIwXZii0qAyIpFJK\\noHNFaEC8CuIMcDF+Ui3CwidwZpnA3TI9V4uSk9M3/L6yoA+brOr9lMdRN0Afu3XZ\\n7Q6WxLPU88QGpCKhTcRKaMd6l7G4Yc8+nLxkIzxvIlbEgXwAcf54aaItqCiMPK7E\\n1Zcn4lHLsnMp+YB5tc8JPbbSadmN66NPRaoADXzZbPcY1rD1I94gJ7aQtyTQ6eB3\\nu2bWeYeGw8scyooWjoDSa/ACnJMJUmR/aRgsHQUuN+Ul6KH9Up+NFHprKKxUhoIB\\nbJWMR4LyvQOHjivwQWJ192IO80sGpgUHFWrJgP9wz17V9C1pxWN6MdMYEkrPSiaH\\nesTpQz4tTxix75+F/cJtiN7Y19qEmyc4JJnvrDcbf3OZUu7wCUHfjt9s2Xl+3qZe\\nOJXCURWstUSDNCAmuIyQJGGxEBDjs+JwdOy9BY0EhgAkTUkj6IXVEpTMYf3++RjB\\nc46a6BuPxY0LGuIcMBLNJVKeAOj0xoAefsSJ2fheyw/d3M8Rv9I/Xx0jZul6ia8b\\nJ/R/uZrWC0WEhq7Kni9/af6F+isXBmq6QVQZndEXpCYLmSkgobjcaC1OXWr44AU+\\n/JF7kfJgCM9il1a7EQNKui+5b9b36aivzaw6naEP+niXAXH4FCSqcvvz03UDe4yL\\nfIu/+oMCAwEAAaNTMFEwHQYDVR0OBBYEFPC2vK/H/yQnBClmmSLgMgrC484RMB8G\\nA1UdIwQYMBaAFPC2vK/H/yQnBClmmSLgMgrC484RMA8GA1UdEwEB/wQFMAMBAf8w\\nDQYJKoZIhvcNAQELBQADggIBADfKfET2JHXqYXy7lUQfSvqqg6yCkbBV1ON5ZFnT\\nFypcgrR5Ik16eT7OFvyuSgQmG+lKGCKuMon4GCJoq0ZyfgPrEIoDPvT6H1UKsBdH\\nKWgdVVQKQUVAHAiXUADi9KOzgYXHrbkkITl7VX0V7D1dQbkZw53lkpCUN8xgujJF\\nWM0yW72VgEMOH+MMSWosYwAUkJfZhwG1/j4Uad1qRRMOnN/o5uupbAifhjRFWbXK\\n8fwh/ewG3aM8azzt1jldu+6An0pzu/6hjnIFJDiEY9cKaqOYVzhsZOZJr/h0h9Og\\nxO25OAgjn/UVo3m/A8J/GRFzlbmT9vEpvUUC3vWio8c1t/xt/3uMIMdWDTkqniqF\\nXB6RKVjMEAuJhTWY8m3qQ5ZqMf1mAOHRffwwr8ghNGR2bNGVZTlvpepQ6bdfR2e9\\njCxT6SBYuwUnr4L5nJqM+/W3FEiCL4LgfOR38BTQWIHiHJKmJ+c4pHs2POegAnF7\\nIX/Ko0rDp20tm96yr1ilWp4+4amVmmu7+1frFReS6ZE1NzrKeNEtIBIM71IoMdr+\\nKlOHo3ZL8gTAlUnZHMhkLUVPUTdj5DjFmew27x/JuUJ4ohiFYB70SKWs9ForMiTH\\nu1sMf4gtmevIwqrht5spwwB2hywnQY/2HrD6un0rSLSZYXe+C9j4ihcTTg8e83s1\\n2I1f\\n-----END CERTIFICATE-----"'

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

    add_application = \
        '{\n'\
        '    "entity": "agent",\n'\
        '    "message": "add-application",\n'\
        '    "params": {\n'\
        '        "applications": [\n'\
        '            {\n'\
        '                "rules": [\n'\
        '                    {\n'\
        '                        "_id": "610a63d8c654eb5b31bcbf4f",\n'\
        '                        "ip": "104.154.0.0/15"\n'\
        '                    }\n'\
        '                ],\n'\
        '                "name": "custom:company_ranges",\n'\
        '                "description": "All company ranges allowed",\n'\
        '                "category": "network",\n'\
        '                "serviceClass": "default",\n'\
        '                "importance": "high",\n'\
        '                "id": "610a63d8c654eb5b31bcbf4d"\n'\
        '            },\n'\
        '            {\n'\
        '                "rules": [\n'\
        '                    {\n'\
        '                        "_id": "610a7a3ac654eb5b31bcdbc4",\n'\
        '                        "ip": "108.175.32.0/20"\n'\
        '                    }\n'\
        '                ],\n'\
        '                "name": "custom:range2",\n'\
        '                "description": "second company range",\n'\
        '                "category": "remote_access",\n'\
        '                "serviceClass": "default",\n'\
        '                "importance": "high",\n'\
        '                "id": "610a7a3ac654eb5b31bcdbc2"\n'\
        '            },\n'\
        '            {\n'\
        '                "name": "custom:range3",\n'\
        '                "description": "third range",\n'\
        '                "category": "network",\n'\
        '                "serviceClass": "default",\n'\
        '                "importance": "high",\n'\
        '                "rules": [\n'\
        '                        {\n'\
        '                            "_id": "610a86fbc654eb5b31bceecf",\n'\
        '                            "ip": "178.236.80.0/20"\n'\
        '                        }\n'\
        '                ],\n'\
        '                "id": "610a86fbc654eb5b31bceecd"\n'\
        '            }\n'\
        '        ]\n'\
        '    }\n'\
        '}\n'\
        ',\n'
    out_stream.write(add_application)

    add_ospf = \
        '{\n'\
        '    "entity":  "agent",\n'\
        '    "message": "add-ospf",\n'\
        '    "params": {\n'\
        '        "redistributeBgp": false\n'\
        '    }\n'\
        '}\n'\
        ',\n'
    out_stream.write(add_ospf)

    add_qos_traffic_map = \
        '{\n'\
        '    "entity":  "agent",\n'\
        '    "message": "add-qos-traffic-map",\n'\
        '    "params": {\n'\
        '        "default": {\n'\
        '            "low": "bestEffortQueue",\n'\
        '            "medium": "standardSelectQueue",\n'\
        '            "high": "primeSelectQueue"\n'\
        '        },\n'\
        '        "real-time": {\n'\
        '            "low": "bestEffortQueue",\n'\
        '            "medium": "standardSelectQueue",\n'\
        '            "high": "realtimeQueue"\n'\
        '        },\n'\
        '        "signaling": {\n'\
        '            "low": "bestEffortQueue",\n'\
        '            "medium": "standardSelectQueue",\n'\
        '            "high": "controlSignalingQueue"\n'\
        '        },\n'\
        '        "telephony": {\n'\
        '            "low": "bestEffortQueue",\n'\
        '            "medium": "standardSelectQueue",\n'\
        '            "high": "realtimeQueue"\n'\
        '        },\n'\
        '        "broadcast-video": {\n'\
        '            "low": "bestEffortQueue",\n'\
        '            "medium": "standardSelectQueue",\n'\
        '            "high": "primeSelectQueue"\n'\
        '        },\n'\
        '        "network-control": {\n'\
        '            "low": "bestEffortQueue",\n'\
        '            "medium": "standardSelectQueue",\n'\
        '            "high": "controlSignalingQueue"\n'\
        '        },\n'\
        '        "oam": {\n'\
        '            "low": "bestEffortQueue",\n'\
        '            "medium": "standardSelectQueue",\n'\
        '            "high": "controlSignalingQueue"\n'\
        '        },\n'\
        '        "high-throughput": {\n'\
        '            "low": "bestEffortQueue",\n'\
        '            "medium": "standardSelectQueue",\n'\
        '            "high": "primeSelectQueue"\n'\
        '        },\n'\
        '        "multimedia-conferencing": {\n'\
        '            "low": "bestEffortQueue",\n'\
        '            "medium": "standardSelectQueue",\n'\
        '            "high": "realtimeQueue"\n'\
        '        },\n'\
        '        "multimedia-streaming": {\n'\
        '            "low": "bestEffortQueue",\n'\
        '            "medium": "standardSelectQueue",\n'\
        '            "high": "primeSelectQueue"\n'\
        '        },\n'\
        '        "low-latency": {\n'\
        '            "low": "bestEffortQueue",\n'\
        '            "medium": "standardSelectQueue",\n'\
        '            "high": "realtimeQueue"\n'\
        '        }\n'\
        '    }\n'\
        '}\n'\
        ',\n'
    out_stream.write(add_qos_traffic_map)

    add_qos_policy = \
        '{\n'\
        '    "entity":  "agent",\n'\
        '    "message": "add-qos-policy",\n'\
        '    "params": {\n'\
        '        "policies": [{\n'\
        '            "name": "Default QoS",\n'\
        '            "interfaces": [\n'\
        '                "__INTERFACE_1__dev_id"\n'\
        '            ],\n'\
        '            "inbound": {\n'\
        '                "policerBandwidthLimitPercent": {\n'\
        '                    "high": 100,\n'\
        '                    "medium": 80,\n'\
        '                    "low": 65\n'\
        '                }\n'\
        '            },\n'\
        '            "outbound": {\n'\
        '                "scheduling": {\n'\
        '                    "realtimeQueue": {\n'\
        '                        "bandwidthLimitPercent": 30,\n'\
        '                        "dscpRewrite": "CS0"\n'\
        '                    },\n'\
        '                    "controlSignalingQueue": {\n'\
        '                        "weight": 40,\n'\
        '                        "dscpRewrite": "CS0"\n'\
        '                    },\n'\
        '                    "primeSelectQueue": {\n'\
        '                        "weight": 30,\n'\
        '                        "dscpRewrite": "CS0"\n'\
        '                    },\n'\
        '                    "standardSelectQueue": {\n'\
        '                        "weight": 20,\n'\
        '                        "dscpRewrite": "CS0"\n'\
        '                    },\n'\
        '                    "bestEffortQueue": {\n'\
        '                        "weight": 10,\n'\
        '                        "dscpRewrite": "CS0"\n'\
        '                    }\n'\
        '                }\n'\
        '            }\n'\
        '        }]\n'\
        '    }\n'\
        '}\n'\
        ',\n'
    out_stream.write(add_qos_policy)

    for i in range(1, num_tunnels+1):
        add_tunnel = \
            '{\n'\
            '    "entity":  "agent",\n'\
            '    "message": "add-tunnel",\n'\
            '    "params": {\n'\
            '        "encryption-mode": "ikev2",\n'\
            '        "dev_id": "__INTERFACE_1__dev_id",\n'\
            f'       "tunnel-id": {i},\n'\
            '        "src": "__INTERFACE_1__addr_no_mask",\n'\
            '        "dst": "20.0.0.4",\n'\
            '        "dstPort": "4789",\n'\
            '        "loopback-iface": {\n'\
            f'            "addr": "10.100.{int((i*2)/256)}.{(i*2)%256}/31",\n'\
            f'            "mac": "02:00:27:fd:{int((i*2)/256):02x}:{((i*2)%256):02x}",\n'\
            '            "mtu": 1500,\n'\
            '            "routing": "ospf",\n'\
            '            "multilink": {\n'\
            '                "labels": [\n'\
            '                    "63a30f80bf4edc10dbbb74c9"\n'\
            '                ]\n'\
            '        },\n'\
            '        "tcp-mss-clamp": 1310,\n'\
            '        "ospf-cost": "100"\n'\
            '    },\n'\
            '    "remoteBandwidthMbps": {\n'\
            '        "tx": 100,\n'\
            '        "rx": 100\n'\
            '    },\n'\
            '    "ikev2": {\n'\
            '        "role": "initiator",\n'\
            '        "remote-device-id": "4C6BE8CA-B14C-4D1C-BB82-A76D32B79065",\n'\
            '        "lifetime": 3600,\n'\
            '        "ike": {\n'\
            '            "crypto-alg": "aes-cbc",\n'\
            '            "integ-alg": "hmac-sha2-256-128",\n'\
            '            "dh-group": "modp-2048",\n'\
            '            "key-size": 256\n'\
            '        },\n'\
            '        "esp": {\n'\
            '            "crypto-alg": "aes-cbc",\n'\
            '            "integ-alg": "hmac-sha2-256-128",\n'\
            '            "dh-group": "ecp-256",\n'\
            '            "key-size": 256\n'\
            '        },\n'\
            f'        "certificate": {certificate}\n'\
            '   }\n'\
            '}\n'\
            '}\n'\
            ',\n'
        out_stream.write(add_tunnel)

    for i in range(1, num_tunnels+1):
        remove_tunnel = \
            '{\n'\
            '    "entity":  "agent",\n'\
            '    "message": "remove-tunnel",\n'\
            '    "params": {\n'\
            f'        "tunnel-id": {i}\n'\
            '        }\n'\
            '}\n'\
            ',\n'
        out_stream.write(remove_tunnel)

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

    parser = argparse.ArgumentParser(
        description='generator of add-tunnel cli for many tunnels')
    parser.add_argument('-n', dest='num_of_tunnels', default=200,
                        help="number of add-tunnel requests in resulted CLI")
    parser.add_argument('-o', '--out', dest='out_filename', nargs='?', const='default',
                        help="name of the output file. The default is 'add-tunnel.200.cli'")
    args = parser.parse_args()

    main(args)
