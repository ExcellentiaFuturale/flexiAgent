#! /usr/bin/python

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

import requests
import fwglobals
import os
from os.path import exists
import subprocess
import tarfile
import json

fwapplications_handlers = {
    'application-install':           {'handler': 'install'},
    'application-uninstall':         {'handler': 'uninstall'},
    'application-configure':         {'handler': 'configure'},
    'application-start':             {'handler': 'start'},
    'application-stop':              {'handler': 'stop'},
    'application-status':            {'handler': 'status'},
    'application-call':              {'handler': 'call'},
}

class FWAPPLICATIONS_API:
    """Services class representation.
    """

    def __init__(self):
        """Constructor method.
        """

    def call(self, request):
        """Invokes API specified by the 'request' parameter.

        :param request: Request name.
        :param params: Parameters from flexiManage.

        :returns: Reply.
        """
        message = request['message']
        params = request['params']

        handler = fwapplications_handlers.get(message)
        assert handler, f'fwapplications_api: "{message}" message is not supported'

        handler_func = getattr(self, handler)
        assert handler_func, 'fwapplications_api: handler=%s not found for req=%s' % (handler, request)

        reply = handler_func(params)
        if reply['ok'] == 0:
            raise Exception("fwagent_api: %s(%s) failed: %s" % (handler_func, format(params), reply['message']))
        return reply

    def _call_application_api(self, identifier, method, params = None):
        cmd = f"python3 {fwglobals.g.APPLICATIONS_DIR + identifier}/application.py"
        cmd += f' {method}'

        if params:
            cmd += f' {json.dumps(params)}'

        # Starting new python process
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE.PIPE)
        stdout, stderr = process.communicate()
        if stderr:
            raise Exception(stderr)
        return stdout


    def install(self, params):
        # identifier: 'com.flexiwan.remotevpn',
        # name: ‘Remote VPN’,
        # installationFilePath: 'https://store.flexiwan.com/com.flexiwan.remotevpn/install.tar.gz',
        # installationPathType: 'url' / 'local'
        # md5: 'sdfgsdfg'

        path_type = params.get('installationPathType')
        identifier = params.get('identifier')
        path = params.get('installationFilePath')

        target_path = fwglobals.g.APPLICATIONS_DIR + identifier + '/'

        if path_type == 'url':
            response = requests.get(path, allow_redirects=True, stream=True)
            if response.status_code == 200:
                with open(target_path, 'wb') as f:
                    f.write(response.raw.read())

        elif (path_type == 'local'):
            if not exists(path):
                raise Exception(f'path {path} is not exists')
            rc = os.system(f'mv {path} {target_path}')
            if rc:
                raise Exception(f'failed to move {path} to the applications directory')

        file = tarfile.open(target_path + 'install.tar.gz')
        file.extractall(target_path)
        file.close()

        self._call_application_api(identifier, 'install')

