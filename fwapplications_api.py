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

import importlib.util
import requests
import fwglobals
import os
import tarfile
from sqlitedict import SqliteDict

import multiprocessing as mp

# set it to "spawn" to reduce as much as possible the resources pass to the child process
mp.set_start_method('spawn', force=True)

fwapplications_handlers = {
    'application-install':           'install',
    'application-uninstall':         'uninstall',
    'application-configure':         'configure',
    'application-start':             'start',
    'application-stop':              'stop',
    'application-status':            'status',
    'application-call':              'call',
}

class FWAPPLICATIONS_API:
    """Services class representation.
    """

    def __init__(self):
        """Constructor method.
        """
        self.applications_db = SqliteDict(fwglobals.g.APPLICATIONS_DB, autocommit=True)

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
        assert handler_func, f'fwapplications_api: handler={handler} not found for req={request}'

        reply = handler_func(params)
        if reply['ok'] == 0:
            raise Exception(f'fwagent_api: {handler_func}({format(params)}) failed: {reply["message"]}')
        return reply

    def _call_application_api(self, identifier, method, params = {}):
        try: 
            path = fwglobals.g.APPLICATIONS_DIR + identifier
            
            q = mp.Queue()
            p = mp.Process(target=subproc, args=(q, path, method, params))

            p.start()
            result = q.get()
            p.join()

            return result
        except Exception as e:
            return (False, str(e))

    def start(self, params):
        try:
            identifier = params.get('identifier')
            success, val = self._call_application_api(identifier, 'start')
            if not success:
                return { 'ok': 0, 'message': val }

            self.update_applications_db(identifier, 'started', True)

            return { 'ok': 1 }
        except Exception as e:
            return { 'ok': 0, 'message': str(e) }

    def stop(self, params):
        try:
            identifier = params.get('identifier')
            success, val = self._call_application_api(identifier, 'stop')
            if not success:
                return { 'ok': 0, 'message': val }

            self.update_applications_db(identifier, 'started', False)
            return { 'ok': 1 }
        except Exception as e:
            return { 'ok': 0, 'message': str(e) }

    def uninstall(self, params):
        try:
            identifier = params.get('identifier')
            success, val = self._call_application_api(identifier, 'uninstall', params)

            if not success:
                return { 'ok': 0, 'message': val }

            self.update_applications_db(identifier, 'configured', False)
            self.update_applications_db(identifier, 'configuration', None)
            self.update_applications_db(identifier, 'installed', False)
            self.update_applications_db(identifier, 'installationConfig', None)
            return { 'ok': 1 }
        except Exception as e:
            return { 'ok': 0, 'message': str(e) }

    def configure(self, params):
        try:
            identifier = params.get('identifier')
            success, val = self._call_application_api(identifier, 'configure', params)

            if not success:
                return { 'ok': 0, 'message': val }

            self.update_applications_db(identifier, 'configured', True)
            self.update_applications_db(identifier, 'configuration', params)

            if fwglobals.g.router_api.state_is_started():
                reply = self.start(params)
                if reply['ok'] == 0:
                    return reply

            return { 'ok': 1 }
        except Exception as e:
            self.update_applications_db(identifier, 'configured', False)
            return { 'ok': 0, 'message': str(e) }

    def install(self, params):
        # identifier: 'com.flexiwan.remotevpn',
        # name: ‘Remote VPN’,
        # installationFilePath: 'https://store.flexiwan.com/com.flexiwan.remotevpn/install.tar.gz',
        # installationPathType: 'url' / 'local'
        # md5: 'sdfgsdfg'
        try:
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
                path = os.path.abspath(path)
                if not os.path.exists(path):
                    raise Exception(f'path {path} is not exists')
                
                # create the application directory
                os.system(f'mkdir -p {target_path}')

                # move install file to application directory
                rc = os.system(f'cp {path} {target_path}')
                if rc:
                    raise Exception(f'failed to move {path} to the applications directory')

            file = tarfile.open(target_path + 'install.tar.gz')
            file.extractall(target_path)
            file.close()

            success, val = self._call_application_api(identifier, 'install')

            if not success:
                return { 'ok': 0, 'message': val }

            # store in database
            self.update_applications_db(identifier, 'installed', True)
            self.update_applications_db(identifier, 'installationConfig', params)
            
            configParams = params.get('configParams')
            if configParams:
                reply = self.configure(configParams)
                if reply['ok'] == 0:
                    return reply

            if fwglobals.g.router_api.state_is_started():
                reply = self.start(params)
                if reply['ok'] == 0:
                    return reply

            return { 'ok': 1 }
        except Exception as e: 
            return { 'ok': 0, 'message': str(e) }

    def update_applications_db(self, identifier, key, value):
        apps_db = self.applications_db
        app = apps_db.get(identifier)
        if not app:
            apps_db[identifier] = {}
            app = apps_db[identifier]

        app[key] = value
        apps_db[identifier] = app
        self.applications_db = apps_db

    def start_applications(self):
        for identifier in self.applications_db:
            app = self.applications_db[identifier]
            is_installed = app.get('installed')
            is_configured = app.get('configured')
            if is_installed and is_configured:
                self.start({'identifier': identifier})
        
    def stop_applications(self):
        for identifier in self.applications_db:
            app = self.applications_db[identifier]
            is_installed = app.get('installed')
            is_configured = app.get('configured')
            if is_installed and is_configured:
                self.stop({'identifier': identifier})

def subproc(q, path, func, params):
    try:
        # os.setuid(0) # TODO: change this number
        # os.chdir('/tmp') # TODO: implement the right dir with permissions

        # import the module
        spec = importlib.util.spec_from_file_location("application", path + '/application.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # get the function
        func = getattr(module, func)

        ret = func(params)
        q.put(ret)
    except Exception as e:
        ret = (False, str(e))
        q.put(ret)
        