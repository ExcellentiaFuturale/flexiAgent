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
import threading
import multiprocessing as mp
import time
import traceback
import copy
import fwutils
from fwobject import FwObject

# flexiManage jobs types
fwapplications_handlers = {
    'application-install':           'install',
    'application-uninstall':         'uninstall',
    'application-configure':         'configure',
    'application-status':            'status',
}

# all hooks supported with a flag indicating whether it is a mandatory hook,
# meaning that if it does not exist, an error will be thrown.
fwapplications_hooks = {
    'install':                 True,
    'uninstall':               True,
    'status':                  True,
    'configure':               True,
    'get_log_file':            False,
    'get_monitoring':          False,
    'router_is_started':       False,
    'router_is_being_to_stop': False,
    'router_is_stopped':       False,
    'agent_reset':             False,
    'start':                   False,
}

class FWAPPLICATIONS_API(FwObject):
    """Services class representation.
    """

    def __init__(self):
        """Constructor method.
        """
        FwObject.__init__(self)

        self.applications_db = fwglobals.g.applications_db
        self.thread_apps_statistics    = None
        self.apps_stats    = {}
        self.application_stats()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.finalize()

    def finalize(self):
        if self.thread_apps_statistics:
            self.thread_apps_statistics.join()
            self.thread_apps_statistics = None
        return

    def reset_db(self):
        self.applications_db.clear()

    def get_applications_stats(self):
        return copy.deepcopy(self.apps_stats)

    def application_stats(self):
        def run(*args):
            slept = 0
            while not fwglobals.g.teardown:
                # Every 10 seconds collection the application status and monitoring
                #
                try:  # Ensure thread doesn't exit on exception
                    timeout = 10
                    if (slept % timeout) == 0:
                        apps = dict(self.applications_db.items())
                        for identifier in apps:
                            is_installed = apps[identifier].get('installed')
                            if not is_installed:
                                continue

                            is_app_running = self.is_app_running(identifier)
                            if not is_app_running:
                                self.start(is_installed)

                            new_stats = {}
                            new_stats['running'] = is_app_running
                            new_stats['monitoring'] = self.get_monitoring_info(identifier)
                            self.apps_stats[identifier] = new_stats
                        slept = 0
                except Exception as e:
                    self.log.excep("%s: %s (%s)" %
                        (threading.current_thread().getName(), str(e), traceback.format_exc()))
                    pass

                time.sleep(1)
                slept += 1

        self.thread_apps_statistics = threading.Thread(target=run, name='Applications Statistics Thread')
        self.thread_apps_statistics.start()

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

        reply = handler_func(request)
        if reply['ok'] == 0:
            raise Exception(f'fwapplications_api: {handler_func}({format(params)}) failed: {reply["message"]}')
        return reply

    def _call_application_api(self, identifier, method, params = {}):
        path = fwglobals.g.APPLICATIONS_DIR + identifier

        # check if the given hook is supported and if it required
        required_hook = fwapplications_hooks.get(method)
        if required_hook == None:
            raise Exception(f'_call_application_api: {method} is not defined')

        q = mp.Queue()
        p = mp.Process(target=subproc, args=(q, path, method, params, required_hook))

        p.start()
        result = q.get()
        p.join()
        p.terminate()

        return result

    def call_hook(self, hook_type, params={}, identifier=None):
        for app_identifier in self.applications_db:
            try:
                # skip applications if filter is passed
                if identifier and app_identifier != identifier:
                    continue

                params['identifier'] = app_identifier
                self._call_application_api(app_identifier, hook_type, params)
            except Exception as e:
                self.log.debug(f'call_hook: hook "{hook_type}" failed. identifier={app_identifier}. err={str(e)}')
                pass

        return { 'ok': 1, 'message': '' }

    def install(self, request):
        try:
            params = request['params']
            path_type = params.get('installationPathType')
            identifier = params.get('identifier')
            path = params.get('installationFilePath')

            target_path = fwglobals.g.APPLICATIONS_DIR + identifier + '/'

            # create the application directory if not exists
            os.system(f'mkdir -p {target_path}')

            if path_type == 'url':
                response = requests.get(path, allow_redirects=True, stream=True)
                if response.status_code == 200:
                    with open(target_path, 'wb') as f:
                        f.write(response.raw.read())

            elif (path_type == 'local'):
                path = os.path.abspath(path)
                if not os.path.exists(path):
                    raise Exception(f'path {path} is not exists')

                # move install file to application directory
                rc = os.system(f'cp {path} {target_path}')
                if rc:
                    raise Exception(f'failed to move {path} to the applications directory')

            file = tarfile.open(target_path + 'install.tar.gz')
            file.extractall(target_path)
            file.close()

            extended_params = dict(params)
            extended_params['router_is_running'] = fwglobals.g.router_api.state_is_started()

            success, val = self._call_application_api(identifier, 'install', extended_params)

            if not success:
                return { 'ok': 0, 'message': val }

            # store in database
            self.update_applications_db(identifier, 'installed', request)

            return { 'ok': 1 }
        except Exception as e:
            return { 'ok': 0, 'message': str(e) }

    def uninstall(self, request):
        try:
            params = request['params']
            identifier = params.get('identifier')
            success, val = self._call_application_api(identifier, 'uninstall', params)

            if not success:
                return { 'ok': 0, 'message': val }

            # remove the application directory
            target_path = fwglobals.g.APPLICATIONS_DIR + identifier + '/'
            os.system(f'rm -rf {target_path}')

            # remove application from db
            apps_db = self.applications_db
            app = apps_db.get(identifier)
            if app:
                del apps_db[identifier]
                self.applications_db = apps_db

            # remove application stats
            app_stats = self.apps_stats.get(identifier)
            if app_stats:
                del self.apps_stats[identifier]

            return { 'ok': 1 }
        except Exception as e:
            return { 'ok': 0, 'message': str(e) }

    def status(self, request):
        try:
            params = request['params']
            identifier = params.get('identifier')
            success, val = self._call_application_api(identifier, 'status')
            if not success:
                return { 'ok': 0, 'message': val }

            return { 'ok': 1, 'message': val }
        except Exception as e:
            return { 'ok': 0, 'message': str(e) }

    def configure(self, request):
        try:
            params = request['params']
            identifier = params.get('identifier')
            success, val = self._call_application_api(identifier, 'configure', params)

            if not success:
                return { 'ok': 0, 'message': val }


            return { 'ok': 1 }
        except Exception as e:
            return { 'ok': 0, 'message': str(e) }

    def is_app_running(self, identifier):
        reply = self.status({'params': { 'identifier': identifier }})
        if reply['ok'] == 0:
            return False
        return reply['message']

    def get_monitoring_info(self, identifier):
        try:
            success, val = self._call_application_api(identifier, 'get_monitoring')
            if not success:
                return {}

            return val
        except:
            return {}

    def get_log_file(self, identifier):
        try:
            success, val = self._call_application_api(identifier, 'get_log_file')
            if not success:
                return None

            return val
        except:
            return None

    def update_applications_db(self, identifier, key, value, add=True):
        apps_db = self.applications_db
        app = apps_db.get(identifier)

        if add:
            if not app:
                apps_db[identifier] = {}
                app = apps_db[identifier]

            app[key] = value
            apps_db[identifier] = app
        else:
            if app and key in app:
                del app[key]
                apps_db[identifier] = app

        self.applications_db = apps_db

    def get_application(self, identifier):
        for app_identifier in self.applications_db:
            if app_identifier == identifier:
                return self.applications_db[identifier]
        return None

    def get_sync_list(self, requests):
        output_requests = []

        current_applications = dict(self.applications_db.items())

        # generate incoming applications list in order to save searches bellow
        incoming_applications = {}
        for incoming_application in requests:
            identifier = incoming_application.get('params').get('identifier')
            incoming_applications[identifier] = incoming_application

        # loop over the existing applications.
        # if the existing application exists in the incoming list:
        #   if the incoming and current params are the same - no need to do anything.
        #   if there is a diff between them - generate uninstall and install application messages
        # if the existing application does not exist in the incoming list:
        #   generate uninstall application message
        #
        for identifier in current_applications:
            install_req = current_applications[identifier].get('installed')
            if not install_req:
                continue

            if identifier in incoming_applications:
                current_params = install_req.get('params')
                input_params  = incoming_applications[identifier]['params']
                if fwutils.compare_request_params(current_params, input_params):
                    # The configuration item has exactly same parameters.
                    # It does not require sync, so remove it from input list.
                    #
                    del incoming_applications[identifier]
                else:
                    install_req['message'] = install_req['message'].replace('-install', '-uninstall')
                    output_requests.append(install_req)
            else:
                install_req['message'] = install_req['message'].replace('-install', '-uninstall')
                output_requests.append(install_req)


        output_requests += list(incoming_applications.values())
        return output_requests

    def sync(self, requests, full_sync=False):
        requests = list([x for x in requests if x['message'] in fwapplications_handlers])

        sync_list = self.get_sync_list(requests)

        if len(sync_list) == 0:
            self.log.info("_sync_device: sync_list is empty, no need to sync")
            return True

        self.log.debug("_sync_device: start smart sync")

        for sync_request in sync_list:
            self.call(sync_request)

        self.log.debug("_sync_device: smart sync succeeded")

    def start(self, request):
        try:
            params = request['params']
            identifier = params.get('identifier')
            success, val = self._call_application_api(identifier, 'start')
            if not success:
                return { 'ok': 0, 'message': val }

            self.update_applications_db(identifier, 'started', True)

            return { 'ok': 1 }
        except Exception as e:
            return { 'ok': 0, 'message': str(e) }

    # def stop(self, params):
    #     try:
    #         identifier = params.get('identifier')
    #         success, val = self._call_application_api(identifier, 'stop')
    #         if not success:
    #             return { 'ok': 0, 'message': val }

    #         self.update_applications_db(identifier, 'started', False)
    #         return { 'ok': 1 }
    #     except Exception as e:
    #         return { 'ok': 0, 'message': str(e) }

def subproc(q, path, method, params, validate_func_exists):
    try:
        # os.setuid(0) # TODO: change this number
        # os.chdir('/tmp') # TODO: implement the right dir with permissions

        # import the module
        spec = importlib.util.spec_from_file_location("application", path + '/application.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # get the function
        if validate_func_exists:
            func = getattr(module, method)
        else:
            func = getattr(module, method, None)
            if not func:
                ret = (False, f'The function {method} does not exist')
                q.put(ret)
                return

        ret = func(params)
        q.put(ret)
    except Exception as e:
        ret = (False, str(e))
        q.put(ret)
