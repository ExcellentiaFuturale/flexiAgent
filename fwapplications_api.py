#! /usr/bin/python

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

import copy
import importlib.util
import multiprocessing as mp
import os
import pathlib
import threading
import time
import traceback

from sqlitedict import SqliteDict

import fwglobals
import fwutils
from fwobject import FwObject

class FWAPPLICATIONS_API(FwObject):
    """Services class representation.
    """

    def __init__(self, application_db_file, run_application_stats = False):
        """Constructor method.
        """
        FwObject.__init__(self)

        self.db = SqliteDict(application_db_file, autocommit=True)
        self.thread_apps_statistics = None
        self.apps_stats    = {}
        self.processing_job = False
        if run_application_stats:
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

        self.db.close()
        return

    def reset_db(self):
        self.db.clear()

    def get_applications_stats(self):
        return copy.deepcopy(self.apps_stats)

    def application_stats(self):
        def run(*args):
            slept = 0
            while not fwglobals.g.teardown:
                # Every 10 seconds collect the application status and statistics
                #
                try:  # Ensure thread doesn't exit on exception
                    timeout = 10
                    if (slept % timeout) == 0 and not self.processing_job:
                        apps = dict(self.db.items())
                        for identifier in apps:
                            is_installed = apps[identifier].get('installed')
                            if not is_installed:
                                continue

                            self.call_app_watchdog(is_installed)

                            new_stats = {}
                            new_stats['running'] = self.is_app_running(identifier)
                            new_stats['statistics'] = self.get_app_statistics(identifier)
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

        handler = message.split('application-')[-1]

        handler_func = getattr(self, handler)
        assert handler_func, f'fwapplications_api: handler={handler} not found for req={request}'

        self.processing_job = True
        reply = handler_func(request)
        self.processing_job = False
        if reply['ok'] == 0:
            raise Exception(f'fwapplications_api: {handler_func}({format(params)}) failed: {reply["message"]}')
        return reply

    def _call_application_api(self, identifier, method, params = {}):
        path = self.get_installation_dir(identifier)

        q = mp.Queue()
        p = mp.Process(target=subproc, args=(q, path, method, params))

        p.start()
        result = q.get()
        p.join()
        p.terminate()

        return result

    def reset(self):
      self.call_hook('uninstall')
      self.reset_db()

    def call_hook(self, hook_type, params={}, identifier=None):
        res = {}
        for app_identifier in self.db:
            try:
                # skip applications if filter is passed
                if identifier and app_identifier != identifier:
                    continue

                params['identifier'] = app_identifier
                success, val = self._call_application_api(app_identifier, hook_type, params)
                if success:
                    res[app_identifier] = val
            except Exception as e:
                self.log.debug(f'call_hook: hook "{hook_type}" failed. identifier={app_identifier}. err={str(e)}')
                pass

        return res

    def get_installation_dir(self, identifier):
        current_dir = str(pathlib.Path(__file__).parent.resolve())
        source_installation_dir = current_dir + '/applications/' + identifier
        return source_installation_dir

    def install(self, request):
        '''
        {
            "entity": "agent",
            "message": "application-install",
            "params": {
                "name": "Remote Worker VPN",
                "identifier": "com.flexiwan.remotevpn",
                "configParams": { ... }
            }
        }
        '''
        try:
            params = request['params']
            identifier = params.get('identifier')

            installation_dir = self.get_installation_dir(identifier)
            if not os.path.exists(installation_dir):
                raise Exception(f'install file ({installation_dir}) is not exists')

            # before the installation make sure that tap related modules are enabled
            # Many applications may use them.
            fwutils.load_linux_tap_modules()
            fwutils.load_linux_tc_modules()

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

            apps_db = self.db
            app = apps_db.get(identifier)
            if not app:
                return { 'ok': 1, 'message': '' }

            success, val = self._call_application_api(identifier, 'uninstall', params)
            if not success:
                return { 'ok': 0, 'message': val }

            # remove application from db
            del apps_db[identifier]
            self.db = apps_db

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
            success, val = self._call_application_api(identifier, 'get_status')
            if not success:
                return { 'ok': 0, 'message': val }

            return { 'ok': 1, 'message': val }
        except Exception as e:
            return { 'ok': 0, 'message': str(e) }

    def call_app_watchdog(self, request):
        try:
            params = request['params']
            identifier = params.get('identifier')

            params['router_is_running'] = fwglobals.g.router_api.state_is_started()

            success, val = self._call_application_api(identifier, 'on_apps_watchdog', params)
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

    def get_app_statistics(self, identifier):
        try:
            success, val = self._call_application_api(identifier, 'get_statistics')
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
        apps_db = self.db
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

        self.db = apps_db

    def get_application(self, identifier):
        for app_identifier in self.db:
            if app_identifier == identifier:
                return self.db[identifier]
        return None

    def get_sync_list(self, requests):
        output_requests = []

        current_applications = dict(self.db.items())

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
        requests = list([x for x in requests if x['message'].startswith('application-')])

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

def subproc(q, path, method, params):
    try:
        # os.setuid(0) # TODO: change this number
        # os.chdir('/tmp') # TODO: implement the right dir with permissions

        # import the module
        spec = importlib.util.spec_from_file_location("application", path + '/application.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        instance = getattr(module, 'Application')
        app = instance()

        # get the function
        func = getattr(app, method, None)
        if not func:
            # required functions must be implemented using the IApplication interface
            q.put(True, None)
            return

        ret = func(params)
        q.put(ret)
    except Exception as e:
        ret = (False, str(e))
        q.put(ret)
