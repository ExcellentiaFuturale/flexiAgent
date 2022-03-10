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
# import importlib.util
# import multiprocessing as mp
import os
import pathlib
import threading
import time
import traceback

from sqlitedict import SqliteDict

import fwglobals
import fwutils
from applications.com_flexiwan_remotevpn.application import \
    Application as RemoteVpn
from fwobject import FwObject


class FWAPPLICATIONS_API(FwObject):
    """Services class representation.
    """

    def __init__(self, application_db_file, run_application_stats = False):
        """Constructor method.
        """
        FwObject.__init__(self)

        self.db = SqliteDict(application_db_file, autocommit=True)
        self.thread_stats = None
        self.stats    = {}
        self.app_files = {
            'com.flexiwan.remotevpn': RemoteVpn()
        }
        self.processing_request = False
        if run_application_stats:
            self.thread_stats = threading.Thread(target=self._run_stats_thread, name='Applications Statistics Thread')
            self.thread_stats.start()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.finalize()

    def finalize(self):
        if self.thread_stats:
            self.thread_stats.join()
            self.thread_stats = None

        self.db.close()
        return

    def call(self, request):
        """Invokes API specified by the request received from flexiManage.

        :param request: Request name.
        :param params: Parameters from flexiManage.

        :returns: Reply.
        """
        try:
            message = request['message']
            params = request['params']

            handler = message.split('application-')[-1]

            handler_func = getattr(self, handler)
            assert handler_func, f'fwapplications_api: handler={handler} not found for req={request}'

            self.processing_request = True
            reply = handler_func(request)
            if reply['ok'] == 0:
                raise Exception(f'fwapplications_api: {handler_func}({format(params)}) failed: {reply["message"]}')
            return reply
        finally:
            self.processing_request = False

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

            installation_dir = self._get_installation_dir(identifier)
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
            self._update_applications_db(identifier, 'installed', request)

            return { 'ok': 1 }
        except Exception as e:
            return { 'ok': 0, 'message': str(e) }

    def uninstall(self, request):
        '''
        {
            "entity": "agent",
            "message": "application-uninstall",
            "params": {
                "name": "Remote Worker VPN",
                "identifier": "com.flexiwan.remotevpn"
            }
        }
        '''
        try:
            params = request['params']
            identifier = params.get('identifier')

            success, val = self._call_application_api(identifier, 'uninstall', params)
            if not success:
                return { 'ok': 0, 'message': val }

            # remove application from db
            apps_db = self.db
            app = apps_db.get(identifier)
            if app:
                del apps_db[identifier]
                self.db = apps_db

            # remove application stats
            app_stats = self.stats.get(identifier)
            if app_stats:
                del self.stats[identifier]

            return { 'ok': 1 }
        except Exception as e:
            return { 'ok': 0, 'message': str(e) }

    def configure(self, request):
        '''
        {
            "entity": "agent",
            "message": "application-configure",
            "params": {
                "name": "Remote Worker VPN",
                "identifier": "com.flexiwan.remotevpn",
                "routeAllTrafficOverVpn": true,
                "port": "1194",
                ...
            }
        }
        '''
        try:
            params = request['params']
            identifier = params.get('identifier')
            success, val = self._call_application_api(identifier, 'configure', params)

            if not success:
                return { 'ok': 0, 'message': val }

            # update in database
            installed = self.db[identifier].get('installed')
            installed['params']['configParams'] = params
            self._update_applications_db(identifier, 'installed', installed)

            return { 'ok': 1 }
        except Exception as e:
            return { 'ok': 0, 'message': str(e) }

    def get_stats(self):
        return copy.deepcopy(self.stats)

    def _run_stats_thread(self):
        slept = 0
        while not fwglobals.g.teardown:
            # Every 10 seconds collect the application status and statistics
            #
            try:  # Ensure thread doesn't exit on exception
                timeout = 10
                if (slept % timeout) == 0 and not self.processing_request:
                    apps = dict(self.db.items())
                    for identifier in apps:
                        installed = apps[identifier].get('installed')
                        if not installed:
                            continue

                        self._call_app_watchdog(installed)

                        new_stats = {}
                        new_stats['running'] = self._is_app_running(identifier)
                        new_stats['statistics'] = self._get_app_statistics(identifier)
                        self.stats[identifier] = new_stats
                    slept = 0
            except Exception as e:
                self.log.excep("%s: %s (%s)" %
                    (threading.current_thread().getName(), str(e), traceback.format_exc()))
                pass

            time.sleep(1)
            slept += 1

    def _call_application_api(self, identifier, method, params = {}):
        try:
            app = self.app_files[identifier]

            # get the function
            func = getattr(app, method, None)
            if not func:
                # A function that is not present is a normal state.
                # There are functions that must exist. They are enforced through the use of interface
                return (True, None)

            res = func(params)
            return res
        except Exception as e:
            return (False, str(e))

    def reset(self):
        self.call_hook('uninstall')
        self.db.clear()

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
                self.log.debug(f'call_hook({hook_type}): failed for identifier={app_identifier}: err={str(e)}')
                pass

        return res

    def get_interfaces(self, type, vpp):
        return self.call_hook('get_interfaces', {type: type, vpp: vpp})

    def _get_installation_dir(self, identifier):
        current_dir = str(pathlib.Path(__file__).parent.resolve())
        identifier = identifier.replace('.', '_') # python modules cannot be imported if the path is with dots
        source_installation_dir = current_dir + '/applications/' + identifier
        return source_installation_dir

    def _status(self, request):
        try:
            params = request['params']
            identifier = params.get('identifier')
            success, val = self._call_application_api(identifier, 'get_status')
            if not success:
                return { 'ok': 0, 'message': val }

            return { 'ok': 1, 'message': val }
        except Exception as e:
            return { 'ok': 0, 'message': str(e) }

    def _call_app_watchdog(self, request):
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

    def _is_app_running(self, identifier):
        reply = self._status({'params': { 'identifier': identifier }})
        if reply['ok'] == 0:
            return False
        return reply['message']

    def _get_app_statistics(self, identifier):
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

    def _update_applications_db(self, identifier, key, value):
        apps_db = self.db
        app = apps_db.get(identifier)

        if not app:
            apps_db[identifier] = {}
            app = apps_db[identifier]

        app[key] = value
        apps_db[identifier] = app

        self.db = apps_db

    def is_application_installed(self, identifier):
        for app_identifier in self.db:
            if app_identifier == identifier:
                return True
        return False

    def _get_sync_list(self, requests):
        output_requests = []

        db_keys = self.db.keys()

        # generate incoming applications list in order to save searches bellow
        sync_applications = {}
        for request in requests:
            identifier = request.get('params').get('identifier')
            sync_applications[identifier] = request

        # loop over the existing applications.
        # if the existing application exists in the incoming list:
        #   if the incoming and current params are the same - no need to do anything.
        #   if there is a diff between them - generate uninstall and install application messages
        # if the existing application does not exist in the incoming list:
        #   generate uninstall application message
        #
        for identifier in db_keys:
            install_req = self.db[identifier].get('installed')
            if not install_req:
                continue

            if identifier in sync_applications:
                current_params = install_req.get('params')
                incoming_params = sync_applications[identifier]['params']
                if fwutils.compare_request_params(current_params, incoming_params):
                    # The configuration item has exactly same parameters.
                    # It does not require sync, so remove it from input list.
                    #
                    del sync_applications[identifier]
                else:
                    install_req['message'] = install_req['message'].replace('-install', '-uninstall')
                    output_requests.append(install_req)
            else:
                install_req['message'] = install_req['message'].replace('-install', '-uninstall')
                output_requests.append(install_req)


        output_requests += list(sync_applications.values())
        return output_requests

    def sync(self, requests, full_sync=False):
        requests = list([x for x in requests if x['message'].startswith('application-')])

        sync_list = self._get_sync_list(requests)

        if len(sync_list) == 0:
            self.log.info("sync: sync_list is empty, no need to sync")
            return True

        self.log.debug("sync: start smart sync")

        for sync_request in sync_list:
            self.call(sync_request)

        self.log.debug("sync: smart sync succeeded")

    # def _start(self, request):
    #     try:
    #         params = request['params']
    #         identifier = params.get('identifier')
    #         success, val = self._call_application_api(identifier, 'start')
    #         if not success:
    #             return { 'ok': 0, 'message': val }

    #         self._update_applications_db(identifier, 'started', True)

    #         return { 'ok': 1 }
    #     except Exception as e:
    #         return { 'ok': 0, 'message': str(e) }

# def subproc(q, path, method, params):
#     try:
#         # os.setuid(0) # TODO: change this number
#         # os.chdir('/tmp') # TODO: implement the right dir with permissions

#         # import the module
#         spec = importlib.util.spec_from_file_location("application", path + '/application.py')
#         module = importlib.util.module_from_spec(spec)
#         spec.loader.exec_module(module)

#         instance = getattr(module, 'Application')
#         app = instance()

#         # get the function
#         func = getattr(app, method, None)
#         if not func:
#             # required functions must be implemented using the IApplication interface
#             q.put(True, None)
#             return

#         ret = func(params)
#         q.put(ret)

#         del app
#     except Exception as e:
#         ret = (False, str(e))
#         q.put(ret)
