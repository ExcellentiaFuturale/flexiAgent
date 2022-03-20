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
import glob
import importlib
import os
import pathlib
import re
import threading
import time
import traceback

from sqlitedict import SqliteDict

import fwglobals
import fwutils
from fwcfg_request_handler import FwCfgRequestHandler


class FWAPPLICATIONS_API(FwCfgRequestHandler):
    """Services class representation.
    """

    def __init__(self, start_application_stats = False):
        """Constructor method.
        """
        FwCfgRequestHandler.__init__(self, {}, None)

        self.db = SqliteDict(fwglobals.g.APPLICATIONS_DB_FILE, autocommit=True)
        self.thread_stats = None
        self.processing_request = False

        self.stats    = {}
        self.app_instances = {}

        self._build_app_instances()

        if start_application_stats:
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

        self.app_instances = {}
        self.db.close()
        return

    def _build_app_instances(self):
        current_dir = str(pathlib.Path(__file__).parent.resolve())
        installed_apps = glob.glob(f'{current_dir}/applications/com_flexiwan_*')

        for installed_app in installed_apps:
            module_name = installed_app.split('/')[-1]
            spec = importlib.util.spec_from_file_location(module_name, installed_app + '/application.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            instance = getattr(module, 'Application')
            app = instance()

            self.app_instances[app.identifier] = app

    def _call_simple(self, request):
        """Invokes API specified by the request received from flexiManage.

        :param request: The request received from flexiManage.

        :returns: dictionary with status code and optional error message.
        """
        try:
            message = request['message']
            params = request['params']

            handler = message.split('application-')[-1]

            handler_func = getattr(self, handler)
            assert handler_func, f'handler={handler} not found for req={request}'

            self.processing_request = True
            reply = handler_func(request)
            if reply['ok'] == 0:
                raise Exception(f'{handler_func}({format(params)}) failed: {reply["message"]}')
            return reply
        except Exception as e:
            self.log.error(f"_call_simple({request}): {str(e)}")
            raise e
        finally:
            self.processing_request = False

    def _get_request_key(self, request):
        request_message = request['message']
        identifier = request['params']['identifier']
        if re.search('-uninstall', request_message):
            request_message = request_message.replace('-uninstall', '-install')
        return f'{identifier}_{request_message}'

    def _save_request_in_db(self, identifier, request):
        req_key = self._get_request_key(request)
        self._update_applications_db(identifier, req_key, request)

    def _get_exists_request(self, identifier, request_message):
        if not identifier in self.db:
            return None

        dummy_req = {'message': request_message, 'params': {'identifier': identifier}}
        req_key = self._get_request_key(dummy_req)
        if not req_key in self.db[identifier]:
            return None

        return dict(self.db[identifier][req_key])

    def _is_app_installed(self, identifier):
        install_req = self._get_exists_request(identifier, 'application-install')
        if not install_req:
            return False
        return True

    def install(self, request):
        '''
        {
            "entity": "agent",
            "message": "application-install",
            "params": {
                "name": "Remote Worker VPN",
                "identifier": "com.flexiwan.remotevpn",
                "applicationParams": {
                    "configParams": { ... }
                }
            }
        }
        '''
        params = request['params']
        identifier = params.get('identifier')

        installation_dir = self._get_installation_dir(identifier)
        if not os.path.exists(installation_dir):
            raise Exception(f'install file ({installation_dir}) is not exists')

        # before the installation make sure that tap related modules are enabled
        # Many applications may use them.
        fwutils.load_linux_tap_modules()
        fwutils.load_linux_tc_modules()

        application_params = {'params': params.get('applicationParams')}
        success, val = self._call_application_api(identifier, 'install', application_params)
        if not success:
            return { 'ok': 0, 'message': val }

        # store in database
        self._save_request_in_db(identifier, request)

        return { 'ok': 1 }

    def uninstall(self, request):
        '''
        {
            "entity": "agent",
            "message": "application-uninstall",
            "params": {
                "name": "Remote Worker VPN",
                "identifier": "com.flexiwan.remotevpn",
                "applicationParams": {}
            }
        }
        '''
        params = request['params']
        identifier = params.get('identifier')

        application_params = params.get('applicationParams')
        success, val = self._call_application_api(identifier, 'uninstall', application_params)
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
        params = request['params']
        identifier = params.get('identifier')

        if not self._is_app_installed(identifier):
            raise Exception(f'application {identifier} is not installed')

        application_params = {'params': params.get('applicationParams')}
        success, val = self._call_application_api(identifier, 'configure', application_params)

        if not success:
            return { 'ok': 0, 'message': val }

        # update in database
        self._save_request_in_db(identifier, request)

        return { 'ok': 1 }

    def get_stats(self):
        return copy.deepcopy(self.stats)

    def _run_stats_thread(self):
        timeout = 10
        slept = 0
        while not fwglobals.g.teardown:
            # Every 10 seconds collect the application status and statistics
            #
            try:  # Ensure thread doesn't exit on exception
                if (slept % timeout) == 0 and not self.processing_request:
                    apps = dict(self.db.items())
                    for identifier in apps:
                        self._call_application_api(identifier, 'on_watchdog')

                        new_stats = {}
                        new_stats['running'] = self._is_app_running(identifier)
                        new_stats['statistics'] = self._get_app_statistics(identifier)
                        self.stats[identifier] = new_stats

                    if not apps and self.stats:
                        self.stats = {}

                    slept = 0
            except Exception as e:
                self.log.excep("%s: %s (%s)" %
                    (threading.current_thread().getName(), str(e), traceback.format_exc()))
                pass

            time.sleep(1)
            slept += 1

    def _call_application_api_parse_result(self, ret):
        val = None
        if ret is None:
            ok  = True
        elif type(ret) == tuple:
            ok  = True if ret[0] else False
            val = ret[1]
        elif type(ret) == dict or type(ret) == list or type(ret) == str or type(ret) == bool:
            ok  = True
            val = ret
        else:
            ok = False
            val = '_call_application_api_parse_result: unsupported type of return: %s' % type(ret)
        return (ok, val)

    def _call_application_api(self, identifier, method, params=None):
        try:
            app = self.app_instances[identifier]
            func = getattr(app, method, None)
            if not func:
                return (True, None)
            ret = func(**params) if params else func()
            ret = self._call_application_api_parse_result(ret)
            return ret
        except Exception as e:
            self.log.error(f'_call_application_api({identifier}, {method}, {str(params)}): {str(e)}')
            return (False, str(e))

    def reset(self):
        self.call_hook('uninstall')
        self.db.clear()

    def call_hook(self, hook_name, params=None, identifier=None):
        res = {}
        identifiers = [identifier] if identifier else list(self.db.keys())
        for app_identifier in identifiers:
            try:
                success, val = self._call_application_api(app_identifier, hook_name, params)
                if success:
                    res[app_identifier] = val
            except Exception as e:
                self.log.debug(f'call_hook({hook_name}): failed for identifier={app_identifier}: err={str(e)}')
                pass

        return res

    def get_interfaces(self, **params):
        return self.call_hook('get_interfaces', params)

    def _get_installation_dir(self, identifier):
        current_dir = str(pathlib.Path(__file__).parent.resolve())
        identifier = identifier.replace('.', '_') # python modules cannot be imported if the path is with dots
        source_installation_dir = current_dir + '/applications/' + identifier
        return source_installation_dir

    def _is_app_running(self, identifier):
        success, val = self._call_application_api(identifier, 'is_app_running')
        if success:
            return val
        return False

    def _get_app_statistics(self, identifier):
        success, val = self._call_application_api(identifier, 'get_statistics')
        if success:
            return val
        return {}

    def get_log_filename(self, identifier):
        if not identifier:
            return None
        success, val = self._call_application_api(identifier, 'get_log_filename')
        if success:
            return val
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

    def sync(self, incoming_requests, full_sync=False):
        incoming_requests = list([x for x in incoming_requests if x['message'].startswith('application-')])
        sync_list = self._get_sync_list(incoming_requests)
        return self.sync_delta(sync_list, full_sync, incoming_requests)

    def _get_sync_list(self, requests):
        # Firstly we hack a little bit the input list as follows:
        # build dictionary out of this list where values are list elements
        # (requests) and keys are request keys that local database would use
        # to store these requests. Accidentally these are exactly same keys
        # dumped by our database below ;)
        #
        input_requests = {}
        for request in requests:
            key = self._get_request_key(request)
            input_requests.update({key:request})


        # Now build exactly the same structure (keys and values) of sync_applications but this time
        # from the data stored in our database
        dumped_requests = {}
        for identifier in self.db:
            dumped_requests.update(dict(self.db[identifier]))


        output_requests = []

        # loop over the existing applications.
        # if the existing application exists in the incoming list:
        #   if the incoming and current params are the same - no need to do anything.
        #   if there is a diff between them - generate uninstall and install application messages
        # if the existing application does not exist in the incoming list:
        #   generate application-uninstall message
        #
        for key, req in dumped_requests.items():
            # if application-install appears in our DB but not in the incoming list - generate application-uninstall
            if not key in input_requests:
                if req['message'] == 'application-install': # fix for application-configure is to reset the db - "fwagent reset -s"
                    req['message'] = 'application-uninstall'
                    output_requests.append(req)
                continue

            # same key exists in both lists - check if params are the same
            existing_params = req.get('params')
            incoming_params  = input_requests[key].get('params')
            if fwutils.compare_request_params(existing_params, incoming_params):
                # The configuration item has exactly same parameters.
                # It does not require sync, so remove it from input list.
                #
                del input_requests[key]
            elif req['message'] == 'application-install':
                # The application-install message params are different
                # We generate uninstall before the incoming install to cleanup the machine.
                #
                req['message'] = req['message'].replace('-install', '-uninstall')
                output_requests.append(req)

        # At this point the input list includes 'add-X' requests that stand
        # for new or for modified configuration items.
        # Just go and add them to the output list 'as-is'.
        #
        output_requests += list(input_requests.values())

        return output_requests

    def get_request_params(self, request):
        message = request['message']

        params = request['params']
        identifier = params.get('identifier')

        if not identifier in self.db:
            return None

        if not message in self.db[identifier]:
            return None

        return self.db[identifier][message].get('params')

def call_applications_hook(hook):
    '''This function calls a function within applications_api even if the agnet object is not initialzied
    '''
    if hasattr(fwglobals.g, 'applications_api'):
        return fwglobals.g.applications_api.call_hook(hook)

    with FWAPPLICATIONS_API() as applications_api:
        return applications_api.call_hook(hook)
