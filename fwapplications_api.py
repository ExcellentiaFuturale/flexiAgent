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

import fwglobals
import fwthread
from fwapplications_cfg import FwApplicationsCfg
from fwcfg_request_handler import FwCfgRequestHandler

fwapplication_translators = {
    'add-app-install':        {'module': __import__('fwtranslate_add_app_install'),   'api':'add_app_install'},
    'remove-app-install':     {'module': __import__('fwtranslate_revert') ,           'api':'revert'},
    'add-app-config':         {'module': __import__('fwtranslate_add_app_config'),    'api':'add_app_config'},
    'remove-app-config':      {'module': __import__('fwtranslate_revert'),            'api':'revert'},
}

class FWAPPLICATIONS_API(FwCfgRequestHandler):
    """Services class representation.
    """

    def __init__(self,start_application_stats = False):
        """Constructor method.
        """
        # FWAPPLICATIONS_API can be called without globals initialization.
        if not hasattr(fwglobals, 'g'):
            fwglobals.initialize()

        cfg = FwApplicationsCfg()
        FwCfgRequestHandler.__init__(self, fwapplication_translators, cfg)

        self.application_thread = None
        self.processing_request = False

        self.stats    = {}
        self.stats_threshold = 10
        self.stats_counter   = 0

        self.app_instances = {}

        self._build_app_instances()

        if start_application_stats:
            self.start_applications_thread()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.finalize()

    def initialize(self):
        self.start_applications_thread()

    def finalize(self):
        self.stop_applications_thread()
        self.app_instances = {}
        return

    def start_applications_thread(self):
        if not self.application_thread:
            self.application_thread = fwthread.FwThread(target=self.applications_thread_func, name='Applications', log=self.log)
            self.application_thread.start()

    def stop_applications_thread(self):
        if self.application_thread:
            self.application_thread.stop()
            self.application_thread = None

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

    def _call_simple(self, request, execute=True, filter=None):
        try:
            self.processing_request = True
            FwCfgRequestHandler._call_simple(self, request, execute=execute, filter=filter)
            return {'ok':1}
        except Exception as e:
            err_str = f"FWAPPLICATIONS_API::_call_simple: {str(e)}"
            self.log.error(err_str)
            raise e
        finally:
            self.processing_request = False

    def install(self, params):
        '''
        {
            "params": {
                "name": "Remote Worker VPN",
                "identifier": "com.flexiwan.remotevpn",
                "applicationParams": {
                    "configParams": { ... }
                }
            }
        }
        '''
        identifier = params.get('identifier')

        installation_dir = self._get_installation_dir(identifier)
        if not os.path.exists(installation_dir):
            raise Exception(f'install file ({installation_dir}) is not exists')

        application_params = {'params': params.get('applicationParams')}
        self._call_application_api(identifier, 'install', application_params)

    def uninstall(self, params):
        '''
        {
            "params": {
                "name": "Remote Worker VPN",
                "identifier": "com.flexiwan.remotevpn",
                "applicationParams": {}
            }
        }
        '''
        identifier = params.get('identifier')

        application_params = params.get('applicationParams')
        self._call_application_api(identifier, 'uninstall', application_params)

        # remove application stats
        app_stats = self.stats.get(identifier)
        if app_stats:
            del self.stats[identifier]

    def configure(self, params):
        '''
        {
            "params": {
                "name": "Remote Worker VPN",
                "identifier": "com.flexiwan.remotevpn",
                "routeAllTrafficOverVpn": true,
                "port": "1194",
                ...
            }
        }
        '''
        identifier = params.get('identifier')

        application_params = {'params': params.get('applicationParams')}
        self._call_application_api(identifier, 'configure', application_params)

    def get_stats(self):
        return copy.deepcopy(self.stats)

    def applications_thread_func(self, ticks):
        if fwglobals.g.router_api.state_is_starting_stopping():
            return

        if (self.stats_counter % self.stats_threshold) == 0 and not self.processing_request:
            apps = self.cfg_db.get_applications()
            for app in apps:
                identifier = app['identifier']
                self._call_application_api(identifier, 'on_watchdog')

                new_stats = {}
                new_stats['running']    = self._call_application_api_safe(identifier, 'is_app_running', default_ret=False)
                new_stats['statistics'] = self._call_application_api_safe(identifier, 'get_statistics', default_ret={})
                self.stats[identifier]  = new_stats

            if not apps and self.stats:
                self.stats = {}

        self.stats_counter += 1


    def _call_application_api(self, identifier, method, params=None):
        if not identifier:
            raise Exception("identifier is required")

        app = self.app_instances[identifier]
        func = getattr(app, method, None)
        if not func:
            return True
        ret = func(**params) if params else func()
        return ret

    def _call_application_api_safe(self, identifier, method, params=None, default_ret=None):
        try:
            ret = self._call_application_api(identifier, method, params=params)
            return ret
        except Exception as e:
            self.log.error(f'_call_application_api_safe({identifier}, {method}, {str(params)}): {str(e)}')
            return default_ret

    def reset(self):
        self.call_hook('uninstall')
        self.cfg_db.clean()

    def call_hook(self, hook_name, params=None, identifier=None):
        res = {}
        apps = self.cfg_db.get_applications()
        for app in apps:
            app_identifier = app['identifier']

            if identifier and identifier != app_identifier:
                continue

            try:
                ret = self._call_application_api(app_identifier, hook_name, params)
                if ret:
                    res[app_identifier] = ret
            except Exception as e:
                self.log.debug(f'call_hook({hook_name}, {identifier}): failed for identifier={app_identifier}: err={str(e)}')

        return res

    def get_interfaces(self, **params):
        return self.call_hook('get_interfaces', params)

    def _get_installation_dir(self, identifier):
        current_dir = str(pathlib.Path(__file__).parent.resolve())
        identifier = identifier.replace('.', '_') # python modules cannot be imported if the path is with dots
        source_installation_dir = current_dir + '/applications/' + identifier
        return source_installation_dir

    def get_log_filename(self, identifier):
        return self._call_application_api_safe(identifier, 'get_log_filename')

def call_applications_hook(hook, identifier=None):
    '''This function calls a function within applications_api even if the agent object is not initialized
    '''
    # when calling this function from fwdump, there is no "g" in fwglobals
    if hasattr(fwglobals, 'g') and hasattr(fwglobals.g, 'applications_api'):
        return fwglobals.g.applications_api.call_hook(hook, identifier=identifier)

    with FWAPPLICATIONS_API() as applications_api:
        return applications_api.call_hook(hook, identifier=identifier)
