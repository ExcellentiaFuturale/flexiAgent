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
import threading
import time
import traceback

import fwglobals
import fwutils
from fwapplications_cfg import FwApplicationsCfg
from fwcfg_request_handler import FwCfgRequestHandler

fwapplication_translators = {
    'add-app-install':        {'module': __import__('fwtranslate_add_application_install'),   'api':'add_app_install'},
    'remove-app-install':     {'module': __import__('fwtranslate_revert') ,                   'api':'revert'},
    'add-app-config':         {'module': __import__('fwtranslate_add_application_config'),    'api':'add_app_config'},
    'remove-app-config':      {'module': __import__('fwtranslate_revert'),                    'api':'revert'},
}

class FWAPPLICATIONS_API(FwCfgRequestHandler):
    """Services class representation.
    """

    def __init__(self,start_application_stats = False):
        """Constructor method.
        """
        cfg = FwApplicationsCfg(fwglobals.g.APPLICATIONS_CFG_FILE)
        FwCfgRequestHandler.__init__(self, fwapplication_translators, cfg)

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
        try:
            self.processing_request = True
            FwCfgRequestHandler._call_simple(self, request)
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

        # before the installation make sure that tap related modules are enabled
        # Many applications may use them.
        fwutils.load_linux_tap_modules()
        fwutils.load_linux_tc_modules()

        application_params = {'params': params.get('applicationParams')}
        success, val = self._call_application_api(identifier, 'install', application_params)
        if not success:
            return { 'ok': 0, 'message': val }

        return { 'ok': 1 }

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
        success, val = self._call_application_api(identifier, 'uninstall', application_params)
        if not success:
            return { 'ok': 0, 'message': val }

        # remove application stats
        app_stats = self.stats.get(identifier)
        if app_stats:
            del self.stats[identifier]

        return { 'ok': 1 }

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
        success, val = self._call_application_api(identifier, 'configure', application_params)

        if not success:
            return { 'ok': 0, 'message': val }

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
                    apps = self.cfg_db.get_applications()
                    for app in apps:
                        identifier = app['identifier']
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
        self.cfg_db.clean()

    def call_hook(self, hook_name, params=None, identifier=None):
        res = {}
        apps = self.cfg_db.get_applications()
        for app in apps:
            try:
                identifier = app['identifier']
                success, val = self._call_application_api(identifier, hook_name, params)
                if success:
                    res[identifier] = val
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

def call_applications_hook(hook):
    '''This function calls a function within applications_api even if the agnet object is not initialzied
    '''
    # when calling this function from fwdump, there is no "g" in fwglobals
    if hasattr(fwglobals, 'g') and hasattr(fwglobals.g, 'applications_api'):
        return fwglobals.g.applications_api.call_hook(hook)

    with FWAPPLICATIONS_API() as applications_api:
        return applications_api.call_hook(hook)
