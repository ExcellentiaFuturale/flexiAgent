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

import os
import re
import time
import threading
import traceback
import yaml
import json
import subprocess

import fwagent
import fwglobals
import fwutils
import fwnetplan

from fwapplications import FwApps
from fwmultilink import FwMultilink
from vpp_api import VPP_API

import fwtunnel_stats

import fwtranslate_add_tunnel
import fwtranslate_add_interface

fwrouter_modules = {
    'fwtranslate_revert':          __import__('fwtranslate_revert') ,
    'fwtranslate_start_router':    __import__('fwtranslate_start_router'),
    'fwtranslate_add_interface':   __import__('fwtranslate_add_interface'),
    'fwtranslate_add_route':       __import__('fwtranslate_add_route'),
    'fwtranslate_add_tunnel':      __import__('fwtranslate_add_tunnel'),
    'fwtranslate_add_dhcp_config': __import__('fwtranslate_add_dhcp_config'),
    'fwtranslate_add_app':         __import__('fwtranslate_add_app'),
    'fwtranslate_add_policy':      __import__('fwtranslate_add_policy')
}

fwrouter_translators = {
    'start-router':               {'module':'fwtranslate_start_router',    'api':'start_router',      'key_func':'get_request_key'},
    'stop-router':                {'module':'fwtranslate_revert',          'api':'revert',            'src':'start-router'},
    'add-interface':              {'module':'fwtranslate_add_interface',   'api':'add_interface',     'key_func':'get_request_key'},
    'remove-interface':           {'module':'fwtranslate_revert',          'api':'revert',            'src':'add-interface'},
    'add-route':                  {'module':'fwtranslate_add_route',       'api':'add_route',         'key_func':'get_request_key'},
    'remove-route':               {'module':'fwtranslate_revert',          'api':'revert',            'src':'add-route'},
    'add-tunnel':                 {'module':'fwtranslate_add_tunnel',      'api':'add_tunnel',        'key_func':'get_request_key'},
    'remove-tunnel':              {'module':'fwtranslate_revert',          'api':'revert',            'src':'add-tunnel'},
    'add-dhcp-config':            {'module':'fwtranslate_add_dhcp_config', 'api':'add_dhcp_config',   'key_func':'get_request_key'},
    'remove-dhcp-config':         {'module':'fwtranslate_revert',          'api':'revert',            'src': 'add-dhcp-config'},
    'add-application':            {'module':'fwtranslate_add_app',         'api':'add_app',           'key_func':'get_request_key'},
    'remove-application':         {'module':'fwtranslate_revert',          'api': 'revert',           'src': 'add-application'},
    'add-multilink-policy':      {'module':'fwtranslate_add_policy',      'api': 'add_policy',       'key_func':'get_request_key'},
    'remove-multilink-policy':   {'module':'fwtranslate_revert',          'api': 'revert',           'src': 'add-multilink-policy'},
}

class FWROUTER_API:
    """This is Router API class representation.
    The Router API class provides control over vpp.
    That includes:
    - start and stop vpp functionality
    - wrappers for vpp configuration APIs
    - collecting statistics about vpp activity
    - monitoring vpp and restart it on exceptions
    - restoring vpp configuration on vpp restart or on device reboot

    :param multilink_db_file: name of file that stores persistent multilink data
    """
    def __init__(self, multilink_db_file):
        """Constructor method
        """
        self.vpp_api         = VPP_API()
        self.multilink       = FwMultilink(multilink_db_file)
        self.router_started  = False
        self.router_failure  = False
        self.thread_watchdog = None
        self.thread_tunnel_stats = None
        self.thread_dhcpc = None

    def finalize(self):
        """Destructor method
        """
        self.vpp_api.finalize()
        self.router_started = False
        self._stop_threads()

    def watchdog(self):
        """Watchdog thread.
        Its function is to monitor if VPP process is alive.
        Otherwise it will start VPP and restore configuration from DB.
        """
        while self.router_started:
            time.sleep(1)  # 1 sec
            try:           # Ensure watchdog thread doesn't exit on exception
                if not fwutils.vpp_does_run():      # This 'if' prevents debug print by restore_vpp_if_needed() every second
                    fwglobals.log.debug("watchdog: initiate restore")

                    self.vpp_api.disconnect()       # Reset connection to vpp to force connection renewal
                    restored = self.restore_vpp_if_needed()  # Rerun VPP and apply configuration

                    if not restored:                # If some magic happened and vpp is alive without restore, connect back to VPP
                        if fwutils.vpp_does_run():
                            fwglobals.log.debug("watchdog: vpp is alive with no restore!!! (pid=%s)" % str(fwutils.vpp_pid))
                            self.vpp_api.connect()
                        fwglobals.log.debug("watchdog: no need to restore")
                    else:
                        fwglobals.log.debug("watchdog: restore finished")
            except Exception as e:
                fwglobals.log.error("watchdog: exception: %s" % str(e))
                pass

    def tunnel_stats_thread(self):
        """Tunnel statistics thread.
        Its function is to monitor tunnel state and RTT.
        It is implemented by pinging the other end of the tunnel.
        """
        self._fill_tunnel_stats_dict()
        while self.router_started:
            time.sleep(1)  # 1 sec
            fwtunnel_stats.tunnel_stats_test()

    def dhcpc_thread(self):
        """DHCP client thread.
        Its function is to monitor state of WAN interfaces with DHCP.
        """
        while self.router_started:
            time.sleep(1)  # 1 sec
            apply_netplan = False
            wan_list = fwglobals.g.router_cfg.get_interfaces(type='wan')

            for wan in wan_list:
                dhcp = wan.get('dhcp', 'no')
                if dhcp == 'no':
                    continue

                name = fwutils.pci_to_tap(wan['pci'])
                addr = fwutils.get_interface_address(name)
                if not addr:
                    fwglobals.log.debug("dhcpc_thread: %s has no ip address" % name)
                    apply_netplan = True

            if apply_netplan:
                try:
                    cmd = 'netplan apply'
                    fwglobals.log.debug(cmd)
                    subprocess.check_output(cmd, shell=True)
                    fwglobals.g.fwagent.disconnect()
                    time.sleep(10)  # 10 sec

                except Exception as e:
                    fwglobals.log.debug("dhcpc_thread: %s failed: %s " % (cmd, str(e)))

    def restore_vpp_if_needed(self):
        """Restore VPP.
        If vpp doesn't run because of crash or device reboot,
        and it was started by management, start vpp and restore it's configuration.
        We do that by simulating 'start-router' request.
        Restore router state always to support multiple instances of Fwagent.

        :returns: `False` if no restore was performed, `True` otherwise.
        """
        self._restore_router_failure()

        # If vpp runs already, or if management didn't request to start it, return.
        vpp_runs = fwutils.vpp_does_run()
        vpp_should_be_started = fwglobals.g.router_cfg.exists('start-router')
        if vpp_runs or not vpp_should_be_started:
            fwglobals.log.debug("restore_vpp_if_needed: no need to restore(vpp_runs=%s, vpp_should_be_started=%s)" %
                (str(vpp_runs), str(vpp_should_be_started)))
            self.router_started = vpp_runs
            if self.router_started:
                fwglobals.log.debug("restore_vpp_if_needed: vpp_pid=%s" % str(fwutils.vpp_pid()))
                self._start_threads()
                netplan_files = fwnetplan.get_netplan_filenames()
                fwnetplan._set_netplan_filename(netplan_files)
            return False

        # Now start router.
        fwglobals.log.info("===restore vpp: started===")
        try:
            with FwApps(fwglobals.g.APP_REC_DB_FILE) as db_app_rec:
                db_app_rec.clean()
            with FwMultilink(fwglobals.g.MULTILINK_DB_FILE) as db_multilink:
                db_multilink.clean()
            self.call('start-router')
        except Exception as e:
            fwglobals.log.excep("restore_vpp_if_needed: %s" % str(e))
            self._set_router_failure("failed to restore vpp configuration")
        fwglobals.log.info("====restore vpp: finished===")
        return True

    def start_router(self):
        """Execute start router command.
        """
        fwglobals.log.info("FWROUTER_API: start_router")
        if self.router_started == False:
            self.call('start-router')
        fwglobals.log.info("FWROUTER_API: start_router: started")

    def stop_router(self):
        """Execute stop router command.
        """
        fwglobals.log.info("FWROUTER_API: stop_router")
        if self.router_started == True:
            self.call('stop-router')
        fwglobals.log.info("FWROUTER_API: stop_router: stopped")

    def call(self, request):
        """Executes router configuration request: 'add-X' or 'remove-X'.

        :param req: The request received from flexiManage.

        :returns: Status codes dictionary.
        """
        # Some requests require preprocessing.
        # For example before handling 'add-application' the currently configured
        # applications should be removed. The simplest way to do that is just
        # to simulate 'remove-application' receiving. To do that the preprocessing
        # is need. It adds the simulated 'remove-application' request to the
        # the real received 'add-application' forming thus new aggregation request.
        #
        request = self._preprocess_request(request)

        if request['message'] == 'aggregated-router-api':
            return self._call_aggregated(request['params']['requests'])
        else:
            return self._call_simple(request)

    def _call_aggregated(self, requests):
        """Execute multiple requests.
        It do that as an atomic operation,
        i.e. if one of requests fails, all the previous are reverted.

        :param requests:         Request list.

        :returns: Status codes dictionary.
        """
        # Go over all remove-* requests and replace their parameters
        # with parameters of the corresponding add-* requests that are stored in request database.
        # Usually the remove-* request has only partial set of parameters
        # received with correspondent add-* request. That makes it impossible
        # to revert remove-* request if one of the subsequent requests
        # in the aggregated request fails and as a result of this whole aggregated request is rollback-ed.
        # For example, 'remove-interface' has 'pci' parameter only, and has no IP, LAN/WAN type, etc.
        fwglobals.log.debug("FWROUTER_API: === start handling aggregated request ===")
        for request in requests:
            try:
                if re.match('remove-', request['message']):
                    request['params'] = fwglobals.g.router_cfg.get_request_params(request)
            except Exception as e:
                fwglobals.log.excep("_call_aggregated: failed to fetch params for %s: %s " % (json.dumps(request), str(e)))
                raise e


        for (idx, request) in enumerate(requests):
            try:
                fwglobals.log.debug("_call_aggregated: executing request %s" % (json.dumps(request)))
                self.call(request)
            except Exception as e:
                # Revert previously succeeded simple requests
                fwglobals.log.error("_call_aggregated: failed to execute %s. reverting previous requests..." % json.dumps(request))
                for request in reversed(requests[0:idx]):
                    try:
                        op = request['message']
                        request['message'] = op.replace('add-','remove-') if re.match('add-', op) else op.replace('remove-','add-')
                        self._call_simple(request)
                    except Exception as e:
                        # on failure to revert move router into failed state
                        err_str = "_call_aggregated: failed to revert request %s while running rollback on aggregated request" % op
                        fwglobals.log.excep("%s: %s" % (err_str, format(e)))
                        self._set_router_failure(err_str)
                        pass
                raise

        fwglobals.log.debug("FWROUTER_API: === end handling aggregated request ===")
        return {'ok':1}

    def _fill_tunnel_stats_dict(self):
        """Get tunnels their corresponding loopbacks ip addresses
        to be used by tunnel statistics thread.
        """
        fwtunnel_stats.tunnel_stats_clear()
        tunnels = fwglobals.g.router_cfg.get_tunnels()
        for params in tunnels:
            id   = params['tunnel-id']
            addr = params['loopback-iface']['addr']
            fwtunnel_stats.tunnel_stats_add(id, addr)

    def _call_simple(self, request):
        """Execute single request.

        :param request: The request received from flexiManage.

        :returns: Status codes dictionary.
        """
        try:
            req = request['message']

            # If device failed, which means it is in not well defined state,
            # reject request immediately as it can't be fulfilled.
            # Permit 'start-router' to try to get out of failed state.
            # Permit configuration requests only ('add-XXX' & 'remove-XXX')
            # in order to enable management to fix configuration.
            #
            if self._test_router_failure() and not ( \
                req == 'start-router' or re.match('add-|remove-',  req)):
                raise Exception("device failed, can't fulfill requests")

            router_was_started = fwutils.vpp_does_run()

            # The 'add-application' and 'add-multilink-policy' requests should
            # be translated and executed only if VPP runs, as the translations
            # depends on VPP API-s output. Therefore if VPP does not run,
            # just save the requests in database and return.
            #
            if router_was_started == False and \
               (req == 'add-application' or req == 'add-multilink-policy'):
               fwglobals.g.router_cfg.update(request)
               return {'ok':1}

            # Translate request to list of commands to be executed
            cmd_list = self._translate(request)

            # Execute list of commands. Do it only if vpp runs.
            # Some 'remove-XXX' requests must be executed
            # even if vpp doesn't run right now. This is to clean stuff in Linux
            # that was added by correspondent 'add-XXX' request if the last was
            # applied to running vpp.
            #
            if router_was_started or req == 'start-router':
                self._execute(request, cmd_list)
                executed = True
            elif re.match('remove-',  req):
                self._execute(request, cmd_list, filter='must')
                executed = True
            else:
                executed = False

            # Save successfully handled configuration request into database.
            # We need it and it's translation to execute future 'remove-X'
            # requests as they are generated by reverting of correspondent
            # 'add-X' translations from last to the first. As well they are
            # needed to restore VPP configuration on device reboot or start of
            # crashed VPP by watchdog.
            #
            try:
                fwglobals.g.router_cfg.update(request, cmd_list, executed)
            except Exception as e:
                self._revert(cmd_list)
                raise e

            if re.match('(add|remove)-tunnel',  req):
                self._fill_tunnel_stats_dict()

        except Exception as e:
            err_str = "FWROUTER_API::_call_simple: %s" % str(traceback.format_exc())
            fwglobals.log.error(err_str)
            if req == 'start-router' or req == 'stop-router':
                self._set_router_failure("failed to " + req)
            raise e

        return {'ok':1}


    def _translate(self, request):
        """Translate request in a series of commands.

        :param request: The request received from flexiManage.

        :returns: Status codes dictionary.
        """
        req    = request['message']
        params = request.get('params')

        api_defs = fwrouter_translators.get(req)
        assert api_defs, 'FWROUTER_API: there is no api for request "%s"' % req

        module = fwrouter_modules.get(fwrouter_translators[req]['module'])
        assert module, 'FWROUTER_API: there is no module for request "%s"' % req

        func = getattr(module, fwrouter_translators[req]['api'])
        assert func, 'FWROUTER_API: there is no api function for request "%s"' % req

        if fwrouter_translators[req]['api'] == 'revert':
            cmd_list = func(request)
            return cmd_list

        cmd_list = func(params) if params else func()
        return cmd_list

    def _execute(self, request, cmd_list, filter=None):
        """Execute request.

        :param request:     The request received from flexiManage.
        :param cmd_list:    Commands list.
        :param filter:      Filter for commands to be executed.
                            If provided and if command has 'filter' field and
                            their values are same, the command will be executed.
                            If None, the check for filter is not applied.
        :returns: None.
        """
        cmd_cache = {}

        req = request['message']

        fwglobals.log.debug("FWROUTER_API: === start execution of %s ===" % (req))

        for idx, t in enumerate(cmd_list):      # 't' stands for command Tuple, though it is Python Dictionary :)
            cmd = t['cmd']

            # If precondition exists, ensure that it is OK
            if 'precondition' in t:
                precondition = t['precondition']
                reply = fwglobals.g.handle_request(
                    { 'message': precondition['name'], 'params':  precondition.get('params') },
                    result)
                if reply['ok'] == 0:
                    fwglobals.log.debug("FWROUTER_API:_execute: %s: escape as precondition is not met: %s" % (cmd['descr'], precondition['descr']))
                    continue

            # If filter was provided, execute only commands that have the provided filter
            if filter:
                if not 'filter' in cmd or cmd['filter'] != filter:
                    fwglobals.log.debug("FWROUTER_API:_execute: filter out command by filter=%s (req=%s, cmd=%s, cmd['filter']=%s, params=%s)" %
                                        (filter, req, cmd['name'], str(cmd.get('filter')), str(cmd.get('params'))))
                    continue

            try:
                # Firstly perform substitutions if needed.
                # The params might include 'substs' key with list of substitutions.
                self._substitute(cmd_cache, cmd.get('params'))

                if 'params' in cmd and type(cmd['params'])==dict:
                    params = fwutils.yaml_dump(cmd['params'])
                elif 'params' in cmd:
                    params = format(cmd['params'])
                else:
                    params = ''
                fwglobals.log.debug("FWROUTER_API:_execute: %s(%s)" % (cmd['name'], params))

                # Now execute command
                result = None if not 'cache_ret_val' in cmd else \
                    { 'result_attr' : cmd['cache_ret_val'][0] , 'cache' : cmd_cache , 'key' :  cmd['cache_ret_val'][1] }
                reply = fwglobals.g.handle_request({ 'message': cmd['name'], 'params':  cmd.get('params')}, result)
                if reply['ok'] == 0:        # On failure go back revert already executed commands
                    fwglobals.log.debug("FWROUTER_API: %s failed ('ok' is 0)" % cmd['name'])
                    raise Exception("API failed: %s" % reply['message'])

            except Exception as e:
                err_str = "_execute: %s(%s) failed: %s, %s" % (cmd['name'], format(cmd.get('params')), str(e), str(traceback.format_exc()))
                fwglobals.log.error(err_str)
                fwglobals.log.debug("FWROUTER_API: === failed execution of %s ===" % (req))
                # On failure go back to the begining of list and revert executed commands.
                self._revert(cmd_list, idx)
                fwglobals.log.debug("FWROUTER_API: === finished revert of %s ===" % (req))
                raise Exception('failed to ' + cmd['descr'])

            # At this point the execution succeeded.
            # Now substitute the revert command, as it will be needed for complement request, e.g. for remove-tunnel.
            if 'revert' in t and 'params' in t['revert']:
                try:
                    self._substitute(cmd_cache, t['revert'].get('params'))
                except Exception as e:
                    fwglobals.log.excep("_execute: failed to substitute revert command: %s\n%s, %s" % \
                                (str(t), str(e), str(traceback.format_exc())))
                    fwglobals.log.debug("FWROUTER_API: === failed execution of %s ===" % (req))
                    self._revert(cmd_list, idx)
                    raise e

        fwglobals.log.debug("FWROUTER_API: === end execution of %s ===" % (req))

    def _revert(self, cmd_list, idx_failed_cmd=-1):
        """Revert list commands that are previous to the failed command with
        index 'idx_failed_cmd'.
        :param cmd_list:        Commands list.
        :param idx_failed_cmd:  The index of command, execution of which
                                failed, so all commands in list before it
                                should be reverted.
        :returns: None.
        """
        idx_failed_cmd = idx_failed_cmd if idx_failed_cmd >= 0 else len(cmd_list)

        for t in reversed(cmd_list[0:idx_failed_cmd]):
            if 'revert' in t:
                rev_cmd = t['revert']
                try:
                    reply = fwglobals.g.handle_request(
                        { 'message': rev_cmd['name'], 'params': rev_cmd.get('params')})
                    if reply['ok'] == 0:
                        err_str = "handle_request(%s) failed" % rev_cmd['name']
                        fwglobals.log.error(err_str)
                        raise Exception(err_str)
                except Exception as e:
                    err_str = "_revert: exception while '%s': %s(%s): %s" % \
                                (t['cmd']['descr'], rev_cmd['name'], format(rev_cmd['params']), str(e))
                    fwglobals.log.excep(err_str)
                    self._set_router_failure("_revert: failed to revert '%s'" % t['cmd']['descr'])

    def _preprocess_request(self, request):
        """Some requests require preprocessing. For example before handling
        'add-application' the currently configured applications should be removed.
        The simplest way to do that is just to simulate 'remove-application'
        receiving: before the 'add-application' is processed we have
        to process the simulated 'remove-application' request.
        To do that we just create the new aggregated request and put the simulated
        'remove-application' request and the original 'add-application' request
        into it.
            Note the main benefit of this approach is automatic revert of
        the simulated requests if the original request fails.

        :param request: The original request received from flexiManage

        :returns: request - The new aggregated request and it's parameters.
                        Note the parameters are list of requests that might be
                        a mix of simulated requests and original requests.
                        This mix should include one original request and one or
                        more simulated requests.
        """
        req    = request['message']
        params = request.get('params')

        multilink_policy_params = fwglobals.g.router_cfg.get_multilink_policy()

        # 'add-application' preprocessing:
        # 1. The currently configured applications should be removed firstly.
        #    We do that by adding simulated 'remove-application' request in
        #    front of the original 'add-application' request.
        # 2. The multilink policy should be re-installed: if exists, the policy
        #    should be removed before application removal/adding and should be
        #    added again after it.
        #
        application_params = fwglobals.g.router_cfg.get_applications()
        if application_params:
            if req == 'add-application':
                updated_requests = [
                    { 'message': 'remove-application', 'params' : application_params },
                    { 'message': 'add-application',    'params' : params }
                ]
                params = { 'requests' : updated_requests }

                if multilink_policy_params:
                    params['requests'][0:0]   = [ { 'message': 'remove-multilink-policy', 'params' : multilink_policy_params }]
                    params['requests'][-1:-1] = [ { 'message': 'add-multilink-policy',    'params' : multilink_policy_params }]

                request = {'message': 'aggregated-router-api', 'params': params}
                fwglobals.log.debug("_preprocess_request: request was replaced with %s" % json.dumps(request))
                return request

        # 'add-multilink-policy' preprocessing:
        # 1. The currently configured policy should be removed firstly.
        #    We do that by adding simulated 'remove-multilink-policy' request in
        #    front of the original 'add-multilink-policy' request.
        #
        if multilink_policy_params:
            if req == 'add-multilink-policy':
                updated_requests = [
                    { 'message': 'remove-multilink-policy', 'params' : multilink_policy_params },
                    { 'message': 'add-multilink-policy',    'params' : params }
                ]
                request = {'message': 'aggregated-router-api', 'params': { 'requests' : updated_requests }}
                fwglobals.log.debug("_preprocess_request: request was replaced with %s" % json.dumps(request))
                return request

        # 'add/remove-tunnel' and 'add/remove-application' preprocessing:
        # 1. The multilink policy should be re-installed: if exists, the policy
        #    should be removed before tunnel/application removal/adding and should be
        #    added again after it.
        #
        if multilink_policy_params:
            if re.match('(add|remove)-(application|tunnel)', req):
                params  = { 'requests' : [
                    { 'message': 'remove-multilink-policy', 'params' : multilink_policy_params },
                    { 'message': req, 'params' : params },
                    { 'message': 'add-multilink-policy',    'params' : multilink_policy_params }
                ] }
                request = {'message': 'aggregated-router-api', 'params': params}
                fwglobals.log.debug("_preprocess_request: request was replaced with %s" % json.dumps(request))
                return request

        # No preprocessing is needed for rest of simple requests, return.
        if req != 'aggregated-router-api':
            return request

        # Now perform same preprocessing for aggregated requests, either
        # original or created above.
        # We do few passes on requests to find insertion points if needed.
        # It is based on the first appearance of the preprocessor requests.
        #
        updated = False

        indexes = {
            'remove-application'      : -1,
            'add-application'         : -1,
            'remove-tunnel'           : -1,
            'add-tunnel'              : -1,
            'remove-multilink-policy' : -1,
            'add-multilink-policy'    : -1
        }

        requests = params['requests']
        for (idx , _request) in enumerate(requests):
            for req_name in indexes:
                if req_name == _request['message']:
                    if indexes[req_name] == -1:
                        indexes[req_name] = idx

        def _insert_request(requests, idx, req_name, params, updated):
            requests.insert(idx, { 'message': req_name, 'params': params })
            # Update indexes
            indexes[req_name] = idx
            for name in indexes:
                if name != req_name and indexes[name] >= idx:
                    indexes[name] += 1
            updated = True

        # Now preprocess 'add-application': insert 'remove-application' if:
        # - there are applications to be removed
        # - the 'add-application' was found in requests
        #
        if application_params and indexes['add-application'] > -1:
            if indexes['remove-application'] == -1:
                # If list has no 'remove-application' at all just add it before 'add-applications'.
                idx = indexes['add-application']
                _insert_request(requests, idx, 'remove-application', application_params, updated)
            elif indexes['remove-application'] > indexes['add-application']:
                # If list has 'remove-application' after the 'add-applications',
                # it is not supported yet ;) Implement on demand
                raise Exception("_preprocess_request: 'remove-application' was found after 'add-application': NOT SUPPORTED")

        # Now preprocess 'add-multilink-policy': insert 'remove-multilink-policy' if:
        # - there are policies to be removed
        # - the 'add-multilink-policy' was found in requests
        #
        if multilink_policy_params and indexes['add-multilink-policy'] > -1:
            if indexes['remove-multilink-policy'] == -1:
                # If list has no 'remove-multilink-policy' at all just add it before 'add-multilink-policy'.
                idx = indexes['add-multilink-policy']
                _insert_request(requests, idx, 'remove-multilink-policy', multilink_policy_params, updated)
            elif indexes['remove-multilink-policy'] > indexes['add-multilink-policy']:
                # If list has 'remove-multilink-policy' after the 'add-multilink-policy',
                # it is not supported yet ;) Implement on demand
                raise Exception("_preprocess_request: 'remove-multilink-policy' was found after 'add-multilink-policy': NOT SUPPORTED")

        # Now preprocess 'add/remove-application' and 'add/remove-tunnel':
        # reinstall multilink policy if exists:
        # - remove policy before the first appearance of one of preprocessing requests
        # - add policy at the end of request list (this is to save find the exact location)
        #
        if multilink_policy_params:
            # Firstly find the right place to insert the 'remove-multilink-policy'.
            # It should be the first appearance of one of the preprocessing requests.
            #
            idx = 10000
            idx_last = -1
            for req_name in indexes:
                if indexes[req_name] > -1:
                    if indexes[req_name] < idx:
                        idx = indexes[req_name]
                    idx_last = indexes[req_name]
            if idx == 10000:
                # No requests to preprocess were found, return
                return request

            # Now add policy reinstallation if needed.
            # Before that filter out all not supported cases.
            #
            if indexes['remove-multilink-policy'] > idx:
                raise Exception(\
                    "_preprocess_request: 'remove-multilink-policy' was found in not supported place: %d, should be before %d" % \
                    (indexes['remove-multilink-policy'], idx))
            if indexes['add-multilink-policy'] < idx_last:  # We exploit the fact that only one 'add-multilink-policy' is possible
                raise Exception(\
                    "_preprocess_request: 'add-multilink-policy' was found in not supported place: %d, should be not before %d" % \
                    (indexes['add-multilink-policy'], idx_last))
            if indexes['remove-multilink-policy'] == -1:
                _insert_request(requests, idx, 'remove-multilink-policy', multilink_policy_params, updated)
            if indexes['add-multilink-policy'] == -1:
                _insert_request(requests, idx_last+1, 'add-multilink-policy', multilink_policy_params, updated)

        if updated:
            fwglobals.log.debug("_preprocess_request: request was replaced with %s" % json.dumps(request))
        return request

    def _start_threads(self):
        """Start all threads.
        """
        if self.thread_watchdog is None:
            self.thread_watchdog = threading.Thread(target=self.watchdog, name='Watchdog Thread')
            self.thread_watchdog.start()
        if self.thread_tunnel_stats is None:
            self.thread_tunnel_stats = threading.Thread(target=self.tunnel_stats_thread, name='Tunnel Stats Thread')
            self.thread_tunnel_stats.start()
        if self.thread_dhcpc is None:
            self.thread_dhcpc = threading.Thread(target=self.dhcpc_thread, name='DHCP Client Thread')
            self.thread_dhcpc.start()

    def _stop_threads(self):
        """Stop all threads.
        """
        if self.thread_watchdog:
            self.thread_watchdog.join()
            self.thread_watchdog = None

        if self.thread_tunnel_stats:
            self.thread_tunnel_stats.join()
            self.thread_tunnel_stats = None

        if self.thread_dhcpc:
            self.thread_dhcpc.join()
            self.thread_dhcpc = None

    def _on_start_router(self):
        """Handles post start VPP activities.
        :returns: None.
        """

        # Reset failure state before start- hopefully we will succeed.
        # On no luck the start will set failure again
        #
        self._unset_router_failure()

        self.router_started = True
        self._start_threads()
        fwglobals.log.info("router was started: vpp_pid=%s" % str(fwutils.vpp_pid()))

    def _on_stop_router(self):
        """Handles pre-VPP stop activities.
        :returns: None.
        """
        self.router_started = False 
        self._stop_threads()
        fwutils.reset_dhcpd()
        fwglobals.log.info("router is being stopped: vpp_pid=%s" % str(fwutils.vpp_pid()))

    def _set_router_failure(self, err_str):
        """Set router failure state.

        :param err_str:          Error string.

        :returns: None.
        """
        fwglobals.log.debug("_set_router_failure(current=%s): '%s'" % \
            (str(self.router_failure), err_str))
        if not self.router_failure:
            self.router_failure = True
            if not os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
                with open(fwglobals.g.ROUTER_STATE_FILE, 'w') as f:
                    if fwutils.valid_message_string(err_str):
                        f.write(err_str + '\n')
                    else:
                        fwglobals.log.excep("Not valid router failure reason string: '%s'" % err_str)
            fwutils.stop_router()

    def _unset_router_failure(self):
        """Unset router failure state.

        :returns: None.
        """
        if self.router_failure:
            self.router_failure = False
            if os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
                os.remove(fwglobals.g.ROUTER_STATE_FILE)

    def _test_router_failure(self):
        """Get router failure state.

        :returns: 'True' if router is in failed state and 'False' otherwise.
        """
        return self.router_failure

    def _restore_router_failure(self):
        """Restore router failure state.

        :returns: None.
        """
        self.router_failure = True if os.path.exists(fwglobals.g.ROUTER_STATE_FILE) else False
        if self.router_failure:
            fwglobals.log.excep("router is in failed state, use 'fwagent reset [--soft]' to recover if needed")

    def _on_apply_router_config(self):
        """Apply router configuration on successful VPP start.
        """
        types = [
            'add-interface',
            'add-tunnel',
            'add-application',
            'add-multilink-policy',
            'add-route',            # Routes should come after tunnels, as they might use them!
            'add-dhcp-config'
        ]
        messages = fwglobals.g.router_cfg.dump(types=types)
        for msg in messages:
            reply = fwglobals.g.handle_request(msg)
            if reply.get('ok', 1) == 0:  # Break and return error on failure of any request
                return reply


    # 'substitute' takes parameters in form of list or dictionary and
    # performs substitutions found in params.
    # Substitutions are kept in special element which is part of parameter list/dictionary.
    # When this function finishes to perform substitutions, it removes this element from params.
    # The substitution element is a dictionary with one key only - 'substs' and list
    # of substitutions as the value of this key: 
    #   { 'substs': [ {<subst1>} , {<subst2>} ... {<substN>} ] }
    # There are few types of substitutions:
    #   - substitution by function (see 'val_by_func' below)
    #   - substitution by value fetched from cache (see 'val_by_key' below)
    # As well 'substitute' function can
    #   - add new parameter to the original 'params' list/dictionary (see 'add_param' below)
    #   - go over all parameters found in 'params' and replace old value with new (see 'replace' below)
    # If function is used, the function argument can be
    #   - explicit value (see 'arg' below)
    #   - value fetched from cache (see 'arg_by_key' and 'val_by_key' below)
    #
    # That results in following format of single substitution element: 
    #   {
    #       'add_param'    : <name of keyword parameter to be added. Used for dict parameters only>
    #       'val_by_func'  : <function that maps argument into value of new 'add_param' parameter. It should sit in fwutils module>
    #       'arg'          : <input argument for 'val_by_func' function> 
    #   }
    #   {
    #       'add_param'    : <name of keyword parameter to be added. Used for dict parameters only>
    #       'val_by_func'  : <function that maps argument into value of new 'add_param' parameter. It should sit in fwutils module>
    #       'arg_by_key'   : <key to get the input argument for 'val_by_func' function from cache> 
    #   }
    #   {
    #       'add_param'    : <name of keyword parameter to be added. Used for dict parameters only>
    #       'val_by_key'   : <key to get the value of new parameter> 
    #   }
    #   {
    #       'replace'      : <substring to be replaced>
    #       'val_by_func'  : <function that maps argument into value of new 'add_param' parameter. It should sit in fwutils module>
    #       'arg'          : <input argument for 'val_by_func' function> 
    #   }
    #   {
    #       'replace'      : <substring to be replaced>
    #       'val_by_func'  : <function that maps argument into value of new 'add_param' parameter. It should sit in fwutils module>
    #       'arg_by_key'   : <key to get the input argument for 'val_by_func' function from cache> 
    #   }
    #   {
    #       'replace'      : <substring to be replaced>
    #       'val_by_key'   : <key to get the value of new parameter> 
    #   }
    #
    # Once function finishes to handle all substitutions found in the 'substs' element,
    # it removes 'substs' element from the 'params' list/dictionary.
    #
    def _substitute(self, cache, params):
        """It takes parameters in form of list or dictionary and
        performs substitutions found in params.
        Once function finishes to handle all substitutions found in the 'substs' element,
        it removes 'substs' element from the 'params' list/dictionary.

        :param cache:          Cache.
        :param params:         Parameters.

        :returns: None.
        """
        if params is None:
            return

        # Fetch list of substitutions
        substs = None
        if type(params)==dict and 'substs' in params:
            substs = params['substs']
        elif type(params)==list:
            for p in params:
                if type(p)==dict and 'substs' in p:
                    substs = p['substs']
                    substs_element = p
                    break
        if substs is None:
            return

        # Go over list of substitutions and perform each of them
        for s in substs:

            # Find the new value to be added to params
            if 'val_by_func' in s:
                func_name = s['val_by_func']
                func = getattr(fwutils, func_name)
                old  = s['arg'] if 'arg' in s else cache[s['arg_by_key']]
                new  = func(old)
                if new is None:
                    raise Exception("fwutils.py:substitute: %s failed to map %s in '%s'" % (func, old, format(params)))
            elif 'val_by_key' in s:
                new = cache[s['val_by_key']]
            else:
                raise Exception("fwutils.py:substitute: not supported type of substitution source in '%s'" % format(params))

            # Add new param/replace old value with new one
            if 'add_param' in s:
                if type(params) is dict:
                    if 'args' in params:        # Take care of cmd['cmd']['name'] = "python" commands
                        params['args'][s['add_param']] = new
                    else:                       # Take care of rest commands
                        params[s['add_param']] = new
                else:  # list
                    params.insert({s['add_param'], new})
            elif 'replace' in s:
                old = s['replace']
                if type(params) is dict:
                    raise Exception("fwutils.py:substitute: 'replace' is not supported for dictionary in '%s'" % format(params))
                else:  # list
                    for (idx, p) in enumerate(params):
                        if fwutils.is_str(p):
                            params.insert(idx, p.replace(old, new))
                            params.remove(p)
            else:
                raise Exception("fwutils.py.substitute: not supported type of substitution in '%s'" % format(params))

        # Once all substitutions are made, remove substitution list from params
        if type(params) is dict:
            del params['substs']
        else:  # list
            params.remove(substs_element)

