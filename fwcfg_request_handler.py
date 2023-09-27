#! /usr/bin/python3

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

import fwglobals
import fw_os_utils
import fwutils

import copy
from functools import partial
import traceback
import json
import re

from fwobject import FwObject

class FwCfgRequestHandler(FwObject):
    """This is Request Handler class representation.
    The RequestHandler class enables user to execute requests received from flexiManage.
    To do that it provides following steps:
    1. Translates request into list of commands to be executed.
       This stage is called translation.
    2. Executes commands out of the translation list one by one.
       This stage is called execution.
       On failure to execute any of commands, the previously executed commands are reverted
       in order to rollback system to the state where it was before request receiving.
    3. Updates the persistent database with request result:
       for 'add-X' and 'modify-X' requests stores the request and it's translation into database,
       for 'remove-X' request deletes the stored request and translation from the database.
    Note these stages are exposed as module API-s to enable user to override the default behavior.

    In addition the Request Handler provides following functionality:
    1. Handle aggregated requests
    2. Implement sync and full sync logic
    """

    def __init__(self, translators, cfg_db, pending_cfg_db=None):
        """Constructor method.
        """
        FwObject.__init__(self)

        self.translators = translators
        self.cfg_db = cfg_db
        self.pending_cfg_db = pending_cfg_db
        self.cache_func_by_name = {}

        self.fwdump_counter_on_start_router = 0

        self.cfg_db.set_translators(translators)
        if self.pending_cfg_db is not None:
            self.pending_cfg_db.set_translators(translators)

    def __enter__(self):
        return self

    def set_request_logger(self, request):
        new_logger = fwglobals.g.loggers.get(request['message'], self.log)
        self.cfg_db.push_logger(new_logger)
        self.push_logger(new_logger)

    def unset_request_logger(self):
        self.cfg_db.pop_logger()
        self.pop_logger()

    def call(self, request, dont_revert_on_failure=False):
        if request['message'] == 'aggregated':
            reply = self._call_aggregated(request['params']['requests'], dont_revert_on_failure)
        else:
            reply = self._call_simple(request)
        return reply

    def rollback(self, request):
        try:
            self.call(request, dont_revert_on_failure=True) # True: Prevent revert of rollback :)
        except Exception as e:
            err_str = "rollback: failed for '%s': %s" % (request['message'], str(e))
            self.log.excep(err_str)

    def _get_func(self, cmd):
        func_name = cmd['func']
        func_path = cmd.get('module', cmd.get('object', ''))
        full_name = func_path + '.' + func_name
        func = self.cache_func_by_name.get(full_name)
        if func:
            return func

        module_name = cmd.get('module')
        if module_name:
            func  = getattr(__import__(module_name), func_name)
            self.cache_func_by_name[full_name] = func
            return func

        # I am a bit lazy to implement proper parsing of the 'object', so just
        # go with explicit strings :) Next time someone get strange exception
        # due to missing string in the switch below - let him to implement
        # the proper parser :)
        #
        object_name = cmd.get('object')
        if object_name:
            func = fwglobals.g.get_object_func(object_name, func_name)
            if not func:
                return None
            self.cache_func_by_name[full_name] = func
            return func

    def _call_simple(self, request, execute=True, filter=None):
        """Execute single request.

        :param request: The request received from flexiManage.

        :returns: dictionary with status code and optional error message.
        """
        self.set_request_logger(request)   # Use request specific logger (this is to offload heavy 'add-application' logging)
        self.cmd_cache = {}
        try:
            # Translate request to list of commands to be executed
            cmd_list = self._translate(request)

            # Execute list of commands. Do it only if vpp runs.
            # Some 'remove-XXX' requests must be executed
            # even if vpp doesn't run right now. This is to clean stuff in Linux
            # that was added by correspondent 'add-XXX' request if the last was
            # applied to running vpp.
            if execute:
                self._execute(request, cmd_list, filter)

            # Save successfully handled configuration request into database.
            # We need it and it's translation to execute future 'remove-X'
            # requests as they are generated by reverting of correspondent
            # 'add-X' translations from last to the first. As well they are
            # needed to restore VPP configuration on device reboot or start of
            # crashed VPP by watchdog.
            try:
                self.cfg_db.update(request, cmd_list, execute)
            except Exception as e:
                self._revert(cmd_list)
                raise e
        except Exception as e:
            err_str = "_call_simple: %s" % str(traceback.format_exc())
            self.log.error(err_str)
            raise e
        finally:
            self.unset_request_logger()

        return {'ok':1}

    def _call_aggregated(self, requests, dont_revert_on_failure=False):
        """Execute multiple requests.
        It do that as an atomic operation,
        i.e. if one of requests fails, all the previous are reverted.

        :param requests:    Request list.
        :param dont_revert_on_failure:  If True the succeeded requests in list
                            will not be reverted on failure of any request.
                            This bizare logic is used for device sync feature,
                            where there is no need to restore configuration,
                            as it is out of sync with the flexiManage.

        :returns: dictionary with status code and optional error message.
        """
        self.log.debug("=== start handling aggregated request ===")

        for (idx, request) in enumerate(requests):

            # Don't print too large requests, if needed check print on request receiving
            #
            str_request = json.dumps(request)
            str_request = (str_request[:1000] + '..') if len(str_request) > 1000 else str_request

            try:
                self.log.debug("_call_aggregated: handle request %s" % str_request)
                self._call_simple(request)
            except Exception as e:
                if dont_revert_on_failure:
                    raise e
                # Revert previously succeeded simple requests
                self.log.error("_call_aggregated: failed to handle %s. reverting previous requests..." % str_request)
                for request in reversed(requests[0:idx]):
                    try:
                        op = request['message']
                        request['message'] = op.replace('add-','remove-') if re.match('add-', op) else op.replace('remove-','add-')
                        self._call_simple(request)
                    except Exception as e_revert:
                        # on failure to revert move router into failed state
                        err_str = "_call_aggregated: failed to revert request %s while running rollback on aggregated request" % op
                        self.log.excep("%s: %s" % (err_str, format(e_revert)))
                        pass
                raise e

        self.log.debug("=== end handling aggregated request ===")
        return {'ok':1}

    def _translate(self, request):
        """Translate request in a series of commands.

        :param request: The request received from flexiManage.

        :returns: list of commands.
        """
        req    = request['message']
        params = request.get('params')

        api_defs = self.translators.get(req)
        assert api_defs, 'there is no api for request "%s"' % req

        module = api_defs.get('module')
        assert module, 'there is no module for request "%s"' % req

        api = api_defs.get('api')
        assert api, 'there is no api for request "%s"' % req

        func = getattr(module, api)
        assert func, 'there is no api function for request "%s"' % req

        if api == 'revert':
            cmd_list = func(request, self.cfg_db)
            return cmd_list

        if re.match('modify-', req):
            old_params = self.cfg_db.get_request_params(request)
            cmd_list = func(params, old_params)
        elif params:
            cmd_list = func(params)
        else:
            cmd_list = func()
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
        req = request['message']

        self.log.debug("=== start execution of %s ===" % (req))

        if req == 'start-router':
            self.fwdump_counter_on_start_router = 0

        for idx, t in enumerate(cmd_list):      # 't' stands for command Tuple, though it is Python Dictionary :)
            cmd = t['cmd']

            # If filter was provided, execute only commands that have the provided filter
            if filter:
                if not 'filter' in cmd or cmd['filter'] != filter:
                    self.log.debug("_execute: filter out command by filter=%s (req=%s, cmd=%s, cmd['filter']=%s, params=%s)" %
                                        (filter, req, cmd['func'], str(cmd.get('filter')), str(cmd.get('params'))))
                    continue

            try:
                # Firstly perform substitutions if needed.
                # The params might include 'substs' key with list of substitutions.
                self.substitute(self.cmd_cache, cmd.get('params'))

                self.log.debug(f"_execute: {self._dump_translation_cmd_params(cmd)}")

                # Now execute command
                execute_result = None if not 'cache_ret_val' in cmd else \
                    { 'result_attr' : cmd['cache_ret_val'][0] , 'cache' : self.cmd_cache , 'key' :  cmd['cache_ret_val'][1] }
                err_str = self._execute_translation_command(cmd, execute_result)
                if err_str:   # On failure go back revert already executed commands
                    fwglobals.g.jobs.update_current_record({'request': req, 'command': cmd, 'error': err_str})
                    self.log.debug(f"_execute_translation_command('{cmd['func']}') failed")
                    raise Exception(err_str)

            except Exception as e:
                err_str = "_execute: %s(%s) failed: %s, %s" % (cmd['func'], format(cmd.get('params')), str(e), str(traceback.format_exc()))
                self.log.error(err_str)
                self.log.debug("=== failed execution of %s ===" % (req))
                if fwglobals.g.router_api.state_is_starting_stopping() and \
                   self.fwdump_counter_on_start_router==0:
                    fwutils.fwdump(filename="start_router_failure")
                    self.fwdump_counter_on_start_router += 1
                # On failure go back to the begining of list and revert executed commands.
                self._revert(cmd_list, idx)
                self.log.debug("=== finished revert of %s ===" % (req))
                cmd_descr = cmd['descr'][0].lower() + cmd['descr'][1:] # ensure the first letter is not capital
                raise Exception(f'failed to {cmd_descr}: {str(e)}')

            # At this point the execution succeeded.
            # Now substitute the revert command, as it will be needed for complement request, e.g. for remove-tunnel.
            if 'revert' in t and 'params' in t['revert']:
                try:
                    self.substitute(self.cmd_cache, t['revert'].get('params'))
                except Exception as e:
                    self.log.excep("_execute: failed to substitute revert command: %s\n%s, %s" % \
                                (str(t), str(e), str(traceback.format_exc())))
                    self.log.debug("=== failed execution of %s ===" % (req))
                    self._revert(cmd_list, idx)
                    raise e

        self.log.debug("=== end execution of %s ===" % (req))


    def _execute_translation_command(self, cmd, result=None):
        """Execute single command out of the list of commands created by
        translation of flexiManage request into list of commands, e.g.

            cmd['func']   = "load_linux_modules"
            cmd['module'] = "fwutils"
            cmd['descr']  = "load vhost-net modules"
            cmd['params'] = { 'modules': ['tap', 'vhost', 'vhost-net'] }

        :param cmd:          The translation command.
        :param result:       Place to store result of the command execution.
                             It is dict of {<attr> , <cache>, <cache key>}.
                             On success we fetch value of attribute <attr>
                             of the object returned by command function and
                             store it in the <cache> by key <cache key>.
                             Note <attr> may be used for any semantic,
                             depeneding on the command. For example, it might
                             contain pattern for grep to be run on command output.

        :returns: Dictionary with error string and status code.
        """
        def _parse_result(res):
            ok, err_str = True, None
            if res is None:
                ok = True
            elif type(res) == bool:
                ok = res
            elif type(res) == tuple:
                ok      = res[0]
                err_str = res[1]
            elif type(res) == dict:
                ok      = res.get('ok', False)
                err_str = res.get('ret')
            else:
                err_str = f'_call_python_api_parse_result: unsupported type of return: {type(res)}'

            if not ok and not err_str:
                err_str = "unspecified error"
            elif ok:
                err_str = None
            return err_str

        try:
            func = self._get_func(cmd)
            args = cmd.get('params', {})
            if result:
                args = copy.deepcopy(args) if args else {}
                args.update({ 'result_cache': result })

            err_str = _parse_result(func(**args))
            if err_str:
                args_str = '' if not args else ', '.join([ "%s=%s" % (arg_name, args[arg_name]) for arg_name in args ])
                self.log.error('%s(%s) failed: %s' % (cmd['func'], args_str, err_str))
            return err_str

        except Exception as e:
            err_str = "%s(%s): %s" % (cmd['func'], format(cmd.get('params', "")), str(e))
            self.log.error(err_str + ': %s' % str(traceback.format_exc()))
            return err_str


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
                self.log.debug(f"_revert: {self._dump_translation_cmd_params(rev_cmd)}")
                try:
                    execute_result = None if not 'cache_ret_val' in rev_cmd else \
                        { 'result_attr' : rev_cmd['cache_ret_val'][0] ,
                         'cache' : self.cmd_cache , 'key' :  rev_cmd['cache_ret_val'][1] }
                    err_str = self._execute_translation_command(rev_cmd, execute_result)
                    if err_str:
                        self.log.error(f"_revert('{rev_cmd['func']}') failed")
                        raise Exception(err_str)
                except Exception as e:
                    err_str = "_revert: exception while '%s': %s(%s): %s" % \
                                (t['cmd']['descr'], rev_cmd['func'], format(rev_cmd.get('params',"")), str(e))
                    self.log.excep(err_str)
                    return   # Don't continue, system is in undefined state now!


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
    def substitute(self, cache, params):
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

        # Perform substitutions in nested dictionaries and lists
        #
        if type(params)==list:
            for p in params:
                if type(p)==list or type(p)==dict:
                    self.substitute(cache, p)
        elif type(params)==dict:
            for item in list(params.items()):
                key = item[0]
                p   = item[1]
                if (type(p)==dict or type(p)==list) and \
                key != 'substs':                       # Escape 'substs' element
                    self.substitute(cache, p)

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
                if isinstance(s['val_by_func'], dict):
                    func = self._get_func(s['val_by_func'])
                else:
                    module , func_name = fwutils , s['val_by_func']
                    if '.' in func_name:
                        module_name, func_name = func_name.split('.', 1)
                        module = __import__(module_name)
                    func = getattr(module, func_name)
                old  = s['arg'] if 'arg' in s else cache[s['arg_by_key']]

                if type(old) == list:
                    new = func(*old)
                elif type(old) == dict:
                    new = func(**old)
                else:
                    new = func(old)
                if new is None:
                    raise Exception("fwutils.py:substitute: %s failed to map %s in '%s'" % (func, old, format(params)))
            elif 'val_by_key' in s:
                new = cache[s['val_by_key']]
            else:
                raise Exception("fwutils.py:substitute: not supported type of substitution source in '%s'" % format(params))

            # Add new param/replace old value with new one
            if 'add_param' in s:
                if type(params) is dict:
                    params[s['add_param']] = new
                else:  # list
                    params.insert({s['add_param'], new})
            elif 'replace' in s:
                old = s['replace']
                if type(params) is dict:

                    # Find element of dict that is referenced by the 'subst'
                    #
                    arg_key = s.get('key')
                    if not arg_key:
                        raise Exception(f"fwutils.py:substitute: 'key' was not found in 'subst' element of 'replace' type: '{format(s)}'")
                    arg_val = params.get(arg_key)
                    if not arg_val:
                        raise Exception("fwutils.py:substitute: key '%s' doesn't exist in params '%s'" % (str(arg_key), format(s)))

                    # Modify it's value according the replacement.
                    #
                    if type(arg_val) == str:
                        if old in arg_val:
                            params[arg_key] = params[arg_key].replace(old, str(new))
                    elif type(arg_val) == list:
                        for (idx, a) in list(enumerate(arg_val)):
                            if type(a) == str and old in a:
                                params[arg_key][idx] = params[arg_key][idx].replace(old, str(new))
                    else:
                        raise Exception(f"fwutils.py:substitute: 'replace' is not supported for the given dictionary: '{format(params)}'")

                else:  # list
                    for (idx, p) in list(enumerate(params)):
                        if type(p) == str:
                            params.insert(idx, p.replace(old, str(new))) # new variable might be vpp_sw_interface_index which is number, so we stringify it
                            params.remove(p)
            else:
                raise Exception("fwutils.py.substitute: not supported type of substitution in '%s'" % format(params))

        # Once all substitutions are made, remove substitution list from params
        if type(params) is dict:
            del params['substs']
        else:  # list
            params.remove(substs_element)


    def _strip_noop_request(self, request):
        """Checks if the request has no impact on configuration.
        For example, the 'remove-X'/'modify-X' for not existing configuration
        item or 'add-X' request for existing configuration item.

        :param request: The request received from flexiManage.

        :returns: request after stripping out no impact requests.
        """
        def _should_be_stripped(__request, aggregated_requests=None):
            req    = __request['message']
            params = __request.get('params', {})
            if re.match('(modify-|remove-)', req) and not self.cfg_db.exists(__request):
                # Ensure that the aggregated request does not include correspondent 'add-X' before.
                noop = True
                if aggregated_requests:
                    complement_req     = re.sub('(modify-|remove-)','add-', req)
                    complement_request = { 'message': complement_req, 'params': params }
                    if _exist_in_list(complement_request, aggregated_requests):
                        noop = False
                if noop:
                    if re.match('remove-',  req) and self.pending_cfg_db.exists(__request):
                        self.pending_cfg_db.update(request)
                    return True
            elif re.match('add-qos-policy', req) and self.cfg_db.exists(__request):
                #Qos-Policy requires full diff
                existing_params = self.cfg_db.get_request_params(__request)
                return True if existing_params == __request.get('params') else False
            elif re.match('add-', req) and self.cfg_db.exists(__request):
                # Ensure this is actually not modification request :)
                existing_params = self.cfg_db.get_request_params(__request)
                if fwutils.compare_request_params(existing_params, __request.get('params')):
                    # Ensure that the aggregated request does not include correspondent 'remove-X' before.
                    noop = True
                    if aggregated_requests:
                        complement_req     = re.sub('add-','remove-', req)
                        complement_request = { 'message': complement_req, 'params': params }
                        if _exist_in_list(complement_request, aggregated_requests):
                            noop = False
                    if noop:
                        return True
            elif re.match('start-router', req) and fw_os_utils.vpp_does_run():
                # start-router & stop-router break add-/remove-/modify- convention.
                return True
            elif re.match('modify-', req):
                # For modification request check if it goes to modify indeed.
                # The check ignores the 'ignored_params' that might be defined
                # in the request translator. This is needed to handle parameters
                # that have no impact on VPP configuration and that are kept in
                # the configuration database to assist pure agent logic.
                # For example, if 'modify-interface' brings new 'publicPort'
                # only, there is nothing to configure, agent just saves it into
                # database.
                #
                ignored_params = {}
                api_defs = self.translators.get(req)
                if api_defs:
                    module   = api_defs.get('module')
                    var_name = api_defs.get('ignored_params')
                    if var_name:
                        ignored_params = getattr(module, var_name)

                if self.compare_modify_params(__request, ignored_params):
                    self.log.debug(f"'{req}' has not impacting modifications only -> save it without execution")
                    self.cfg_db.update(__request)
                    return True
            return False

        def _exist_in_list(__request, requests):
            """Checks if the list of requests has request for the same
            configuration item as the one denoted by the provided __request.
            """
            for r in requests:
                if (__request['message'] == r['message'] and
                    self.cfg_db.is_same_cfg_item(__request, r)):
                    return True
            return False

        def _replace_modify(modify_request):
            """The 'modify-X' requests are supposed to modify any parameter
            of the configuration item, like IP address of the interface that was
            added using the 'add-interface' request. But! At this stage we don't
            support such pinpoint modifications. Instead we just replace
            the 'modify-X' request with pair of the correspondent 'remove-X' and
            'add-X' requests, thus recreating the configuration item from scratch.
            The substituted 'remove-X' request uses parameters stored
            in the configuration database, and the substituted 'add-X' request uses
            modified parameters from the 'modify-X' request and all the rest of
            parameters it takes from the configuration database. That makes it possible
            the 'modify-X' request to hold only modified parameters. In addition it
            should include the key parameters needed to identify the configuration item,
            e.g. 'modify-tunnel' might include modified remote address 'dst' and it
            should include the 'tunnel-id' key parameter.
                Note some 'modify-X' requests are supported partially and don't
            require recreation by remove & add. The related info is stored
            in the translator modules.

            :param modify_request: The original request with modified parameters
                                    received from flexiManage.

            :returns: The pair of pair of 'remove-X' and 'add-X' requests,
                      if modification is not supported for this configuration
                      item. Otherwise the original 'modify_request' is returned.
            """
            _req    = modify_request['message']
            _params = modify_request['params']

            api_defs = self.translators.get(_req)
            if api_defs and api_defs.get('supported_params'):
                # 'modify-X' is supported and list of parameters that can be modified is defined
                module   = api_defs.get('module')
                var_name = api_defs.get('supported_params')
                if var_name:
                    supported_params = getattr(module, var_name)
                    if supported_params and self.compare_modify_params(modify_request, supported_params):
                        # request contains only modifiable parameters -> no need to replace
                        return [modify_request]

            # At this point the 'modify-X' either is not supported at all,
            # or set of supported for modification parameters was not defined for it.
            # Go and replace it with pair of 'remove-X' and 'add-X'.
            #
            remove_req = _req.replace("modify-", "remove-")
            old_params = self.cfg_db.get_request_params(modify_request)
            add_req    = _req.replace("modify-", "add-")
            new_params = copy.deepcopy(old_params)
            fwutils.dict_deep_update(new_params, _params)
            return [
                { 'message': remove_req, 'params' : old_params },
                { 'message': add_req,    'params' : new_params }
            ]


        out_requests = []
        if request['message'] != 'aggregated':
            if _should_be_stripped(request):
                self.log.debug("_strip_noop_request: request has no impact: %s" % json.dumps(request))
                return None
            out_requests = [request]
        else:  # aggregated request
            inp_requests = request['params']['requests']
            for _request in inp_requests:
                if _should_be_stripped(_request, inp_requests):
                    self.log.debug("_strip_noop_request: embedded request has no impact: %s" % json.dumps(request))
                else:
                    out_requests.append(_request)
            if not out_requests:
                self.log.debug("_strip_noop_request: aggregated request has no impact")
                return None
            if len(out_requests) < len(inp_requests):
                self.log.debug("_strip_noop_request: aggregation after strip: %s" % json.dumps(out_requests))

        # At this point we have all no-op requests stripped out.
        # Now handle modify-X requests. The native modification can be not supported
        # for some requests. In this case we have to replace the modify-X with
        # pair of remove-X and add-X to recreate the configuration item from scratch.
        #
        final_requests = []
        for _request in out_requests:
            if re.match('modify-', _request['message']):
                final_requests += _replace_modify(_request)
            else:
                final_requests.append(_request)
        if len(final_requests) > len(out_requests):
            self.log.debug("_strip_noop_request: aggregation after modify-X replacement: %s" % json.dumps(final_requests))

        if len(final_requests) == 1:
            return final_requests[0]
        return {'message': 'aggregated', 'params': {'requests': final_requests}}



    def restore_configuration(self, types=None):
        """Restore configuration.
        Run all configuration translated commands.
        """
        try:
            self.log.info("===restore configuration: started===")

            requests = self.cfg_db.dump(keys=True, types=types)
            if requests:
                for req in requests:
                    reply = fwglobals.g.handle_request(req)
        except Exception as e:
            self.log.excep("restore_configuration failed: %s" % str(e))

        self.log.info("====restore configuration: finished===")

    def sync_full(self, incoming_requests):
        sync_request = {
            'message':   'aggregated',
            'params':    { 'requests': incoming_requests },
        }
        reply = self.call(sync_request, dont_revert_on_failure=True)
        if reply['ok'] == 0:
            raise Exception("sync_full failed: " + str(reply.get('message')))

    def sync(self, incoming_requests, full_sync=False):
        incoming_requests = list([x for x in incoming_requests if x['message'] in self.translators])
        sync_list         = self.cfg_db.get_sync_list(incoming_requests)

        if len(sync_list) == 0 and not full_sync:
            self.log.info("_sync_device: sync_list is empty, no need to sync")
            return True

        if full_sync:
            self.sync_full(incoming_requests)
            return

        # At this point no full sync was requested, so try firstly the smart
        # sync - sync without stopping VPP - just find configuration items
        # out of sync and try to modify them.
        # If that fails, we will try the full sync.
        #
        self.log.debug("_sync_device: start smart sync")

        sync_request = {
            'message':   'aggregated',
            'params':    { 'requests': sync_list }
        }

        try:
            reply = self.call(sync_request, dont_revert_on_failure=True)
            if reply['ok'] == 1:
                self.log.debug("_sync_device: smart sync succeeded")
                return
            else:
                self.log.error(f"_sync_device: smart sync failed, go to full sync: {str(reply['message'])}")
        except Exception as e:
            self.log.error(f"_sync_device: smart sync exception, go to full sync: {str(e)} {traceback.format_exc()}")

        self.sync_full(incoming_requests)

    def _dump_translation_cmd_params(self, cmd):
        if 'params' in cmd and type(cmd['params'])==dict:
            return "%s(%s)" % (cmd['func'], fwutils.yaml_dump(cmd['params']))
        else:
            return "%s(%s)" % (cmd['func'], format(cmd.get('params','')))

    def compare_modify_params(self, request, ignore_params={}):
        """Helper function that detects if 'modify-X' request received from
        flexiManage brings same parameters that already stored in configuration
        database, except the ones specified by the 'ignore_params' argument.
        In other words, it checks if the modify-X assumes real changes.
        We use this function in two cases:
            1. To spot if modify-X contains changes of modifiable parameters only.
        In this case it will be translated into list of commands and will be
        executed. Otherwise it will be replaced with remove-X & add-X pair
        to recreate the configuration item from scratch.
            2. To spot if modify-X contains changes of not impacting parameters
        only. In this case there is no need to execute it at all, just save
        the update into configuration database. Example of not impacting
        parameters can be 'PublicPort' and 'PublicIp' for 'modify-interface'.
        They are no provisioned into VPP, just saved for FwStunWrapper needs.

        :param request: the modify-X request received from flexiManage.
                        Can include partial set of parameters of configuration item.
                        Must include key parameters to identify the item.
        :param ignore_params: the parameters that should be ignored while comparing
                        modify-X parameters to stored parameters.

        :return: True if all received parameters have same values as stored ones,
                except the parameters specified by 'ignore_params'.
        """

        def _compare_modify_params(_modify_params, _existing_params, _ignore_params):
            """Recursive function for dict deep comparison.
            """
            for key, value in _modify_params.items():
                if isinstance(value, dict):
                    if not _compare_modify_params(value,
                                _existing_params.get(key,{}), _ignore_params.get(key,{})):
                        return False
                else:
                    if key in _ignore_params:
                        continue
                    if not key in _existing_params:
                        if not value:
                            continue  # ignore new falsy parameter even if it does not exist (falsy means None, False, "", etc.)
                        self.log.debug(f"compare_modify_params: _modify_params: key '{key}' not found in '_existing_params.get(key)'")
                        return False
                    if value != _existing_params[key]:
                        self.log.debug(f"compare_modify_params: _modify_params['{key}']={value} != {_existing_params.get(key)}")
                        return False
            return True

        existing_params = self.cfg_db.get_request_params(request)
        return _compare_modify_params(request['params'], existing_params, ignore_params)

class FwCfgMultiOpsWithRevert():
    """This class is used as a helper function to perform several operations, one after the other, 4
    taking responsibility for the revert of each operation in case one of the operations fails.
    If one of the operations failed, you should do a revert of the functions that have already passed successfully
    to clean the system of settings that were not completed correctly.
    """

    def __init__(self):
        """Constructor.
        """
        self.revert_functions = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return

    def exec(self, func, params=None, revert_func=None, revert_params=None):
        """Execute the given function and save its revert function to a list.

        :param func:          Function to execute now.
        :param params:        Dictionary of params to call the function with. Keep None to call function without params.
        :param revert_func:   Revert function to save in order to run on a failure.
        :param revert_params: Params of the revert function.

        :returns: reply from the executed function.
        """
        try:
            ret = func(**params) if params else func()
            self.add_revert_func(revert_func, revert_params)
            return ret
        except Exception as e:
            fwglobals.log.error(f"FwCfgMultiOpsWithRevert(): func {func.__name__}({params}) failed. err: {str(e)}")
            self.revert(e)

    def add_revert_func(self, revert_func=None, revert_params=None):
        """Save the revert function in a list. The list will be run in case of failure in one of the functions.

        :param revert_func:   Revert function to save in order to run on a failure.
        :param revert_params: Params of the revert function.
        """
        if revert_func and revert_params:
            self.revert_functions.append(partial(revert_func, **revert_params))
        elif revert_func:
            self.revert_functions.append(partial(revert_func))

    def revert(self, error):
        """Execute all the saved revert functions.

        :param error: Error to throw at the end of the process..
        """
        if not self.revert_functions:
            raise error

        self.revert_functions.reverse()
        for revert_function in self.revert_functions:
            try:
                revert_function()
            except Exception as revert_e: # on revert, don't raise exceptions to prevent infinite loop of failure -> revert failure -> revert of revert failure and so on (:
                fwglobals.log.excep(f"FwCfgMultiOpsWithRevert(): revert func {str(revert_function)} failed. err: {str(revert_e)}")

        self.revert_functions = []
        raise error