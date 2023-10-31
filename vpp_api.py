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

from logging.handlers import SysLogHandler

import copy
import os
import fnmatch
import threading
import time

from fwobject import FwObject
import fw_os_utils
import fwutils


try:
    from vpp_papi import VPPApiClient
    vppWrapper = False
except Exception as e:
    print(str(e) + ": use dummy VPP wrapper. Only for testing!!!")
    from vpp_papi_dummy import VPPApiClient
    vppWrapper = True

class VPP_API_CLIENT(VPPApiClient):
    """This object wraps the fdio VPPApiClient object.
    It's main method is call(), it invokes VPP API functions.
    """
    def __init__(self, log, vpp_json_dir='/usr/share/vpp/api/'):
        """Constructor method
        """
        self.jsonfiles = []
        for root, _, filenames in os.walk(vpp_json_dir):
            for filename in fnmatch.filter(filenames, '*.api.json'):
                self.jsonfiles.append(os.path.join(root, filename))
        if not self.jsonfiles and not vppWrapper:
            raise Exception("VPP_API_CLIENT: no vpp *.api.json files were found")
        VPPApiClient.__init__(self, apifiles=self.jsonfiles, use_socket=False, read_timeout=30, loglevel='WARNING')
        self.logger.addHandler(SysLogHandler(address='/dev/log'))
        self.lock = threading.RLock()
        self.log = log

#        vpp_methods = []
#        for method_name in dir(self):
#            if callable(getattr(self, method_name)):
#                vpp_methods.append(method_name)
#        print("vpp.methods: " + format(vpp_methods))
#        vpp_api_methods = []
#        for method_name in dir(self.api):
#            if callable(getattr(self.api, method_name)):
#                vpp_api_methods.append(method_name)
#        print("vpp.api.methods: " + format(vpp_api_methods))


    def call(self, api_name, **kwargs):
        """Calls VPP API.

        :param api_name:       name of the VPP API to be called.
        :param kwargs:         the parameters to be provided to the VPP API.

        :returns: value returned by the VPP API call.
        """
        # Lock VPP access to ensure no simultaneous VPP API calls from different
        # python threads, libvppapiclient.so does not support this. Actually we
        # should use separate instance of the VPPApiClient in any thread that
        # calls VPP API-s. Alternatively, we could use same VPPApiClient instance
        # that runs dedicated thread, where all VPP API-s are called from within.
        # For now (Dec-2021), it was decided to serialize access to
        # VPP using lock and to pray :)

        with self.lock:
            api_func = getattr(self.api, api_name)
            assert api_func, 'vpp_api: api=%s not found' % (api_name)

            rv = api_func(**kwargs)

            # Skip return code check for vmxnet3_create and vmxnet3_delete API.
            # The root cause of the error code is yet to be analyzed. The retval check had been
            # missing (not working right) for a long time. When retval check was corrected,
            # vmxnet3 API started to fail.
            if api_name == 'vmxnet3_create' or api_name == 'vmxnet3_delete':
                return rv


            retval = None
            try:
                # 'retval' is the attribute returned by the VPP API to indicate success or error
                # Note: VPP Dump APIs do not return this attribute
                retval = getattr(rv, 'retval')
            except:
                if api_name.endswith("_dump"):
                    retval = 0
            if retval is None or retval != 0:
                self.log.error('VPP API call failed rv=%s: API: %s)' % (retval, api_name))
                return None
            else:
                return rv


    def connect(self, name):
        with self.lock:
            return VPPApiClient.connect(self, name)

    def disconnect(self):
        with self.lock:
            return VPPApiClient.disconnect(self)

class VPP_API(FwObject):
    """This is VPP API class representation.
    """
    def __init__(self, vpp_json_dir='/usr/share/vpp/api/'):
        """Constructor method
        """
        FwObject.__init__(self)

        self.vpp = VPP_API_CLIENT(self.log)

        self.connected_to_vpp = False
        if fw_os_utils.vpp_does_run():
            self.connect_to_vpp()

    def finalize(self):
        """Destructor method
        """
        if self.connected_to_vpp:
            self.disconnect_from_vpp()

    def connect_to_vpp(self):
        """Connect to VPP.

        :param vpp_json_dir:         Path to json files with API description.
        """
        if self.connected_to_vpp:
            self.log.debug("connect_to_vpp: already connected")
            return True
        self.log.debug("connect_to_vpp: connecting")

        num_retries = 9
        for i in range(num_retries):
            try:
                self.log.debug("connect_to_vpp: trying to connect, num " + str(i))
                self.vpp.connect('fwagent')
                break
            except Exception as e:
                if not fw_os_utils.vpp_does_run():  # No need to retry if vpp crashed
                    raise Exception("vpp process not found")
                if i == num_retries-1:
                    raise e
                else:
                    time.sleep(20)
        self.connected_to_vpp = True
        self.log.debug("connect_to_vpp: connected")


    def disconnect_from_vpp(self):
        """Disconnect from VPP.

        :returns: None.
        """
        if self.connected_to_vpp:
            self.vpp.disconnect()
            self.connected_to_vpp = False
            self.log.debug("disconnect_from_vpp: disconnected")
        else:
            self.log.debug("disconnect_from_vpp: not connected")

    def call_vpp_api(self, api, args={}, result_cache=None):
        """Calls VPP API specified by function name.

        :param api:           Name of the VPP API function to be called.
        :param args:          The arguments to be provided to the VPP API. Dict.
        :param result_cache:  Cache to store return value of the VPP API.
                              It describes what field of the object returned
                              by the VPP API should be stored in cache, and what
                              cache and what key should be used for that.
                              Example:
                                {
                                  'result_attr' : <name of attribute of returned object>,
                                  'cache'       : <cache to store the value of the attribute in>,
                                  'key'         : <key by which to store the value>
                                }

        :returns: result of VPP API invocation in format of the flexiManage reply.
        """
        if not self.connected_to_vpp:
            return (False, "vpp doesn't run")

        rv = self.vpp.call(api, **args)
        if rv:
            if result_cache:  # If asked to store some attribute of the returned object in cache
                res = getattr(rv, result_cache['result_attr'])
                result_cache['cache'][result_cache['key']] = res
            return (True, '')
        else:
            return (False, f'{api} failed')

    def cli(self, cmd):
        """Execute command in VPP CLI.

        :param cmd:            VPP CLI command.

        :returns: Reply message.
        """
        if not self.connected_to_vpp:
            self.log.excep("cli: not connected to VPP")
            return None
        res = self.vpp.call('cli_inband', cmd=cmd)
        if res is None:
            return None
        return res.reply
