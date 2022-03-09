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

import logging
from logging.handlers import SysLogHandler
import os
import fnmatch
import threading
import time

from fwobject import FwObject
import fwutils


try:
    from vpp_papi import VPPApiClient
    vppWrapper = False
except Exception as e:
    print(str(e) + ": use dummy VPP wrapper. Only for testing!!!")
    from vpp_papi_dummy import VPPApiClient
    vppWrapper = True

class VPP_API(FwObject):
    """This is VPP API class representation.
    """
    def __init__(self, vpp_json_dir='/usr/share/vpp/api/'):
        """Constructor method
        """
        FwObject.__init__(self)

        self.jsonfiles = []
        for root, _, filenames in os.walk(vpp_json_dir):
            for filename in fnmatch.filter(filenames, '*.api.json'):
                self.jsonfiles.append(os.path.join(root, filename))
        if not self.jsonfiles and not vppWrapper:
            raise Exception("VPP_API: no vpp *.api.json files were found")
        self.vpp = VPPApiClient(apifiles=self.jsonfiles, use_socket=False, read_timeout=30, loglevel='WARNING')
        self.vpp.logger.addHandler(SysLogHandler(address='/dev/log'))

        self.vpp_api_lock = threading.RLock()

        self.connected_to_vpp = False
        if fwutils.vpp_does_run():
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

        num_retries = 5
        for i in range(num_retries):
            try:
                self.log.debug("connect_to_vpp: trying to connect, num " + str(i))
                self.vpp.connect('fwagent')
                break
            except Exception as e:
                if not fwutils.vpp_does_run():  # No need to retry if vpp crashed
                    raise Exception("vpp process not found")
                if i == num_retries-1:
                    raise e
                else:
                    time.sleep(20)
        self.connected_to_vpp = True
        self.log.debug("connect_to_vpp: connected")

#        vpp_methods = []
#        for method_name in dir(self.vpp):
#            if callable(getattr(self.vpp, method_name)):
#                vpp_methods.append(method_name)
#        print("vpp.methods: " + format(vpp_methods))
#        vpp_api_methods = []
#        for method_name in dir(self.vpp.api):
#            if callable(getattr(self.vpp.api, method_name)):
#                vpp_api_methods.append(method_name)
#        print("vpp.api.methods: " + format(vpp_api_methods))

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

    # result - describes what field of the object returned by the API,
    #          should be stored in cache, what cache and what key
    #          should be used for that:
    #           {
    #               'result_attr' : <name of attribute of returned object> ,
    #               'cache'       : <cache to store the value of the attribute in> ,
    #               'key'         : <key by which to store the value>
    #           }
    #
    def call_by_request(self, request, result=None):
        """Calls VPP command according the request received from flexiManage.

        :param request:        the received request.
        :param result:         Cache to store return value of the VPP API.

        :returns: reply to be sent to the flexiManage.
        """
        api_name = request['message']
        params   = request.get('params', {})

        if not self.connected_to_vpp:
            reply = {'message':"vpp doesn't run", 'ok':0}
            return reply

        rv = self.call(api_name, **params)
        if rv:
            if result:  # If asked to store some attribute of the returned object in cache
                res = getattr(rv, result['result_attr'])
                result['cache'][result['key']] = res
            reply = {'ok':1}
        else:
            reply = {'message': f'{api_name} failed', 'ok':0}
        return reply


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

        with self.vpp_api_lock:
            api_func = getattr(self.vpp.api, api_name)
            assert api_func, 'vpp_api: api=%s not found' % (api_name)

            rv = api_func(**kwargs)
            if isinstance(rv, type) == False:  # If returned value is built-in type
                return rv
            else:                              # If returned value is object that represents VPP API reply
                if rv.retval == 0:
                    return rv
                else:
                    self.log.error('rv=%s: %s(%s)' % (rv.retval, api_name, str(**kwargs)))
                    return None


    def cli(self, cmd):
        """Execute command in VPP CLI.

        :param cmd:            VPP CLI command.

        :returns: Reply message.
        """
        if not self.connected_to_vpp:
            self.log.excep("cli: not connected to VPP")
            return None
        res = self.call('cli_inband', cmd=cmd)
        if res is None:
            return None
        return res.reply
