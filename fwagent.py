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

import json
import os
import glob

from urllib import request as ureq
from urllib import parse as uparse
from urllib import error as uerr
from http import server as hsvr

import ssl
import socket
import sys
import time
import random
import signal
import Pyro4
import re
import subprocess
import threading
import traceback
import yaml
import fwglobals
import fwikev2
import fwmultilink
import fwstats
import fwutils
import fwwebsocket
import loadsimulator
import jwt

from fwobject import FwObject

# Global signal handler for clean exit
def global_signal_handler(signum, frame):
    """Global signal handler for CTRL+C

    :param signum:         Signal type
    :param frame:          Stack frame.

    :returns: None.
    """
    exit(1)

signal.signal(signal.SIGINT, global_signal_handler)

class FwAgent(FwObject):
    """This class implements abstraction of mediator between manager called
    flexiManage and device called flexiEdge. The manager runs on remote server,
    the Fwagent runs on device. The Fwagent establishes protected connection
    to the manager and starts infinite message handling loop. It receives
    message, called request, invokes global message handler that routes
    the request to the appropriate request handler, takes response
    returned by the message handler and sends it back to the manager.
    Only one request can be processed at any time.
    The global message handler sits in the Fwglobals module.

    :param handle_signals: A flag to handle system signals
    """
    def __init__(self, handle_signals=True):
        """Constructor method
        """
        FwObject.__init__(self)

        self.token                = None
        self.versions             = fwutils.get_device_versions(fwglobals.g.VERSIONS_FILE)
        self.thread_statistics    = None
        self.thread_stun          = None
        self.pending_msg_replies  = []
        self.reconnecting         = False

        self.ws = fwwebsocket.FwWebSocketClient(
                                    on_open    = self._on_open,
                                    on_message = self._on_message,
                                    on_close   = self._on_close)

        if handle_signals:
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Signal handler for CTRL+C

        :param signum:         Signal type
        :param frame:          Stack frame.

        :returns: None.
        """
        self.log.info("got %s" % fwglobals.g.signal_names[signum])
        self.__exit__(None, None, None)
        exit(1)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.finalize()

    def finalize(self):
        self.ws.finalize()

    def _mark_connection_failure(self, err):
        try:
            with open(fwglobals.g.CONN_FAILURE_FILE, 'w') as f:
                fwutils.file_write_and_flush(f, 'Failed to connect to flexiManage: %s' % err)
                self.log.debug("_mark_connection_failure: %s" % str(err))
        except Exception as e:
            self.log.excep("Failed to create connection failure file: %s" % str(e))

    def _clean_connection_failure(self):
        if os.path.exists(fwglobals.g.CONN_FAILURE_FILE):
            os.remove(fwglobals.g.CONN_FAILURE_FILE)
            self.log.debug("_clean_connection_failure")

    def _setup_repository(self, repo):
        # Extract repo info. e.g. 'https://deb.flexiwan.com|flexiWAN|main'
        repo_split = repo.split('|')
        if len(repo_split) != 3:
            self.log.error("Registration error: Incorrect repository info %s" % (repo))
            return False
        repo_server, repo_repo, repo_name = repo_split[0], repo_split[1], repo_split[2]
        # Get current repo configuration
        repo_files = glob.glob(fwglobals.g.REPO_SOURCE_DIR + "flexiwan*")
        if len(repo_files) != 1:
            self.log.error("Registration error: Folder %s must include a single repository file, found %d" %
                (fwglobals.g.REPO_SOURCE_DIR, len(repo_files)))
            return False
        repo_file = repo_files[0]
        with open(repo_file, 'r') as f:
            repo_config = f.readline().strip()
        # format of repo_config is, get all parameters
        # deb [ arch=amd64 ] https://deb.flexiwan.com/flexiWAN bionic main
        repo_match = re.match(r'^deb[ \t]+\[[ \t]+arch=(.+)[ \t]+\][ \t]+(http.*)/(.+)[ \t]+(.+)[ \t]+(.+)$',
            repo_config)
        if not repo_match:
            self.log.error("Registration error: repository configuration can't be parsed. File=%s, Config=%s" %
                (repo_file, repo_config))
            return False
        (found_arch, found_server, found_repo, found_distro, found_name) = repo_match.group(1,2,3,4,5)
        # Check if not the same as configured
        if (found_server != repo_server or found_repo != repo_repo or found_name != repo_name):
            new_repo_config = "deb [ arch=%s ] %s/%s %s %s\n" % (found_arch, repo_server, repo_repo, found_distro, repo_name)
            with open(repo_file, 'w') as f:
                fwutils.file_write_and_flush(f, new_repo_config)
            self.log.info("Overwriting repository from token, token_repo=%s, prev_repo_config=%s, new_repo_config=%s" %
                (repo, repo_config, new_repo_config))
        return True

    def _decode_token_and_setup_environment(self, token):
        """Decode token and setup environment variables if required.
        The environment setup is needed when the non default flexiManage server is used.
        This could be on test, a dedicated, or a self hosting flexiManage setup.
        After installing the flexiEdge software, it contains the default server and repository.
        The software can be installed as a debian install on Linux, an ISO installation or,
        pre installed by the hardware vendor.
        In this case the server and repository flexiEdge has are different than what should be used.
        The token is generated in flexiManage and installed on the device.
        The token may encode the server and the repository parameters.
        When the token is installed on flexiEdge, we check the server and repository decoded and
        setup the system accordingly.
        We call this function before registration when the token file is first processed

        :returns: `True` if succeeded, `False` otherwise.
        """
        parsed_token = jwt.decode(token, options={"verify_signature": False})

        # If repository defined in token, make sure device works with that repo
        # Repo is sent if device is connected to a flexiManage that doesn't work with
        # the default flexiWAN repository
        repo = parsed_token.get('repo')
        if repo:
            if not self._setup_repository(repo): return False

        # Setup the flexiManage server to work with
        server = parsed_token.get('server')
        if server:
            # Use server from token
            fwglobals.g.cfg.MANAGEMENT_URL = server
            self.log.info("Using management url from token: %s" % (server))

        # Setup passed, return True
        return True

    def is_registered(self):
        """Check if agent is already registered with the flexiManage.

        :returns: `True` if registered, `False` otherwise.
        """
        if os.path.exists(fwglobals.g.DEVICE_TOKEN_FILE):
            return True
        return False

    def register(self, machine_id=None):
        """Registers device with the flexiManage.
        To do that the Fwagent establishes secure HTTP connection to the manager
        and sends GET request with various data regarding device.
        When user approves device on manager, the Fwagent establishes secure
        WebSocket connection to the manager and starts to listen for flexiManage
        requests.

        :returns: device token obtained during successfull registration.
        """
        self.log.info("registering with flexiManage...")

        self.register_error = ''

        try:
            with open(fwglobals.g.cfg.TOKEN_FILE, 'r') as f:
                self.token = f.readline().strip()
        except:
            err = "register: failed to load token from %s: %s (%s)" % \
                (fwglobals.g.cfg.TOKEN_FILE, format(sys.exc_info()[1]),  format(sys.exc_info()[0]))
            self.log.error(err)
            return None

        # Token found, decode token and setup environment parameters from token
        try:
            if not self._decode_token_and_setup_environment(self.token):
                return None
        except Exception as e:
            self.log.excep("Failed to decode and setup environment: %s (%s)" %(str(e), traceback.format_exc()))
            return None

        if fwutils.vpp_does_run():
            self.log.error("register: router is running, it by 'fwagent stop' and retry by 'fwagent start'")
            return None

        if not machine_id:
            machine_id = fwutils.get_machine_id()
            if not machine_id:
                self.log.error("register: get_machine_id failed, make sure you're running in sudo privileges")
                return None

        machine_name = socket.gethostname()
        all_ip_list = socket.gethostbyname_ex(machine_name)[2]
        interfaces          = list(fwutils.get_linux_interfaces(cached=False).values())
        (dr_via, dr_dev, _, _) = fwutils.get_default_route()
        # get up to 4 IPs
        ip_list = ', '.join(all_ip_list[0:min(4,len(all_ip_list))])
        serial = fwutils.get_machine_serial()
        url = fwglobals.g.cfg.MANAGEMENT_URL  + "/api/connect/register"

        data = {'token': self.token.rstrip(),
                'fwagent_version' : self.versions['components']['agent']['version'],
                'router_version' : self.versions['components']['router']['version'],
                'device_version' : self.versions['device'],
                'machine_id' : machine_id,
                'serial' : serial,
                'machine_name': machine_name,
                'ip_list': ip_list,
                'default_route': dr_via,
                'default_dev': dr_dev,
                'interfaces': interfaces
        }
        self.log.debug("Registering to %s with: %s" % (url, json.dumps(data)))
        data.update({'interfaces': json.dumps(interfaces)})
        data = uparse.urlencode(data).encode()
        req = ureq.Request(url, data)
        ctx = ssl.create_default_context()
        if fwglobals.g.cfg.BYPASS_CERT:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            resp = ureq.urlopen(req, context=ctx)
            device_token = resp.read().decode()
            self.log.info("Registation successful with parameters:")
            self.log.info("  Hostname:  " + machine_name)
            self.log.info("  IP List:   " + ip_list)
            self.log.info("  Device ID: " + machine_id)
            self.log.info("Run connect after approving device in flexiManage")
            return device_token

        except uerr.URLError as e:
            if hasattr(e, 'code'):
                server_response = e.read().decode()
                latestVersion = e.headers.get('latestVersion','None')
                self.log.error('register: got %s - %s' % (str(e.code), hsvr.BaseHTTPRequestHandler.responses[e.code][0]))
                self.log.error('register: Server response: %s' % server_response)
                self.log.error('latestVersion: %s' % (latestVersion))
                try:
                    register_response = json.loads(server_response)
                    if 'error' in register_response:
                        self.register_error = register_response['error'].lower()
                except:
                    pass
                if e.code == 403: # version too low, try to upgrade immediately
                    self.log.error('Trying device auto upgrade...')
                    fwglobals.g.handle_request({'message':'upgrade-device-sw','params':{'version':latestVersion}})
            elif hasattr(e, 'reason'):
                self.log.error('register: failed to connect to %s: %s' % (fwglobals.g.cfg.MANAGEMENT_URL, e.reason))
            return None
        except:
            self.log.error('register: failed to send request to server %s: %s' % \
                        (fwglobals.g.cfg.MANAGEMENT_URL, format(sys.exc_info()[1])))
            return None

    def connect(self, machine_id=None, device_token=None):
        """Establishes the main WebSocket connection between device and manager,
        on which Fwagent receives manager requests, and enters into the infinite
        event loop on it.

        :param machine_id:   the UUID of the device to be used for connection
        :param device_token: the device token obtained during registration

        :returns: `True` if connection was established and than was closed gracefully,
                  `False` otherwise.
        """
        self.log.info("connecting to flexiManage...")

        self.connection_error_code = 0

        try:
            if not machine_id:
                machine_id = fwutils.get_machine_id()
                if machine_id == None:
                    raise Exception("failed to retrieve UUID")

            if not device_token:   # If device token was not provided, load it from file
                with open(fwglobals.g.DEVICE_TOKEN_FILE, 'r') as fin:
                    device_token = fin.readline()
            device_token_data = json.loads(device_token)

            url = "wss://%s/%s?token=%s" % (device_token_data['server'], machine_id, device_token_data['deviceToken'])
            headers = {
                "User-Agent": "fwagent/%s" % (self.versions['components']['agent']['version'])
            }

            self.ws.connect(url, headers = headers, check_certificate=(not fwglobals.g.cfg.BYPASS_CERT))
            self.ws.run_loop_send_recv(timeout=30)                 # flexiManage should send 'get-device-stats' every 10 sec
            self.log.info("connection to flexiManage was closed")  # ws is disconnected implicitly by run_send_recv_loop()
            return True

        except Exception as e:
            error = str(e)
            if 'status_code' in dir(e):   # see https://pypi.org/project/websocket-client/ for format of 'e'
                self.connection_error_code = e.status_code
                if e.status_code == fwglobals.g.WS_STATUS_ERROR_NOT_APPROVED:
                    error  = "not approved"
            else:
                self.connection_error_code = fwglobals.g.WS_STATUS_ERROR_LOCAL_ERROR
            self.log.error(f"connect: {error}")

            # Create a file to signal the upgrade process that the
            # upgraded agent failed to connect to the management.
            #
            self._mark_connection_failure(error)
            return False


    def reconnect(self):
        """Closes and reestablishes the main WebSocket connection between
        device and manager, on which Fwagent receives manager requests.
        When WAN address or default route are changed, the connection might
        loose connectivity, while relying on TCP/WebSocket keep-alive mechanism
        to detect that. That might take up to few minutes! As we have full
        control of device IPs and routes, we can short the connection down period
        significantly by enforcing connection re-establishment.
        This function closes the current connection and opens the new one.
        """
        if self.ws == None:
            self.log.info("flexiManage is not connected, ignore reconnection request")
        elif self.reconnecting:
            self.log.info("reconnection to flexiManage was initiated already")
        else:
            self.log.info("initiate reconnection to flexiManage")
            self.reconnecting = True
            self.ws.disconnect()
            # The new connection will be opened by the FwagentDaemon object from
            # within the connection loop, when the current connection
            # will be closed gracefully.


    def _on_close(self):
        """Websocket connection close handler

        :param ws:  Websocket handler.

        :returns: None.
        """
        self.log.info("_on_close: connection to flexiManage is closed")
        if self.thread_statistics:
            self.connected = False
            self.thread_statistics.join()

    def _on_open(self):
        """Websocket connection open handler

        :param ws:  Websocket handler.

        :returns: None.
        """
        self.log.info("connected to flexiManage")

        self.connected    = True
        self.reconnecting = False
        self._clean_connection_failure()

        # Send pending message replies to the flexiManage upon connection reopen.
        # These are replies to messages that might have cause the connection
        # to the flexiManage to disconnect, and thus have to be sent on the new connection.
        if len(self.pending_msg_replies) > 0:
            self.log.info("_on_open: send %d pending replies to flexiManage" % len(self.pending_msg_replies))
            for reply in self.pending_msg_replies:
                self.log.debug("_on_open: sending reply: " + json.dumps(reply))
                self.ws.send(json.dumps(reply))
            del self.pending_msg_replies[:]

        self.thread_statistics = threading.Thread(
                                    target=fwstats.update_stats_tread,
                                    name='Statistics Thread', args=(self.log, self))
        self.thread_statistics.start()

        if not fwutils.vpp_does_run():
            self.log.info("connect: router is not running, start it in flexiManage")


    def _on_message(self, message):
        """Websocket received message handler.
        This callbacks invokes global handler of the received request defined
        in the fwglobals.py module, gets back the response from the global
        handler and sends it back to the server. The global handler dispatches
        requests to appropriate request handlers. It is implemented
        in the fwglobals.py module.

        :param ws:       Websocket handler.
        :param message:  Message instance.

        :returns: None.
        """
        pmsg    = json.loads(message)
        request = pmsg['msg']
        seq     = str(pmsg['seq'])              # Sequence number of the received message
        job_id  = str(pmsg.get('jobid',''))     # ID of job on flexiManage that sent this message

        self.log.debug(seq + " job_id=" + job_id + " request=" + json.dumps(request))

        # In load simulator mode always reply ok on sync message
        if fwglobals.g.loadsimulator and request["message"] == "sync-device":
            reply = {"ok":1}
        else:
            reply = self.handle_received_request(request)

        reply_str = reply if 'message' in request and not re.match('get-device-(logs|packet-traces)', request['message']) else {"ok":1}
        self.log.debug(seq + " job_id=" + job_id + " reply=" + json.dumps(reply_str))

        # Messages that change the interfaces might break the existing connection
        # (for example, if the WAN interface IP/mask has changed). Since sending
        # the reply on a broken connection will not work, we close the connection
        # before sending the reply and save the reply into pending queue.
        # Later, when daemon re-opens the new connection by connection loop,
        # we will pop the reply out of queue and will send it to the flexiManage.
        #
        if self.reconnecting == True:
            self.log.info("_on_message: goes to reestablish connection, queue reply %s" % str(pmsg['seq']))
            self.pending_msg_replies.append({'seq':pmsg['seq'], 'msg':reply})
        else:
            self.ws.send(json.dumps({'seq':pmsg['seq'], 'msg':reply}))

    def disconnect(self):
        """Shutdowns the WebSocket connection.

        :returns: None.
        """
        if self.ws:
            self.ws.disconnect()

    def handle_received_request(self, received_msg):
        """Handles received request: invokes the global request handler
        while logging the request and the response returned by the global
        request handler. Note the global request handler is implemented
        in the fwglobals.py module. It dispatches requests to the appropriate
        request handlers.

        :param received_msg:  the receive instance.

        :returns: (reply, msg), where reply is reply to be sent back to server,
                  msg is normalized received message.
        """
        logger = None
        try:
            msg = fwutils.fix_received_message(received_msg)

            print_message = False if re.match('get-device-', msg['message']) else fwglobals.g.cfg.DEBUG

            # 'add-application' request is huge, so we log it into dedicated file.
            # This is in addition to log into default file, where lines are truncated to 4K.
            #
            logger = fwglobals.g.get_logger(msg)

            if print_message:
                log_line = "handle_received_request:request\n" + json.dumps(msg, sort_keys=True, indent=1)
                self.log.debug(log_line)
                if logger:
                    logger.debug(log_line)

            reply = fwglobals.g.handle_request(msg, received_msg=received_msg)
            if not 'entity' in reply and 'entity' in msg:
                reply.update({'entity': msg['entity'] + 'Reply'})
            if not 'message' in reply:
                reply.update({'message': 'success'})

            if print_message:
                log_line = "handle_received_request:reply\n" + json.dumps(reply, sort_keys=True, indent=1)
                self.log.debug(log_line)
                if logger:
                    logger.debug(log_line)

        except Exception as e:
             self.log.error("handle_received_request failed: %s" + str(e))
             return {'ok': 0, 'message': str(e)}
        return reply

    def inject_requests(self, filename, ignore_errors=False, json_requests=None):
        """Injects requests loaded from within 'file' JSON file,
        thus simulating receiving requests over network from the flexiManage.
        This function is used for Unit Testing.

        :param filename:      name of the JSON file, were from to load requests.

        :param ignore_errors: if False, failure to inject some of the loaded
                              requests will cause this function to return, so
                              rest of loaded requests will be not executed.
        :returns: N/A.
        """
        self.log.debug("inject_requests(filename=%s, ignore_errors=%s)" % \
            (filename, str(ignore_errors)))

        if json_requests:
            requests = json.loads(json_requests)
        else:
            with open(filename, 'r') as f:
                requests = json.loads(f.read())

        if type(requests) is list:   # Take care of file with list of requests
            for (idx, req) in enumerate(requests):
                reply = self.handle_received_request(req)
                if reply['ok'] == 0 and ignore_errors == False:
                    raise Exception('failed to inject request #%d in %s: %s' % \
                                    ((idx+1), filename, reply['message']))
            return None
        else:   # Take care of file with single request
            reply = self.handle_received_request(requests)
            if reply['ok'] == 0:
                raise Exception('failed to inject request from within %s: %s' % \
                                (filename, reply['message']))
            return reply

def version():
    """Handles 'fwagent version' command.

    :returns: None.
    """
    with open(fwglobals.g.VERSIONS_FILE, 'r') as stream:
        versions = yaml.load(stream, Loader=yaml.BaseLoader)

        # Find the longest name of component
        width = 0
        for component in versions['components']:
            if len(component) > width:
                width = len(component)
        delimiter = '-' * (width + 10)

        print(delimiter)
        print('Device %s' % versions['device'])
        print(delimiter)
        for component in sorted(list(versions['components'].keys())):
            print('%s %s' % (component.ljust(width), versions['components'][component]['version']))
        print(delimiter)

def dump(filename, path, clean_log):
    fwutils.dump(filename=filename, path=path, clean_log=clean_log)

def reset(soft=False, quiet=False):
    """Handles 'fwagent reset' command.
    Resets device to the initial state. Once reset, the device MUST go through
    the registration procedure.

    :param soft:  Soft reset: resets router configuration only.
                  No re-registration is needed.
    :param quiet: Quiet reset: resets router configuration without confirmation
                  of device deletion in management.

    :returns: None.
    """
    # prevent reset configuration when vpp is run
    if fwutils.vpp_does_run() and soft:
        print("Router must be stopped in order to reset the configuration")
        return

    if soft:
        fwutils.reset_device_config()
        return

    with fwikev2.FwIKEv2() as ike:
        ike.reset()

    reset_device = True
    if not quiet:
        CSTART = "\x1b[0;30;43m"
        CEND = "\x1b[0m"
        choice = input(CSTART + "Device must be deleted in flexiManage before resetting the agent. " +
                        "Already deleted in flexiManage y/n [n]" + CEND)
        if choice != 'y' and choice != 'Y':
            reset_device = False

    if reset_device:
        if fwutils.vpp_does_run():
            print("stopping the router...")
        daemon_rpc('stop', stop_router=True)
        fwutils.reset_device_config()

        if os.path.exists(fwglobals.g.DEVICE_TOKEN_FILE):
            os.remove(fwglobals.g.DEVICE_TOKEN_FILE)

        # stop LTE connections
        lte_interfaces = fwutils.get_lte_interfaces_dev_ids()
        for dev_id in lte_interfaces:
            fwutils.lte_disconnect(dev_id, False)

        fwglobals.log.info("Reset operation done")
    else:
        fwglobals.log.info("Reset operation aborted")
    daemon_rpc('start')     # Start daemon main loop if daemon is alive

def stop(reset_device_config, stop_router):
    """Handles 'fwagent stop' command.
    Stops the infinite connection loop run by Fwagent in daemon mode.
    See documentation on FwagentDaemon class.

    :param reset_device_config:  Reset device configuration.
    :param stop_router:          Stop router, thus disabling packet routing.

    :returns: None.
    """
    fwglobals.log.info("stopping router...")
    try:
        daemon_rpc('stop', stop_router=stop_router)
    except:
        # If failed to stop, kill vpp from shell and get interfaces back to Linux
        if stop_router:
            fwglobals.log.excep("failed to stop vpp gracefully, kill it")
            fwutils.stop_vpp()

    if reset_device_config:
        fwutils.reset_device_config()
    fwglobals.log.info("done")

def start(start_router):
    """Handles 'fwagent start' command.
    Starts the infinite connection loop run by Fwagent in daemon mode.
    See documentation on FwagentDaemon class.

    :param start_router:  Start router, while applying router configuration.

    :returns: None.
    """
    fwglobals.log.info("start router...")
    daemon_rpc('start', start_vpp=start_router) # if daemon runs, start connection loop and router if required
    fwglobals.log.info("done")

def show(agent, configuration, database, status):
    """Handles 'fwagent show' command.
    This commands prints various information about device and it's components,
    like router configuration, software version, etc.
    For full list of available options to show use 'fwagent --help'.

    :param agent:          Agent information.
    :param configuration:  Configuration information.
    :param database:       Databases information.
    :param status:         Status information.

    :returns: None.
    """

    if configuration:
        if configuration == 'all':
            fwutils.print_router_config()
            fwutils.print_system_config()
        elif configuration == 'router':
            fwutils.print_router_config()
        elif configuration == 'system':
            fwutils.print_system_config()
        elif configuration == 'multilink-policy':
            fwutils.print_router_config(basic=False, multilink=True)
        elif configuration == 'signature':
            fwutils.print_device_config_signature()

    if agent:
        out = daemon_rpc('show', what=agent)
        if out:
            print(out)

    if database:
        if database == 'router':
            fwutils.print_router_config(full=True)
        elif database == 'system':
            fwutils.print_system_config(full=True)
        elif database == 'general':
            fwutils.print_general_database()
        elif database == 'multilink':
            with fwmultilink.FwMultilink(fwglobals.g.MULTILINK_DB_FILE, fill_if_empty=False) as multilink_db:
                print(multilink_db.dumps())

    if status:
        if status == 'daemon':
            try:
                daemon = Pyro4.Proxy(fwglobals.g.FWAGENT_DAEMON_URI)
                daemon.ping()   # Check if daemon runs
                fwglobals.log.info("running")
            except Pyro4.errors.CommunicationError:
                fwglobals.log.info("not running")
        elif status == 'router':
            fwglobals.log.info('Router state: %s (%s)' % (fwutils.get_router_state()[0], fwutils.get_router_state()[1]))

@Pyro4.expose
class FwagentDaemon(FwObject):
    """This class implements abstraction of Fwagent that runs in daemon mode.
    When the Fwagent runs as a daemon, someone has to create it and to invoke
    registration, connection and other Fwagent functionality, while keeping
    the Fwagent connected to flexiManage. These tasks are performed
    by the FwagentDaemon object.
    So the FwagentDaemon is responsible for:
        1. Creation and configuration the Fwagent object
        2. Running infinite loop of the Fwagent registration & WebSocket
           connection retrials, named the 'main daemon loop'.
        3. Listening for CLI commands that effect on the main daemon loop,
           like 'fwagent start', 'fwagent stop', etc.
        4. Listening for CLI commands that are designated for the Fwagent object
           itself and proxying them to it.

    The FwagentDaemon object is created by the 'fwagent daemon' command.
    """
    def __init__(self, standalone=False):
        """Constructor method.

        :param standalone: if True, the agent will be not connected to flexiManage,
                           hence no need in network activity, like STUN.
                           The standalone mode is used by CLI-based tests.
        """
        FwObject.__init__(self)

        self.agent          = None
        self.active         = False
        self.thread_main    = None
        self.standalone     = standalone

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT,  self._signal_handler)

    def _signal_handler(self, signum, frame):
        self.log.info("got %s" % fwglobals.g.signal_names[signum])
        exit(1)

    def __enter__(self):
        self.agent = fwglobals.g.initialize_agent(standalone=self.standalone)
        return self

    def __exit__(self, exc_type, exc_value, tb):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.log.debug("goes to exit")
        self.stop(stop_router=False)  # Keep VPP running to continue packet routing. To stop is use 'fwagent stop'
        fwglobals.g.finalize_agent()
        self.agent = None
        self.log.debug("exited")

    def _check_system(self):
        """Check system requirements.

        :returns: None.
        """
        root = os.path.dirname(os.path.realpath(__file__))
        checker = os.path.join(root, 'tools' , 'system_checker' , 'fwsystem_checker.py')
        try:
            subprocess.check_call(['python3' , checker , '--check_only'])
            return True
        except subprocess.CalledProcessError as err:
            self.log.excep("+====================================================")
            self.log.excep("| System checker failed (%d)" % err.returncode)
            self.log.excep("| Fix problems and run 'fwagent start'")
            self.log.excep("| To check and configure system run 'fwsystem_checker'")
            self.log.excep("+=====================================================")
            return False

    def ping(self):
        self.log.debug("ping: alive")

    def start(self, start_vpp=False, check_system=True):
        """Starts the main daemon loop.
        The main daemon loop keeps Fwagent connected to flexiManage.
        To stop registration/connection retrials use the 'fwagent stop' command.

        :param start_vpp:       Start router, while applying configuration to it.
        :param check_system:    Check system requirements.

        :returns: None.
        """
        self.log.debug("start (start_vpp=%s)" % str(start_vpp))

        if self.active:
            self.log.debug("already started, ignore")
            return

        # Reload configuration.
        fwglobals.g.load_configuration_from_file()

        # Ensure system compatibility with our soft
        if check_system and fwglobals.g.router_api.state_is_started():
            check_system = False    # No need to check system if VPP runs, it is too late :)
        if check_system and self._check_system() == False:
            self.log.excep("system checker failed")

        if start_vpp:
            try:
                fwglobals.g.router_api.start_router()
                self.log.debug("vpp started")
            except Exception as e:
                self.log.excep("failed to start vpp: " + str(e))
                return
        self.active  = True
        self.thread_main = threading.Thread(target=self.main, name='FwagentDaemon Main Thread')
        self.thread_main.start()
        self.log.debug("started")

    def stop(self, stop_router=True):
        """Stop main daemon loop.
        Once stopped, no more registration or connection retrials are performed.
        To resume registration/connection use the 'fwagent start' command.

        :param stop_router: Stop router, thus cheesing the packet routing.

        :returns: None.
        """
        self.log.debug("stop")

        # Initiate connection shutdown
        if self.active:
            self.active = False
            self.agent.disconnect()  # Break WebSocket connection event loop to get control back to main()
            self.log.debug("disconnect from server was initiated")
        # Stop vpp ASAP, as no more requests can arrive on connection
        if stop_router:
            try:
                fwglobals.g.handle_request({'message':'stop-router'})
                self.log.debug("router stopped")
            except Exception as e:
                self.log.excep("failed to stop router: " + str(e))
        elif fwglobals.g.router_api.state_is_started():
            self.log.debug("vpp alive, use 'fwagent stop' to stop it")
        # Stop main connection loop
        if self.thread_main:
            self.thread_main.join()
            self.thread_main = None

        self.log.debug("stopped")

    def reset(self):
        """Restart the main daemon loop.

        :returns: None.
        """
        self.log.debug("reset")
        self.stop()
        self.start()

    def show(self, what=None):
        if what == 'version':
            return fwutils.get_device_versions(fwglobals.g.VERSIONS_FILE)['components']['agent']['version']
        if what == 'cache':
            return json.dumps(fwglobals.g.cache.db, indent=2, sort_keys=True, default=lambda x: x.__dict__)
        if what == 'threads':
            thread_list = []
            for thd in threading.enumerate():
                thread_list.append(thd.name)
            return json.dumps(sorted(thread_list), indent=2, sort_keys=True)


    def main(self):
        """Implementation of the main daemon loop.
        The main daemon loop keeps Fwagent registered and connected to flexiManage.

        :returns: None.
        """
        self.log.debug(f"tid={fwutils.get_thread_tid()}: {threading.current_thread().name}")

        self.log.info("connection loop was started, use 'fwagent stop' to stop it if needed")

        # Register with Manager if needed
        # -------------------------------------
        if self.agent.is_registered():
            self.log.info("already registered, to refresh run 'fwagent reset' and retry")
        else:
            prev_register_error = ''
            device_token = self.agent.register()
            while self.active and not device_token:
                # If registration failed due to invalid authentication token,
                # probe the token file in loop until it is modified.
                # Otherwise sleep random period and retry registration.
                if self.agent.register_error == 'token not found' or \
                self.agent.register_error == 'invalid token':
                    self.log.debug('poll %s for modification' % fwglobals.g.cfg.TOKEN_FILE)
                    token   = self.agent.token
                    elapsed = 0
                    while token == self.agent.token and self.active:
                        time.sleep(1)               # Check self.active every second to detect Ctrl-C as soon as possible
                        elapsed += 1
                        if (elapsed % 10) == 0:     # Check if token was updated every 10 seconds
                            with open(fwglobals.g.cfg.TOKEN_FILE, 'r') as f:
                                token = f.readline()
                    self.agent.token = token
                # If we got same registration reject twice - stop retrials
                elif self.agent.register_error != '' and \
                    self.agent.register_error == prev_register_error:
                    self.log.info("stop registration trials, use 'fwagent start' to resume")
                    self.active = False
                    return
                # Sleep a little bit and retry
                else:
                    prev_register_error = self.agent.register_error
                    retry_sec = random.randint(fwglobals.g.RETRY_INTERVAL_MIN, fwglobals.g.RETRY_INTERVAL_MAX)
                    self.log.info("retry registration in %d seconds" % retry_sec)
                    time.sleep(retry_sec)

                device_token = self.agent.register()

            # Store device token on disk, so no registration will be performed
            # on next daemon start.
            #
            with open(fwglobals.g.DEVICE_TOKEN_FILE, 'w') as f:
                fwutils.file_write_and_flush(f, device_token)

        # Establish main connection to Manager.
        # That start infinite receive-send loop in Fwagent::connect().
        # -------------------------------------
        while self.active:

            closed_gracefully = self.agent.connect()
            if not closed_gracefully and self.active:
                # If connection was closed by flexiManage because of not approved
                # device (reject 403), retry connection in few seconds.
                # Otherwise - in few minutes in order to prevent DoS attack.
                #
                if self.agent.connection_error_code in fwglobals.g.ws_reconnect_status_codes:
                    retry_sec = random.randint(fwglobals.g.RETRY_INTERVAL_MIN, fwglobals.g.RETRY_INTERVAL_MAX)
                else:
                    retry_sec = random.randint(fwglobals.g.RETRY_INTERVAL_LONG_MIN, fwglobals.g.RETRY_INTERVAL_LONG_MAX)
                self.log.info("retry connection in %d seconds" % retry_sec)
                while retry_sec > 0 and self.active:
                    time.sleep(1)   # Check self.active every second to detect Ctrl-C as soon as possible
                    retry_sec -= 1

        self.log.info("connection loop was stopped, use 'fwagent start' to start it again")


    def api(self, api_name, api_args=None):
        """Wrapper for Fwagent methods
        """
        if self.agent:
            api_func = getattr(self.agent, api_name)
            if api_args:
                ret = api_func(**api_args)
            else:
                ret = api_func()
            return ret

def daemon(standalone=False):
    """Handles 'fwagent daemon' command.
    This command runs Fwagent in daemon mode. It creates the wrapping
    FwagentDaemon object that manages the instance of the Fwagent class and
    keeps it registered and connected to flexiManage.
    For more info See documentation on FwagentDaemon class.

    :param standalone: if False the register-and-connect loop will not be started.

    :returns: None.
    """
    fwglobals.log.set_target(to_syslog=True, to_terminal=False)
    fwglobals.log.info("starting in daemon mode (standalone=%s)" % str(standalone))

    with FwagentDaemon(standalone) as agent_daemon:

        # Start the FwagentDaemon main function in separate thread as it is infinite,
        # and we need to get to Pyro4.Daemon.serveSimple() call to run rpc loop.
        if not standalone:
            agent_daemon.start()

        # Register FwagentDaemon object with Pyro framework and start Pyro request loop:
        # listen for rpc that invoke FwagentDaemon methods
        fwglobals.log.debug("going to listen on " + fwglobals.g.FWAGENT_DAEMON_URI)
        Pyro4.Daemon.serveSimple(
            {agent_daemon: fwglobals.g.FWAGENT_DAEMON_NAME},
            host=fwglobals.g.FWAGENT_DAEMON_HOST,
            port=fwglobals.g.FWAGENT_DAEMON_PORT,
            ns=False,
            verbose=False)

def daemon_rpc(func, **kwargs):
    """Wrapper for methods of the FwagentDaemon object that runs on background
    as a daemon. It is used to fullfil CLI commands that can be designated
    either to the FwagentDaemon object itself or to the Fwagent object managed
    by the FwagentDaemon. See for example 'fwagent start' command.

    :param func:      Name of FwagentDaemon method to be called.
    :param kwargs:    Method parameters.

    :returns: None.
    """
    try:
        agent_daemon = Pyro4.Proxy(fwglobals.g.FWAGENT_DAEMON_URI)
        remote_func = getattr(agent_daemon, func)
        fwglobals.log.debug("invoke remote FwagentDaemon::%s(%s)" % (func, json.dumps(kwargs)), to_terminal=False)
        return remote_func(**kwargs)
    except Pyro4.errors.CommunicationError:
        fwglobals.log.debug("ignore FwagentDaemon::%s(%s): daemon does not run" % (func, json.dumps(kwargs)))
        return None
    except Exception as e:
        fwglobals.log.debug("FwagentDaemon::%s(%s) failed: %s" % (func, json.dumps(kwargs), str(e)))
        ex_type, ex_value, ex_tb = sys.exc_info()
        Pyro4.util.excepthook(ex_type, ex_value, ex_tb)
        return None

def cli(clean_request_db=True, api=None, script_fname=None, template_fname=None, ignore_errors=False):
    """Handles 'fwagent cli' command.
    This command is not used in production. It assists unit testing.
    The 'fwagent cli' reads function names and their arguments from prompt and
    executes them on agent that runs in background. If no agent runs in
    background, the command creates new instance of it. When done, this instance
    is destroyed.
        The agent API to be invoked can be provided in one line with command,
    e.g. 'fwagent cli stop()'. In this case the command will not run prompt loop,
    but will execute this API and will exit immediately.
        To stop the read-n-execute loop just ^C it.

    :param clean_request_db:    Clean request database before return.
                                Effectively this flag resets the router configuration.
    :param api:                 The fwagent function to be executed in list format,
                                where the first element is api name, the rest
                                elements are api arguments.
                                e.g. [ 'inject_requests', 'requests.json' ].
                                If provided, no prompt loop will be run.
    :param script_fname:        Shortcat for --api==inject_requests(<script_fname>)
                                command. Is kept for backward compatibility.
    :param template_fname:      Path to template file that includes variables to replace in the cli request.
    :returns: None.
    """
    fwglobals.log.info("started in cli mode (clean_request_db=%s, api=%s, ignore_errors=%s)" % \
                        (str(clean_request_db), str(api), ignore_errors))

    # Preserve historical 'fwagent cli -f' option, as it involve less typing :)
    # Generate the 'api' value out of '-f/--script_file' value.
    if script_fname:
        # Convert relative path into absolute, as daemon fwagent might have
        # working directory other than the typed 'fwagent cli -f' command.
        script_fname = os.path.abspath(script_fname)
        api = ['inject_requests' , 'filename=%s' % script_fname ]
        if ignore_errors:
            api.append('ignore_errors=True')

        if template_fname:
            requests = fwutils.replace_file_variables(template_fname, script_fname)
            api.append('json_requests=%s' % json.dumps(requests, sort_keys=True))
            fwglobals.log.debug(
                "cli: generate 'api' out of 'script_fname' and 'template_fname': " + str(api))
        else:
            fwglobals.log.debug(
                "cli: generate 'api' out of 'script_fname': " + str(api))

    import fwagent_cli
    with fwagent_cli.FwagentCli() as cli:
        if api:
            ret = cli.execute(api)

            # We return dictionary with serialized return value of the invoked API,
            # so cli output can be parsed by invoker to extract the returned object.
            #
            if ret['succeeded']:
                if ret['return-value']:
                    ret_val = json.dumps(ret['return-value'])
                else:
                    ret_val = json.dumps({'ok': 1})
            else:
                ret_val = json.dumps({'ok': 0, 'error': ret['error']})
            fwglobals.log.info('return-value-start ' + ret_val + ' return-value-end')
        else:
            cli.run_loop()
    if clean_request_db:
        fwglobals.g.router_cfg.clean()


if __name__ == '__main__':
    import argcomplete
    import argparse

    fwglobals.initialize()

    command_functions = {
                    'version':lambda args: version(),
                    'reset': lambda args: reset(soft=args.soft, quiet=args.quiet),
                    'stop': lambda args: stop(reset_device_config=args.reset_softly, stop_router=(not args.dont_stop_vpp)),
                    'start': lambda args: start(start_router=args.start_router),
                    'daemon': lambda args: daemon(standalone=args.dont_connect),
                    'simulate': lambda args: loadsimulator.simulate(count=int(args.count)),
                    'dump': lambda args: dump(filename=args.filename, path=args.path, clean_log=args.clean_log),
                    'show': lambda args: show(
                        agent=args.agent,
                        configuration=args.configuration,
                        database=args.database,
                        status=args.status),
                    'cli': lambda args: cli(
                        script_fname=args.script_fname,
                        clean_request_db=args.clean,
                        api=args.api,
                        template_fname=args.template_fname,
                        ignore_errors=args.ignore_errors)}

    parser = argparse.ArgumentParser(
        description="Device Agent for FlexiWan orchestrator\n" + \
                    "--------------------------------------------------------------\n" + \
                    "Use 'fwagent.py <command> --help' for help on specific command",
        formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(help='Agent commands', dest='command')
    subparsers.required = True
    parser_version = subparsers.add_parser('version', help='show components and their versions')
    parser_reset = subparsers.add_parser('reset', help='Reset device: clear router configuration and remove device registration')
    parser_reset.add_argument('-s', '--soft', action='store_true',
                        help="clean router configuration only, device remains registered")
    parser_reset.add_argument('-q', '--quiet', action='store_true',
                        help="don't print info onto screen, print into syslog only")
    parser_stop = subparsers.add_parser('stop', help='Stop router and reset interfaces')
    parser_stop.add_argument('-s', '--reset_softly', action='store_true',
                        help="reset router softly: clean router configuration")
    parser_stop.add_argument('-r', '--dont_stop_vpp', action='store_true',
                        help="stop agent connection loop only")
    parser_stop.add_argument('-q', '--quiet', action='store_true',
                        help="don't print info onto screen, print into syslog only")
    parser_start = subparsers.add_parser('start', help='Resumes daemon connection loop if it was stopped by "fwagent stop"')
    parser_start.add_argument('-q', '--quiet', action='store_true',
                        help="don't print info onto screen, print into syslog only")
    parser_start.add_argument('-r', '--start_router', action='store_true',
                        help="start router before loop is started")
    parser_daemon = subparsers.add_parser('daemon', help='Run agent in daemon mode: infinite register-connect loop')
    parser_daemon.add_argument('-d', '--dont_connect', action='store_true',
                        help="Don't start connection loop on daemon start")
    parser_simulate = subparsers.add_parser('simulate', help='register and connect many fake devices with flexiManage')
    parser_simulate.add_argument('-c', '--count', dest='count',
                        help="How many devices to simulate")
    parser_show = subparsers.add_parser('show', help='Prints various information to stdout')
    parser_show.add_argument('--agent', choices=['version', 'cache', 'threads'],
                        help="show various agent parameters")
    parser_show.add_argument('--configuration', const='all', nargs='?',
                        choices=['all', 'router', 'system', 'multilink-policy', 'signature'],
                        help="show flexiEdge configuration")
    parser_show.add_argument('--database',
                        choices=['applications', 'general', 'multilink', 'router', 'system'],
                        help="show whole flexiEdge database")
    parser_show.add_argument('--status', choices=['daemon', 'router'],
                        help="show flexiEdge status")
    parser_cli = subparsers.add_parser('cli', help='runs agent in CLI mode: read flexiManage requests from command line')
    parser_cli.add_argument('-f', '--script_file', dest='script_fname', default=None,
                        help="File with requests to be executed")
    parser_cli.add_argument('-t', '--template', dest='template_fname', default=None,
                        help="File with substitutions for the script file, see -f")
    parser_cli.add_argument('-I', '--ignore_errors', dest='ignore_errors', action='store_true',
                        help="Ignore errors")
    parser_cli.add_argument('-c', '--clean', action='store_true',
                        help="clean request database on exit")
    parser_cli.add_argument('-i', '--api', dest='api', default=None, nargs='+',
                        help="fwagent API to be invoked with space separated arguments, e.g. '--api inject_requests request.json'")
                        # If arguments include spaces escape them with slash, e.g. "--api inject_requests my\ request.json"
                        # or surround argument with single quotes, e.g. "--api inject_requests 'my request.json'"
                        # Note we don't use circle brackets, e.g. "--api inject_requests(request.json)" to avoid bash confuse
    parser_dump = subparsers.add_parser('dump', help='Dump various system info into x.tar.gz file')
    parser_dump.add_argument('-f', '--file', dest='filename', default=None,
                        help="The name of the result archive file. Can be full path. The default is 'fwdump_<hostname>_<YYYYMMDD>_<HHMMSS>.tar.gz")
    parser_dump.add_argument('-p', '--path', dest='path', default=None,
                        help="The path to the final name. The default is %s" % fwglobals.g.DUMP_FOLDER)
    parser_dump.add_argument('-c', '--clean_log', action='store_true',
                        help="Clean agent log")
    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if hasattr(args, 'quiet') and args.quiet:
        fwglobals.log.set_target(to_syslog=True, to_terminal=False)

    if not args.command in [ 'show', 'version' ]:
        if not fwutils.check_root_access():
            sys.exit(1)

    fwglobals.log.debug("---> exec " + str(args), to_terminal=False)
    command_functions[args.command](args)
