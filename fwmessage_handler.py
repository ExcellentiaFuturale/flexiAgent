#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2023  flexiWAN Ltd.
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
import fwthread
import fwutils

import queue
from functools import partial
import traceback
import json
import re

from fwobject import FwObject

class FwMessageHandler(FwObject):
    """This class handles requests received from flexiManage and
    retrieves replies for previously received requests that were processed
    asynchronously.
    """

    def __init__(self):
        """Constructor method.
        """
        FwObject.__init__(self)

        self.queue_incoming_messages = queue.Queue(maxsize=100)    # 100 should be more than enough: most requests are sequential on flexiManage
        self.queue_outgoing_messages = queue.Queue()
        self.thread_handle_messages  = fwthread.FwThread(
                                            target=self.thread_handle_messages_func,
                                            name='Message Receiver',
                                            log=self.log)

    def initialize(self):
        self.thread_handle_messages.start()
        fwthread.set_request_processing_thread(self.thread_handle_messages.ident)

    def finalize(self):
        fwthread.unset_request_processing_thread(self.thread_handle_messages.ident)
        self.thread_handle_messages.stop()

    def handle_incoming_message(self, incoming_msg=None):
        """Handles request received from flexiManage.

        :param incoming_msg: the received message in following format:
                            {
                                'seq':  12345
                                'jobid: 6789    // optional, might not exist
                                'msg': {
                                    "message": "add-route",
                                    "params": {
                                        "addr": "9.9.9.9",
                                        "via": "192.168.56.154",
                                        "dev_id":"pci:0000:02:00.0"
                                    }
                                }
                            }
                            The 'incoming_msg' might be None. In that case this
                            function just retrieves the asynchronous replies for
                            the messages that were received earlier.

        :returns: list of replies to be sent to flexiManage.
                  This list might include reply to the 'incoming_msg' message,
                  if it was processes synchronously.
                  As well, the list might include replies for the messages
                  received earlier that were processed asynchronously.
                  Format of the replies in this list is as follows:
                            {
                                'seq': 12345
                                'msg': {
                                    "ok":      [0|1]
                                    "message": <dict or error string or ''>
                                }
                            }

        """
        outgoing_messages = []
        try:
            if incoming_msg:
                incoming_msg.update({'request': fwutils.fix_received_message(incoming_msg['msg'])})
                self._log_request(incoming_msg)

                # Non configuration requests, like 'exec_timeout' are supposed
                # to be processed quickly and should have no impact
                # on monitoring or configuring threads, so we just inject them
                # directly into global request handler, thus bypassing both
                # the received message queue (self.queue_incoming_messages)
                # and thread suspending mechanism (see self._handle_received_request()).
                #
                request, original_request = incoming_msg['request'], incoming_msg['msg']
                processing = incoming_msg.get('processing')
                if not processing:
                    processing = fwglobals.request_handlers.get(request.get('message',''),{}).get('processing')
                bypass_queue = processing.get('synchronous', False) if processing else False
                lock_system  = processing.get('exclusive', True)    if processing else True

                self.log.debug(incoming_msg['log_prefix'] + f"bypass_queue={bypass_queue}, lock_system={lock_system}")

                if bypass_queue:
                    fwthread.set_request_processing_thread()
                    reply = fwglobals.g.handle_request(request, original_request, lock_system)
                    fwthread.unset_request_processing_thread()
                    incoming_msg.update({'reply': reply})
                    outgoing_messages.append(incoming_msg)
                else:
                    try:
                        self.queue_incoming_messages.put_nowait(incoming_msg)
                    except (queue.Full, Exception) as e:
                        if isinstance(e, queue.Full):
                            err_str = 'flexiEdge message queue is full'
                            self.log.error(f"handle_incoming_message: {err_str}")
                        else:
                            err_str = f"handle_incoming_message: on pushing requests: {str(e)}"
                            self.log.error(err_str)
                        fwglobals.g.jobs.add_record(incoming_msg.get('jobid'), {'error': err_str})
                        incoming_msg.update({'reply': { 'ok':0, 'message': err_str }})
                        outgoing_messages.append(incoming_msg)

            # Fetch ready-to-send replies
            try:
                while not fwglobals.g.router_threads.teardown:
                    msg = self.queue_outgoing_messages.get_nowait()
                    outgoing_messages.append(msg)
            except queue.Empty:
                pass
            except Exception as e:
                err_str = f"handle_incoming_message: on popping replies: {str(e)}"
                if incoming_msg:
                    fwglobals.g.jobs.add_record(incoming_msg.get('jobid'), {'error': err_str})
                self.log.error(err_str)
                pass

            # Log replies and convert them into format expected by flexiManage
            #
            final_outgoing_messages = []
            for msg in outgoing_messages:
                self._log_reply(msg)

                if not 'message' in msg['reply']:
                    msg['reply'].update({'message': 'success'})
                if not 'entity' in msg['reply'] and 'entity' in msg['request']:
                    msg['reply'].update({'entity': msg['request']['entity'] + 'Reply'})
                final_msg = {'seq': msg['seq'], 'msg': msg['reply']}

                final_outgoing_messages.append(final_msg)
            return final_outgoing_messages

        except Exception as e:
            self.log.excep("handle_incoming_message: %s%s" % {{str(e)}, ": "+json.dumps(incoming_msg) if incoming_msg else ""})
            return []

    def thread_handle_messages_func(self, ticks):

        while not fwglobals.g.router_threads.teardown:
            try:
                msg = self.queue_incoming_messages.get_nowait()
                fwglobals.g.jobs.start_recording(msg['jobid'], msg['request'])
                try:
                    msg['reply'] = self._handle_received_request(msg['request'], msg['msg'])
                except Exception as e:
                    err_str = f"thread_handle_messages_func: {str(e)} {traceback.format_exc()}"
                    fwglobals.g.jobs.update_job_error(err_str)
                    self.log.error(err_str)
                    msg['reply'] = {'ok':0, 'message': {'errors' : [err_str]}}
                fwglobals.g.jobs.stop_recording(msg['jobid'], msg['reply'])
                self.queue_outgoing_messages.put(msg)
            except queue.Empty:
                return
            except Exception as e:
                err_str = f"thread_handle_messages_func: {str(e)}"
                self.log.excep(err_str)
                return

    def _handle_received_request(self, request, original_request):
        '''Handles requests popped out of processing queue. Format of 'request'
        should match format of the 'msg' field of messages received from flexiManage:
                        {
                            "message": "add-route",
                            "params": {
                                "addr": "9.9.9.9",
                                "via": "192.168.56.154",
                                "dev_id":"pci:0000:02:00.0"
                            }
                        }
        :param request:          The request received from flexiManage after
                                 transformation by fwutils.fix_received_message().
        :param original_request: The original request received from flexiManage.

        :returns: dict with status code and either error string in case of
                  failure or dict with fetched info. For example,
                                {
                                    "ok":      0
                                    "message": "failed to assign interface"
                                }
        '''

        # We use 'request_cond_var' conditional variable to suspend monitoring
        # threads as long as handling of the configuration request received from
        # flexiManage is not finished.

        rt = fwglobals.g.router_threads
        with rt.request_cond_var:
            rt.handling_request = True

            if len(rt.thread_names) > 0:
                self.log.debug(f"_handle_received_request: wait for {rt.thread_names} threads to finish")
            rt.request_cond_var.wait_for(rt.is_no_active_threads)

            default_route_before = fwutils.get_default_route()

            reply = fwglobals.g.handle_request(request, original_request)

            default_route_after = fwutils.get_default_route()
            if default_route_before[2] != default_route_after[2]:  # reconnect the agent to avoid WebSocket timeout
                self.log.debug(f"reconnect as default route was changed: '{default_route_before}' -> '{default_route_after}'")
                fwglobals.g.fwagent.reconnect()

            rt.handling_request = False
            return reply

    def _log_request(self, msg):
        received_request    = msg['msg']
        fixed_request       = msg['request']
        log_fixed_request   = None

        log_prefix = f"seq={msg['seq']}: "
        if msg.get('jobid'):
            log_prefix += f"job_id={msg.get('jobid')}: "

        log_line = log_prefix + "request\n" + json.dumps(received_request, sort_keys=True, indent=1)
        self.log.debug(log_line)

        if received_request != fixed_request:
            log_fixed_request = "fixed\n" + json.dumps(fixed_request, sort_keys=True, indent=1)
            self.log.debug(log_fixed_request)

        # Some requests like 'add-application' are huge, so we log them into
        # dedicated file. This is in addition to logging into default file,
        # where lines are truncated to 4K.
        #
        logger = fwglobals.g.get_logger(fixed_request)
        if logger:
            logger.debug(log_line)
            if log_fixed_request:
                logger.debug(log_fixed_request)

        # Save temporary data for logging reply
        #
        msg.update({'log_prefix': log_prefix})
        msg.update({'logger':     logger })

    def _log_reply(self, msg):
        request     = msg['request']
        reply       = msg['reply']
        logger      = msg['logger']
        log_prefix  = msg['log_prefix']

        # Mask huge or security sensitive replies
        #
        if re.match('get-device-(logs|packet-traces)|exec', request.get('message',"")):
            reply = {"ok":1}

        log_line = log_prefix + "reply\n" + json.dumps(reply, sort_keys=True, indent=1, cls=fwutils.FwJsonEncoder)
        self.log.debug(log_line)
        if logger:
            logger.debug(log_line)
