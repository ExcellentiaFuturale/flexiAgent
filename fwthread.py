#! /usr/bin/python3

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

import threading
import time
import traceback

import fwglobals
import fwutils


class FwRouterThreading:
    def __init__(self):
        self.teardown         = False
        self.request_cond_var = threading.Condition()
        self.thread_names     = []
        self.handling_request = False

    def is_no_active_threads(self):
        return len(self.thread_names) == 0

class FwThread(threading.Thread):
    """Implements abstraction of monitoring thread.
    The monitoring thread wakes up every second, runs until the agent is not
    teared down and never exits on exception.
    """
    def __init__(self, target, name, log, args=(), kwargs={}):
        threading.Thread.__init__(self, target=None, name='FwThread ' + name, args=args, kwargs=kwargs)
        self.log            = log
        self.func           = target
        self.stop_called    = False

    def _thread_func(self, args, kwargs):
        self.log.debug(f"tid={fwutils.get_thread_tid()} ({self.getName()})")

        while not fwglobals.g.router_threads.teardown and not self.stop_called:
            time.sleep(1)
            try:
                self.func(*args, **kwargs)
            except Exception as e:
                self.log.error("%s: %s (%s)" % (self.getName(), str(e), traceback.format_exc()))

    def run(self):
        """Overrides the threading.Thread.run() function to enable calling
        the _thread_func() with arguments packed into () and {}. This is needed
        as user can create FwThread-s with different arguments, so _thread_func()
        definition can't match all use cases if arguments are unpacked.
        """
        self._thread_func(self._args, self._kwargs)

    def stop(self, block=True):
        """Enables other threads to break the _thread_func() main loop.
        This function should be used to stop & join threads that can be started
        and stopped during agent lifecycle, as the _thread_func() break condition
        'fwglobals.g.router_threads.teardown' is still True.

        :param block: if True, this function is blocked until thread function exits.
        """
        self.stop_called = True
        if block:
            self.join()

class FwRouterThread(FwThread):
    """Implements variation of monitoring thread, which does not run,
    if there is undergoing re-configuration of router. The reconfiguration
    happens when agent receives request from flexiManage.
    """
    def __init__(self, target, name, log, args=(), kwargs={}):
        FwThread.__init__(self, target=target, name=name, log=log, args=args, kwargs=kwargs)
        self.join_called = False

    def _thread_func(self, args, kwargs):
        self.log.debug(f"tid={fwutils.get_thread_tid()} ({self.getName()})")

        rt = fwglobals.g.router_threads
        while not rt.teardown and not self.stop_called:
            time.sleep(1)        # 1 sec ticks for monitoring functionality

            # 'request_cond_var' ensures there is no undergoing routing configuration
            #
            rt.request_cond_var.acquire()
            if self.join_called:     # Avoid deadlock when join() is called by request processing thread
                self.join_called = False
                rt.request_cond_var.release()
                return
            if rt.handling_request:  # Avoid starvation of request thread - skip this iteration
                rt.request_cond_var.release()
                continue
            rt.thread_names.append(self.getName())
            rt.request_cond_var.release()

            try:                      # 'try' prevents thread to exit on exception
                self.func(*args, **kwargs)
            except Exception as e:
                self.log.error("%s: %s (%s)" % (self.name, str(e), traceback.format_exc()))

            rt.request_cond_var.acquire()
            rt.thread_names.remove(self.getName())
            rt.request_cond_var.notify()
            rt.request_cond_var.release()

    def join(self):
        """Overrides the threading.Thread.join() function to avoid deadlock,
        when join() is called by the request processing thread, e.g. when
        monitoring threads are stopped on handling 'stop-router' request.
        In this case request processing thread takes the 'request_cond_var' lock
        and calls join(), when the monitoring thread might be blocked
        on the 'request_cond_var' lock while waiting the request processing thread
        to finish. To avoid deadlock the overriding join() does not block, but
        raises the flag. So the request processing thread with continue and will
        finish the request processing. The monitoring thread will check the flag
        as soon as it takes the lock. So it will exit at least on next iteration.
        """
        self.join_called= True
