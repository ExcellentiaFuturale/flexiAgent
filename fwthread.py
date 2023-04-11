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
        self.request_processing_thread_ident = None

    def is_no_active_threads(self):
        return len(self.thread_names) == 0

class FwThread(threading.Thread):
    """Implements abstraction of monitoring thread.
    The monitoring thread wakes up every second, runs until the agent is not
    teared down and never exits on exception.
    """
    def __init__(self, target, name, log, args=(), kwargs={}):
        my_name             = 'FwThread ' + name
        threading.Thread.__init__(self, target=None, name=my_name, args=args, kwargs=kwargs)
        self.tid            = ""
        self.log            = log
        self.func           = target
        self.stop_called    = False
        self.exiting        = False
        self.name           = my_name

    def _thread_func(self, args, kwargs):
        ticks = 0
        while not fwglobals.g.router_threads.teardown and not self.stop_called:
            time.sleep(1)
            ticks += 1
            try:
                self.func(ticks, *args, **kwargs)
            except Exception as e:
                self.log.error("%s: %s (%s)" % (self.getName(), str(e), traceback.format_exc()))

    def run(self):
        """Overrides the threading.Thread.run() function to enable calling
        the _thread_func() with arguments packed into () and {}. This is needed
        as user can create FwThread-s with different arguments, so _thread_func()
        definition can't match all use cases if arguments are unpacked.
        """
        self.tid = fwutils.get_thread_tid()
        self.log.debug(f"tid={self.tid}: {self.name}: started")

        self.exiting = False
        self._thread_func(self._args, self._kwargs)
        self.exiting = True

        self.log.debug(f"tid={self.tid}: {self.name}: stopped")
        self.ticks = 0

    def stop(self, block=True):
        """Enables other threads to break the _thread_func() main loop.
        This function should be used to stop & join threads that can be started
        and stopped during agent lifecycle, as the _thread_func() break condition
        'fwglobals.g.router_threads.teardown' is still True.

        :param block: if True, this function is blocked until thread function exits.
        """
        if self.exiting:
            return  # no need to print confusing 'stopping' for exited thread
        self.log.debug(f"tid={self.tid}: {self.name}: stopping (block={str(block)})")
        self.stop_called = True
        if block:
            self.join()

    def log_error(self, log_str):
        self.log.error(f"tid={self.tid}: {self.name}: {log_str}")

class FwRouterThread(FwThread):
    """Implements variation of monitoring thread, which does not run,
    if there is undergoing re-configuration of router. The reconfiguration
    happens when agent receives request from flexiManage.
    """
    def __init__(self, target, name, log, args=(), kwargs={}):
        FwThread.__init__(self, target=target, name=name, log=log, args=args, kwargs=kwargs)
        self.join_called = False

    def _thread_func(self, args, kwargs):
        ticks = 0
        rt = fwglobals.g.router_threads
        while not rt.teardown and not self.stop_called:
            time.sleep(1)        # 1 sec ticks for monitoring functionality
            ticks += 1

            # 'request_cond_var' ensures there is no undergoing routing configuration
            #
            rt.request_cond_var.acquire()
            if self.join_called:     # Avoid deadlock when join() is called by request processing thread
                self.join_called = False
                rt.request_cond_var.release()
                self.log.debug(f"tid={self.tid}: {self.name}: exit on join()")
                return
            if rt.handling_request:  # Avoid starvation of request thread - skip this iteration
                rt.request_cond_var.release()
                continue
            rt.thread_names.append(self.getName())
            rt.request_cond_var.release()

            try:                      # 'try' prevents thread to exit on exception
                self.func(ticks, *args, **kwargs)
            except Exception as e:
                self.log.error("%s: %s (%s)" % (self.name, str(e), traceback.format_exc()))

            rt.request_cond_var.acquire()
            rt.thread_names.remove(self.getName())
            rt.request_cond_var.notify()
            rt.request_cond_var.release()

    def join(self):
        """Overrides the threading.Thread.join() function to avoid deadlock,
        when the request processing thread calls the monitoring thread's join(),
        e.g. on handling 'stop-router' request.
        In this case request processing thread takes the 'request_cond_var' lock
        and calls <monitoring thread>.join(), when the monitoring thread might
        be blocked on the 'request_cond_var' lock while waiting the request
        processing thread to finish. To avoid deadlock the overriding join()
        does not block, but raises the flag. So the request processing thread
        will be not blocked, will continue and will finish the request processing.
        The monitoring thread will check the flag as soon as it takes the lock.
        So, it will exit at most on next iteration.
        """
        if threading.current_thread().ident == fwglobals.g.router_threads.request_processing_thread_ident:
            self.join_called = True
        else:
            FwThread.join(self)

def set_request_processing_thread():
    fwglobals.g.router_threads.request_processing_thread_ident = threading.current_thread().ident

def unset_request_processing_thread():
    fwglobals.g.router_threads.request_processing_thread_ident = None
