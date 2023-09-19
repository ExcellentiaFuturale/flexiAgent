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

import threading
import uuid
import fwglobals
import random
import time
import signal

import fwagent

from fwstats import UPDATE_LIST_MAX_SIZE
from fwobject import FwObject

class LoadSimulator(FwObject):
    """This is a load simulator class.
       It is used to emulate a big number of fake devices.
    """
    def __init__(self):
        """Constructor method
        """
        FwObject.__init__(self)
        self.started = False
        self.simulate_agents = []
        self.simulate_threads = []
        self.simulate_stats = {'tx_pkts': 0, 'tx_bytes': 0, 'rx_bytes': 0, 'rx_pkts': 0}
        self.simulate_tunnel_stats = {"1": {"status": "up", "rtt": 10, "drop_rate": 0}}
        self.interface_wan = '0000:00:03.00'
        self.interface_lan = '0000:00:08.00'
        self.thread_statistics = None

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT,  self._signal_handler)

    def _signal_handler(self, signum, frame):
        self.log.info("got %s" % fwglobals.g.signal_names[signum])
        self.stop()

    def stop(self):
        """Stop simulated devices.

        :returns: None.
        """
        self.started = False

        for agent in self.simulate_agents:
            agent.disconnect()
        self.simulate_agents = []

        for t in self.simulate_threads:
            t.join()
        self.simulate_threads = []
        fwglobals.g.destroy_agent()



    def start(self, count):
        """Starts the simulation.

        :param count: number of the simulated devices.
        """
        # We have to initialize agent once, as it initializes various global data.
        # All the rest of simulated agents should be not initialized but created.
        #
        agent = fwglobals.g.create_agent()

        self.started = True
        for id in range(count):

            simulated_agent = agent if id==0 else None
            machine_id      = str(uuid.uuid1())

            t = threading.Thread(
                        target=self.device_thread,
                        name='Simulate Device Thread ' + str(id),
                        args=(simulated_agent, id, machine_id, ))
            self.simulate_threads.append(t)
            t.start()

        while self.started:
            time.sleep(1)


    def device_thread(self, simulated_agent, id, machine_id):
        """Simulates device - constructs agent, if not provided yet and runs register & connect loop.
        """
        agent = simulated_agent if simulated_agent else fwagent.FwAgent(handle_signals=False)

        self.simulate_agents.append(agent)

        device_token = agent.register(machine_id)
        while not device_token:
            retry_sec = random.randint(fwglobals.g.RETRY_INTERVAL_MIN, fwglobals.g.RETRY_INTERVAL_MAX)
            self.log.info(f"agent {id}: retry registration in {retry_sec} seconds")
            time.sleep(retry_sec)
            if not self.started:
                return
            device_token = agent.register(machine_id)

        self.log.info(f"agent {id}: registered")

        while not agent.connect(machine_id=machine_id, device_token=device_token) and self.started:
            retry_sec = random.randint(fwglobals.g.RETRY_INTERVAL_MIN, fwglobals.g.RETRY_INTERVAL_MAX)
            self.log.info(f"agent {id}: retry connection in {retry_sec} seconds")
            time.sleep(retry_sec)


    def update_stats(self):
        """Update fake statistics.

        :returns: None.
        """
        if not self.started:
            return

        self.simulate_stats['tx_pkts'] += 10
        self.simulate_stats['tx_bytes'] += 1000
        self.simulate_stats['rx_bytes'] += 2000
        self.simulate_stats['rx_pkts'] += 20

        new_stats = {'ok': 1,
                     'message': {self.interface_wan: dict(self.simulate_stats),
                                 self.interface_lan: dict(self.simulate_stats)}}

        if new_stats['ok'] == 1:
            fwstats = fwglobals.g.statistics
            prev_stats = dict(fwstats.stats)  # copy of prev stats
            fwstats.stats['time'] = time.time()
            fwstats.stats['last'] = new_stats['message']
            fwstats.stats['ok'] = 1
            # Update info if previous stats valid
            if prev_stats['ok'] == 1:
                if_bytes = {}
                for intf, counts in list(fwstats.stats['last'].items()):
                    prev_stats_if = prev_stats['last'].get(intf, None)
                    if prev_stats_if != None:
                        rx_bytes = 1.0 * (counts['rx_bytes'] - prev_stats_if['rx_bytes'])
                        rx_pkts = 1.0 * (counts['rx_pkts'] - prev_stats_if['rx_pkts'])
                        tx_bytes = 1.0 * (counts['tx_bytes'] - prev_stats_if['tx_bytes'])
                        tx_pkts = 1.0 * (counts['tx_pkts'] - prev_stats_if['tx_pkts'])
                        if_bytes[intf] = {
                            'rx_bytes': rx_bytes,
                            'rx_pkts': rx_pkts,
                            'tx_bytes': tx_bytes,
                            'tx_pkts': tx_pkts
                        }

                fwstats.stats['bytes'] = if_bytes
                fwstats.stats['tunnel_stats'] = self.simulate_tunnel_stats
                fwstats.stats['period'] = fwstats.stats['time'] - prev_stats['time']
                fwstats.stats['running'] = True
        else:
            fwstats.stats['ok'] = 0

        # Add the update to the list of updates. If the list is full,
        # remove the oldest update before pushing the new one
        if len(fwstats.updates_list) is UPDATE_LIST_MAX_SIZE:
            fwstats.updates_list.pop(0)

        fwstats.updates_list.append({
            'ok': fwstats.stats['ok'],
            'running': fwstats.stats['running'],
            'stats': fwstats.stats['bytes'],
            'period': fwstats.stats['period'],
            'tunnel_stats': fwstats.stats['tunnel_stats'],
            'utc': time.time()
        })

def simulate(count=1):
    fwglobals.g.loadsimulator = LoadSimulator()
    fwglobals.g.loadsimulator.start(count)
    # Press CTRL-C to stop the simulation

