"""
Maintains QoS context and functions to generate VPP QoS Commands
"""
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

from math import ceil
import fw_traffic_identification
import fwglobals
import fwutils
from fwobject import FwObject
from sqlitedict import SqliteDict
import json
import math
import copy



# Commonly used JSON tags and constant strings
REALTIME_QUEUE          = 'realtimeQueue'
CONTROL_SIGNALING_QUEUE = 'controlSignalingQueue'
PRIME_SELECT_QUEUE      = 'primeSelectQueue'
STANDARD_SELECT_QUEUE   = 'standardSelectQueue'
BEST_EFFORT_QUEUE       = 'bestEffortQueue'
DSCP_REWRITE            = 'dscpRewrite'
DEFAULT_DSCP_TAG        = 'CS0'

# FlexiWAN WAN QoS uses two traffic classes of DPDK scheduler
# The number is based from DPDK Scheduler traffic class identifiers
# For more information on DPDK QoS framework, Please refer
# https://doc.dpdk.org/guides/prog_guide/qos_framework.html
SCHEDULER_REALTIME_TRAFFIC_CLASS_ID  = 11
SCHEDULER_DATA_TRAFFIC_CLASS_ID      = 12

# Constant map between queue-name and its (traffic-class, queue)
QOS_QUEUES = {
    REALTIME_QUEUE          : ( SCHEDULER_REALTIME_TRAFFIC_CLASS_ID, 0 ),
    CONTROL_SIGNALING_QUEUE : ( SCHEDULER_DATA_TRAFFIC_CLASS_ID, 0 ),
    PRIME_SELECT_QUEUE      : ( SCHEDULER_DATA_TRAFFIC_CLASS_ID, 1 ),
    STANDARD_SELECT_QUEUE   : ( SCHEDULER_DATA_TRAFFIC_CLASS_ID, 2 ),
    BEST_EFFORT_QUEUE       : ( SCHEDULER_DATA_TRAFFIC_CLASS_ID, 3)
}

# Constant map between DSCP tag and its integer value
DSCP_MAP = {
    'CS0'   : 0,
    'CS1'   : 8,
    'CS2'   : 16,
    'CS3'   : 24,
    'CS4'   : 32,
    'CS5'   : 40,
    'CS6'   : 48,
    'CS7'   : 56,
    'AF11'  : 10,
    'AF12'  : 12,
    'AF13'  : 14,
    'AF21'  : 18,
    'AF22'  : 20,
    'AF23'  : 22,
    'AF31'  : 26,
    'AF32'  : 28,
    'AF33'  : 30,
    'AF41'  : 34,
    'AF42'  : 36,
    'AF43'  : 38,
    'EF'    : 46,
    'VA'    : 44
}

# The bestEffortQueue is used to represent the default traffic class and queue id
QOS_SCHED_MAP_DEFAULT_VALUE = (QOS_QUEUES[BEST_EFFORT_QUEUE][0], QOS_QUEUES[BEST_EFFORT_QUEUE][1])

# The VPP DSCP MAP table's max count of values
QOS_MARK_MAX_SLOTS = 256


class FwQoS(FwObject):
    """
    Flexiwan QoS uses DPDK QoS scheduler enabled as part of VPP
    DPDK QoS has two levels of hierarchy between port and traffic classes. The first level
    is called subport and the second is called pipe. In FlexiWAN QoS, the subport is used
    represents the sub-interfaces (example VLAN interfaces) and the pipe represents the
    tunnels formed on this sub-interface. Each sub-interface shall be identified by a unique
    hierarchy ID indicating the allocated subport. Similarly each tunnel shall be identified
    by a unique hierarchy ID indicating the allocated pipe.
    The traffic classes - realtime and data - come under each pipe.
    Additional details of the DPDK QoS can be got from the below link
    https://doc.dpdk.org/guides/prog_guide/qos_framework.html

    A map is maintained on a per interface level to mark the packets with
    the corresponding subport and pipe value. The marking is done as part of
    the VPP qos-mark feature which additionally also handles the DSCP marking.
    The map is filled with keys that represent the tunnel-id and the value represents
    the corresponding subport and pipe. The packet metadata are marked with the
    tunnel-id as part of the tunnel encapsulation and this serves as the key for the map.
    When packets traverses qos-mark feature, this key is used to lookup and identify
    the subport and pipe id (hierarchy IDs) allocated to it.
    """

    def __init__(self):
        """
        Init defaults and QoS context (qos_db)
        """
        FwObject.__init__(self)
        self.__QOS_SCHED_DEFAULT_SUB_PORT_ID = 0
        self.__QOS_SCHED_DEFAULT_PIPE_ID = 0
        self.__QOS_SCHED_MAX_TRAFFIC_CLASSES = 13 #DPDK traffic class count
        self.__INTERFACE_BANDWIDTH_DEFAULT_BPS = 12500000 #100Mbps in Bytes
        self.__INTERFACE_BANDWIDTH_MAX_BPS =  1250000000 #10 Gbps in Bytes
        self.__MEGA_BITS_TO_BYTES_MULTIPLIER = 125000
        self.__qos_sched_max_memory_KB = 0
        self.__wan_qos_id = 0

        # Based on practical measurements in VPP - Subject to change on config change and
        # in new VPP versions
        self.__SCHED_PER_PIPE_MEMORY_USE_KB = 10
        self.__max_subports_per_interface = 0
        self.__max_pipes_per_subport = 0

        # Default scheduling configuration
        self.__DEFAULT_REALTIME_BANDWIDTH_LIMIT = 30
        self.__DEFAULT_WRR = [40, 30, 20, 10]

        '''
        Structure of qos_db
        qos_db : {
            interfaces : {
                'dev-id-1' : {
                    'qos-subport-id-list' : Array of free QoS subport IDs
                    'sub-dev-id-1.1' : {
                        'id' : Unique_integer identifier for device. Used in dscp egress map.
                        'qos-subport-id': id,
                        'tunnels' : {
                            tunnel_id-1: qos_tunnel_id,
                            tunnel_id-2: qos_tunnel_id,
                            ...
                        }
                        'qos-pipe-id-list' : Array of free QoS pipe IDs
                    },
                    'sub-dev-id-1.2' : {
                        ...
                    }
                },
                'dev-id-2' : {
                    ....
                }
            },
            free-id-list : [] # List of free interface unique identifiers
            # qos_traffic_map is an array indexed by [service_class][importance] providing
            # corresponding traffic-class and queue-id values
            traffic-map : [[]]
        }
        '''
        self.__qos_db = SqliteDict(fwglobals.g.QOS_DB_FILE, autocommit=True)
        self.reset()


    def finalize(self):
        self.__qos_db.close()


    def reset(self):
        """
        Reset all internal QoS context. It can be used when VPP is restarted to clear all
        contexts setup during VPP runtime
        """
        self.log.debug('QoS Reset internal states')
        self.__qos_db.clear()
        self.__qos_db['interfaces'] = {}
        self.__qos_db['traffic-map'] = get_default_qos_traffic_map()
        self.__qos_db['free-id-list'] = []
        self.__total_worker_cores = 0
        self.__hqos_core_enabled = False


    def __get_qos_policy (self, dev_id):
        """
        Get QoS policy parameters for the given device identifier by fetching ad-qos-policy
        message from configuration DB

        :param dev_id: Device identifier
        :type dev_id: String
        :return: QoS policy configuration
        :rtype: dict
        """
        params = fwglobals.g.router_cfg.get_qos_policy()
        if params:
            policies = params.get('policies')
            for policy in policies:
                interfaces = policy.get('interfaces')
                for dev_id_value in interfaces:
                    if dev_id == dev_id_value:
                        return policy
        return None


    def __is_qos_state_setup (self, parent_dev_id, dev_id):
        """
        Checks if internal QoS states are setup for the given device ID

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :return: True if internal states are setup else False
        :rtype: Boolean
        """
        if (self.__qos_db['interfaces'].get(parent_dev_id) and \
            self.__qos_db['interfaces'][parent_dev_id].get(dev_id)):
            return True
        return False


    def __get_hqos_sched_params(self, tx_Bps):
        """
        tc_period and tb_size are DPDK scheduler configuration variables. Based on practical
        measurements, the below method works well. Documentation does not have information
        on the method to be used to compute these variables. This is more of a reasonable start
        that has been identified through experimentation and practical measurements.

        :param tx_Bps: The bandwidth (Bytes per second) to be configured on the interface or tunnel
        :type tx_Bps: Integer
        :return: Computed tc_period and tb_size value
        :rtype: Integers
        """
        # Approximately taking default tb_size = number of queue slots multiplied * max packet size
        # Data traffic class has four queues with 32 (4 *32 = 128) slots and taking
        # maximum packet size as 2048 bytes
        tb_size = 128 * 2048

        # Interval in millisecond after which a max size packet can be sent for the given bandwidth
        min_tc_period = ceil((1000) / (tx_Bps / 2048))
        if tb_size > tx_Bps:
            tb_size = tx_Bps

        # Taking tc_period as time taken to get accumulate tb_size of bytes
        tc_period = int((tb_size * 1000) / tx_Bps)
        if tc_period == 0:
            # Case where tc_period is < 1ms. Set tc_period to 1ms and compute tb_size for 1ms
            tc_period = 1
            tb_size = int(tx_Bps / 1000)
        else:
            # In my current understanding, high tc_period can increase the burstiness, so bringing
            # it down by few times. As more context is built on this topic, the reasoning or the
            # logic of the method can be made better
            if (tc_period > (8 * min_tc_period)):
                tc_period = 8 * min_tc_period
        return tc_period, tb_size


    def setup_hqos (self, hqos_core_enabled, num_worker_cores, total_memory_in_GB):
        """
        Maintain context on if hqos core is enabled and the number of available total cpu workers.
        It shall later be used to decide if QoS policy need to be processed or not. And also to
        provision the suitable number of subports and pipes

        :param hqos_core_enabled: Is HQoS thread configured
        :type hqos_core_enabled: Boolean
        :param num_worker_cores: Total number of available cpu workers cores
        :type hqos_core_enabled: Integer
        :param total_memory_in_GB: Total memory (in GB) available for the VPP router process
        :type total_memory_in_GB: Integer
        """
        self.__hqos_core_enabled = hqos_core_enabled
        self.__total_worker_cores = num_worker_cores
        self.__qos_sched_max_memory_KB = \
            fwglobals.g.QOS_SCHED_MAX_MEMORY_PERCENT * (total_memory_in_GB * 1024 * 1024) / 100

        # The parent_dev_id_count and the total_qos interface count is used to calculate the number
        # of subports and pipes factoring the available memory. The provisioning of number of
        # subports and pipes are made during VPP start via startup.conf.
        parent_dev_id_list, total_qos_iface_count = get_qos_parent_dev_id_list()
        if total_qos_iface_count:
            # extra 1 for including default subport that handles non-qos interface traffic
            total_qos_iface_count += 1
            if (total_qos_iface_count < 4):
                # Set minimum to 4, to minimize restarts on addition of each new QoS sub-interface
                total_qos_iface_count =  4
            # The number of subports and pipes has to be a power of 2 - Requirement of dpdk QoS lib
            total_qos_iface_count = \
                (1 if total_qos_iface_count < 2 else 2**(total_qos_iface_count - 1).bit_length())
            self.__max_subports_per_interface = total_qos_iface_count
            self.__max_pipes_per_subport = int (self.__qos_sched_max_memory_KB / \
                (self.__SCHED_PER_PIPE_MEMORY_USE_KB * self.__max_subports_per_interface *
                len (parent_dev_id_list)))
            self.__max_pipes_per_subport =\
                2 ** (math.floor(math.log(self.__max_pipes_per_subport, 2)))
            if self.__max_pipes_per_subport == 0:
                self.__max_pipes_per_subport = 1
        self.log.info('VPP QoS is configured with max subports: %d and pipes: %d' %
                       (self.__max_subports_per_interface, self.__max_pipes_per_subport))

    def get_hqos_worker_state(self):
        """
        Return current state of hqos core assignment and number of available total cpu workers

        :return hqos_core_enabled: Is HQoS thread configured
        :rtype hqos_core_enabled: Boolean
        :return num_worker_cores: Total number of available cpu workers cores
        :rtype hqos_core_enabled: Integer
        """
        return self.__hqos_core_enabled, self.__total_worker_cores


    def get_max_subports_and_pipes(self):
        """
        Return the current computed configuration of max_subports and max_pipes

        :return max_subports_per_interface: Max subports configured per interface
        :rtype max_subports_per_interface: Integer
        :return max_pipes_per_subport: Max pipes configured per subport
        :rtype max_pipes_per_subport: Integer
        """
        return self.__max_subports_per_interface, self.__max_pipes_per_subport


    def restart_check_on_qos_interfaces_update(self, qos_policy_params):
        """
        Compares the QoS interfaces list of the policy with the current applied list of
        QoS enabled interfaces.
        Returns True (restart required) if,
        - A new parent interface is seen
        - An add is detected and that exceeds the current limit of subports provisioned.
        - A delete that requires disabling hqos in startup conf
        Returns False (restart not required) if,
        - An add (sub-interface) is detected on a parent interface that already has hqos enabled
        - A delete (sub-interface) is detected on a parent interface that has other
        interface(s) with hqos

        :param qos_policy_params: QoS policy parameters
        :type qos_policy_params: dict
        :return: Result of the comparison
        :rtype: Boolean
        """
        parent_dev_id_list, _ = get_qos_parent_dev_id_list()
        input_parent_dev_id_list, input_qos_interface_count =\
            get_qos_parent_dev_id_list(qos_policy_params)
        parent_dev_id_list.sort()
        input_parent_dev_id_list.sort()
        if input_parent_dev_id_list != parent_dev_id_list:
            # Add/Delete in parent interface detected - Restart
            return True
        if input_qos_interface_count >= self.__max_subports_per_interface:
            # Current subport provisioning is not sufficient
            return True
        return False


    def build_qos_traffic_map (self, params):
        """
        Build QoS Traffic Map from the given qos-traffic-map parameters. The QoS traffic map
        carries configuration map between (service-class + importance) to Scheduler's
        traffic-class and queue. The function updates the object's qos_traffic_map context
        based on the configuration

        :param params: QoS Traffic Map parameters
        :type params: dict
        """
        qos_traffic_map = get_default_qos_traffic_map()
        for service_class, value in params.items():
            service_class_id = fw_traffic_identification.TRAFFIC_SERVICE_CLASS_VALUES.get(service_class)
            if service_class_id is None:
                # Unsupported service class - Default not overridden
                self.log.warning('Service class %s not mapped in Agent' % service_class)
                continue

            for importance, queue_name in value.items():
                importance_id = fw_traffic_identification.TRAFFIC_IMPORTANCE_VALUES.get(importance)
                if importance_id is None:
                    # Unsupported importance value - Default not overridden
                    self.log.warning('Traffic importance %s not mapped in Agent' % importance)
                    continue
                qos_traffic_map[service_class_id][importance_id] =\
                    (QOS_QUEUES[queue_name][0], QOS_QUEUES[queue_name][1])
        self.__qos_db['traffic-map'] = qos_traffic_map


    def reset_qos_traffic_map (self):
        """
        Reset the internal QoS Traffic Map state to the default values
        """
        self.__qos_db['traffic-map'] = get_default_qos_traffic_map()


    def build_egress_map(self, scheduling_params, dev_id, egress_map):
        """
        The function is used to build the DSCP mark bytes based on the configured QoS Policy
        and QoS Traffic map

        :param scheduling_params: Scheduling configuration provided in QoS policy
        :type scheduling_params: dict
        :param egress_map: Configuration to be provided to VPP command for DSCP marking
        :type egress_map: dict
        :return: Updated egress map configuration
        :rtype: dict
        """
        egress_map['id'] = self.get_subport_unique_id (dev_id)
        output_map = [0] * QOS_MARK_MAX_SLOTS
        for i in range(fw_traffic_identification.MAX_TRAFFIC_SERVICE_CLASSES * \
            fw_traffic_identification.MAX_TRAFFIC_IMPORTANCE_VALUES):
            service_class = (i >> 2) & 0xF
            importance = i & 0x3
            if service_class >= fw_traffic_identification.MAX_TRAFFIC_SERVICE_CLASSES or\
                service_class > fw_traffic_identification.HIGHEST_IN_USE_TRAFFIC_CLASS:
                service_class = fw_traffic_identification.TRAFFIC_SERVICE_CLASS_VALUES['default']

            if importance >= len(fw_traffic_identification.TRAFFIC_IMPORTANCE_VALUES):
                importance = fw_traffic_identification.TRAFFIC_IMPORTANCE_VALUES['low']

            # Fetch traffic-class and Queue ID value from QoS traffic Map
            tc = self.get_traffic_class(service_class, importance)
            queue = self.get_queue_id(service_class, importance)

            # Fetch DSCP value from QoS policy using (traffic-class + queue-id) as key
            if tc == QOS_QUEUES[REALTIME_QUEUE][0] and queue == QOS_QUEUES[REALTIME_QUEUE][1]:
                dscp_value = DSCP_MAP.get(scheduling_params[REALTIME_QUEUE].get(DSCP_REWRITE))
            elif tc == QOS_QUEUES[CONTROL_SIGNALING_QUEUE][0] and queue == QOS_QUEUES[CONTROL_SIGNALING_QUEUE][1]:
                dscp_value = DSCP_MAP.get(scheduling_params[CONTROL_SIGNALING_QUEUE].get(DSCP_REWRITE))
            elif tc == QOS_QUEUES[PRIME_SELECT_QUEUE][0] and queue == QOS_QUEUES[PRIME_SELECT_QUEUE][1]:
                dscp_value = DSCP_MAP.get(scheduling_params[PRIME_SELECT_QUEUE].get(DSCP_REWRITE))
            elif tc == QOS_QUEUES[STANDARD_SELECT_QUEUE][0] and queue == QOS_QUEUES[STANDARD_SELECT_QUEUE][1]:
                dscp_value = DSCP_MAP.get(scheduling_params[STANDARD_SELECT_QUEUE].get(DSCP_REWRITE))
            elif tc == QOS_QUEUES[BEST_EFFORT_QUEUE][0] and queue == QOS_QUEUES[BEST_EFFORT_QUEUE][1]:
                dscp_value = DSCP_MAP.get(scheduling_params[BEST_EFFORT_QUEUE].get(DSCP_REWRITE))

            if dscp_value is None:
                dscp_value = DSCP_MAP.get(DEFAULT_DSCP_TAG)
            elif dscp_value:
                fwglobals.log.debug('Set DSCP tag for (Service: %d and Importance: %d) to dscp: %d' % \
                    (service_class, importance, dscp_value))
            output_map[i] = dscp_value

        egress_map['rows'][3]['outputs'] = bytes(output_map)
        return egress_map


    def get_subport_qos_hierarchy_id (self, parent_dev_id, dev_id):
        """
        Lookup the given subport's QoS hierarchy ID from the internal context

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :return: ID representing the subport in the QoS hierarchy
        :rtype: Integer
        """
        return self.__qos_db['interfaces'][parent_dev_id][dev_id]['qos-subport-id']


    def get_tunnel_qos_hierarchy_id (self, parent_dev_id, dev_id, tunnel_id):
        """
        Lookup the given tunnel's QoS hierarchy ID from the internal context

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param tunnel_id: Unique tunnel identifier received in tunnel configuration message
        :type tunnel_id: Integer
        :return: ID representing the tunnel in the QoS hierarchy
        :rtype: Integer
        """
        return self.__qos_db['interfaces'][parent_dev_id][dev_id]['tunnels'].get(tunnel_id)


    def cache_subport_bandwidth_params (self, parent_dev_id, dev_id,
                                        interface_params, result_cache):
        """
        Compute the interface bandwidth related configurations and store it in the result cache.
        This can be later used by other commands to lookup bandwidth values from the cache

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param interface_params: Interface configuration parameters
        :type interface_params: dict
        :param result_cache: The cache where the result needs to be updated
        :type result_cache: dict
        """
        subport_id = self.get_subport_qos_hierarchy_id(parent_dev_id, dev_id)
        # Default subport ID represents non-WAN sub-interfaces. It shall always be set
        # with the max possible bandwidth value
        if (interface_params and (subport_id != self.__QOS_SCHED_DEFAULT_SUB_PORT_ID)):
            result_cache['cache']['tb_rate'] =\
                self.get_interface_tx_bandwidth_Bps (interface_params)
        else:
            result_cache['cache']['tb_rate'] = self.__INTERFACE_BANDWIDTH_MAX_BPS
        result_cache['cache']['tc_rate'] =\
            [result_cache['cache']['tb_rate']] * self.__QOS_SCHED_MAX_TRAFFIC_CLASSES
        result_cache['cache']['tc_period'], result_cache['cache']['tb_size'] =\
            self.__get_hqos_sched_params (result_cache['cache']['tb_rate'])


    def cache_tunnel_bandwidth_params(self, parent_dev_id, dev_id, interface_params,
                                      tunnel_params, realtime_limit, result_cache):
        """
        Compute the tunnel bandwidth related configurations and store it in the result cache.
        This can be later used by other commands to lookup bandwidth values from the cache

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param interface_params: Interface configuration parameters
        :type interface_params: dict
        :param tunnel_params: Tunnel configuration parameters
        :type tunnel_params: dict
        :param realtime_limit: Bandwidth percentage to be reserved for realtime traffic class
        :type realtime_limit: Integer
        :param result_cache: The cache where the result needs to be updated
        :type result_cache: dict
        """
        tunnel_id = tunnel_params.get('tunnel-id') if tunnel_params else 0
        pipe_id = self.get_tunnel_qos_hierarchy_id(parent_dev_id, dev_id, tunnel_id)
        subport_id = self.get_subport_qos_hierarchy_id (parent_dev_id, dev_id)
        # Default subport ID represents non-WAN sub-interfaces which shall always be using
        # the max bandwidth value
        if (interface_params and subport_id != self.__QOS_SCHED_DEFAULT_SUB_PORT_ID):
            interface_tx_Bps = self.get_interface_tx_bandwidth_Bps (interface_params)
            # Default pipe ID represents internet traffic. It shall always be set
            # with the bandwidth of the subport interface i.e. remote bandwidth
            # factoring is not applicable in this case
            if (pipe_id != self.__QOS_SCHED_DEFAULT_PIPE_ID):
                tunnel_bandwidth_mbps = tunnel_params.get('remoteBandwidthMbps')
                tunnel_rx_Bps = 0
                if tunnel_bandwidth_mbps:
                    tunnel_rx_Bps = int(tunnel_bandwidth_mbps.get('rx') * \
                        self.__MEGA_BITS_TO_BYTES_MULTIPLIER)
                if tunnel_rx_Bps == 0:
                    tunnel_rx_Bps = self.__INTERFACE_BANDWIDTH_DEFAULT_BPS
                result_cache['cache']['tb_rate'] = min(tunnel_rx_Bps, interface_tx_Bps)
            else:
                result_cache['cache']['tb_rate'] = interface_tx_Bps
            result_cache['cache']['tc_rate'] =\
                [result_cache['cache']['tb_rate']] * self.__QOS_SCHED_MAX_TRAFFIC_CLASSES
            result_cache['cache']['tc_rate'][SCHEDULER_REALTIME_TRAFFIC_CLASS_ID] =\
                int((realtime_limit * result_cache['cache']['tb_rate'])/100)
            tc_period, tb_size = self.__get_hqos_sched_params(result_cache['cache']['tb_rate'])
            realtime_tc_period, realtime_tb_size = self.__get_hqos_sched_params\
                (result_cache['cache']['tc_rate'][SCHEDULER_REALTIME_TRAFFIC_CLASS_ID])
            result_cache['cache']['tc_period'] = min (tc_period, realtime_tc_period)
            result_cache['cache']['tb_size'] = max (tb_size, realtime_tb_size)
        else:
            result_cache['cache']['tb_rate'] = self.__INTERFACE_BANDWIDTH_MAX_BPS
            result_cache['cache']['tc_rate'] =\
                [result_cache['cache']['tb_rate']] * self.__QOS_SCHED_MAX_TRAFFIC_CLASSES
            result_cache['cache']['tc_period'], result_cache['cache']['tb_size'] =\
                self.__get_hqos_sched_params(result_cache['cache']['tb_rate'])


    def get_traffic_class(self, service_class, importance):
        """
        Lookup traffic class for a given service-class and importance from the QoS traffic Map.
        It is a helper function used by command generation functions

        :param service_class: Traffic service class identifier
        :type service_class: Integer
        :param importance: Traffic importance identifier
        :type importance: Integer
        :return: Traffic-class value
        :rtype: Integer
        """
        return self.__qos_db['traffic-map'][service_class][importance][0]


    def get_queue_id(self, service_class, importance):
        """
        Lookup Queue ID for a given service-class and importance from the QoS traffic Map.
        It is a helper function used by command generation functions

        :param service_class: Traffic service class identifier
        :type service_class: Integer
        :param importance: Traffic importance identifier
        :type importance: Integer
        :return: Queue ID value
        :rtype: Integer
        """
        return self.__qos_db['traffic-map'][service_class][importance][1]


    def get_subport_unique_id (self, dev_id):
        """
        Get the subport ID allocated for the given device. The allocated value is maintained in
        internal qos states.

        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :return: Subport ID allocated for the device
        :rtype: Integer
        """
        parent_dev_id = fwutils.dev_id_get_parent(dev_id)
        return self.__qos_db['interfaces'][parent_dev_id][dev_id]['id']


    def setup_tunnel_qos_state (self, parent_dev_id, dev_id, tunnel_id):
        """
        Initializes the internal tunnel qos states. Sets up a unique ID to represent the
        tunnel in QoS hierarchy. Allocates a value between 0 to Max tunnels supported.
        If unique ID is exhausted then the default ID is used

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param tunnel_id: Unique tunnel identifier received in tunnel configuration message
        :type tunnel_id: Integer
        """
        if not self.__is_qos_state_setup(parent_dev_id, dev_id):
            return
        interfaces_config = self.__qos_db['interfaces']
        qos_subport_config = interfaces_config[parent_dev_id][dev_id]
        qos_tunnel_id = qos_subport_config['tunnels'].get(tunnel_id)
        if qos_tunnel_id is not None:
            return
        qos_pipe_id_list = qos_subport_config['qos-pipe-id-list']
        if qos_pipe_id_list:
            qos_tunnel_id = qos_pipe_id_list.pop()
        else:
            self.log.warning('QoS tunnel ID exhausted in device %s:%s' % (parent_dev_id, dev_id))
            self.log.warning('QoS tunnel ID assigned as default (%d) for tunnel: %d'\
                % (self.__QOS_SCHED_DEFAULT_PIPE_ID, tunnel_id))
            qos_tunnel_id = self.__QOS_SCHED_DEFAULT_PIPE_ID
        qos_subport_config['tunnels'][tunnel_id] = qos_tunnel_id
        self.__qos_db['interfaces'] = interfaces_config


    def clear_tunnel_qos_state (self, parent_dev_id, dev_id, tunnel_id):
        """
        Clears the internal tunnel qos states and release the tunnel's QoS Hierarchy ID
        to the free-list of pipe-id maintained within each sub-interface context

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param tunnel_id: Unique tunnel identifier received in tunnel configuration message
        :type tunnel_id: Integer
        """
        if not self.__is_qos_state_setup(parent_dev_id, dev_id):
            return
        interfaces_config = self.__qos_db['interfaces']
        qos_subport_config = interfaces_config[parent_dev_id][dev_id]
        qos_tunnel_id = qos_subport_config['tunnels'].get(tunnel_id)
        if  qos_tunnel_id is None:
            return
        if qos_tunnel_id != self.__QOS_SCHED_DEFAULT_PIPE_ID:
            qos_subport_config['qos-pipe-id-list'].append(qos_tunnel_id)
        del qos_subport_config['tunnels'][tunnel_id]
        self.__qos_db['interfaces'] = interfaces_config


    def setup_sub_interface_qos_state (self, parent_dev_id, dev_id):
        """
        Initializes the internal subport qos states. Sets up a unique ID to represent the
        subport in QoS hierarchy. Allocates a value between 0 to Max subports supported.
        If unique ID is exhausted then the default ID is used

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        """
        interfaces_config = self.__qos_db['interfaces']
        qos_interface_config = interfaces_config[parent_dev_id]
        qos_subport_id_list = qos_interface_config['qos-subport-id-list']
        dev_id_qos = {}
        if qos_subport_id_list:
            qos_subport_id = qos_subport_id_list.pop()
        else:
            self.log.warning('QoS subport ID exhausted in device %s' % parent_dev_id)
            self.log.warning('Using default QoS subport ID (%d) for device: %s'\
                             % (self.__QOS_SCHED_DEFAULT_SUB_PORT_ID, dev_id))
            qos_subport_id = self.__QOS_SCHED_DEFAULT_SUB_PORT_ID

        dev_id_qos['qos-subport-id'] = qos_subport_id
        qos_pipe_id_list = list()
        # 0 to max_tunnels - Used as LIFO. Higher IDs shall be used only when
        # all lower IDs are already in use. Reverse inserted to have pop happen in ascending order
        for i in range ((self.__max_pipes_per_subport - 1), -1, -1):
            qos_pipe_id_list.append(i)

        dev_id_qos['tunnels'] = {}
        dev_id_qos['qos-pipe-id-list'] = qos_pipe_id_list
        # A unique ID per QoS interface - Used in DSCP Map create / identification
        free_id_list = self.__qos_db['free-id-list']
        if free_id_list:
            dev_id_qos['id'] = free_id_list.pop()
            self.__qos_db['free-id-list'] = free_id_list
        else:
            dev_id_qos['id'] = self.__wan_qos_id
            self.__wan_qos_id += 1
        qos_interface_config[dev_id] = dev_id_qos
        interfaces_config[parent_dev_id] = qos_interface_config
        self.__qos_db['interfaces'] = interfaces_config
        # Setup the default internet pipe for the subport
        self.setup_tunnel_qos_state (parent_dev_id, dev_id, 0)


    def clear_sub_interface_qos_state (self, parent_dev_id, dev_id):
        """
        Clears the internal subport qos states and release the subport's QoS Hierarchy ID
        to the free subport-id-list maintained within each interface context

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        """
        interfaces_config = self.__qos_db['interfaces']
        qos_interface_config = interfaces_config.get(parent_dev_id)
        if qos_interface_config:
            qos_subport_config = qos_interface_config.get(dev_id)
        if qos_interface_config is None or qos_subport_config is None:
            return
        qos_interface_config = interfaces_config[parent_dev_id]
        qos_subport_id_list = qos_interface_config['qos-subport-id-list']
        qos_subport_id = qos_subport_config['qos-subport-id']

        if qos_subport_id != self.__QOS_SCHED_DEFAULT_SUB_PORT_ID:
            qos_subport_id_list.append(qos_subport_id)
        unique_device_id = qos_subport_config['id']
        del qos_interface_config[dev_id]
        self.__qos_db['interfaces'] = interfaces_config

        free_id_list = self.__qos_db['free-id-list']
        free_id_list.append (unique_device_id)
        self.__qos_db['free-id-list'] = free_id_list


    def setup_interface_qos_state (self, parent_dev_id):
        """
        Initializes the internal parent interface qos states.

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        """
        interfaces_config = self.__qos_db['interfaces']
        parent_dev_id_qos = {}
        parent_dev_id_qos['qos-subport-id-list'] = list()
        # 0 to max_subports - Used as LIFO. Higher IDs shall be used only when
        # lower IDs are already in use. Reverse inserted to have pop happen in ascending order
        for i in range ((self.__max_subports_per_interface - 1), -1, -1):
            parent_dev_id_qos['qos-subport-id-list'].append(i)
        interfaces_config[parent_dev_id] = parent_dev_id_qos
        self.__qos_db['interfaces'] = interfaces_config
        # Create a default subport to be used for non-qos (sub-)interfaces
        self.setup_sub_interface_qos_state (parent_dev_id, 'default')


    def clear_interface_qos_state (self, parent_dev_id):
        """
        Clears the internal parent interface qos states

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        """
        interfaces_config = self.__qos_db['interfaces']
        del interfaces_config[parent_dev_id]
        self.__qos_db['interfaces'] = interfaces_config


    def get_interface_tx_bandwidth_Bps (self, interface_params):
        """
        Get the Tx bandwidth of the interface.
        Returns the default bandwidth if not provided in the configuration

        :param interface_params: Interface configuration parameters
        :type interface_params: dict
        """
        bandwidth_mbps = interface_params.get('bandwidthMbps')
        if bandwidth_mbps:
            tx_Bps = int(bandwidth_mbps.get('tx') * self.__MEGA_BITS_TO_BYTES_MULTIPLIER)
        else:
            tx_Bps = self.__INTERFACE_BANDWIDTH_DEFAULT_BPS
        return tx_Bps


    def construct_qos_hierarchy_id (self, parent_dev_id, dev_id, key_value_pairs):
        """
        The key_value pairs come with keys that represent the tunnel identifier.
        The function assigns values that are the QoS Hierarchy IDs allocated for each key.

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param key_value_pairs: Array of dict with key and value parameters
        :type key_value_pairs: Array
        :return: Return the updated array of key_value_pairs
        :rtype: Array
        """
        if self.__is_qos_state_setup(parent_dev_id, dev_id):
            subport_hierarchy_id = self.get_subport_qos_hierarchy_id(parent_dev_id, dev_id) << 16
            for key_value in key_value_pairs:
                key_value['value'] = subport_hierarchy_id | \
                    self.get_tunnel_qos_hierarchy_id (parent_dev_id, dev_id, key_value['key'])
        return key_value_pairs


    def __get_build_qos_traffic_map_command(self, qos_traffic_map_params, cmd_list):
        """
        Setup command to generate internal state of qos traffic map

        :param qos_traffic_map_params: Qos Traffic Map configuration parameters
        :type qos_traffic_map_params: dict
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "build_qos_traffic_map"
        cmd['cmd']['object'] = "fwglobals.g.qos"
        cmd['cmd']['descr']  = "Build QoS Traffic Map"
        cmd['cmd']['params'] = { 'params' : qos_traffic_map_params }

        cmd['revert'] = {}
        cmd['revert']['func']   = "reset_qos_traffic_map"
        cmd['revert']['object'] = "fwglobals.g.qos"
        cmd['revert']['descr']  = "Reset QoS Traffic Map"
        cmd_list.append(cmd)


    def __get_setup_tunnel_qos_state_commands (self, parent_dev_id, dev_id, tunnel_id, cmd_list):
        """
        Generates command to call the tunnel qos setup function

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param tunnel_id: Unique tunnel identifier received in tunnel configuration message
        :type tunnel_id: Integer
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "setup_tunnel_qos_state"
        cmd['cmd']['object']    = "fwglobals.g.qos"
        cmd['cmd']['descr']     = "Setup tunnel context for dev-id: %s tunnel-id: %d" % (dev_id, tunnel_id)
        cmd['cmd']['params']    =   {
            'parent_dev_id' : parent_dev_id,
            'dev_id'        : dev_id,
            'tunnel_id'     : tunnel_id
        }

        cmd['revert'] = {}
        cmd['revert']['func']      = "clear_tunnel_qos_state"
        cmd['revert']['object']    = "fwglobals.g.qos"
        cmd['revert']['descr']     = "Clear tunnel context for dev-id: %s tunnel-id: %d" % (dev_id, tunnel_id)
        cmd['revert']['params']    =   {
            'parent_dev_id' : parent_dev_id,
            'dev_id'        : dev_id,
            'tunnel_id'     : tunnel_id
        }
        cmd_list.append(cmd)


    def __get_setup_sub_interface_qos_state_commands (self, parent_dev_id, dev_id, cmd_list):
        """
        Generate commands to call the subport qos setup function

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "setup_sub_interface_qos_state"
        cmd['cmd']['object']    = "fwglobals.g.qos"
        cmd['cmd']['descr']     = "Setup subport context for dev-id: %s" % dev_id
        cmd['cmd']['params']    =   {
            'parent_dev_id' : parent_dev_id,
            'dev_id'        : dev_id
        }

        cmd['revert'] = {}
        cmd['revert']['func']      = "clear_sub_interface_qos_state"
        cmd['revert']['object']    = "fwglobals.g.qos"
        cmd['revert']['descr']     = "Clear subport context for dev-id: %s" % dev_id
        cmd['revert']['params']    =   {
            'parent_dev_id' : parent_dev_id,
            'dev_id'        : dev_id,
        }
        cmd_list.append(cmd)


    def __get_setup_interface_qos_state_commands (self, parent_dev_id, cmd_list):
        """
        Generate commands to call the parent interface qos setup function

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "setup_interface_qos_state"
        cmd['cmd']['object']    = "fwglobals.g.qos"
        cmd['cmd']['descr']     = "Setup interface context for dev-id: %s" % parent_dev_id
        cmd['cmd']['params']    =   {
            'parent_dev_id' : parent_dev_id
        }

        cmd['revert'] = {}
        cmd['revert']['func']      = "clear_interface_qos_state"
        cmd['revert']['object']    = "fwglobals.g.qos"
        cmd['revert']['descr']     = "Clear interface context for dev-id: %s" % parent_dev_id
        cmd['revert']['params']    =   {
            'parent_dev_id' : parent_dev_id
        }
        cmd_list.append(cmd)


    def __get_qos_hierarchy_setup_command(self, parent_dev_id, dev_id, tunnel_ids,
                                          on_revert_reset_all, cmd_list):
        """
        Generates command to setup key value map on the interface. The key is the unique
        tunnel identifier and the value is the QoS hierarchy ID allocated to it. The map
        is used (by VPP's qos-mark feature) to update the packet metadata with the allocated
        subport and pipe values.

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param tunnel_ids: Array of unique tunnel identifiers
        :type tunnel_ids: Array
        :param on_revert_reset_all: Flag to indicate if revert needs to clean the entire map
        :type on_revert_reset_all: _type_
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """

        key_value_pairs = []
        for tunnel_id in tunnel_ids:
            key_value_pairs.append ({
                'key'   : tunnel_id,
                'value' : 0
            })
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "call_vpp_api"
        cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']     = "Update packet-metadata-map on dev-id: %s" % dev_id
        cmd['cmd']['params']    =   {
            'api'  : 'qos_mark_buffer_metadata_map',
            'args' : {
                'count'  : len (key_value_pairs),
                'substs' : [
                    {
                        'add_param'  : 'key_value_pairs',
                        'val_by_func': {
                            'func'      : 'construct_qos_hierarchy_id',
                            'object'    : 'fwglobals.g.qos'
                        },
                        'arg'        : [parent_dev_id, dev_id, key_value_pairs]
                    },
                    {
                        'add_param'  : 'sw_if_index',
                        'val_by_func': 'dev_id_to_vpp_sw_if_index',
                        'arg'        : dev_id
                    }
                ]
            }
        }
        cmd['revert'] = {}
        cmd['revert']['func']      = "call_vpp_api"
        cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr']     = "Clear packet-metadata-map on dev-id: %s" % dev_id
        cmd['revert']['params']    = {
            'api' : 'qos_mark_buffer_metadata_map_delete'
        }
        if on_revert_reset_all:
            cmd['revert']['params']['args'] = {
                'count' : 0
            }
        else:
            cmd['revert']['params']['args'] = {
                'keys'  : copy.deepcopy (tunnel_ids),
                'count' : len (tunnel_ids)
            }
        cmd['revert']['params']['args']['substs'] = [
            {
                'add_param'  : 'sw_if_index',
                'val_by_func': 'dev_id_to_vpp_sw_if_index',
                'arg'        : dev_id
            }
        ]
        cmd_list.append(cmd)


    def __get_interface_bandwidth_update_command (self, parent_dev_id, dev_id,
                                                  interface_params, cmd_list):
        """
        Generate commands to update interface bandwidth value. In our WAN-QoS model, the subport
        level in DPDK HQOS hierarchy represents the interface WAN bandwidth. This function updates
        the subport profile to set the desired WAN bandwidth

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param interface_params: Interface configuration parameters
        :type interface_params: dict
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        # Compute and cache the subport bandwidth configurations
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "cache_subport_bandwidth_params"
        cmd['cmd']['object']    = "fwglobals.g.qos"
        cmd['cmd']['descr']     = "Cache Tx bandwidth value of dev_id: %s" % dev_id
        cmd['cmd']['params']    =   {
            'parent_dev_id'    : parent_dev_id,
            'dev_id'           : dev_id,
            'interface_params' : interface_params
        }
        cmd['cmd']['cache_ret_val'] = ('tb_rate', 'tb_rate')

        cmd['revert'] = {}
        cmd['revert']['func']   = "cache_subport_bandwidth_params"
        cmd['revert']['object'] = "fwglobals.g.qos"
        cmd['revert']['descr']  = "Cache default Tx bandwidth value of dev_id: %s" % dev_id
        cmd['revert']['params'] =   {
            'parent_dev_id'    : parent_dev_id,
            'dev_id'           : dev_id,
            'interface_params' : None
        }
        cmd['revert']['cache_ret_val'] = ('tb_rate', 'tb_rate')
        cmd_list.append(cmd)

        # Update subport profile with the bandwidth configurations
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "call_vpp_api"
        cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']     = "Set bandwidth profile for dev_id: %s" % dev_id
        cmd['cmd']['params']    =   {
            'api' : 'sw_interface_set_dpdk_hqos_subport_profile',
            'args': {
                'substs': [
                    {
                        'add_param'  : 'sw_if_index',
                        'val_by_func': 'dev_id_to_vpp_sw_if_index',
                        'arg'        : parent_dev_id
                    },
                    {
                        'add_param'  : 'profile',
                        'val_by_func': {
                            'func'      : 'get_subport_qos_hierarchy_id',
                            'object'    : 'fwglobals.g.qos'
                        },
                        'arg'        : [parent_dev_id, dev_id]
                    },
                    { 'add_param': 'tb_rate',   'val_by_key': 'tb_rate' },
                    { 'add_param': 'tc_rate',   'val_by_key': 'tc_rate' },
                    { 'add_param': 'tc_period', 'val_by_key': 'tc_period' },
                    { 'add_param': 'tb_size',   'val_by_key': 'tb_size' },
                ]
            }
        }
        cmd['revert'] = {}
        cmd['revert']['func']      = "call_vpp_api"
        cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr']     = "Reset bandwidth profile for dev_id: %s" % dev_id
        cmd['revert']['params']    = copy.deepcopy (cmd['cmd']['params'])
        cmd_list.append(cmd)

        # Update subport in QoS hierarchy to use updated profile
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "call_vpp_api"
        cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']     = "Set profile for dev_id: %s" % dev_id
        cmd['cmd']['params']    =   {
            'api' : 'sw_interface_set_dpdk_hqos_subport',
            'args': {
                'substs': [
                    {
                        'add_param'  : 'sw_if_index',
                        'val_by_func': 'dev_id_to_vpp_sw_if_index',
                        'arg'        : parent_dev_id
                    },
                    {
                        'add_param'  : 'profile',
                        'val_by_func': {
                            'func'      : 'get_subport_qos_hierarchy_id',
                            'object'    : 'fwglobals.g.qos'
                        },
                        'arg'        : [parent_dev_id, dev_id]
                    },
                    {
                        'add_param'  : 'subport_id',
                        'val_by_func': {
                            'func'      : 'get_subport_qos_hierarchy_id',
                            'object'    : 'fwglobals.g.qos'
                        },
                        'arg'        : [parent_dev_id, dev_id]
                    }
                ]
            }
        }
        cmd['revert'] = {}
        cmd['revert']['func']      = "call_vpp_api"
        cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr']     = "Reset profile for dev_id: %s" % dev_id
        cmd['revert']['params']    =   {
            'api' : 'sw_interface_set_dpdk_hqos_subport',
            'args': {
                'profile'     : self.__QOS_SCHED_DEFAULT_SUB_PORT_ID,
                'subport_id'  : self.__QOS_SCHED_DEFAULT_SUB_PORT_ID,
                'substs': [
                    {
                        'add_param'  : 'sw_if_index',
                        'val_by_func': 'dev_id_to_vpp_sw_if_index',
                        'arg'        : parent_dev_id
                    },
                ]
            }
        }
        cmd_list.append(cmd)


    def __get_tunnel_bandwidth_update_command(self, parent_dev_id, dev_id, interface_params,
                                              tunnel_params, scheduling_params, cmd_list):
        """
        Generate commands to update tunnel bandwidth value. In FlexiWan QoS model, the pipe
        level in DPDK HQOS hierarchy represents the tunnel bandwidth. This function updates
        the pipe profile to set the desired tunnel bandwidth. The function also sets the
        WRR (Weighted Round Robin) configuration to setup weighted allocation of bandwidth to
        different queues under the data traffic class

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param interface_params: Interface configuration parameters
        :type interface_params: dict
        :param tunnel_params: Tunnel configuration parameters
        :type tunnel_params: dict
        :param scheduling_params: Scheduling param for the given device identifier
        :type scheduling_params: dict
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        tunnel_id = tunnel_params.get('tunnel-id') if tunnel_params else 0
        # Compute and cache the pipe bandwidth configurations
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "cache_tunnel_bandwidth_params"
        cmd['cmd']['object']    = "fwglobals.g.qos"
        cmd['cmd']['descr']     = "Cache Tx bandwidth params of Tunnel-%d on %s" % (tunnel_id, dev_id)
        cmd['cmd']['params']    =   {
            'parent_dev_id'    : parent_dev_id,
            'dev_id'           : dev_id,
            'interface_params' : interface_params,
            'tunnel_params'    : tunnel_params,
            'realtime_limit'   : scheduling_params[REALTIME_QUEUE]['bandwidthLimitPercent'],
        }
        cmd['cmd']['cache_ret_val'] = ('tb_rate', 'tb_rate')

        cmd['revert'] = {}
        cmd['revert']['func']   = "cache_tunnel_bandwidth_params"
        cmd['revert']['object'] = "fwglobals.g.qos"
        cmd['revert']['descr']  =\
             "Cache default Tx bandwidth params of Tunnel-%d on %s" % (tunnel_id, dev_id)
        cmd['revert']['params'] =   {
            'parent_dev_id'    : parent_dev_id,
            'dev_id'           : dev_id,
            'interface_params' : None,
            'tunnel_params'    : None,
            'realtime_limit'    : 100 #100% - No limit
        }
        cmd['revert']['cache_ret_val'] = ('tb_rate', 'tb_rate')
        cmd_list.append(cmd)

        # Sets up a Tunnel QoS profile with bandwidth, rate-limiting and WRR values
        wrr = [
                scheduling_params[CONTROL_SIGNALING_QUEUE]['weight'],
                scheduling_params[PRIME_SELECT_QUEUE]['weight'],
                scheduling_params[STANDARD_SELECT_QUEUE]['weight'],
                scheduling_params[BEST_EFFORT_QUEUE]['weight']
                ]
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "call_vpp_api"
        cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']     = "Set bandwidth profile dev-id: %s tunnel-id: %d" % (dev_id, tunnel_id)
        cmd['cmd']['params']    =   {
            'api'         : 'sw_interface_set_dpdk_hqos_pipe_profile',
            'args'        : {
                'wrr'         : wrr,
                'substs'  : [
                    {
                        'add_param'  : 'sw_if_index',
                        'val_by_func': 'dev_id_to_vpp_sw_if_index',
                        'arg'        : parent_dev_id
                    },
                    {
                        'add_param'  : 'subport_id',
                        'val_by_func': {
                            'func'   : 'get_subport_qos_hierarchy_id',
                            'object' : 'fwglobals.g.qos'
                        },
                        'arg'        : [parent_dev_id, dev_id]
                    },
                    {
                        'add_param'  : 'profile',
                        'val_by_func': {
                            'func'      : 'get_tunnel_qos_hierarchy_id',
                            'object'    : 'fwglobals.g.qos'
                        },
                        'arg'        : [parent_dev_id, dev_id, tunnel_id]
                    },
                    { 'add_param': 'tb_rate',   'val_by_key': 'tb_rate' },
                    { 'add_param': 'tc_rate',   'val_by_key': 'tc_rate' },
                    { 'add_param': 'tc_period', 'val_by_key': 'tc_period' },
                    { 'add_param': 'tb_size',   'val_by_key': 'tb_size' },
                ]
            }
        }
        cmd['revert'] = {}
        cmd['revert']['func']      = "call_vpp_api"
        cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr']     =\
            "Reset bandwidth profile for dev-id: %s tunnel-id: %d" % (dev_id, tunnel_id)
        cmd['revert']['params']    =   {
            'api'         : 'sw_interface_set_dpdk_hqos_pipe_profile',
            'args'        : {
                'wrr'       : self.__DEFAULT_WRR,
                'substs'    : copy.deepcopy(cmd['cmd']['params']['args']['substs'])
            }
        }
        cmd_list.append(cmd)

        # Update tunnel (pipe) in QoS hierarchy to use updated profile
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "call_vpp_api"
        cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']     = "Set profile for dev-id: %s tunnel-id: %d" % (dev_id, tunnel_id)
        cmd['cmd']['params']    =   {
            'api'         : 'sw_interface_set_dpdk_hqos_pipe',
            'args'        : {
                'substs': [
                    {
                        'add_param'  : 'sw_if_index',
                        'val_by_func': 'dev_id_to_vpp_sw_if_index',
                        'arg'        : parent_dev_id
                    },
                    {
                        'add_param'  : 'subport_id',
                        'val_by_func': {
                            'func'      : 'get_subport_qos_hierarchy_id',
                            'object'    : 'fwglobals.g.qos'
                        },
                        'arg'        : [parent_dev_id, dev_id]
                    },
                    {
                        'add_param'  : 'pipe_id',
                        'val_by_func': {
                            'func'      : 'get_tunnel_qos_hierarchy_id',
                            'object'    : 'fwglobals.g.qos'
                        },
                        'arg'        : [parent_dev_id, dev_id, tunnel_id]
                    },
                    {
                        'add_param'  : 'profile',
                        'val_by_func': {
                            'func'      : 'get_tunnel_qos_hierarchy_id',
                            'object'    : 'fwglobals.g.qos'
                        },
                        'arg'        : [parent_dev_id, dev_id, tunnel_id]
                    }
                ]
            }
        }
        cmd_list.append(cmd)


    def __get_interface_traffic_map_update_commands(self, parent_dev_id, dev_id,
                                                    scheduling_params, cmd_list):
        """
        Generate commands to update Two tables and enables DSCP marking on WAN interfaces
        1. HQOS TC Table  - Maps [service-class][importance] to Scheduler traffic class and queue
        2. DSCP Table - Maps given [service-class][importance] to configured DSCP value

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param scheduling_params: Scheduling param for the given device identifier
        :type scheduling_params: dict
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        # Setup DSCP Map
        egress_map = {
            'id'   : 0,
            'rows' : [
                { 'outputs' : bytes([0] * QOS_MARK_MAX_SLOTS) },
                { 'outputs' : bytes([0] * QOS_MARK_MAX_SLOTS) },
                { 'outputs' : bytes([0] * QOS_MARK_MAX_SLOTS) },
                { 'outputs' : bytes([0] * QOS_MARK_MAX_SLOTS) },
            ]
        }
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "call_vpp_api"
        cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']     = "Setup Egress MAP for DSCP rewrite on dev-id: %s" % dev_id
        cmd['cmd']['params']    =   {
            'api'   : 'qos_egress_map_update',
            'args'  : {
                'substs': [
                    {
                        'add_param'  : 'map',
                        'val_by_func': {
                            'func'      : 'build_egress_map',
                            'object'    : 'fwglobals.g.qos'
                        },
                        'arg'        : [scheduling_params, dev_id, egress_map]
                    }
                ]
            }
        }
        cmd['revert'] = {}
        cmd['revert']['func']      = "call_vpp_api"
        cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr']     = "Reset Egress MAP for DSCP rewrite on dev-id: %s" % dev_id
        cmd['revert']['params']    =   {
            'api'   : 'qos_egress_map_update',
            'args'  : {
                'map': {
                    'substs': [{
                        'add_param'  : 'id',
                        'val_by_func': {
                            'func'      : 'get_subport_unique_id',
                            'object'    : 'fwglobals.g.qos'
                        },
                        'arg'        : dev_id
                    }],
                    'rows' : [
                        { 'outputs' : bytes([0] * QOS_MARK_MAX_SLOTS) },
                        { 'outputs' : bytes([0] * QOS_MARK_MAX_SLOTS) },
                        { 'outputs' : bytes([0] * QOS_MARK_MAX_SLOTS) },
                        { 'outputs' : bytes([0] * QOS_MARK_MAX_SLOTS) },
                    ]
                }
            }
        }
        cmd_list.append(cmd)

        # Enable DSCP marking on the interface
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "call_vpp_api"
        cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']     = "Enable DSCP rewrite on dev-id: %s" % dev_id
        cmd['cmd']['params']    =   {
            'api'  : 'qos_mark_enable_disable',
            'args' : {
                'mark' : {
                    'output_source': 3,
                    'substs': [
                        {
                            'add_param'  : 'map_id',
                            'val_by_func': {
                                'func'      : 'get_subport_unique_id',
                                'object'    : 'fwglobals.g.qos'
                            },
                            'arg'        : dev_id
                        },
                        {
                            'add_param'  : 'sw_if_index',
                            'val_by_func': 'dev_id_to_vpp_sw_if_index',
                            'arg'        : dev_id
                        }
                    ]
                }
            }
        }
        cmd['revert'] = {}
        cmd['revert']['func']      = "call_vpp_api"
        cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr']     = "Disable DSCP rewrite on dev-id: %s" % dev_id
        cmd['revert']['params']    =   {
            'api'  : 'qos_mark_enable_disable',
            'args' : {
                'enable' : False,
                'mark'   : {
                    'output_source': 3,
                    'substs'       : [
                        {
                            'add_param'  : 'map_id',
                            'val_by_func': {
                                'func'      : 'get_subport_unique_id',
                                'object'    : 'fwglobals.g.qos'
                            },
                            'arg'        : dev_id
                        },
                        {
                            'add_param'  : 'sw_if_index',
                            'val_by_func': 'dev_id_to_vpp_sw_if_index',
                            'arg'        : dev_id
                        }
                    ]
                }
            }
        }
        cmd_list.append(cmd)

        # Setup HQoS TC table
        for i in range(fw_traffic_identification.MAX_TRAFFIC_SERVICE_CLASSES * \
            fw_traffic_identification.MAX_TRAFFIC_IMPORTANCE_VALUES):
            # DPDK HQoS has a traffic-class/queue selector map with 64 slots - 6 bits
            # The output of traffic classification is service-class and importance and this
            # is encoded as 6 bits(4 bits for service-class and 2 bits for importance).
            # Each slot is indexed by this service-class and importance combination and the result
            # shall contain the traffic class and queue id
            service_class = (i >> 2) & 0xF
            importance = i & 0x3
            if service_class >= fw_traffic_identification.MAX_TRAFFIC_SERVICE_CLASSES or\
                service_class > fw_traffic_identification.HIGHEST_IN_USE_TRAFFIC_CLASS:
                service_class = fw_traffic_identification.TRAFFIC_SERVICE_CLASS_VALUES['default']

            if importance >= len(fw_traffic_identification.TRAFFIC_IMPORTANCE_VALUES):
                importance = fw_traffic_identification.TRAFFIC_IMPORTANCE_VALUES['low']

            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['func']      = "call_vpp_api"
            cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
            cmd['cmd']['descr']     = "Set QoS traffic Map for \
                service-class: %d and importance: %d on dev-id: %s" % (service_class, importance, dev_id)
            cmd['cmd']['params']    =   {
                'api'         : 'sw_interface_set_dpdk_hqos_tctbl',
                'args'        : {
                    'entry'     : i,
                    'substs'    : [
                        {
                            'add_param'  : 'tc',
                            'val_by_func': {
                                'func'      : 'get_traffic_class',
                                'object'    : 'fwglobals.g.qos'
                            },
                            'arg'        : [service_class, importance]
                        },
                        {
                            'add_param'  : 'queue',
                            'val_by_func': {
                                'func'      : 'get_queue_id',
                                'object'    : 'fwglobals.g.qos'
                            },
                            'arg'        : [service_class, importance]
                        },
                        {
                            'add_param'  : 'sw_if_index',
                            'val_by_func': 'dev_id_to_vpp_sw_if_index',
                            'arg'        : parent_dev_id
                        }
                    ]
                }
            }
            cmd['revert'] = {}
            cmd['revert']['func']      = "call_vpp_api"
            cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
            cmd['revert']['descr']     = "Revert QoS traffic Map for \
                service-class: %d and importance: %d on dev-id: %s" % (service_class, importance, dev_id)
            cmd['revert']['params']    =   {
                'api'         : 'sw_interface_set_dpdk_hqos_tctbl',
                'args'        : {
                    'entry'       : i,
                    'tc'          : QOS_SCHED_MAP_DEFAULT_VALUE[0],
                    'queue'       : QOS_SCHED_MAP_DEFAULT_VALUE[1],
                    'substs': [
                        {
                            'add_param'  : 'sw_if_index',
                            'val_by_func': 'dev_id_to_vpp_sw_if_index',
                            'arg'        : parent_dev_id
                        }
                    ]
                }
            }
            cmd_list.append(cmd)


    def __get_interface_tunnel_setup_command(self, parent_dev_id, dev_id, interface_params,
                                             scheduling_params, cmd_list):
        """
        On applying QoS policy on the interface, all tunnels under the interface need to be
        setup for QoS.

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param interface_params: Interface configuration parameters
        :type interface_params: dict
        :param scheduling_params: Scheduling param for the given device identifier
        :type scheduling_params: dict
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        tunnel_messages = fwglobals.g.router_cfg.get_tunnels()
        setup_tunnel_list = [0] #including default '0' that represents internet (DIA)
        for tunnel_params in tunnel_messages:
            tunnel_id = tunnel_params["tunnel-id"]
            tunnel_dev_id = tunnel_params['dev_id']
            if tunnel_dev_id != dev_id:
                continue
            self.__get_setup_tunnel_qos_state_commands (parent_dev_id, dev_id, tunnel_id, cmd_list)
            self.__get_tunnel_bandwidth_update_command (parent_dev_id, dev_id, interface_params,\
                                                        tunnel_params, scheduling_params, cmd_list)
            setup_tunnel_list.append(tunnel_id)
        # Program the qos mark buffer-metadata-map with hierarchy ID values
        self.__get_qos_hierarchy_setup_command(parent_dev_id, dev_id,
                                               setup_tunnel_list, True, cmd_list)


    def __get_interface_tunnel_bandwidth_update_command(self, parent_dev_id, dev_id, interface_params,
                                                        scheduling_params, cmd_list):
        """
        On change of interface bandwidth, all tunnels under the interface need to be
        updated. The update-flow checks both the new interface bandwidth
        and the existing tunnel bandwidth configuration. The existing tunnel bandwidth
        data is fetched from the corresponding add-tunnel message in configuration DB

        :param parent_dev_id: Unique identifier of the device's parent interface
        :type parent_dev_id: String
        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param interface_params: Interface configuration parameters
        :type interface_params: dict
        :param scheduling_params: Scheduling param for the given device identifier
        :type scheduling_params: dict
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        tunnels = self.__qos_db['interfaces'][parent_dev_id][dev_id].get('tunnels')
        if tunnels is None:
            return
        for tunnel_id in tunnels.keys():
            tunnel_params = fwglobals.g.router_cfg.get_tunnel(tunnel_id)
            self.__get_tunnel_bandwidth_update_command(parent_dev_id, dev_id, interface_params,\
                                                       tunnel_params, scheduling_params, cmd_list)


    def get_traffic_map_update_commands(self, params):
        """
        Generate commands to process qos-traffic-map request. Apply the traffic map settings on
        each of the QoS enabled WAN interfaces by calling functions that setup HQoS TC and DSCP
        Map table

        :param params: QoS Traffic Map parameters
        :type params: dict
        :return: Array of commands generated
        :rtype: Array
        """
        cmd_list = []
        if (not self.__hqos_core_enabled):
            return cmd_list

        self.__get_build_qos_traffic_map_command (params, cmd_list)
        wan_if_list = fwglobals.g.router_cfg.get_interfaces(type='wan')
        for wan_if in wan_if_list:
            dev_id = wan_if['dev_id']
            parent_dev_id = fwutils.dev_id_get_parent(dev_id)
            qos_policy = self.__get_qos_policy(dev_id)
            if (qos_policy and self.__is_qos_state_setup(parent_dev_id, dev_id)):
                scheduling_params = qos_policy['outbound']['scheduling']
                self.__get_interface_traffic_map_update_commands\
                    (parent_dev_id, dev_id, scheduling_params, cmd_list)

        return cmd_list


    def get_add_interface_qos_commands (self, interface_params, cmd_list):
        """
        Generate commands to setup QoS - Called when interface is added/modified.
        On interface update, all tunnels will be reprogrammed based on the configuration
        On new add-interface add, enable classification on the interface. The setting up
        of QoS on this new interface shall be done as part of add-qos-policy processing

        :param params: Interface configuration parameters
        :type params: dict
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        if (not self.__hqos_core_enabled):
            return
        dev_id = interface_params.get('dev_id')
        get_interface_classification_setup_commands(dev_id, None, cmd_list)
        parent_dev_id = fwutils.dev_id_get_parent (dev_id)
        if not self.__is_qos_state_setup(parent_dev_id, dev_id):
            return

        # Setup Device bandwidth limit at DPDK sub-port hierarchy
        self.__get_interface_bandwidth_update_command\
            (parent_dev_id, dev_id, interface_params, cmd_list)

        qos_policy = self.__get_qos_policy(dev_id)
        scheduling_params = qos_policy['outbound']['scheduling']
        # Setup Default internet pipe limit at DPDK pipe hierarchy
        self.__get_tunnel_bandwidth_update_command\
            (parent_dev_id, dev_id, interface_params, None, scheduling_params,cmd_list)

        # Update bandwidth of all tunnels on this interface
        self.__get_interface_tunnel_bandwidth_update_command\
            (parent_dev_id, dev_id, interface_params, scheduling_params, cmd_list)


    def get_add_tunnel_qos_commands (self, params, cmd_list):
        """
        Generate commands to setup Tunnel QoS - Called when tunnel is added
        Initialize new pipe in QoS Hierarchy and setup required internal context to
        map tunnel id to QoS hierarchy pipe-id

        :param params: Tunnel configuration parameters
        :type params: dict
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        if (not self.__hqos_core_enabled):
            return
        dev_id = params.get('dev_id')
        parent_dev_id = fwutils.dev_id_get_parent (dev_id)
        tunnel_id = params.get('tunnel-id')
        # If QoS is not enabled on this interface, below calls make no changes to the internal state
        # But if later QoS is added on this interface, the revert commands ensures
        # the contexts are cleaned up on tunnel delete
        self.__get_setup_tunnel_qos_state_commands (parent_dev_id, dev_id, tunnel_id, cmd_list)
        self.__get_qos_hierarchy_setup_command (parent_dev_id, dev_id, [tunnel_id], False, cmd_list)

        if self.__is_qos_state_setup(parent_dev_id, dev_id):
            qos_policy = self.__get_qos_policy(dev_id)
            scheduling_params = qos_policy['outbound']['scheduling']
            interface_params = fwglobals.g.router_cfg.get_interfaces('wan', dev_id)[0]
            self.__get_tunnel_bandwidth_update_command\
                (parent_dev_id, dev_id, interface_params, params, scheduling_params, cmd_list)


    def get_modify_tunnel_qos_commands (self, params, previous_params, cmd_list):
        """
        Generate commands to modify Tunnel QoS - Called when tunnel is modified. Like, if there
        is change in bandwidth at the remote end of the tunnel. The pipe profile representing
        the tunnel shall be reconfigured

        :param params: Tunnel configuration parameters
        :type params: dict
        :param previous_params: Currently applied tunnel configuration parameters
        :type previous_params: dict
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        if (not self.__hqos_core_enabled):
            return
        dev_id = params.get('dev_id')
        parent_dev_id = fwutils.dev_id_get_parent (dev_id)
        tunnel_id = params.get('tunnel-id')

        if params.get('remoteBandwidthMbps') == previous_params.get('remoteBandwidthMbps'):
            self.log.debug('QoS(Interface: %s) - No bandwidth change detected on \
                modify tunnel-id : %d' % (dev_id, tunnel_id))
            return

        qos_policy = self.__get_qos_policy(dev_id)
        if qos_policy:
            scheduling_params = qos_policy['outbound']['scheduling']
            interface_params = fwglobals.g.router_cfg.get_interfaces('wan', dev_id)[0]
            self.__get_tunnel_bandwidth_update_command\
                (parent_dev_id, dev_id, interface_params, params, scheduling_params, cmd_list)


    def get_classification_setup_commands (self, sw_if_index_key, dev_id, cmd_list):
        """
        Get commands to enable classification on the interface

        :param dev_id: Unique identifier of the device
        :type dev_id: String
        :param sw_if_index_key: It can either be an integer representing the VPP interface or
         a key to be used to lookup the actual sw_if_index from command cache
        :type sw_if_index_key: Integer or String
        :param cmd_list: Array of generated configuration commands
        :type cmd_list: Array
        """
        if not self.__hqos_core_enabled:
            return
        if dev_id:
            # setup classification only if dev_id has QoS enabled on it
            qos_policy = self.__get_qos_policy(dev_id)
            # Enable if QoS is enabled and policy is applied on the WAN interface
            if qos_policy:
               get_interface_classification_setup_commands(None, sw_if_index_key, cmd_list)
        else:
            get_interface_classification_setup_commands(None, sw_if_index_key, cmd_list)


    def add_qos_policy (self, params):
        """
        Generate commands to apply QoS policy on interfaces - Called on add-qos-policy
        Updates all configured interfaces, tunnels under interfaces and Mapping tables like
        HQoS TC and DSCP map

        :param params: QoS policy configuration to be applied
        :type params: dict
        :return: Command array with the commands
        :rtype: Array
        """
        cmd_list = []
        if (not self.__hqos_core_enabled):
            self.log.warning('No Op - QoS policy - HQoS not enabled')
            return cmd_list

        parent_dev_id_list = []
        policies = params.get('policies')
        for policy in policies:
            interfaces = policy.get('interfaces')
            for dev_id in interfaces:

                scheduling_params = policy['outbound']['scheduling']
                interface_params = fwglobals.g.router_cfg.get_interfaces('wan', dev_id)[0]
                parent_dev_id = fwutils.dev_id_get_parent (dev_id)

                # Initialize device QoS states
                if parent_dev_id not in parent_dev_id_list:
                    self.__get_setup_interface_qos_state_commands (parent_dev_id, cmd_list)
                    parent_dev_id_list.append(parent_dev_id)
                self.__get_setup_sub_interface_qos_state_commands (parent_dev_id, dev_id, cmd_list)

                # Setup Device bandwidth limit at DPDK sub-port hierarchy
                self.__get_interface_bandwidth_update_command\
                    (parent_dev_id, dev_id, interface_params, cmd_list)

                # Setup Default internet pipe limit at DPDK pipe hierarchy
                self.__get_tunnel_bandwidth_update_command\
                    (parent_dev_id, dev_id, interface_params, None, scheduling_params, cmd_list)

                # Setup QoS on all tunnels on this interface
                self.__get_interface_tunnel_setup_command\
                    (parent_dev_id, dev_id, interface_params, scheduling_params, cmd_list)

                # Update traffic map and DSCP marking based on policy
                self.__get_interface_traffic_map_update_commands\
                    (parent_dev_id, dev_id, scheduling_params, cmd_list)

        return cmd_list

#####################################################################
# QoS helper functions used during configuration - command generation
#####################################################################

def get_default_qos_traffic_map():
    """
    Generate default QoS Traffic Map. The default maps all service-class and importance
    combinations to bestEffortQueue in the QoS scheduler

    :return: The generated QoS traffic Map shall be indexed by [service-class][importance]
    :rtype: Array
    """
    qos_traffic_map = []
    for _ in range(fw_traffic_identification.MAX_TRAFFIC_SERVICE_CLASSES):
        importance_values = []
        for _ in range(fw_traffic_identification.MAX_TRAFFIC_IMPORTANCE_VALUES):
            importance_values.append((QOS_SCHED_MAP_DEFAULT_VALUE[0],
                QOS_SCHED_MAP_DEFAULT_VALUE[1]))
        qos_traffic_map.append(importance_values)
    return qos_traffic_map


def get_qos_parent_dev_id_list (params=None):
    """
    Compute the list of unique parent interfaces that QoS enabled on it
    by parsing the qos policy message

    :param params: QoS policy configuration
    :type params: dict
    :return: Returns the list of parent interfaces with QoS enabled and the number of Qos interfaces
    :rtype: Array, Integer
    """
    parent_dev_id_list = []
    total_qos_interfaces_count = 0
    dev_id_list = []
    if params is None:
        params = fwglobals.g.router_cfg.get_qos_policy()

    if params:
        policies = params.get('policies')
        for policy in policies:
            interfaces = policy.get('interfaces')
            dev_id_list.extend(interfaces)

        for dev_id in dev_id_list:
            total_qos_interfaces_count += 1
            parent_dev_id = fwutils.dev_id_get_parent (dev_id)
            if parent_dev_id in parent_dev_id_list:
                continue
            else:
                parent_dev_id_list.append (parent_dev_id)
    return parent_dev_id_list, total_qos_interfaces_count


def has_qos_policy(dev_id=None, check_parent_dev_id=False):
    """
    Function to check if QoS is enabled on a given interface ID.
    If dev_id is None, then the function just checks if there is a QoS policy in configuration DB

    :param dev_id: Device identifier
    :type dev_id: String
    :return: True if it exists else False
    :rtype: Boolean
    """
    params = fwglobals.g.router_cfg.get_qos_policy()
    if params:
        if dev_id is None:
            return True
        policies = params.get('policies')
        for policy in policies:
            qos_interfaces = policy.get('interfaces')
            for qos_dev_id in qos_interfaces:
                if qos_dev_id == dev_id:
                    return True
                if check_parent_dev_id:
                    if dev_id == fwutils.dev_id_get_parent (qos_dev_id):
                        return True

    return False


def qos_db_dumps():
    """
    Function to return all QoS contexts in qos_db as JSON dump

    :return: Dump of QoS context in JSON format
    :rtype: String
    """
    with SqliteDict(fwglobals.g.QOS_DB_FILE,  flag='r') as qos_db:
        db_keys = sorted(qos_db.keys())
        dump = [ { key: qos_db[key] } for key in db_keys ]
        return json.dumps(dump, indent=2, sort_keys=True)


def get_interface_classification_setup_commands(dev_id, sw_if_index_key, cmd_list):
    """
    Generate commands to attach classification ACLs to the given interface

    :param dev_id: Device identifier
    :type dev_id: String
    :param sw_if_index_key: key to be used to lookup the actual sw_if_index from command cache
    :type sw_if_index_key: String
    :param cmd_list: Array of generated configuration commands
    :type cmd_list: Array
    """
    sw_if_index_by_key = False if dev_id else True

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "call_vpp_api"
    cmd['cmd']['descr']  = "Attach classification ACLs to interface : %s" %\
        (sw_if_index_key if sw_if_index_by_key else dev_id)
    cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['params'] = {
        'api' :  "classifier_acls_set_interface",
        'args': {
            'is_add': True,
        }
    }
    if sw_if_index_by_key:
        cmd['cmd']['params']['args']['substs'] = [
            {
                'add_param' : 'sw_if_index',
                'val_by_key': sw_if_index_key
            }
        ]
    else:
        cmd['cmd']['params']['args']['substs'] = [
            {
                'add_param'  : 'sw_if_index',
                'val_by_func': 'dev_id_to_vpp_sw_if_index',
                'arg': dev_id
            }
        ]

    cmd['revert'] = {}
    cmd['revert']['func']   = "call_vpp_api"
    cmd['revert']['descr']  = "Detach classification ACLs to interface : %s" %\
        (sw_if_index_key if sw_if_index_by_key else dev_id)
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['params'] = {
        'api' : "classifier_acls_set_interface",
        'args': {
            'is_add': False,
        }
    }
    if sw_if_index_by_key:
        cmd['revert']['params']['args']['substs'] = [
            {
                'add_param' : 'sw_if_index',
                'val_by_key': sw_if_index_key
            }
        ]
    else:
        cmd['revert']['params']['args']['substs'] = [
            {
                'add_param'  : 'sw_if_index',
                'val_by_func': 'dev_id_to_vpp_sw_if_index',
                'arg'        : dev_id
            }
        ]
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "call_vpp_api"
    cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr']     = "Enable ACL based classification on interface: %s" %\
        (sw_if_index_key if sw_if_index_by_key else dev_id)
    cmd['cmd']['params']    = {
        'api'  : "classifier_acls_enable_disable",
        'args' : {
            'enable_disable': True
        }
    }
    if sw_if_index_by_key:
        cmd['cmd']['params']['args']['substs'] = [
            {
                'add_param' : 'sw_if_index',
                'val_by_key': sw_if_index_key
            }
        ]
    else:
        cmd['cmd']['params']['args']['substs'] = [
            {
                'add_param'  : 'sw_if_index',
                'val_by_func': 'dev_id_to_vpp_sw_if_index',
                'arg'        : dev_id
            }
        ]

    cmd['revert'] = {}
    cmd['revert']['func']      = "call_vpp_api"
    cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['descr']     = "Enable ACL based classification on interface: %s" %\
        (sw_if_index_key if sw_if_index_by_key else dev_id)
    cmd['revert']['params']    =   {
        'api'  : "classifier_acls_enable_disable",
        'args' : {
            'enable_disable': False,
        }
    }
    if sw_if_index_by_key:
        cmd['revert']['params']['args']['substs'] = [
            {
                'add_param' : 'sw_if_index',
                'val_by_key': sw_if_index_key
            }
        ]
    else:
        cmd['revert']['params']['args']['substs'] = [
            {
                'add_param'  : 'sw_if_index',
                'val_by_func': 'dev_id_to_vpp_sw_if_index',
                'arg'        : dev_id
            }
        ]
    cmd_list.append(cmd)


def update_interface_qos_classification(vpp_if_name, add):
    """
    Commands to attach / detach classification ACLs on the given interface

    :param vpp_if_name: Interface name on which classification is to be enabled
    :type vpp_if_name: String
    :param add: Flag indicating to attach or detach
    :type add: Boolean
    """
    vpp_commands = []
    params = vpp_if_name if add else vpp_if_name + ' del'
    vpp_commands.append('classifier-acls set %s' % params)
    vpp_commands.append('classifier-acls enable %s' % params)
    status, err = fwutils.vpp_cli_execute(vpp_commands)
    if not status:
        fwglobals.log.error('Error in enabling QoS classification on: %s (%s)' % (vpp_if_name, err))
