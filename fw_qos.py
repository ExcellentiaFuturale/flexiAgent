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

    def __init__(self):
        """
        Init defaults and QoS context (qos_db)
        """
        FwObject.__init__(self)
        self.__QOS_SCHED_DEFAULT_SUB_PORT_PROFILE_ID = 0
        self.__QOS_SCHED_DEFAULT_SUB_PORT_ID = 0
        self.__QOS_SCHED_DEFAULT_TUNNEL_ID = 0
        self.__QOS_SCHED_MAX_TRAFFIC_CLASSES = 13 #DPDK traffic class count
        self.__INTERFACE_BANDWIDTH_DEFAULT_BPS = 12500000 #100Mbps in Bytes
        self.__MEGA_BITS_TO_BYTES_MULTIPLIER = 125000
        self.__TUNNEL_ID_KEY_PREFIX = 'tunnel-id-%d'
        self.__total_worker_cores = 0
        self.__hqos_core_enabled = False

        # DPDK provides max 4K count of identifiers under an interface or a sub-port
        self.__QOS_HIERARCHY_MAX_COUNT = 4096

        # Default scheduling configuration
        self.__DEFAULT_REALTIME_BANDWIDTH_LIMIT = 30
        self.__DEFAULT_WRR = [40, 30, 20, 10]

        '''
        Structure of qos_db
        qos_db : {
            interfaces : {
                'dev-id-1' : {
                    'id' : unique_integer identifier for device,
                    'tunnels' : {
                        tunnel_id-1: qos_hierarchy_id,
                        tunnel_id-2: qos_hierarchy_id,
                        ...
                        }
                    },
                    'qos_hierarchy_id_list' : Array of free QoS hierarchy IDs
                },
                'dev-id-2' : {
                    ....
                }
            },
            # qos_traffic_map is an array indexed by [service_class][importance] providing
            # corresponding traffic-class and queue-id values
            traffic-map : [[]]
        }
        '''
        self.__qos_db = SqliteDict(fwglobals.g.QOS_DB_FILE, autocommit=True)
        self.__qos_db.clear()
        self.__qos_db['interfaces'] = {}
        self.__qos_db['traffic-map'] = get_default_qos_traffic_map()


    def __del__(self):
        """
        Destructor - Close SqliteDict
        """
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
        self.__total_worker_cores = 0
        self.__hqos_core_enabled = False


    def __get_wan_interface_bandwidth_Bps (self, dev_id):
        """
        Returns interface bandwidth in Bytes per second by reading corresponding
        add-interface message in the configuration DB

        :param dev_id: Device identifier
        :type dev_id: String
        :return: Tx and Rx bandwidth values in bytes per second
        :rtype: two integers
        """
        params = fwglobals.g.router_cfg.get_interfaces(type='wan', dev_id=dev_id)
        bandwidth_mbps = params[0].get('bandwidthMbps')
        tx_Bps = rx_Bps = 0
        if bandwidth_mbps:
            tx_Bps = int(bandwidth_mbps.get('tx') * self.__MEGA_BITS_TO_BYTES_MULTIPLIER)
            rx_Bps = int(bandwidth_mbps.get('rx') * self.__MEGA_BITS_TO_BYTES_MULTIPLIER)
        if tx_Bps == 0:
            tx_Bps = self.__INTERFACE_BANDWIDTH_DEFAULT_BPS
        if rx_Bps == 0:
            rx_Bps = self.__INTERFACE_BANDWIDTH_DEFAULT_BPS
        return tx_Bps, rx_Bps


    def __get_tunnel_tx_bandwidth_Bps (self, tunnel_params, interface_tx_Bps=None):
        """
        Get the TX bandwidth of the tunnel. It is computed as min of interface TX bandwidth
        and the remote interface RX bandwidth - As we do not want oversubscribe the remote
        interface bandwidth limits

        :param tunnel_params: Tunnel configuration parameters
        :type tunnel_params: dict
        :param interface_tx_Bps: Interface TX bandwidth in Bytes per second
        :type interface_tx_Bps: Integer
        :return: Supported TX bandwidth on the tunnel
        :rtype: Integer
        """
        if interface_tx_Bps is None:
            dev_id = tunnel_params.get('dev_id')
            interface_tx_Bps, _ = self.__get_wan_interface_bandwidth_Bps(dev_id)
        tunnel_bandwidth_mbps = tunnel_params.get('remoteBandwidthMbps')
        tunnel_rx_Bps = 0
        if tunnel_bandwidth_mbps:
            tunnel_rx_Bps = int(tunnel_bandwidth_mbps.get('rx') * \
                self.__MEGA_BITS_TO_BYTES_MULTIPLIER)
        if tunnel_rx_Bps == 0:
            tunnel_rx_Bps = self.__INTERFACE_BANDWIDTH_DEFAULT_BPS
        return min(tunnel_rx_Bps, interface_tx_Bps)


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


    def __get_interface_bandwidth_update_command(self, dev_id, sw_if_index, tx_Bps, cmd_list):
        """
        Generate commands to update interface bandwidth value. In our WAN-QoS model, the subport
        level in DPDK HQOS hierarchy represents the interface WAN bandwidth. This function updates
        the subport profile to set the desired WAN bandwidth

        :param dev_id: Device identifier
        :type dev_id: String
        :param sw_if_index: VPP identifier for given dev_id
        :type sw_if_index: Integer
        :param tx_Bps: TX bandwidth of the interface in Bytes Per Second
        :type tx_Bps: Integer
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        tc_rate = [tx_Bps] * self.__QOS_SCHED_MAX_TRAFFIC_CLASSES
        tc_period, tb_size = self.__get_hqos_sched_params(tx_Bps)
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "call_vpp_api"
        cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']     = "Set bandwidth limit for dev_id: %s" % dev_id
        cmd['cmd']['params']    =   {
            'api' : 'sw_interface_set_dpdk_hqos_subport_profile',
            'args': {
                'sw_if_index' : sw_if_index,
                'profile'     : self.__QOS_SCHED_DEFAULT_SUB_PORT_PROFILE_ID,
                'tb_rate'     : tx_Bps,
                'tc_rate'     : tc_rate,
                'tc_period'   : tc_period,
                'tb_size'     : tb_size,
            }
        }
        revert_tc_rate = [self.__INTERFACE_BANDWIDTH_DEFAULT_BPS] * self.__QOS_SCHED_MAX_TRAFFIC_CLASSES
        revert_tc_period, revert_tb_size =\
            self.__get_hqos_sched_params(self.__INTERFACE_BANDWIDTH_DEFAULT_BPS)
        cmd['revert'] = {}
        cmd['revert']['func']      = "call_vpp_api"
        cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr']     = "Set bandwidth limit for dev_id: %s" % dev_id
        cmd['revert']['params']    =   {
            'api' : 'sw_interface_set_dpdk_hqos_subport_profile',
            'args': {
                'sw_if_index' : sw_if_index,
                'profile'     : self.__QOS_SCHED_DEFAULT_SUB_PORT_PROFILE_ID,
                'tb_rate'     : self.__INTERFACE_BANDWIDTH_DEFAULT_BPS,
                'tc_rate'     : revert_tc_rate,
                'tc_period'   : revert_tc_period,
                'tb_size'     : revert_tb_size,
            }
        }
        cmd_list.append(cmd)


    def __get_tunnel_bandwidth_update_command(self, dev_id, sw_if_index,
        scheduling_params, tunnel_id, qos_hierarchy_id, tx_Bps, previous_tx_Bps, cmd_list):
        """
        Generate commands to update tunnel bandwidth value. In our WAN-QoS model, the pipe
        level in DPDK HQOS hierarchy represents the tunnel bandwidth. This function updates
        the pipe profile to set the desired tunnel bandwidth. The function also sets the
        WRR (Weighted Round Robin) configuration to setup weighted allocation of bandwidth to
        different queues under DATA traffic class

        :param dev_id: Device identifier
        :type dev_id: String
        :param sw_if_index: VPP identifier for given dev_id
        :type sw_if_index: Integer
        :param scheduling_params: Scheduling param for the given device identifier
        :type scheduling_params: dict
        :param tunnel_id: Tunnel identifier received in add-tunnel message
        :type tunnel_id: Integer
        :param qos_hierarchy_id: ID representing the tunnel in QoS hierarchy
        :type qos_hierarchy_id: Integer
        :param tx_Bps: TX bandwidth of the tunnel in Bytes Per Second
        :type tx_Bps: Integer
        :param previous_tx_Bps: Previous TX bandwidth of the tunnel in Bytes Per Second
        :type previous_tx_Bps: Integer
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        apply_tc_rate = [tx_Bps] * self.__QOS_SCHED_MAX_TRAFFIC_CLASSES
        apply_tc_rate[SCHEDULER_REALTIME_TRAFFIC_CLASS_ID] =\
                int((scheduling_params[REALTIME_QUEUE]['bandwidthLimitPercent'] * tx_Bps)/100)

        wrr = [
                scheduling_params[CONTROL_SIGNALING_QUEUE]['weight'],
                scheduling_params[PRIME_SELECT_QUEUE]['weight'],
                scheduling_params[STANDARD_SELECT_QUEUE]['weight'],
                scheduling_params[BEST_EFFORT_QUEUE]['weight']
                ]
        tc_period, tb_size = self.__get_hqos_sched_params(tx_Bps)
        realtime_tc_period, realtime_tb_size = \
            self.__get_hqos_sched_params(apply_tc_rate[SCHEDULER_REALTIME_TRAFFIC_CLASS_ID])
        # Sets up a Tunnel QoS profile with bandwidth, rate-limiting and WRR values
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "call_vpp_api"
        cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']     = "Set tunnel QoS for dev-id: %s tunnel-id: %d" % (dev_id, tunnel_id)
        cmd['cmd']['params']    =   {
            'api'         : 'sw_interface_set_dpdk_hqos_pipe_profile',
            'args'        : {
                'sw_if_index' : sw_if_index,
                'subport_id'  : self.__QOS_SCHED_DEFAULT_SUB_PORT_ID,
                'tb_rate'     : tx_Bps,
                'tc_rate'     : apply_tc_rate,
                'wrr'         : wrr,
                'tc_period'   : min(tc_period, realtime_tc_period),
                'tb_size'     : max(tb_size, realtime_tb_size)
            }
        }
        if (tunnel_id == self.__QOS_SCHED_DEFAULT_TUNNEL_ID):
            cmd['cmd']['params']['args']['profile'] = 0
        else:
            if (qos_hierarchy_id is None):
                tunnel_id_key = self.__TUNNEL_ID_KEY_PREFIX % tunnel_id
                cmd['cmd']['params']['args']['substs'] = [
                    { 'add_param': 'profile', 'val_by_key': tunnel_id_key }
                ]
            else:
                cmd['cmd']['params']['args']['profile'] = qos_hierarchy_id

        if previous_tx_Bps:
            revert_tx_Bps = previous_tx_Bps
        else:
            revert_tx_Bps = self.__INTERFACE_BANDWIDTH_DEFAULT_BPS
        revert_tc_rate = [revert_tx_Bps] * self.__QOS_SCHED_MAX_TRAFFIC_CLASSES
        revert_tc_rate[SCHEDULER_REALTIME_TRAFFIC_CLASS_ID] =\
                int((self.__DEFAULT_REALTIME_BANDWIDTH_LIMIT * revert_tx_Bps)/100)
        revert_wrr = self.__DEFAULT_WRR

        revert_tc_period, revert_tb_size =\
            self.__get_hqos_sched_params(revert_tc_rate[SCHEDULER_REALTIME_TRAFFIC_CLASS_ID])
        realtime_revert_tc_period, realtime_revert_tb_size = \
            self.__get_hqos_sched_params(apply_tc_rate[SCHEDULER_REALTIME_TRAFFIC_CLASS_ID])

        cmd['revert'] = {}
        cmd['revert']['func']      = "call_vpp_api"
        cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr']     = "Set tunnel QoS for dev-id: %s tunnel-id: %d" % (dev_id, tunnel_id)
        cmd['revert']['params']    =   {
            'api'         : 'sw_interface_set_dpdk_hqos_pipe_profile',
            'args'        : {
                'sw_if_index' : sw_if_index,
                'subport_id'  : self.__QOS_SCHED_DEFAULT_SUB_PORT_ID,
                'tb_rate'     : revert_tx_Bps,
                'tc_rate'     : revert_tc_rate,
                'wrr'         : revert_wrr,
                'tc_period'   : min(revert_tc_period, realtime_revert_tc_period),
                'tb_size'     : max(revert_tb_size, realtime_revert_tb_size),
            }
        }
        if (tunnel_id == self.__QOS_SCHED_DEFAULT_TUNNEL_ID):
            cmd['revert']['params']['args']['profile'] = 0
        else:
            if (qos_hierarchy_id is None):
                tunnel_id_key = self.__TUNNEL_ID_KEY_PREFIX % tunnel_id
                cmd['revert']['params']['args']['substs'] = [
                    { 'add_param': 'profile', 'val_by_key': tunnel_id_key }
                ]
            else:
                cmd['revert']['params']['args']['profile'] = qos_hierarchy_id

        cmd_list.append(cmd)

        # Update tunnel (pipe) in QoS hierarchy to use updated profile
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "call_vpp_api"
        cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']     = "Set tunnel QoS for dev-id: %s tunnel-id: %d" % (dev_id, tunnel_id)
        cmd['cmd']['params']    =   {
            'api'         : 'sw_interface_set_dpdk_hqos_pipe',
            'args'        : {
                'sw_if_index' : sw_if_index,
                'subport_id'  : self.__QOS_SCHED_DEFAULT_SUB_PORT_ID
            }
        }
        if (tunnel_id == self.__QOS_SCHED_DEFAULT_TUNNEL_ID):
            cmd['cmd']['params']['args']['pipe_id'] = 0
            cmd['cmd']['params']['args']['profile'] = 0
        else:
            tunnel_id_key = self.__TUNNEL_ID_KEY_PREFIX % tunnel_id
            if (qos_hierarchy_id is None):
                tunnel_id_key = self.__TUNNEL_ID_KEY_PREFIX % tunnel_id
                cmd['cmd']['params']['args']['substs'] = [
                    { 'add_param': 'pipe_id', 'val_by_key': tunnel_id_key },
                    { 'add_param': 'profile', 'val_by_key': tunnel_id_key }
                ]
            else:
                cmd['cmd']['params']['args']['pipe_id'] = qos_hierarchy_id
                cmd['cmd']['params']['args']['profile'] = qos_hierarchy_id
        cmd_list.append(cmd)


    def __get_tunnel_bandwidth_add_command(self, dev_id, sw_if_index,
        scheduling_params, tunnel_id, tx_Bps, cmd_list):
        """
        Generate commands to setup tunnel in QoS hierarchy. In our WAN-QoS model, the pipe
        level in DPDK HQOS hierarchy represents the WAN tunnels. In this function, a unique
        pipe is allocated for each WAN tunnel and the pipe is provisioned based on the
        configuration parameters

        :param dev_id: Device identifier
        :type dev_id: String
        :param sw_if_index: VPP identifier for given dev_id
        :type sw_if_index: Integer
        :param scheduling_params: Scheduling param for the given device identifier
        :type scheduling_params: dict
        :param tunnel_id: Tunnel identifier received in add-tunnel message
        :type tunnel_id: Integer
        :param tx_Bps: TX bandwidth of the tunnel in Bytes Per Second
        :type tx_Bps: Integer
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        tunnel_id_key = self.__TUNNEL_ID_KEY_PREFIX % tunnel_id
        if tunnel_id != self.__QOS_SCHED_DEFAULT_TUNNEL_ID:
            # Default tunnel-id (0) represents the internet traffic - its corresponding
            # QoS Hierarchy ID is reserved as 0 at interface init
            # Command to allocate a unique QoS hierarchy ID for the tunnels
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['func']      = "allocate_tunnel_qos_hierarchy_id"
            cmd['cmd']['object']    = "fwglobals.g.qos"
            cmd['cmd']['descr']     = "Allocate tunnel hierarchy id for dev-id: %s tunnel-id: %d" % (dev_id, tunnel_id)
            cmd['cmd']['params']    =   {
                'dev_id'        : dev_id,
                'tunnel_id'     : tunnel_id
            }
            cmd['cmd']['cache_ret_val'] = ('qos_hierarchy_id', tunnel_id_key)

            cmd['revert'] = {}
            cmd['revert']['func']      = "release_tunnel_qos_hierarchy_id"
            cmd['revert']['object']    = "fwglobals.g.qos"
            cmd['revert']['descr']     = "Release tunnel hierarchy id for dev-id: %s tunnel-id: %d" % (dev_id, tunnel_id)
            cmd['revert']['params']    =   {
                'dev_id'        : dev_id,
                'tunnel_id'     : tunnel_id
            }
            cmd_list.append(cmd)

        self.__get_tunnel_bandwidth_update_command(dev_id, sw_if_index, scheduling_params, \
            tunnel_id, None, tx_Bps, None, cmd_list)


    def __get_interface_tunnel_bandwidth_update_command(self, dev_id, sw_if_index,
        scheduling_params, tx_Bps, cmd_list):
        """
        On change of interface bandwidth, all tunnels under the interface need to be
        reconfigured. The reconfiguration checks both the new interface bandwidth
        and the existing tunnel bandwidth configuration. The existing tunnel bandwidth
        data is fetched from the corresponding add-tunnel message in configuration DB

        :param dev_id: Device identifier
        :type dev_id: String
        :param sw_if_index: VPP identifier for given dev_id
        :type sw_if_index: Integer
        :param scheduling_params: Scheduling param for the given device identifier
        :type scheduling_params: dict
        :param tx_Bps: TX bandwidth of the tunnel in Bytes Per Second
        :type tx_Bps: Integer
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        tunnels = self.__qos_db['interfaces'][dev_id].get('tunnels')
        if tunnels is None:
            return
        for tunnel_id, tunnel_value in tunnels.items():
            tunnel_params = fwglobals.g.router_cfg.get_tunnel(tunnel_id)
            if tunnel_params:
                tx_Bps = self.__get_tunnel_tx_bandwidth_Bps(tunnel_params, interface_tx_Bps=tx_Bps)

            self.__get_tunnel_bandwidth_update_command\
                (dev_id, sw_if_index, scheduling_params, \
                    tunnel_id, tunnel_value, tx_Bps, None, cmd_list)


    def __get_interface_traffic_map_update_commands(self, dev_id, sw_if_index,
        scheduling_params, update_qos_map, cmd_list):
        """
        Generate commands to update Two tables and enables DSCP marking on WAN interfaces
        1. HQOS TC Table  - Maps [service-class][importance] to Scheduler traffic class and queue
        2. DSCP Table - Maps given [service-class][importance] to configured DSCP value

        :param dev_id: Device identifier
        :type dev_id: String
        :param sw_if_index: VPP identifier for given dev_id
        :type sw_if_index: Integer
        :param scheduling_params: Scheduling param for the given device identifier
        :type scheduling_params: dict
        :param update_qos_map: Flag to indicate if DPDK Traffic class table needs update
        :type update_qos_map: Boolean
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        # Setup DSCP Map
        egress_map = {
            'id'   : self.__qos_db['interfaces'][dev_id]['id'],
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
                        'add_param': 'map',
                        'val_by_func': 'fw_qos.build_egress_map',
                        'arg': [scheduling_params, egress_map]
                    }
                ]
            }
        }
        cmd['revert'] = {}
        cmd['revert']['func']      = "call_vpp_api"
        cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr']     = "Setup Egress MAP for DSCP rewrite on dev-id: %s" % dev_id
        cmd['revert']['params']    =   {
            'api'   : 'qos_egress_map_update',
            'args'  : {
                'map': {
                    'id'   : self.__qos_db['interfaces'][dev_id]['id'],
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
                'sw_if_index'  : sw_if_index,
                'map_id'       : self.__qos_db['interfaces'][dev_id]['id'],
                'output_source': 3
                }
            }
        }
        cmd_list.append(cmd)

        if update_qos_map is False:
            return

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
                    'sw_if_index' : sw_if_index,
                    'entry'       : i,
                    'substs': [
                        {
                            'add_param': 'tc',
                            'val_by_func': 'fw_qos.get_traffic_class',
                            'arg': [service_class, importance]
                        },
                        {
                            'add_param': 'queue',
                            'val_by_func': 'fw_qos.get_queue_id',
                            'arg': [service_class, importance]
                        },
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
                    'sw_if_index' : sw_if_index,
                    'entry'       : i,
                    'tc'          : QOS_SCHED_MAP_DEFAULT_VALUE[0],
                    'queue'       : QOS_SCHED_MAP_DEFAULT_VALUE[1]
                }
            }
            cmd_list.append(cmd)


    def __get_enable_classification_acls_commands(self, sw_if_index, cmd_list):
        """
        The traffic classification ACLs are added while processing add-application message.
        But the classification shall not be enabled till QoS policy is applied. This
        function enables the already configured classification-ACLs on the given interface

        :param sw_if_index: VPP identifier for given dev_id
        :type sw_if_index: Integer
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        """
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "call_vpp_api"
        cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']     = "Enable ACL based classification on LAN sw_if_index: %d" % sw_if_index
        cmd['cmd']['params']    =   {
            'api'  : "classifier_acls_enable_disable",
            'args' : {
                'sw_if_index'   : sw_if_index,
                'enable_disable': True
            }
        }
        cmd['revert'] = {}
        cmd['revert']['func']      = "call_vpp_api"
        cmd['revert']['object']    = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr']     = "Enable ACL based classification on LAN sw_if_index: %d" % sw_if_index
        cmd['revert']['params']    =   {
            'api'  : "classifier_acls_enable_disable",
            'args' : {
                'sw_if_index'   : sw_if_index,
                'enable_disable': False
            }
        }
        cmd_list.append(cmd)


    def update_hqos_worker_state(self, hqos_core_enabled, num_worker_cores):
        """
        Maintain context on if hqos core is enabled and the number of available total cpu workers.
        It shall later be used to decide if QoS policy need to be processed or not

        :param hqos_core_enabled: Is HQoS thread configured
        :type hqos_core_enabled: Boolean
        :param num_worker_cores: Total number of available cpu workers cores
        :type hqos_core_enabled: Integer
        """
        self.__hqos_core_enabled = hqos_core_enabled
        self.__total_worker_cores = num_worker_cores


    def get_hqos_worker_state(self):
        """
        Return current state of hqos core assignment and number of available total cpu workers

        :return hqos_core_enabled: Is HQoS thread configured
        :rtype hqos_core_enabled: Boolean
        :return num_worker_cores: Total number of available cpu workers cores
        :rtype hqos_core_enabled: Integer
        """
        return self.__hqos_core_enabled, self.__total_worker_cores


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
        if (self.__hqos_core_enabled is False):
            self.log.warning('No Op - QoS traffic Map - HQoS not enabled')
            return cmd_list

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "build_qos_traffic_map"
        cmd['cmd']['object']    = "fwglobals.g.qos"
        cmd['cmd']['descr']     = "Build QoS Traffic Map"
        cmd['cmd']['params']    = { 'params' : params }
        cmd_list.append(cmd)

        wan_if_list = fwglobals.g.router_cfg.get_interfaces(type='wan')
        for wan_if in wan_if_list:
            dev_id = wan_if['dev_id']
            qos_policy = self.__get_qos_policy(dev_id)
            if qos_policy:
                scheduling_params = qos_policy['outbound']['scheduling']
                sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(wan_if['dev_id'])
                self.__get_interface_traffic_map_update_commands\
                    (dev_id, sw_if_index, scheduling_params, True, cmd_list)

        return cmd_list


    def lookup_qos_traffic_map (self, service_class, importance):
        """
        Return traffic-class, queue ID from the qos_traffic_map context that was earlier built
        from qos-traffic-map parameters

        :param service_class: Traffic service class identifier
        :type service_class: Integer
        :param importance: Traffic importance identifier
        :type importance: Integer
        :return: traffic-class and queue ID
        :rtype: Two Integers
        """
        return self.__qos_db['traffic-map'][service_class][importance]


    def allocate_tunnel_qos_hierarchy_id (self, dev_id, tunnel_id, result_cache=None):
        """
        Allocate a unique ID to represent the tunnel in QoS hierarchy. Allocates a value between
        0 to __QOS_HIERARCHY_MAX_COUNT. If unique ID is exhausted then the default ID is used

        :param dev_id: Device identifier
        :type dev_id: String
        :param tunnel_id: Tunnel identifier received in add-tunnel message
        :type tunnel_id: Integer
        :param result_cache: Command execution cache, defaults to None
        :type result_cache: dict, optional
        """
        qos_interface_db = self.__qos_db['interfaces']
        qos_hierarchy_id_list = qos_interface_db[dev_id]['qos_hierarchy_id_list']
        if len(qos_hierarchy_id_list) > 0:
            qos_hierarchy_id = qos_hierarchy_id_list.pop()
            qos_interface_db[dev_id]['tunnels'][tunnel_id] = qos_hierarchy_id
        else:
            self.log.warning('QoS hierarchy ID exhausted in device \
                (Tunnel: %s assigned Default): %s' % (dev_id, tunnel_id))
            qos_interface_db[dev_id]['tunnels'][tunnel_id] = self.__QOS_SCHED_DEFAULT_TUNNEL_ID

        self.__qos_db['interfaces'] = qos_interface_db
        if result_cache and result_cache['result_attr'] == 'qos_hierarchy_id':
            key = result_cache['key']
            result_cache['cache'][key] = qos_hierarchy_id


    def release_tunnel_qos_hierarchy_id (self, dev_id, tunnel_id):
        """
        Release the tunnel's QoS Hierarchy ID to the per interface free-list

        :param dev_id: Device identifier
        :type dev_id: String
        :param tunnel_id: Tunnel identifier received in add-tunnel message
        :type tunnel_id: Integer
        """
        if tunnel_id != self.__QOS_SCHED_DEFAULT_TUNNEL_ID:
            qos_interface_db = self.__qos_db['interfaces']
            qos_hierarchy_id = qos_interface_db[dev_id]['tunnels'][tunnel_id]
            qos_interface_db[dev_id]['qos_hierarchy_id_list'].append(qos_hierarchy_id)
            del qos_interface_db[dev_id]['tunnels'][tunnel_id]
            self.__qos_db['interfaces'] = qos_interface_db


    def get_tunnel_qos_hierarchy_id (self, dev_id, tunnel_id):
        """
        Lookup QoS hierarchy ID in the internal context using dev_id and tunnel_id as key

        :param dev_id: Device identifier
        :type dev_id: String
        :param tunnel_id: Tunnel identifier received in add-tunnel message
        :type tunnel_id: Integer
        :return: ID representing the tunnel in QoS hierarchy
        :rtype: Integer
        """
        if self.__qos_db['interfaces'].get(dev_id):
            return self.__qos_db['interfaces'][dev_id]['tunnels'][tunnel_id]
        return self.__QOS_SCHED_DEFAULT_TUNNEL_ID


    def compare_qos_interfaces(self, interfaces):
        """
        Compares the given array of QoS interfaces with the current QoS enabled interfaces.
        Returns False if the array compare fails i.e. A new add or delete is detected

        :param interfaces: Interfaces to be compared
        :type interfaces: Array
        :return: Result of the comparison
        :rtype: Boolean
        """
        qos_interfaces = None
        qos_interface_db = self.__qos_db.get('interfaces')
        if qos_interface_db:
            qos_interfaces = list(qos_interface_db.keys())
            qos_interfaces.sort()
            if interfaces:
                interfaces.sort()
                if qos_interfaces == interfaces:
                    return True
            return False
        elif interfaces:
            # Existing context is empty but passed interfaces has values
            return False
        else:
            #Both are empty
            return True


    def get_add_interface_qos_commands (self, params, cmd_list):
        """
        Generate commands to setup QoS - Called when interface is added/modified.
        On new add-interface add, per interface contexts are initialized then the interface
        WAN bandwidth and the default pipe representing the internet shall be setup.
        On interface update, all tunnels will be reprogrammed based on the configuration

        :param params: Interface configuration parameters
        :type params: dict
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        :return: Array of commands generated
        :rtype: Array
        """
        dev_id = params.get('dev_id')
        qos_policy = self.__get_qos_policy(dev_id)
        if (self.__hqos_core_enabled is False) or qos_policy is None:
            self.log.debug('Add-Interface : QoS is not supported/configured: %s' % dev_id)
            return cmd_list

        tx_Bps = 0
        bandwidth_mbps = params.get('bandwidthMbps')
        if bandwidth_mbps:
            tx_Bps = int(bandwidth_mbps.get('tx') * self.__MEGA_BITS_TO_BYTES_MULTIPLIER)
        if tx_Bps == 0:
            tx_Bps = self.__INTERFACE_BANDWIDTH_DEFAULT_BPS
        scheduling_params = qos_policy['outbound']['scheduling']
        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)

        if self.__qos_db['interfaces'].get(dev_id) is None:
            # IF-Path: Flow of add-interface during VPP startup
            qos_hierarchy_id_list = list()
            # 0 to __QOS_HIERARCHY_MAX_COUNT - Used as LIFO. Higher IDs shall be used only when
            # lower IDs are already in use. Reverse inserted to have pop happen in ascending order
            for i in range ((self.__QOS_HIERARCHY_MAX_COUNT - 1), -1, -1):
                qos_hierarchy_id_list.append(i)
            qos_interface_db = self.__qos_db['interfaces']
            dev_id_qos = {}
            dev_id_qos['tunnels'] = {}
            dev_id_qos['qos_hierarchy_id_list'] = qos_hierarchy_id_list
            # A unique ID per interface - Used in DSCP Map create / identification
            dev_id_qos['id'] = len(self.__qos_db['interfaces'])
            qos_interface_db[dev_id] = dev_id_qos
            self.__qos_db['interfaces'] = qos_interface_db
            # Reserve Qos-Hierarchy-ID 0 for default non-tunnel interface traffic
            self.allocate_tunnel_qos_hierarchy_id(dev_id, 0)
        else:
            # ELSE-Path: Flow of add-interface due to interface parameter change(bandwidth)
            self.__get_interface_tunnel_bandwidth_update_command\
                (dev_id, sw_if_index, scheduling_params, tx_Bps, cmd_list)

        #Setup default QoS node (pipe) to carry internet traffic
        self.__get_tunnel_bandwidth_add_command\
            (dev_id, sw_if_index, scheduling_params, 0, tx_Bps, cmd_list)

        # Setup Device bandwidth limit at DPDK sub-port hierarchy
        self.__get_interface_bandwidth_update_command(dev_id, sw_if_index, tx_Bps, cmd_list)


    def get_add_tunnel_qos_commands (self, params, cmd_list):
        """
        Generate commands to setup Tunnel QoS - Called when tunnel is added
        Initialize new pipe in QoS Hierarchy and setup required internal context to
        map tunnel id to QoS hierarchy pipe-id

        :param params: Tunnel configuration parameters
        :type params: dict
        :param cmd_list: Command array to be updated with commands
        :type cmd_list: Array
        :return: Array of commands generated
        :rtype: Array
        """
        dev_id = params.get('dev_id')
        qos_policy = self.__get_qos_policy(dev_id)
        if (self.__hqos_core_enabled is False) or qos_policy is None:
            self.log.debug('Add-Tunnel : QoS is not supported/configured: %s' % dev_id)
            return cmd_list

        tx_Bps = self.__get_tunnel_tx_bandwidth_Bps (params)
        scheduling_params = qos_policy['outbound']['scheduling']
        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)
        tunnel_id = params.get('tunnel-id')

        self.__get_tunnel_bandwidth_add_command\
            (dev_id, sw_if_index, scheduling_params, tunnel_id, tx_Bps, cmd_list)


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
        :return: Array of commands generated
        :rtype: Array
        """
        dev_id = params.get('dev_id')
        qos_policy = self.__get_qos_policy(dev_id)
        if (self.__hqos_core_enabled is False) or qos_policy is None:
            self.log.debug('Modify-Tunnel : QoS is not supported/configured: %s' % dev_id)
            return cmd_list

        tx_Bps = self.__get_tunnel_tx_bandwidth_Bps (params)
        previous_tx_Bps = self.__get_tunnel_tx_bandwidth_Bps (previous_params)

        tunnel_id = params.get('tunnel-id')
        if tx_Bps == previous_tx_Bps:
            #No change detected
            self.log.debug('QoS(Interface: %s) - No bandwidth change detected on \
                modify tunnel-id : %d' % (dev_id, tunnel_id))
            return cmd_list

        scheduling_params = qos_policy['outbound']['scheduling']
        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)

        qos_hierarchy_id = self.__qos_db['interfaces'][dev_id]['tunnels'][tunnel_id]
        self.__get_tunnel_bandwidth_update_command\
            (dev_id, sw_if_index, scheduling_params, tunnel_id,
            qos_hierarchy_id, tx_Bps, previous_tx_Bps, cmd_list)


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
        if (self.__hqos_core_enabled is False):
            self.log.warning('No Op - QoS policy - HQoS not enabled')
            return cmd_list

        policies = params.get('policies')
        for policy in policies:
            interfaces = policy.get('interfaces')
            for dev_id in interfaces:

                tx_Bps, _ = self.__get_wan_interface_bandwidth_Bps(dev_id)
                scheduling_params = policy['outbound']['scheduling']
                sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)

                # Update all tunnels with QoS policy
                self.__get_interface_tunnel_bandwidth_update_command\
                    (dev_id, sw_if_index, scheduling_params, tx_Bps, cmd_list)

                # Update traffic map and DSCP marking based on policy
                self.__get_interface_traffic_map_update_commands\
                    (dev_id, sw_if_index, scheduling_params, False, cmd_list)

                # Enable ACL based classification on the WAN interfaces
                self.__get_enable_classification_acls_commands(sw_if_index, cmd_list)

        # Enable ACL based classification on all LAN interfaces
        lan_if_list = fwglobals.g.router_cfg.get_interfaces(type='lan')
        for lan_if in lan_if_list:
            lan_sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(lan_if['dev_id'])
            self.__get_enable_classification_acls_commands(lan_sw_if_index, cmd_list)

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


def get_traffic_class(service_class, importance):
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
    tc_q = fwglobals.g.qos.lookup_qos_traffic_map(service_class, importance)
    return tc_q[0]


def get_queue_id(service_class, importance):
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
    tc_q = fwglobals.g.qos.lookup_qos_traffic_map(service_class, importance)
    return tc_q[1]


def build_egress_map(scheduling_params, egress_map):
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
        tc_q = fwglobals.g.qos.lookup_qos_traffic_map(service_class, importance)
        tc = tc_q[0]
        queue = tc_q[1]

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


def get_tunnel_qos_identifier(dev_id, tunnel_id):
    """
    Function called when creating VxLAN tunnel, to fetch the allocated QoS hierarchy for the tunnel.
    This value is used to setup the tunnel to a specific QoS hierarchy for all the tunnel packets.

    :param dev_id: Device identifier
    :type dev_id: String
    :param tunnel_id: Tunnel identifier received in add-tunnel message
    :type tunnel_id: Integer
    :return: ID representing the tunnel in QoS hierarchy
    :rtype: Integer
    """
    return fwglobals.g.qos.get_tunnel_qos_hierarchy_id(dev_id, tunnel_id)


def check_policy_has_interface_add_del(params):
    """
    Function to compare if existing QoS ON interfaces is matching with the new QoS policy params

    :param params: QoS policy configuration
    :type params: dict
    :return: True if it is same else False
    :rtype: Boolean
    """
    params_interfaces = []
    policies = params.get('policies')
    for policy in policies:
        interfaces = policy.get('interfaces')
        params_interfaces.extend(interfaces)
    return (not fwglobals.g.qos.compare_qos_interfaces(params_interfaces))


def has_qos_policy(dev_id=None):
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
            interfaces = policy.get('interfaces')
            for interface_dev_id in interfaces:
                if interface_dev_id == dev_id:
                    return True
    return False
