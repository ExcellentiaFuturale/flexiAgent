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

import copy
import glob
import json
import hashlib
import os
import Pyro4
import re
import signal
import traceback
import yaml
from fwqos import FwQoS
import fw_os_utils
import fwutils
import threading
import fw_vpp_coredump_utils
import fwlte

from sqlitedict import SqliteDict

from fwagent import FwAgent
from fwobject import FwObject
from fwrouter_api import FWROUTER_API
from fwsystem_api import FWSYSTEM_API
from fwagent_api import FWAGENT_API
from fwapplications_api import FWAPPLICATIONS_API
from os_api import OS_API
from fwlog import FwLogFile
from fwlog import FwSyslog
from fwlog import FWLOG_LEVEL_INFO
from fwlog import FWLOG_LEVEL_DEBUG
from fwpolicies import FwPolicies
from fwrouter_cfg import FwRouterCfg
from fwroutes import FwRoutes
from fwsystem_cfg import FwSystemCfg
from fwjobs import FwJobs
from fwstun_wrapper import FwStunWrap
from fwpppoe import FwPppoeClient
from fwthread import FwRouterThreading
from fwwan_monitor import FwWanMonitor
from fwikev2 import FwIKEv2
from fw_traffic_identification import FwTrafficIdentifications

# sync flag indicated if module implement sync logic.
# IMPORTANT! Please keep the list order. It indicates the sync priorities
modules = {
    'fwsystem_api':       { 'module': __import__('fwsystem_api'),       'sync': True,  'object': 'system_api' },       # fwglobals.g.system_api
    'fwagent_api':        { 'module': __import__('fwagent_api'),        'sync': False, 'object': 'agent_api' },        # fwglobals.g.agent_api
    'fwrouter_api':       { 'module': __import__('fwrouter_api'),       'sync': True,  'object': 'router_api' },       # fwglobals.g.router_api
    'os_api':             { 'module': __import__('os_api'),             'sync': False, 'object': 'os_api' },           # fwglobals.g.os_api
    'fwapplications_api': { 'module': __import__('fwapplications_api'), 'sync': True,  'object': 'applications_api' }, # fwglobals.g.applications_api,
}

cli_commands = {
    'configure':    {'help': 'Configure flexiEdge components', 'modules': []},
}
cli_modules = {
    # Will be filled automatically out of content of the 'cli' folder
}

request_handlers = {

    ##############################################################
    # DEVICE API-s
    # ------------------------------------------------------------
    # These API-s implement interface between FlexiEdge device
    # and FlexiManage server. The device API-s are invoked using
    # requests sent by server to device over secured connection.
    ##############################################################

    # Agent API
    'get-device-info':                   {'name': '_call_agent_api'},
    'get-device-stats':                  {'name': '_call_agent_api'},
    'get-device-logs':                   {'name': '_call_agent_api'},
    'get-device-packet-traces':          {'name': '_call_agent_api'},
    'get-device-os-routes':              {'name': '_call_agent_api'},
    'get-device-config':                 {'name': '_call_agent_api'},
    'upgrade-device-sw':                 {'name': '_call_agent_api'},
    'reset-device':                      {'name': '_call_agent_api'},
    'sync-device':                       {'name': '_call_agent_api'},
    'get-wifi-info':                     {'name': '_call_agent_api'},
    'get-lte-info':                      {'name': '_call_agent_api'},
    'reset-lte':                         {'name': '_call_agent_api'},
    'modify-lte-pin':                    {'name': '_call_agent_api'},
    'get-device-certificate':            {'name': '_call_agent_api'},
    'set-cpu-info':                      {'name': '_call_agent_api'},

    # Aggregated API
    'aggregated':                   {'name': '_call_aggregated', 'sign': True},

    # Router API
    'start-router':                 {'name': '_call_router_api', 'sign': True},
    'stop-router':                  {'name': '_call_router_api', 'sign': True},
    'add-interface':                {'name': '_call_router_api', 'sign': True},
    'remove-interface':             {'name': '_call_router_api', 'sign': True},
    'modify-interface':             {'name': '_call_router_api', 'sign': True},
    'add-route':                    {'name': '_call_router_api', 'sign': True},
    'remove-route':                 {'name': '_call_router_api', 'sign': True},
    'add-tunnel':                   {'name': '_call_router_api', 'sign': True},
    'remove-tunnel':                {'name': '_call_router_api', 'sign': True},
    'modify-tunnel':                {'name': '_call_router_api', 'sign': True},
    'add-dhcp-config':              {'name': '_call_router_api', 'sign': True},
    'remove-dhcp-config':           {'name': '_call_router_api', 'sign': True},
    'add-application':              {'name': '_call_router_api', 'sign': True},
    'remove-application':           {'name': '_call_router_api', 'sign': True},
    'add-multilink-policy':         {'name': '_call_router_api', 'sign': True},
    'remove-multilink-policy':      {'name': '_call_router_api', 'sign': True},
    'add-ospf':                     {'name': '_call_router_api', 'sign': True},
    'remove-ospf':                  {'name': '_call_router_api', 'sign': True},
    'add-routing-bgp':              {'name': '_call_router_api', 'sign': True},
    'remove-routing-bgp':           {'name': '_call_router_api', 'sign': True},
    'modify-routing-bgp':           {'name': '_call_router_api', 'sign': True},
    'add-routing-filter':           {'name': '_call_router_api', 'sign': True},
    'remove-routing-filter':        {'name': '_call_router_api', 'sign': True},
    'add-switch':                   {'name': '_call_router_api', 'sign': True},
    'remove-switch':                {'name': '_call_router_api', 'sign': True},
    'add-firewall-policy':          {'name': '_call_router_api', 'sign': True},
    'remove-firewall-policy':       {'name': '_call_router_api', 'sign': True},
    'add-qos-traffic-map':          {'name': '_call_router_api', 'sign': True},
    'remove-qos-traffic-map':       {'name': '_call_router_api', 'sign': True},
    'add-qos-policy':               {'name': '_call_router_api', 'sign': True},
    'remove-qos-policy':            {'name': '_call_router_api', 'sign': True},

    # System API
    'add-lte':                      {'name': '_call_system_api'},
    'remove-lte':                   {'name': '_call_system_api'},

    # Applications api
    'add-app-install':             {'name': '_call_applications_api', 'sign': True},
    'remove-app-install':          {'name': '_call_applications_api', 'sign': True},
    'add-app-config':              {'name': '_call_applications_api', 'sign': True},
    'remove-app-config':           {'name': '_call_applications_api', 'sign': True},

    # OS API
    'cpuutil':                      {'name': '_call_os_api'},
    'exec':                         {'name': '_call_os_api'},
    'exec_timeout':                 {'name': '_call_os_api'},
}

global g_initialized
g_initialized = False

@Pyro4.expose
class Fwglobals(FwObject):
    """This is global data class representation.

    """
    class FwConfiguration:
        """This is configuration class representation.

        :param filename:    YAML configuration file name.
        :param data_path:   Path to token file.
        """
        def __init__(self, filename, data_path, log=None):
            """Constructor method
            """
            DEFAULT_BYPASS_CERT    = False
            DEFAULT_DEBUG          = False
            DEFAULT_MANAGEMENT_URL = 'https://manage.flexiwan.com:443'
            DEFAULT_TOKEN_FILE     = data_path + 'token.txt'
            DEFAULT_UUID           = None
            DEFAULT_WAN_MONITOR_UNASSIGNED_INTERFACES = True
            DEFAULT_WAN_MONITOR_SERVERS = ['1.1.1.1','8.8.8.8']
            DEFAULT_DAEMON_SOCKET_NAME  = "127.0.0.1:9090"  # Used for RPC to daemon
            try:
                with open(filename, 'r') as conf_file:
                    conf = yaml.load(conf_file, Loader=yaml.SafeLoader)
                agent_conf = conf.get('agent', {})
                self.BYPASS_CERT    = agent_conf.get('bypass_certificate', DEFAULT_BYPASS_CERT)
                self.DEBUG          = agent_conf.get('debug',  DEFAULT_DEBUG)
                self.MANAGEMENT_URL = agent_conf.get('server', DEFAULT_MANAGEMENT_URL)
                self.TOKEN_FILE     = agent_conf.get('token',  DEFAULT_TOKEN_FILE)
                self.UUID           = agent_conf.get('uuid',   DEFAULT_UUID)
                self.WAN_MONITOR_UNASSIGNED_INTERFACES = agent_conf.get('monitor_wan',{}).get('monitor_unassigned_interfaces', DEFAULT_WAN_MONITOR_UNASSIGNED_INTERFACES)
                self.WAN_MONITOR_SERVERS = agent_conf.get('monitor_wan',{}).get('servers', DEFAULT_WAN_MONITOR_SERVERS)
                self.DAEMON_SOCKET_NAME  = agent_conf.get('daemon_socket',  DEFAULT_DAEMON_SOCKET_NAME)
            except Exception as e:
                if log:
                    log.excep("%s, set defaults" % str(e))
                self.BYPASS_CERT    = DEFAULT_BYPASS_CERT
                self.DEBUG          = DEFAULT_DEBUG
                self.MANAGEMENT_URL = DEFAULT_MANAGEMENT_URL
                self.TOKEN_FILE     = DEFAULT_TOKEN_FILE
                self.UUID           = DEFAULT_UUID
                self.WAN_MONITOR_UNASSIGNED_INTERFACES = DEFAULT_WAN_MONITOR_UNASSIGNED_INTERFACES
                self.WAN_MONITOR_SERVERS = DEFAULT_WAN_MONITOR_SERVERS
                self.DAEMON_SOCKET_NAME  = DEFAULT_DAEMON_SOCKET_NAME
            if self.DEBUG and log:
                log.set_level(FWLOG_LEVEL_DEBUG)
            self.debug = {
                'daemon': {
                    'standalone': False,
                },
                'agent': {
                    'features': {
                        'pppoe': {
                            'enabled': True
                        },
                        'stun': {
                            'enabled': True
                        },
                        'wan_monitor': {
                            'enabled': True
                        },
                    },
                },
            }


    class FwCache:
        """Storage for data that is valid during one FwAgent lifecycle only.
        """
        def __init__(self):
            self.db = {
                'LINUX_INTERFACES': {},
                'DEV_ID_TO_VPP_IF_NAME': {},
                'DEV_ID_TO_VPP_TAP_NAME': {},
                'STUN': {},
                'SYMMETRIC_NAT': {},
                'SYMMETRIC_NAT_TUNNELS': {},
                'VPP_IF_NAME_TO_DEV_ID': {},
                'LINUX_INTERFACES_BY_NAME': {},
                'WAN_MONITOR': {
                    'enabled_routes':  {},
                    'disabled_routes': {},
                },
                'LTE': {}
            }
            self.lock                       = threading.RLock()
            self.linux_interfaces           = self.db['LINUX_INTERFACES']
            self.dev_id_to_vpp_if_name      = self.db['DEV_ID_TO_VPP_IF_NAME']
            self.dev_id_to_vpp_tap_name     = self.db['DEV_ID_TO_VPP_TAP_NAME']
            self.stun_cache                 = self.db['STUN']
            self.sym_nat_cache              = self.db['SYMMETRIC_NAT']
            self.sym_nat_tunnels_cache      = self.db['SYMMETRIC_NAT_TUNNELS']
            self.vpp_if_name_to_dev_id      = self.db['VPP_IF_NAME_TO_DEV_ID']
            self.linux_interfaces_by_name   = self.db['LINUX_INTERFACES_BY_NAME']
            self.wan_monitor                = self.db['WAN_MONITOR']
            self.lte                        = self.db['LTE']


    def __init__(self, log=None):
        """Constructor method
        """
        FwObject.__init__(self, log=log)

        # Set default configuration
        self.RETRY_INTERVAL_MIN  = 5 # seconds - is used for both registration and main connection
        self.RETRY_INTERVAL_MAX  = 15
        self.RETRY_INTERVAL_LONG_MIN = 50
        self.RETRY_INTERVAL_LONG_MAX = 70
        self.DATA_PATH           = '/etc/flexiwan/agent/'
        self.FWAGENT_CONF_FILE   = self.DATA_PATH + 'fwagent_conf.yaml'  # Optional, if not present, defaults are taken
        self.DEBUG_CONF_FILE     = self.DATA_PATH + 'debug_conf.yaml'
        self.DEVICE_TOKEN_FILE   = self.DATA_PATH + 'fwagent_info.txt'
        self.VERSIONS_FILE       = self.DATA_PATH + '.versions.yaml'
        self.ROUTER_CFG_FILE     = self.DATA_PATH + '.requests.sqlite'
        self.ROUTER_PENDING_CFG_FILE = self.DATA_PATH + '.requests.pending.sqlite'
        self.SYSTEM_CFG_FILE     = self.DATA_PATH + '.system.sqlite'
        self.APPLICATIONS_CFG_FILE = self.DATA_PATH + '.applications.sqlite'
        self.JOBS_FILE           = self.DATA_PATH + '.jobs.sqlite'
        self.ROUTER_STATE_FILE   = self.DATA_PATH + '.router.state'
        self.CONN_FAILURE_FILE   = self.DATA_PATH + '.upgrade_failed'
        self.IKEV2_FOLDER        = self.DATA_PATH + 'ikev2/'
        self.ROUTER_LOG_FILE     = '/var/log/flexiwan/agent.log'
        self.APPLICATION_IDS_LOG_FILE = '/var/log/flexiwan/application_ids.log'
        self.AGENT_UI_LOG_FILE   = '/var/log/flexiwan/agentui.log'
        self.SYSTEM_CHECKER_LOG_FILE = '/var/log/flexiwan/system_checker.log'
        self.REPO_SOURCE_DIR     = '/etc/apt/sources.list.d/'
        self.HOSTAPD_LOG_FILE     = '/var/log/hostapd.log'
        self.SYSLOG_FILE         = '/var/log/syslog'
        self.DHCP_LOG_FILE       = '/var/log/dhcpd.log'
        self.VPP_LOG_FILE        = '/var/log/vpp/vpp.log'
        self.FRR_LOG_FILE       = '/var/log/frr/ospfd.log'
        self.VPP_CONFIG_FILE     = '/etc/vpp/startup.conf'
        self.VPP_CONFIG_FILE_BACKUP   = '/etc/vpp/startup.conf.baseline'
        self.VPP_CONFIG_FILE_RESTORE = '/etc/vpp/startup.conf.orig'
        self.VPP_TRACE_FILE_EXT  = '.vpp.api'
        self.FRR_ZEBRA_FILE      = '/etc/frr/zebra.conf'
        self.FRR_DAEMONS_FILE    = '/etc/frr/daemons'
        self.FRR_CONFIG_FILE     = '/etc/frr/frr.conf'
        self.FRR_OSPFD_FILE      = '/etc/frr/ospfd.conf'
        self.FRR_BGPD_FILE      = '/etc/frr/bgpd.conf'
        self.FRR_VTYSH_FILE      = '/etc/frr/vtysh.conf'
        self.FRR_OSPF_ACL       = 'fw-redist-ospf-acl'
        self.FRR_OSPF_ROUTE_MAP = 'fw-redist-ospf-rm'
        self.FRR_BGP_ACL       = 'fw-redist-bgp-acl'
        self.FRR_BGP_ROUTE_MAP = 'fw-redist-bgp-rm'
        self.DHCPD_CONFIG_FILE   = '/etc/dhcp/dhcpd.conf'
        self.DHCPD_CONFIG_FILE_BACKUP = '/etc/dhcp/dhcpd.conf.fworig'
        self.ISC_DHCP_CONFIG_FILE = '/etc/default/isc-dhcp-server'
        self.ISC_DHCP_CONFIG_FILE_BACKUP = '/etc/default/isc-dhcp-server.fworig'
        self.PPPOE_CONFIG_PATH   = '/etc/ppp/'
        self.PPPOE_CONFIG_PROVIDER_FILE   = 'flexiwan-dsl-provider'
        self.FRR_DB_FILE         = self.DATA_PATH + '.frr.sqlite'
        self.PPPOE_DB_FILE       = self.DATA_PATH + '.pppoe.sqlite'
        self.POLICY_REC_DB_FILE  = self.DATA_PATH + '.policy.sqlite'
        self.MULTILINK_DB_FILE   = self.DATA_PATH + '.multilink.sqlite'
        self.DATA_DB_FILE        = self.DATA_PATH + '.data.sqlite'
        self.TRAFFIC_ID_DB_FILE  = self.DATA_PATH + '.traffic_identification.sqlite'
        self.QOS_DB_FILE         = self.DATA_PATH + '.qos.sqlite'
        self.HOSTAPD_CONFIG_DIRECTORY = '/etc/hostapd/'
        self.NETPLAN_FILES       = {}
        self.NETPLAN_FILE        = '/etc/netplan/99-flexiwan.fwrun.yaml'
        self.WS_STATUS_ERROR_NOT_APPROVED = 403
        self.WS_STATUS_ERROR_LOCAL_ERROR  = 800 # Should be over maximal HTTP STATUS CODE - 699
        self.fwagent = None
        self.pppoe = None
        self.loadsimulator = None
        self.routes = None
        self.router_api = None
        self.cache   = self.FwCache()
        self.WAN_FAILOVER_WND_SIZE         = 20         # 20 pings, every ping waits a second for response
        self.WAN_FAILOVER_THRESHOLD        = 12         # 60% of pings lost - enter the bad state, 60% of pings are OK - restore to good state
        self.WAN_FAILOVER_METRIC_WATERMARK = 2000000000 # Bad routes will have metric above 2000000000
        self.LOOPBACK_ID_SWITCHES          = [16300, 16384] # Loopback id in vpp is up to 16384, so we use this range for switch feature
        self.LOOPBACK_ID_TUNNELS           = [0, 16299]  # Loopback id in vpp is up to 16384, so we use this range for tunnels
        self.DUMP_FOLDER                   = '/var/log/flexiwan/fwdump'
        self.DEFAULT_DNS_SERVERS           = ['8.8.8.8', '8.8.4.4']
        self.router_threads                = FwRouterThreading() # Primitives used for synchronization of router configuration and monitoring threads
        self.handle_request_lock           = threading.RLock()
        self.is_gcp_vm                     = fwutils.detect_gcp_vm()

        # Load configuration from file
        self.cfg = self.FwConfiguration(self.FWAGENT_CONF_FILE, self.DATA_PATH, log=log)
        self.load_debug_configuration_from_file(self.DEBUG_CONF_FILE)

        self.FWAGENT_DAEMON_HOST = self.cfg.DAEMON_SOCKET_NAME.split(":")[0]
        self.FWAGENT_DAEMON_PORT = int(self.cfg.DAEMON_SOCKET_NAME.split(":")[1])
        self.FWAGENT_DAEMON_NAME = 'fwagent.daemon'
        self.FWAGENT_DAEMON_URI  = 'PYRO:%s@%s:%d' % (self.FWAGENT_DAEMON_NAME, self.FWAGENT_DAEMON_HOST, self.FWAGENT_DAEMON_PORT)

        self.db = SqliteDict(self.DATA_DB_FILE, autocommit=True)  # IMPORTANT! set the db variable regardless of agent initialization

        # Load websocket status codes on which agent should reconnect into a list
        self.ws_reconnect_status_codes = []
        for a in dir(self):
            if re.match("WS_STATUS_", a):
                self.ws_reconnect_status_codes.append(getattr(self, a))

        # Load signal to string map
        self.signal_names = dict((getattr(signal, n), n) \
                                for n in dir(signal) if n.startswith('SIG') and '_' not in n )

        # Load cli modules
        #
        root_dir = os.path.dirname(os.path.realpath(__file__))
        for cmd_name, cli_command in cli_commands.items():
            cli_command_files = glob.glob(f'{root_dir}/cli/fwcli_{cmd_name}*.py')
            for filename in cli_command_files:
                cli_module_name = os.path.splitext(os.path.basename(filename))[0] # .../cli/fwcli_configure_router.py -> "fwcli_configure_router"
                cli_command['modules'].append(cli_module_name)
                cli_import = __import__(f'cli.{cli_module_name}')
                cli_module = getattr(cli_import, cli_module_name)
                cli_modules.update({cli_module_name: cli_module})

    def load_configuration_from_file(self):
        """Load configuration from YAML file.

        :returns: None.
        """
        # Load configuration
        self.cfg.__init__(self.FWAGENT_CONF_FILE, self.DATA_PATH)
        # Print loaded configuration into log
        if self.cfg.DEBUG:
            self.log.debug("Fwglobals configuration: " + self.__str__(), to_terminal=False)
            # for a in dir(self.cfg):
            #     val = getattr(self, a)
            #     if isinstance(val, (int, float, str, unicode)):
            #         log.debug("  %s: %s" % (a, str(val)), to_terminal=False)
            # for a in dir(self):
            #     val = getattr(self, a)
            #     if isinstance(val, (int, float, str, unicode)):
            #         log.debug("  %s: %s" % (a, str(val)), to_terminal=False)

    def load_debug_configuration_from_file(self, debug_conf_file):
        """Load debug configuration from YAML file.

        :returns: None.
        """
        if not os.path.isfile(debug_conf_file):
            # The default file might not exist - we do not expose it to users.
            if debug_conf_file != self.DEBUG_CONF_FILE:
                raise Exception(f"load_debug_configuration_from_file: {debug_conf_file} not found")
            return

        with open(debug_conf_file, 'r') as debug_conf_file:
            self.cfg.debug = yaml.load(debug_conf_file, Loader=yaml.SafeLoader)

    def create_agent(self, initialize=True):
        """Create the fwagent and the rest of supporting objects (that are globals for historical reasons).
        """
        if self.fwagent:
            self.log.warning('Fwglobals.initialize_agent: agent exists')
            return self.fwagent

        # Create loggers
        #
        self.logger_add_application = FwLogFile(
            filename=self.APPLICATION_IDS_LOG_FILE, level=log.level)
        self.loggers = {
            'add-application':      self.logger_add_application,
            'remove-application':   self.logger_add_application,
        }

        # Some lte modules have a problem with drivers binding.
        # As workaround, we reload the driver to fix it.
        # We run it only if vpp is not running to make sure that we reload the driver
        # only on boot, and not if a user run `systemctl restart flexiwan-router` when vpp is running.
        if not fw_os_utils.vpp_does_run():
            fwlte.reload_lte_drivers_if_needed()

        self.db               = SqliteDict(self.DATA_DB_FILE, autocommit=True)  # IMPORTANT! Load data at the first place!
        self.fwagent          = FwAgent(handle_signals=False)
        self.router_cfg       = FwRouterCfg(self.ROUTER_CFG_FILE) # IMPORTANT! Initialize database at the first place!
        self.system_cfg       = FwSystemCfg(self.SYSTEM_CFG_FILE)
        self.jobs             = FwJobs(self.JOBS_FILE)
        self.agent_api        = FWAGENT_API()
        self.system_api       = FWSYSTEM_API(self.system_cfg)
        self.router_api       = FWROUTER_API(self.router_cfg, self.ROUTER_PENDING_CFG_FILE, self.MULTILINK_DB_FILE, self.FRR_DB_FILE)
        self.applications_api = FWAPPLICATIONS_API()
        self.os_api           = OS_API()
        self.policies         = FwPolicies(self.POLICY_REC_DB_FILE)
        self.wan_monitor      = FwWanMonitor()
        self.stun_wrapper     = FwStunWrap()
        self.ikev2            = FwIKEv2()
        self.pppoe            = FwPppoeClient(start=True)
        self.routes           = FwRoutes()
        self.qos              = FwQoS()

        self.system_api.restore_configuration() # IMPORTANT! The System configurations should be restored before restore_vpp_if_needed!

        fwutils.set_default_linux_reverse_path_filter(2)  # RPF set to Loose mode
        fwutils.disable_ipv6()
        # Increase allowed multicast group membership from default 20 to 4096
        # OSPF need that to be able to discover more neighbors on adjacent links
        fwutils.set_linux_igmp_max_memberships(4096)

        # Set sys params to setup VPP coredump
        fw_vpp_coredump_utils.vpp_coredump_sys_setup()

        # Increase allowed max socket receive buffer size to 2Mb
        # VPPSB need that to handle more netlink events on a heavy load
        fwutils.set_linux_socket_max_receive_buffer_size(2048000)

        self.stun_wrapper.initialize()   # IMPORTANT! The STUN should be initialized before restore_vpp_if_needed!

        self.traffic_identifications = FwTrafficIdentifications(self.TRAFFIC_ID_DB_FILE, logger=self.logger_add_application)

        if initialize:
            self.initialize_agent()
        return self.fwagent

    def destroy_agent(self, finalize=True):
        """Graceful shutdown...
        """
        if finalize:
            self.finalize_agent()

        del self.routes
        del self.pppoe
        self.pppoe = None
        del self.wan_monitor
        del self.stun_wrapper
        del self.policies
        del self.traffic_identifications
        del self.os_api
        del self.router_api
        del self.agent_api
        del self.applications_api
        del self.logger_add_application
        del self.fwagent
        self.fwagent = None
        self.db.close()

    def initialize_agent(self):
        """Restore VPP if needed and start various features.
        """
        self.log.debug('initialize_agent: started')

        self.router_api.restore_vpp_if_needed()

        fwutils.get_linux_interfaces(cached=False) # Fill global interface cache

        # IMPORTANT! Some of the features below should be initialized after restore_vpp_if_needed
        #
        self.wan_monitor.initialize()
        self.pppoe.initialize()
        self.system_api.initialize()  # This one does not depend on VPP :)
        self.routes.initialize()
        self.applications_api.initialize()

        self.log.debug('initialize_agent: completed')

    def finalize_agent(self):
        self.log.debug('finalize_agent: started')
        self.router_threads.teardown = True   # Stop all threads in parallel to speedup gracefull exit
        try:
            self.qos.finalize()
            self.routes.finalize()
            self.pppoe.finalize()
            self.wan_monitor.finalize()
            self.stun_wrapper.finalize()
            self.system_api.finalize()
            self.router_api.finalize()
            self.applications_api.finalize()
            self.fwagent.finalize()
            self.router_cfg.finalize() # IMPORTANT! Finalize database at the last place!
        except Exception as e:
            self.log.error(f"finalize_agent: {str(e)}")
        self.log.debug('finalize_agent: completed')

    def __str__(self):
        """Get string representation of configuration.

        :returns: String in JSON format.
        """
        return json.dumps({
            'MANAGEMENT_URL':       self.cfg.MANAGEMENT_URL,
            'TOKEN_FILE':           self.cfg.TOKEN_FILE,
            'BYPASS_CERT':          self.cfg.BYPASS_CERT,
            'DEBUG':                self.cfg.DEBUG,
            'UUID':                 self.cfg.UUID,
            'FWAGENT_CONF_FILE':    self.FWAGENT_CONF_FILE,
            'RETRY_INTERVAL_MIN':   self.RETRY_INTERVAL_MIN,
            'RETRY_INTERVAL_MAX':   self.RETRY_INTERVAL_MAX,
            }, indent = 2)

    def _call_agent_api(self, request):
        return self.agent_api.call(request)

    def _call_system_api(self, request):
        return self.system_api.call(request)

    def _call_router_api(self, request):
        return self.router_api.call(request)

    def _call_os_api(self, request):
        return self.os_api.call_simple(request)

    def _call_applications_api(self, request):
        return self.applications_api.call(request)

    def handle_request(self, request, received_msg=None):
        """Handle request received from flexiManage or injected locally.

        :param request:      The request received from flexiManage after
                             transformation by fwutils.fix_received_message().
        :param received_msg: The original message received from flexiManage.

        :returns: Dictionary with error string and status code.
        """
        with self.handle_request_lock:
            try:
                req    = request['message']
                params = request.get('params')

                handler      = request_handlers.get(req)
                handler_func = getattr(self, handler.get('name'))

                reply = handler_func(request)
                if reply['ok'] == 0:
                    vpp_trace_file = fwutils.build_timestamped_filename('',self.VPP_TRACE_FILE_EXT)
                    os.system('sudo vppctl api trace save %s' % (vpp_trace_file))
                    raise Exception(reply['message'])

                # On router configuration request, e.g. add-interface,
                # remove-tunnel, etc. update the configuration database
                # signature. This is needed to assists the database synchronization
                # feature that keeps the configuration set by user on the flexiManage
                # in sync with the one stored on the flexiEdge device.
                # Note we update signature on configuration requests received from flexiManage only,
                # but retrieve it into replies for all requests. This is to simplify
                # flexiManage code.
                #
                if reply['ok'] == 1 and handler.get('sign') and received_msg:
                    fwutils.update_device_config_signature(received_msg)
                reply['router-cfg-hash'] = fwutils.get_device_config_signature()

                return reply

            except Exception as e:
                global log
                err_str = "%s(%s): %s" % (req, format(params), str(e))
                log.error(err_str + ': %s' % str(traceback.format_exc()))
                reply = {"message":err_str, 'ok':0}
                return reply

    def _get_api_object_attr(self, api_type, attr):
        if api_type == '_call_router_api':
            return getattr(self.router_api, attr)
        elif api_type == '_call_system_api':
            return getattr(self.system_api, attr)
        elif api_type == '_call_applications_api':
            return getattr(self.applications_api, attr)

    def _call_aggregated(self, request):
        """Handle aggregated request from flexiManage.

        :param request: the aggregated request like:
            {
                "entity": "agent",
                "message": "aggregated",
                "params": {
                    "requests": [
                        {
                            "entity": "agent",
                            "message": "remove-lte",
                            "params": {
                                "apn": "we",
                                "enable": false,
                                "dev_id": "usb:usb1/1-3/1-3:1.4"
                            }
                        },
                        {
                            "entity": "agent",
                            "message": "remove-interface",
                            "params": {
                                "dhcp": "yes",
                                "addr": "10.93.172.31/26",
                                "addr6": "fe80::b82a:beff:fe44:38e8/64",
                                "PublicIP": "46.19.85.31",
                                "PublicPort": "4789",
                                "useStun": true,
                                "monitorInternet": true,
                                "gateway": "10.93.172.32",
                                "metric": "",
                                "routing": "NONE",
                                "type": "WAN",
                                "configuration": {
                                    "apn": "we",
                                    "enable": false
                                },
                                "deviceType": "lte",
                                "dev_id": "usb:usb1/1-3/1-3:1.4",
                                "multilink": {
                                    "labels": []
                                }
                            }
                        }
                    ]
                }
            }

        :returns: dictionary with status code and optional error message.
        """
        # Break the received aggregated request into aggregations by API type
        #
        # !!! IMPORTANT !!!
        # ATM we decided to run system-api requests before router-api requests.
        #
        aggregations = {}
        for _request in request['params']['requests']:

            handler = request_handlers.get(_request['message'])
            assert handler, '"%s" request is not supported' % _request['message']

            api = handler.get('name')
            assert api, 'api for "%s" not found' % _request['message']

            # Create the aggregations for the current API type, if it was not created yet.
            #
            if not api in aggregations:
                aggregations[api] = {
                    "message": "aggregated",
                    "params": {
                        "requests": []
                    }
                }

            # Finally add the current request to the current aggregation.
            #
            aggregations[api]['params']['requests'].append(_request)


        # Now generate the rollback aggregated requests for the aggregations created above.
        # We need them in case of failure to execute any of the created requests,
        # as we have to revert the previously executed request. This is to ensure
        # atomic handling of the original aggregated request received from flexiManage.
        #
        rollback_aggregations = self._build_rollback_aggregations(aggregations)

        # Go over list of aggregations and execute their requests one by one.
        #
        apis = list(aggregations.keys())
        executed_apis = []

        for api in ['_call_system_api', '_call_router_api', '_call_applications_api']:
            if api in aggregations:
                api_call_func = self._get_api_object_attr(api, 'call')
                try:
                    api_call_func(aggregations[api])
                    executed_apis.append(api)
                except Exception as e:
                    # Revert the previously executed aggregated requests
                    for api in executed_apis:
                        rollback_func = self._get_api_object_attr(api, 'rollback')
                        rollback_func(rollback_aggregations[api])
                    raise e

        return {'ok': 1}


    def _build_rollback_aggregations(self, aggregations):
        '''Generates rollback data for the list of aggregated requests grouped by type of api they belong to.
        The input list format is:
            {
                <api name, e.g. "router_api", "system_api", etc>:
                    {
                        "message": "aggregated",
                        "params": {
                            "requests": [ ... ]
                        }
                    }
                }
                ,
                ...
            }

        The output rollback data represents clone of the input list, where the leaf requests
        (requests in list element['params']['requests'])
        perform opposite operation. That means, the "add-X" is replaced with
        "remove-X", the "remove-X" is replaced with "add-X", and parameters of the "modify-X"
        are replaced with the old parameters that are currently stored in the configuration database.
        '''
        rollbacks_aggregations = copy.deepcopy(aggregations)
        for (api, aggregated) in list(rollbacks_aggregations.items()):
            cfg_db = self._get_api_object_attr(api, 'cfg_db')
            for request in aggregated['params']['requests']:

                op = request['message']
                if re.match('add-', op):
                    request['message'] = op.replace('add-','remove-')

                elif re.match('start-', op):
                    request['message'] = op.replace('start-','stop-')

                elif re.match('remove-', op):
                    request['message'] = op.replace('remove-','add-')
                    # The "remove-X" might have only subset of configuration parameters.
                    # To ensure proper rollback, populate the correspondent "add-X" with
                    # full set of configuration parameters. They are stored in database.
                    #
                    request['params'] = cfg_db.get_request_params(request)
                    if request['params'] == None:
                        request['params'] = {} # Take a care of removal of not existing configuration item

                elif re.match('modify-', op):
                    # For "modify-X" replace it's parameters with the old parameters,
                    # that are currently stored in the configuration database.
                    #
                    old_params = cfg_db.get_request_params(request)
                    for param_name in list(request['params']): #request['params'].keys() doesn't work in python 3
                        if old_params and param_name in old_params:
                            request['params'][param_name] = old_params[param_name]
                        else:
                            del request['params'][param_name]
                else:
                    raise Exception("_build_rollback_aggregations: not expected request: %s" % op)

        return rollbacks_aggregations

    def get_logger(self, request):
        if type(request) == list:
            requests = request   # Accommodate to call by update_device_config_signature()
        elif re.match('aggregated|sync-device', request['message']):
            requests = request['params']['requests']
        else:
            requests = [request]

        for r in requests:
            if r['message'] in self.loggers:
                return self.loggers[r['message']]
        return None


def initialize(log_level=FWLOG_LEVEL_INFO, quiet=False):
    """Initialize global instances of LOG, and GLOBALS.

    :param log_level:    LOG severity level.

    :returns: None.
    """
    global g_initialized
    if not g_initialized:
        global log
        log = FwSyslog(log_level)
        if quiet:
            log.set_target(to_terminal=False)
        global g
        g = Fwglobals(log)
        g_initialized = True
