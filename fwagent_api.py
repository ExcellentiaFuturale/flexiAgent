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

import yaml
import sys
import os
from shutil import copyfile
import subprocess
import json
import fwglobals
import fwstats
import fwutils
import fwlte
import fwwifi
import fwroutes

from fwobject import FwObject

system_checker_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tools/system_checker/")
sys.path.append(system_checker_path)
import fwsystem_checker_common

fwagent_api = {
    'get-device-certificate':        '_get_device_certificate',
    'get-device-config':             '_get_device_config',
    'get-device-info':               '_get_device_info',
    'get-device-logs':               '_get_device_logs',
    'get-device-os-routes':          '_get_device_os_routes',
    'get-device-packet-traces':      '_get_device_packet_traces',
    'get-device-stats':              '_get_device_stats',
    'get-lte-info':                  '_get_lte_info',
    'get-wifi-info':                 '_get_wifi_info',
    'modify-lte-pin':                '_modify_lte_pin',
    'reset-lte':                     '_reset_lte',
    'reset-device':                  '_reset_device_soft',
    'sync-device':                   '_sync_device',
    'upgrade-device-sw':             '_upgrade_device_sw',
    'set-cpu-info':                  '_set_cpu_info',
    'get-bgp-status':                '_get_bgp_status',
}

class FWAGENT_API(FwObject):
    """This class implements fwagent level APIs of flexiEdge device.
       Typically these APIs are used to monitor various components of flexiEdge.
       They are invoked by the flexiManage over secure WebSocket
       connection using JSON requests.
       For list of available APIs see the 'fwagent_api' variable.
    """
    def __init__(self):
        FwObject.__init__(self)

    def call(self, request):
        """Invokes API specified by the 'req' parameter.

        :param request: The request received from flexiManage.

        :returns: Reply.
        """
        req    = request['message']
        params = request.get('params')

        handler = fwagent_api.get(req)
        assert handler, 'fwagent_api: "%s" request is not supported' % req

        handler_func = getattr(self, handler)
        assert handler_func, 'fwagent_api: handler=%s not found for req=%s' % (handler, req)

        reply = handler_func(params)
        if reply['ok'] == 0:
            self.log.error(f"fwagent_api: {handler}({format(params)}) failed: {reply['message']}")
            raise Exception(reply['message'])
        return reply

    def _prepare_tunnel_info(self, tunnel_ids):
        tunnel_info = []
        tunnels = fwglobals.g.router_cfg.get_tunnels()
        for params in tunnels:
            try:
                tunnel_id = params["tunnel-id"]
                if tunnel_id in tunnel_ids:
                    # key1-key4 are the crypto keys stored in
                    # the management for each tunnel
                    key1 = ""
                    key2 = ""
                    key3 = ""
                    key4 = ""
                    if "ipsec" in params:
                        key1 = params["ipsec"]["local-sa"]["crypto-key"]
                        key2 = params["ipsec"]["local-sa"]["integr-key"]
                        key3 = params["ipsec"]["remote-sa"]["crypto-key"]
                        key4 = params["ipsec"]["remote-sa"]["integr-key"]
                    tunnel_info.append({
                        "id": str(tunnel_id),
                        "key1": key1,
                        "key2": key2,
                        "key3": key3,
                        "key4": key4
                    })

            except Exception as e:
                self.log.excep("failed to create tunnel information %s" % str(e))
                raise e
        return tunnel_info

    def _get_device_info(self, params):
        """Get device information.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        try:
            stats = fwstats.get_stats()
            info = {}
            # Load component versions
            with open(fwglobals.g.VERSIONS_FILE, 'r') as stream:
                info = yaml.load(stream, Loader=yaml.BaseLoader)
            info['stats'] = stats['message'][-1]
            # Load network configuration.
            info['network'] = {}
            info['network']['interfaces'] = list(fwutils.get_linux_interfaces(cached=False).values())
            info['reconfig'] = '' if fwglobals.g.loadsimulator else fwutils.get_reconfig_hash()
            if fwglobals.g.ikev2.is_private_key_created():
                info['ikev2'] = fwglobals.g.ikev2.get_certificate_expiration()
            # Load tunnel info, if requested by the management
            if params and params.get('tunnels'):
                info['tunnels'] = self._prepare_tunnel_info(params['tunnels'])
            if params and params.get('jobs'):
                info['jobs'] = fwglobals.g.jobs.dump(job_ids=params['jobs'])
            info['cpuInfo'] = fwsystem_checker_common.Checker().get_cpu_info()

            return {'message': info, 'ok': 1}
        except:
            raise Exception("_get_device_info: failed to get device info: %s" % format(sys.exc_info()[1]))


    def _set_cpu_info(self, params):
        """Get device information.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        try:
            vpp_cores = params.get('vppCores')
            power_saving = params.get('powerSaving')
            with fwsystem_checker_common.Checker() as checker:
                update_vpp, update_grub = checker.set_cpu_info(vpp_cores, power_saving)
                reply = {'ok': 1, 'message': {'cpuInfo' : checker.get_cpu_info()} }
                if update_grub:
                    self.log.info("_set_cpu_info: Rebooting the system for changes to take effect.")
                    os.system('sudo reboot')
                elif update_vpp and fwglobals.g.router_api.state_is_started():
                    self.log.info("_set_cpu_info: Restart the router to apply changes in VPP configuration.")
                    fwglobals.g.handle_request({'message':'stop-router'})
                    fwglobals.g.handle_request({'message': 'start-router'})
        except Exception as e:
            reply = {'ok': 0, 'message': str(e) }
        return reply

    def _get_device_stats(self, params):
        """Get device and interface statistics.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with statistics.
        """
        reply = fwstats.get_stats()
        return reply

    def _upgrade_device_sw(self, params):
        """Upgrade device SW.

        :param params: Parameters from flexiManage.

        :returns: Message and status code.
        """
        dir = os.path.dirname(os.path.realpath(__file__))

        # Copy the fwupgrade.sh file to the /tmp folder to
        # prevent overriding it with the fwupgrade.sh file
        # from the new version.
        try:
            copyfile('{}/fwupgrade.sh'.format(dir), '/tmp/fwupgrade.sh')
        except Exception as e:
            return { 'message': 'Failed to copy upgrade file', 'ok': 0 }

        job_id = fwglobals.g.jobs.current_job_id
        cmd = 'bash /tmp/fwupgrade.sh {} {} {} {} {} >> {} 2>&1 &' \
            .format(params['version'], fwglobals.g.VERSIONS_FILE, \
                    fwglobals.g.CONN_FAILURE_FILE, \
                    fwglobals.g.ROUTER_LOG_FILE, \
                    job_id, \
                    fwglobals.g.ROUTER_LOG_FILE)
        os.system(cmd)
        return { 'message': 'Started software upgrade process', 'ok': 1 }

    def _get_device_logs(self, params):
        """Get device logs.

        :param params: Parameters from flexiManage.
            examples of possible parameters:
                {
                    'lines': 100,
                    'filter': 'fwagent',
                },
                {
                    'lines': 100,
                    'filter': 'application',
                    'application': {
                        identifier: 'com.flexiwan.remotevpn'
                    }
                }

        :returns: Dictionary with logs and status code.
        """
        application = params.get('application')
        dl_map = {
            'fwagent': fwglobals.g.ROUTER_LOG_FILE,
            'application_ids': fwglobals.g.APPLICATION_IDS_LOG_FILE,
            'syslog': fwglobals.g.SYSLOG_FILE,
            'dhcp': fwglobals.g.DHCP_LOG_FILE,
            'vpp': fwglobals.g.VPP_LOG_FILE,
            'ospf': fwglobals.g.FRR_LOG_FILE,
            'hostapd': fwglobals.g.HOSTAPD_LOG_FILE,
            'agentui': fwglobals.g.AGENT_UI_LOG_FILE,
            'application': fwglobals.g.applications_api.get_log_filename(application.get('identifier')) if application else '',
        }
        file = dl_map.get(params['filter'], '')
        try:
            logs = fwutils.get_device_logs(file, params['lines'])
            return {'message': logs, 'ok': 1}
        except:
            raise Exception("_get_device_logs: failed to get device logs: %s" % format(sys.exc_info()[1]))

    def _get_device_packet_traces(self, params):
        """Get device packet traces.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with logs and status code.
        """
        try:
            traces = fwutils.get_device_packet_traces(params['packets'], params['timeout'])
            return {'message': traces, 'ok': 1}
        except:
            raise Exception("_get_device_packet_traces: failed to get device packet traces: %s" % format(sys.exc_info()[1]))

    def _get_device_os_routes(self, params):
        """Get device ip routes.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with routes and status code.
        """

        route_entries = []
        routes_linux = fwroutes.FwLinuxRoutes().values()
        for route in routes_linux:
            route_entries.append({
                'destination': route.prefix,
                'gateway': route.via,
                'metric': route.metric,
                'interface': route.dev,
                'protocol': route.proto
            })

        return {'message': route_entries, 'ok': 1}

    def _get_device_config(self, params):
        """Get device configuration from DB.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with configuration and status code.
        """
        router_config = fwutils.dump_router_config()
        system_config = fwutils.dump_system_config()
        applications_config = fwutils.dump_applications_config()
        config = router_config + system_config + applications_config
        reply = {'ok': 1, 'message': config if config else []}
        return reply

    def _reset_device_soft(self, params=None):
        """Soft reset device configuration.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with status code.
        """
        if fwglobals.g.router_api.state_is_started():
            fwglobals.g.handle_request({'message':'stop-router'})   # Stop VPP if it runs
        fwutils.reset_device_config()
        return {'ok': 1}

    def _sync_device(self, params):
        """Handles the 'sync-device' request: synchronizes device configuration
        to the configuration stored on flexiManage. During synchronization
        all interfaces, tunnels, routes, etc, that do not appear
        in the received 'sync-device' request are removed, all entities
        that do appear in the request but do not appear on device are added
        and all entities that appear in both but are different are modified.
        The same entities are ignored.

        :param params: Request parameters received from flexiManage:
                        {
                          'requests': <list of 'add-X' requests that represent
                                    device configuration stored on flexiManage>
                        }
        :returns: Dictionary with status code.
        """
        self.log.info("_sync_device STARTED")

        full_sync_enforced = params.get('type', '') == 'full-sync'

        # Check that all messages are supported
        non_supported_messages = list([x for x in params['requests'] if x['message'] not in fwglobals.request_handlers])
        if non_supported_messages:
            raise Exception("_sync_device: unsupported requests found: %s" % str(non_supported_messages))

        err_str = ''

        for module_name, module in list(fwglobals.modules.items()):
            if module.get('sync', False) == True:
                # get api module. e.g router_api, system_api
                api_module = getattr(fwglobals.g, module.get('object'))
                try:
                    api_module.sync(params['requests'], full_sync_enforced)
                except Exception as e:
                    self.log.error(f"{module_name}.sync() failed: {str(e)}")
                    err_str += f"{module_name}.sync() failed: {str(e)} ; "

        if err_str:
            return {'message': err_str, 'ok': 0}

        fwutils.reset_device_config_signature(log=self.log)
        self.log.info("_sync_device FINISHED")
        return {'ok': 1}

    def _get_wifi_info(self, params):
        try:
            wifi_info = fwwifi.collect_wifi_info(params['dev_id'])
            return {'message': wifi_info, 'ok': 1}
        except Exception as e:
            self.log.error('Failed to get Wifi information. %s' % str(e))
            return {'message': str(e), 'ok': 0}

    def _get_lte_info(self, params):
        try:
            reply = fwlte.collect_lte_info(params['dev_id'])
            return {'message': reply, 'ok': 1}
        except Exception as e:
            self.log.error('Failed to get LTE information. %s' % str(e))
            return {'message': str(e), 'ok': 0}

    def _reset_lte(self, params):
        """Reset LTE modem card.

        :param params: Parameters to use.

        :returns: Dictionary status code.
        """
        try:
            fwlte.reset_modem(params['dev_id'])

            # restore lte connection if needed
            fwglobals.g.system_api.restore_configuration(types=['add-lte'])

            return {'ok': 1, 'message': ''}
        except Exception as e:
            return {'ok': 0, 'message': str(e)}

    def _modify_lte_pin(self, params):
        try:
            dev_id = params['dev_id']
            new_pin = params.get('newPin')
            current_pin = params.get('currentPin')
            enable = params.get('enable', False)
            puk = params.get('puk')
            fwlte.handle_pin_modifications(dev_id, current_pin, new_pin, enable, puk)
            reply = {'ok': 1, 'message': { 'err_msg': None, 'data': fwlte.get_pin_state(dev_id)}}
        except Exception as e:
            reply = {'ok': 0, 'message': { 'err_msg': str(e), 'data': fwlte.get_pin_state(dev_id)} }
        return reply

    def _get_device_certificate(self, params):
        """IKEv2 certificate generation.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with status code.
        """
        return fwglobals.g.ikev2.create_private_key(params['days'], params['new'])

    def _get_bgp_status(self, params):
        """Get BGP Status.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with BGP Status.
        """
        if not fwglobals.g.router_api.state_is_started():
            return {'ok': 1, 'message': { }}

        if not fwglobals.g.router_cfg.get_bgp():
            return {'ok': 1, 'message': { }}

        try:
            cmd = 'vtysh -c "show bgp summary json"'
            frr_json_output = subprocess.check_output(cmd, shell=True).decode().strip()
            data = json.loads(frr_json_output)
            return {'ok': 1, 'message': data.get('ipv4Unicast', {}) }
        except Exception as e:
            return {'ok': 0, 'message': str(e) }