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


import os
import re
import subprocess
import sys

import fwsystem_checker_common

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)
import fwutils

class Checker(fwsystem_checker_common.Checker):
    """This is Checker class representation.
    """
    def _is_service_active(self, service):
        """Return True if service is running"""
        cmd = '/bin/systemctl status %s.service' % service
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        lines = proc.communicate()[0].decode().split('\n')
        for line in lines:
            if 'Active:' in line:
                if '(running)' in line:
                    return True
        return False

    def _start_service(self, service):
        """Start and enable service"""
        os.system('/bin/systemctl unmask %s.service > /dev/null 2>&1' % service)
        os.system('/bin/systemctl enable %s.service > /dev/null 2>&1' % service)
        os.system('/bin/systemctl start %s.service > /dev/null 2>&1' % service)

    def _stop_service(self, service):
        """Stop and disable service"""
        os.system('/bin/systemctl stop %s.service > /dev/null 2>&1' % service)
        os.system('/bin/systemctl disable %s.service > /dev/null 2>&1' % service)
        os.system('/bin/systemctl mask %s.service > /dev/null 2>&1' % service)

    def soft_check_networkd(self, fix=False, silently=False, prompt=None):
        """Check if networkd is running.

        :param fix:             Run networkd.
        :param silently:        Run silently.
        :param prompt:          Ask user for prompt.

        :returns: 'True' if it networkd is running, 'False' otherwise.
        """
        running = False
        try:
            running = self._is_service_active("systemd-networkd")
            if running == False:
                raise Exception(prompt + 'networkd is not running')
            else:
                running = True
            return True
        except Exception as e:
            self.log.error(prompt + str(e))
            if not fix:
                return False
            else:
                if silently:
                    # Run the daemon if not running
                    if not running:
                        self._start_service("systemd-networkd")
                    return True
                else:
                    # Run the daemon if not running
                    if not running:
                        choice = input(prompt + "start networkd? [Y/n]: ")
                        if choice == 'y' or choice == 'Y' or choice == '':
                            self._start_service("systemd-networkd")
                            return True
                        else:
                            return False

    def soft_check_network_manager(self, fix=False, silently=False, prompt=None):
            """Check if NetworkManager is not running.

            :param fix:             Stop NetworkManager.
            :param silently:        Stop silently.
            :param prompt:          Ask user for prompt.

            :returns: 'True' if NetworkManager is not running, 'False' otherwise.
            """
            running = False
            try:
                running = self._is_service_active("NetworkManager")
                if running == True:
                    raise Exception(prompt + 'NetworkManager is running')
                else:
                    return True
            except Exception as e:
                self.log.error(prompt + str(e))
                if not fix:
                    return False
                else:
                    # Stop the daemon if running
                    if running:
                        if not silently:
                            choice = input(prompt + "stop NetworkManager? [Y/n]: ")
                            if choice != 'y' and choice != 'Y' and choice != '':
                                return False
                        self._stop_service("NetworkManager")
                        self._stop_service("NetworkManager-dispatcher")
                        self._stop_service("NetworkManager-wait-online")
                    return True

    def soft_check_disable_linux_autoupgrade(self, fix=False, silently=False, prompt=None):
        """Check if Linux autoupgrade is disabled.

        :param fix:             Disable autoupgrade.
        :param silently:        Run silently.
        :param prompt:          Ask user for prompt.

        :returns: 'True' if it autoupgrade is disabled, 'False' otherwise.
        """
        autoupgrade_file   = '/etc/apt/apt.conf.d/20auto-upgrades'
        autoupgrade_params = [
            'APT::Periodic::Update-Package-Lists',
            'APT::Periodic::Unattended-Upgrade'
        ]

        def _fetch_autoupgrade_param(param):
            try:
                out = subprocess.check_output("grep '%s' %s " % (param, autoupgrade_file) , shell=True).decode().strip().split('\n')[0]
                # APT::Periodic::Update-Package-Lists "0";
                m = re.search(' "(.)";', out)
                if m:
                    enabled = True if int(m.group(1)) else False
                    return enabled
                raise Exception("not supported format in %s (out=%s)" % (autoupgrade_file, out))
            except subprocess.CalledProcessError:
                raise Exception("not found")
            return False

        def _set_autoupgrade_param(param, val):
            # Firstly remove parameter from file if exist.
            # Than add the parameter as a new line.
            # Example of line in file: APT::Periodic::Update-Package-Lists "0";
            os.system('sed -i -E "/%s /d" %s' % (param, autoupgrade_file))
            os.system('printf "%s \\"%s\\";\n" >> %s' % (param, str(val), autoupgrade_file))

        # Firstly ensure that autoupgrade configuration file exists.
        # If it doesn't exist, create it.
        #
        if not os.path.isfile(autoupgrade_file):
            if not fix:
                self.log.error(prompt + '%s not found' % autoupgrade_file)
                return False
            else:
                os.system('touch ' + autoupgrade_file)

        # Check if there is a least one parameter that should be fixed
        params_to_fix = []
        for param in autoupgrade_params:
            try:
                enabled = _fetch_autoupgrade_param(param)
                if enabled:
                    params_to_fix.append({'name': param, 'status': 'enabled'})
            except Exception as e:
                params_to_fix.append({'name': param, 'status': str(e)})
        if len(params_to_fix) == 0:
            return True

        # Fix parameter if needed
        if not fix:
            for param in params_to_fix:
                self.log.error(prompt + '%s %s' % (param['name'], param['status']))
            return False
        else:
            succeeded = True
            for param in params_to_fix:
                try:
                    _set_autoupgrade_param(param['name'], 0)
                except Exception as e:
                    self.log.error(prompt + 'failed to disable %s: %s' % (param['name'], str(e)))
                    succeeded = False
            return succeeded


    def soft_check_utc_timezone(self, fix=False, silently=False, prompt=None):
        """Check if UTC zone is configured.

        :param fix:             Configure UTC zone.
        :param silently:        Run silently.
        :param prompt:          Ask user for prompt.

        :returns: 'True' if it UTC zone is configured, 'False' otherwise.
        """
        #>> timedatectl
        #          Local time: Wed 2019-10-30 17:22:24 UTC
        #      Universal time: Wed 2019-10-30 17:22:24 UTC
        #            RTC time: Wed 2019-10-30 17:22:24
        #           Time zone: Etc/UTC (UTC, +0000)
        # System clock synchronized: no
        # systemd-timesyncd.service active: yes
        #     RTC in local TZ: no
        try:
            out = subprocess.check_output("timedatectl | grep 'Time zone:'", shell=True).decode().strip()
        except Exception as e:
            self.log.error(prompt + str(e))
            return False
        if 'Time zone: Etc/UTC' in out or 'Time zone: UTC' in out:
            return True

        if not fix:
            self.log.error(prompt + 'time zone is not UTC: ' + out)
            return False

        ret = os.system('timedatectl set-timezone UTC')
        if ret != 0:
            return False
        return True