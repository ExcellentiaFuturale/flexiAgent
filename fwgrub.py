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

import subprocess

import fwutils

from fwobject import FwObject

class FwGrub:
    '''Wrapper for all GRUB related activities.
    '''
    def __init__(self, log=None):
        '''
        :param log: FwLog logger
        '''
        self.log                = log
        self.grub_filename      = '/etc/default/grub'
        self.updated            = False
        self.requires_reboot    = False
        self.parameters         = {}

        # Load parameters from the GRUB_CMDLINE_LINUX_DEFAULT line into dictionary
        try:
            cmd = f"grep -oP '^GRUB_CMDLINE_LINUX_DEFAULT=\K.*' {self.grub_filename}"
            params = subprocess.check_output(cmd, shell=True).decode().strip('\n').replace('"','').split(' ')
            for param in params:
                name_val = param.split('=')
                name     = name_val[0]
                value    = name_val[1] if len(name_val) > 1 else ''
                self.parameters.update({name: value})
        except:
            pass

    def get_param(self, name):
        return self.parameters.get(name)

    def set_param(self, name, value=''):
        if name in self.parameters and self.parameters[name] == value:
            return
        self.parameters.update({name: value})
        self.updated = True

    def unset_param(self, name):
        if name in self.parameters:
            del self.parameters[name]
            self.updated = True

    def flush(self):
        '''Flushes dictionary with parameters into the GRUB_CMDLINE_LINUX_DEFAULT
        line in the /etc/default/grub file.
        '''
        if not self.updated:
            return
        params = ''
        for name in self.parameters.keys():
            if self.parameters[name]:
                params += f'{name}={self.parameters[name]} '
            else:
                params += f'{name} '
        params = params.strip()

        cmd = f'sudo sed -i -E "s/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\\\"{params}\\\"/" {self.grub_filename}'
        subprocess.check_call(cmd, shell=True)
        subprocess.check_call("sudo update-grub > /dev/null 2>&1", shell=True)
        self.updated         = False
        self.requires_reboot = True

    def set_cpu_info(self, cores):
        """Configures the /etc/default/grub with number of cores to be isolated
        toward VPP.
        """
        if cores == 0:
            self.unset_param('isolcpus')
            self.unset_param('nohz_full')
            self.unset_param('rcu_nocbs')
        else:
            if cores == 1:
                self.set_param('isolcpus',  '1')
                self.set_param('nohz_full', '1')
                self.set_param('rcu_nocbs', '1')
            else:
                self.set_param('isolcpus',  f'1-{cores}')
                self.set_param('nohz_full', f'1-{cores}')
                self.set_param('rcu_nocbs', f'1-{cores}')
            if fwutils.check_if_virtual_environment():
                self.set_param('iommu', 'pt')
                self.set_param('intel_iommu', 'on')
        self.flush()

    def soft_check(self, params, fix, prompt=''):
        '''Implements soft check logic of the fwsystem_checker for the GRUB
        related parameters:
            - checks if provided parameters exist in the GRUB file
            - if 'fix' is True, add the missing parameters to the GRUB file

        :param params: list of parameters, where every parameter might have or
                       might have no value, separated by '='.
        :param fix:    if True, the missing parameters should be added to GRUB
        :param prompt: prompt prefix to be used for logging

        :returns: True on successful check/fix, False on the failure
        '''
        # Build helper dictionary that holds various information about parameters
        #
        parameters = {}
        for param in params:
            name_val = param.split('=')
            name     = name_val[0]
            value    = name_val[1] if len(name_val) > 1 else ''
            parameters.update({param:
                {
                    'name':    name,
                    'value':   value,
                    'old_val': self.get_param(name),
                }
            })

        # If no need to fix, just ensure that all parameters present in GRUB
        #
        if not fix:
            all_found = True
            for param in params:
                if parameters[param]['value'] != parameters[param]['old_val']:
                    self.log.error(prompt + f"'{param}' was not found in {self.grub_filename}")
                    all_found = False
            return all_found

        # Go and fix - add missing or update existing parameters
        #
        for param in params:
            if parameters[param]['value'] != parameters[param]['old_val']:
                name, value  = parameters[param]['name'], parameters[param]['value']
                self.set_param(name, value)
        self.flush()
        return True
