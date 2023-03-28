#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2021  flexiWAN Ltd.
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


# This script checks if system is capable to run FlexiWAN Edge device.
# It adjusts various system parameters, if approved by user.
# This script should be run by the flexiwan-router installer
# as the last step of installation and before flexiwan-router.service is up.
# If it returns failure, the flexiwan-router.service should not be started.
# The script exits with:
#   0 on success
#   1 on unmet hard requirements
#   2 on unmet soft requirements
#   3 on system configuration failure
#   4 on on user aborted configuration

import os
import subprocess

import getopt
import importlib
import distro
import sys
import shutil
import time

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)
import fwglobals
import fwutils

FW_EXIT_CODE_OK = 0
FW_EXIT_CODE_ERROR_UNMET_HARDWARE_REQUIREMENTS        = 0x1
FW_EXIT_CODE_ERROR_UNMET_SYSTEM_REQUIREMENTS          = 0x2
FW_EXIT_CODE_ERROR_FAILED_TO_FIX_SYSTEM_CONFIGURATION = 0x4
FW_EXIT_CODE_ERROR_ABORTED_BY_USER                    = 0x8

hard_checkers = [
    { 'hard_check_cpu_number'         : [ 2,    'critical', 'At least 2 logical CPU-s are required' ] },
    { 'hard_check_kernel_io_modules'  : [ True, 'optional', 'Kernel has i/o modules' ] },
    { 'hard_check_ram'                : [ 3.9,  'critical', 'At least 4GB RAM is required' ] },
    { 'hard_check_nic_drivers'        : [ True, 'optional', 'Supported network cards' ] },
    { 'hard_check_nic_number'         : [ 2,    'critical', 'At least 2 Network Interfaces are required' ] },
    { 'hard_check_sse42'              : [ True, 'critical', 'Support in SSE 4.2 is required' ] },
]

soft_checkers = [
    { 'soft_check_coredump_settings'             : { 'severity': 'critical' }},
    { 'soft_check_default_route'                 : { 'severity': 'critical', 'interactive': 'must' }},
    { 'soft_check_default_routes_metric'         : { 'severity': 'critical' }},
    { 'soft_check_disable_linux_autoupgrade'     : { 'severity': 'critical' }},
    { 'soft_check_disable_transparent_hugepages' : { 'severity': 'optional' }},
    { 'soft_check_duplicate_netplan_sections'    : { 'severity': 'critical' }},
    { 'soft_check_iommu_on'                      : { 'severity': 'critical' }},
    { 'soft_check_hostname_syntax'               : { 'severity': 'critical', 'interactive': 'must' }},   # This check should be before 'soft_check_hostname_in_hosts', as last might insert bad syntax hostname into /etc/hosts file
    { 'soft_check_hostname_in_hosts'             : { 'severity': 'critical' }},
    { 'soft_check_hugepage_number'               : { 'severity': 'optional', 'interactive': 'optional' }},
    { 'soft_check_multiple_interface_definitions': { 'severity': 'critical' }},
    { 'soft_check_networkd'                      : { 'severity': 'critical' }},
    { 'soft_check_networkd_configuration'        : { 'severity': 'critical' }},
    { 'soft_check_network_manager'               : { 'severity': 'critical' }},
    { 'soft_check_lte_mbim_mode'                 : { 'severity': 'critical' }},
    { 'soft_check_utc_timezone'                  : { 'severity': 'critical' }},
    { 'soft_check_uuid'                          : { 'severity': 'critical' }},
    { 'soft_check_vfio_iommu_unsafe_interrupts'  : { 'severity': 'optional', 'interactive': 'must' }},   # enforce interaction, because we don't know what are risks behind this option
    { 'soft_check_wifi_driver'                   : { 'severity': 'critical' }},
]

class TXT_COLOR:
    BG_FAILURE_CRITICAL = '\x1b[30;41m'  # Red
    BG_FAILURE_OPTIONAL = '\x1b[30;43m'  # Yellow
    BG_WARNING          = '\x1b[30;43m'  # Yellow
    FG_SUCCESS          = '\x1b[32m'     # Green
    FG_FAILURE_CRITICAL = '\x1b[31m'     # Red
    FG_FAILURE_OPTIONAL = '\x1b[33m'     # Yellow
    FG_SKIPPED          = '\x1b[2;36m'   # Faded Cyan
    FG_BOLD             = '\x1b[1m'
    FG_FADED            = '\x1b[2m'
    FG_UNDERLINE        = '\x1b[4m'
    END                 = '\x1b[0m'

def checker_name_to_description(checker_name):
    """Convert checker name into description.

    :param checker_name:         Checker name.

    :returns: Description.
    """
    result_string = ' '.join(checker_name.split('_')[1:])
    # convert first character to uppercase
    return result_string[0].upper() + result_string[1:]

def report_checker_result(logger, succeeded, severity, description, failure_reason=None):
    """Report checker results.

    :param succeeded:       Success status.
    :param severity:        Severity level.
    :param description:     Description.
    :param failure_reason:  Extended failure info.

    :returns: None.
    """
    if succeeded is None:
        status   = TXT_COLOR.FG_SKIPPED + ' SKIPPED ' + TXT_COLOR.END
    elif succeeded is True:
        status   = TXT_COLOR.FG_SUCCESS + ' PASSED  ' + TXT_COLOR.END
    else:
        if severity == 'optional':
            status   = TXT_COLOR.BG_FAILURE_OPTIONAL + ' FAILED  ' + TXT_COLOR.END
        else:
            status   = TXT_COLOR.BG_FAILURE_CRITICAL + ' FAILED  ' + TXT_COLOR.END
    result_string = '%s: %s : %s' % (status, severity.upper(), description)
    if failure_reason:
        result_string = result_string + ' : %s' % failure_reason
    logger.info(result_string)

def check_hard_configuration(checker, check_only):
    """Check hard configuration.

    :param checker:         Checker name.
    :param check_only:      Check only mode.

    :returns: 'True' if succeeded.
    """
    succeeded = True
    for element in hard_checkers:
        (checker_name, checker_params) = list(element.items())[0]

        # Don't run connectivity checkers in check only mode,
        # as every check waits 5 seconds for ping response on every found interface.
        # That might suspend agent start too long, making user experience bad.
        if 'connectivity' in checker_name and check_only:
            continue

        checker_func = getattr(checker, checker_name)
        args         = checker_params[0]
        severity     = checker_params[1]
        description  = checker_params[2]
        result = checker_func(args)
        if not result and severity == 'critical':
            succeeded = False
        report_checker_result(checker.log, result, severity, description)
    return succeeded

def check_soft_configuration(checker, fix=False, quiet=False):
    """Check hard configuration.

    :param checker:         Checker name.
    :param fix:             Fix problem.
    :param quiet:           Do not prompt user.

    :returns: 'True' if succeeded.
    """
    succeeded = True
    for element in soft_checkers:
        (checker_name, checker_params) = list(element.items())[0]
        description = checker_name_to_description(checker_name)
        prompt = description + ': '

        try:
            checker_func = getattr(checker, checker_name)
            severity     = checker_params['severity']
            interactive  = checker_params.get('interactive')

            # Run the checker and cache result to avoid unnecessary runs (and prints)
            #
            if 'result' not in checker_params:
                result = checker_func(fix=False, prompt=prompt)
                checker_params.update({'result': result})
            else:
                result = checker_params['result']

            # Print result and go to the next check if:
            #  - no fix was requested
            #  - check should be skipped (result == None)
            #  - check succeeded (result == True) and no fix in interactive mode
            #    was requested or the interactive mode is not supported by this check.
            #
            if fix == False or \
               result == None or \
               (result == True and (quiet == True or not interactive)):
                report_checker_result(checker.log, result, severity, description)
                continue

            # At this point we have to fix the failed check.

            if not result and quiet and interactive == 'must':
                # If it is not possible to fix as non-interactive mode was requested,
                # but fix requires interaction, report result and continue.
                # If the check is critical, fail the system checker.
                #
                report_checker_result(checker.log, result, severity, description)
                if severity == 'critical':
                    succeeded = False
                continue

            run_check = True
            if not quiet:
                while True:
                    choice = input(prompt + "configure? [y/N/q]: ")
                    if choice == 'y' or choice == 'Y':
                        break
                    elif choice == 'n' or choice == 'N' or choice == '':
                        run_check = False
                        break
                    elif choice == 'q' or choice == 'Q':
                        sys.exit(FW_EXIT_CODE_ERROR_ABORTED_BY_USER)

            if run_check:
                result = checker_func(fix=True, silently=quiet, prompt=prompt)
                checker_params.update({'result': result})
                if not result and severity == 'critical':
                    succeeded = False

            report_checker_result(checker.log, result, severity, description)

        except Exception as e:
            report_checker_result(checker.log, None, severity, description, str(e))

    # If we fixed some parameters, reset the cache of results,
    # so next check will find and print the problems that still exist.
    if fix:
        for element in soft_checkers:
            checker_params = list(element.values())[0]
            if 'result' in checker_params:
                del checker_params['result']
    return succeeded

def reset_system_to_defaults(checker):
    """ reset vpp configuration to default

    :returns: 'True' if succeeded.
    """
    # This function does the following:
    # 1. Copies the startup.conf.orig over the start.conf and startup.conf.baseline files.
    # 2. reset /etc/default/grub to a single core configuration
    # 3. Reboot.

    reboot_needed = False
    while True:
        choice = input("Resetting to Factory Defaults. Are you sure? [y/N]: ")
        if choice == 'n' or choice == 'N' or choice == '':
            return True
        elif choice == 'y' or choice == 'Y':
            shutil.copyfile (fwglobals.g.VPP_CONFIG_FILE_RESTORE, fwglobals.g.VPP_CONFIG_FILE)
            if os.path.exists(fwglobals.g.VPP_CONFIG_FILE_BACKUP):
                shutil.copyfile (fwglobals.g.VPP_CONFIG_FILE_RESTORE, fwglobals.g.VPP_CONFIG_FILE_BACKUP)
            checker.set_cpu_info_into_grub_file(reset=True)
            reboot_needed = True
            break

    if reboot_needed == True:
        while True:
            choice = input("Reboot the system? [Y/n]: ")
            if choice == 'n' or choice == 'N':
                print ("Please reboot the system for changes to take effect.")
                return True
            elif choice == 'y' or choice == 'Y' or choice == '':
                print ("Rebooting....")
                os.system('reboot now')
    return True

def main(args):
    """Checker entry point.

    :param args:            Command line arguments.

    :returns: Bitmask with status codes.
    """
    module_name = distro.name().lower()
    module = importlib.import_module(module_name)
    with module.Checker(args.debug) as checker:

        # Check hardware requirements
        # -----------------------------------------
        hard_status_code = FW_EXIT_CODE_OK
        if not args.soft_only:
            if not args.hard_only:
                print('\n=== hard configuration ====')
            success = check_hard_configuration(checker, args.check_only)
            hard_status_code = FW_EXIT_CODE_OK if success else FW_EXIT_CODE_ERROR_UNMET_HARDWARE_REQUIREMENTS
            if args.hard_only:
                return hard_status_code

        # Check software and configure it if needed
        # -----------------------------------------
        if not (args.hard_only or args.soft_only):
            print('\n=== soft configuration ====')
        if args.check_only:
            success = check_soft_configuration(checker, fix=False)
            soft_status_code = FW_EXIT_CODE_OK if success else FW_EXIT_CODE_ERROR_UNMET_SYSTEM_REQUIREMENTS
            if not success:
                print('')
                print("===================================================================================")
                print("! system checker errors, run 'fwsystem_checker' with no flags to fix configuration!")
                print("===================================================================================")
                print('')
            return (soft_status_code | hard_status_code)

        if args.quiet:
            # In silent mode just go and configure needed stuff
            success = check_soft_configuration(checker, fix=True, quiet=True)
            soft_status_code = FW_EXIT_CODE_OK if success else FW_EXIT_CODE_ERROR_FAILED_TO_FIX_SYSTEM_CONFIGURATION
            return  (soft_status_code | hard_status_code)

        # Firstly show to user needed configuration adjustments.
        # The start interaction with user.
        check_soft_configuration(checker, fix=False)
        choice = 'x'
        while not (choice == '' or choice == '0' or choice == '4'):
            choice = input(
                            "\n" +
                            "\t[0] - quit and use fixed parameters\n" +
                            "\t 1  - check system configuration\n" +
                            "\t 2  - configure system silently\n" +
                            "\t 3  - configure system interactively\n" +
                            "\t 4  - restore system checker settings to default\n" +
                            "\t------------------------------------------------\n" +
                            "Choose: ")
            if choice == '1':
                print('')
                success = check_soft_configuration(checker, fix=False)
            elif choice == '2':
                print('')
                success = check_soft_configuration(checker, fix=True, quiet=True)
            elif choice == '3':
                print('')
                success = check_soft_configuration(checker, fix=True, quiet=False)
            elif choice == '4':
                print ('')
                success = reset_system_to_defaults(checker)
            else:
                success = True

        if choice == '0' or choice == '':   # Note we restart daemon and not use 'fwagent restart' as fwsystem_checker might change python code too ;)
            if success == True:
                print ("Please wait..")
                os.system("sudo systemctl stop flexiwan-router")
                checker.save_config()
                if checker.grub.requires_reboot:
                    rebootSys = 'x'
                    while not (rebootSys == "n" or rebootSys == 'N' or rebootSys == 'y' or rebootSys == 'Y'):
                        rebootSys = input("Changes to kernel configuration requires system reboot.\n" +
                                        "Would you like to reboot now (Y/n)? ")
                        if rebootSys == 'y' or rebootSys == 'Y' or rebootSys == '':
                            print ("Rebooting...")
                            os.system('reboot now')

                os.system("sudo systemctl start flexiwan-router")
                # Wait two seconds for the agent to reload the LTE drivers
                time.sleep(2)

                print ("Done.")

        soft_status_code = FW_EXIT_CODE_OK if success else FW_EXIT_CODE_ERROR_FAILED_TO_FIX_SYSTEM_CONFIGURATION
        return (soft_status_code | hard_status_code)

if __name__ == '__main__':
    import argparse
    global arg

    if not fwutils.check_root_access():
        sys.exit(1)

    # Ensure that VPP does not run.
    # Otherwise driver interface checks might fail and user will be scared for
    # no reason. Note it is too late to check system, if router was started :)
    #
    try:
        subprocess.check_call(['pidof', 'vpp'])
        # If we reached this point, i.e. if no exception occurred, the vpp pid was found
        print ("error: cannot run fwsystem_checker when the router is running, please stop router first")
        sys.exit(FW_EXIT_CODE_OK)
    except Exception as e:
        pass


    parser = argparse.ArgumentParser(description='FlexiEdge configuration utility')
    parser.add_argument('-c', '--check_only', action='store_true',
                        help="check configuration and exit")
    parser.add_argument('-q', '--quiet', action='store_true',
                        help="adjust system configuration silently")
    parser.add_argument('-r', '--hard_only', action='store_true',
                        help="check hard configuration only")
    parser.add_argument('-s', '--soft_only', action='store_true',
                        help="check soft configuration only")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="don't clean temporary files and enable debug prints")
    args = parser.parse_args()
    res = main(args)
    ####### For now (Dec-2019) don't block installation and agent start on failure
    # sys.exit(res)
    sys.exit(FW_EXIT_CODE_OK)
