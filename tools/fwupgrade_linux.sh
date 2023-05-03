#! /bin/bash

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

# Exports
export DEBIAN_FRONTEND=noninteractive

# Constants
AGENT_SERVICE_FILE='/lib/systemd/system/flexiwan-router.service'
AGENT_SERVICE='flexiwan-router'
SCRIPT_NAME="$(basename $BASH_SOURCE)"

# Constants passed to the script by fwagent
AGENT_LOG_FILE="$1"
JOB_ID="$2"

log() {
    echo `date +'%b %e %R:%S'`" $HOSTNAME $SCRIPT_NAME:" "$@" >> "$AGENT_LOG_FILE" 2>&1
}

update_fwjob() {
    log "$1": "$2"
    fwagent configure jobs update --job_id $JOB_ID --request 'upgrade-linux-sw' --command "$1" --job_error "$2"
}

handle_upgrade_failure() {
    log "Software upgrade failed"
    update_fwjob "$1" "$2"
    systemctl restart "$AGENT_SERVICE"
}

update_service_conf_file() {
    if [ ! -f "$AGENT_SERVICE_FILE" ]; then
        update_fwjob "update service.unit file" "${AGENT_SERVICE_FILE} not found"
        return 1
    fi

    # Don't add the configuration if it already exists
    kill_mode_conf=`grep KillMode=process "$AGENT_SERVICE_FILE"`
    if [ -z "$kill_mode_conf" ]; then
        echo -e "\n[Service]\nKillMode=process" >> "$AGENT_SERVICE_FILE"
        systemctl daemon-reload
    fi
}

linux_upgrade() {

    # Set "KillMode" option in the service file, to make sure systemd
    # doesn't kill the 'fwupgrade_linux.sh' process itself on stopping the fwagent process,
    # as today the 'fwupgrade_linux.sh' is invoked by the fwagent on receiving
    # 'upgrade-linux-sw' request from flexiManage. Note, the vpp and rest processes
    # in the fwagent control group are not stopped too, but we are OK with this for now.
    #
    update_service_conf_file
    ret=${PIPESTATUS[0]}
    if [ ${ret} != 0 ]; then
        update_fwjob "upgrade linux" "update_service_conf_file failed: ${ret}"
        return 1
    fi

    log "INFO: Running apt upgrade -y ..."
    apt upgrade -y
    log "INFO: Running apt dist-upgrade -y ..."
    apt dist-upgrade -y
    log "INFO: Running apt install -y update-manager-core ..."
    apt install -y update-manager-core

    # Check if system needs a reboot before proceeding with Ubuntu upgrade
    if [ -f /var/run/reboot-required ] ; then
        log "INFO: A reboot is required before proceeding with Ubuntu upgrade."
        log "INFO: Disabling the required reboot in order to proceed and deferring the reboot at the end of the full upgrade."
        rm -rf /var/run/reboot-required /var/run/reboot-required.pkgs
    fi

    log "INFO: Running do-release-upgrade -f DistUpgradeViewNonInteractive ..."
    do-release-upgrade -f DistUpgradeViewNonInteractive

    expected_ubuntu_version="focal"
    current_ubuntu_version="$(lsb_release -cs)"
    log "INFO: Running lsb_release -cs returns $current_ubuntu_version"
    if [ "$current_ubuntu_version" != "$expected_ubuntu_version" ] ; then
        log "ERR: Ubuntu upgrade check failed."
        handle_upgrade_failure 'upgrade linux' 'Failed to upgrade Host OS - OS check failed'
    fi

    log "INFO: Fixing apt sources list files ..."
    apt_source_list_file="/etc/apt/sources.list.d/flexiwan.source.list"
    if [ -f $apt_source_list_file ] ; then
        log "INFO: Fixing $apt_source_list_file ..."
        sed -i -e 's/^# //g' -e 's/#.*//g' $apt_source_list_file
    fi

    apt_source_list_file="/etc/apt/sources.list.d/flexiwan.testing.source.list"
    if [ -f $apt_source_list_file ] ; then
        log "INFO: Fixing $apt_source_list_file ..."
        sed -i -e 's/^# //g' -e 's/#.*//g' $apt_source_list_file
    fi

    apt_source_list_file="/etc/apt/sources.list.d/flexiwan.unstable.source.list"
    if [ -f $apt_source_list_file ] ; then
        log "INFO: Fixing $apt_source_list_file ..."
        sed -i -e 's/^# //g' -e 's/#.*//g' $apt_source_list_file
    fi

    apt_source_list_file="/etc/apt/sources.list.d/openvpn-aptrepo.list"
    if [ -f $apt_source_list_file ] ; then
        log "INFO: Fixing $apt_source_list_file ..."
        sed -i -e 's/^# //g' -e 's/#.*//g' $apt_source_list_file
    fi

    rm -rf /etc/apt/sources.list.d/*.distUpgrade /etc/apt/sources.list.distUpgrade

    # Mark wifi drivers packages as holded in apt,
    # in order to avoid installing new ones on systems running kernel 5.4.0
    log "INFO: Marking flexiwan-ath9k-dkms and flexiwan-ath10k-dkms as holded packages ..."
    apt-mark hold flexiwan-ath9k-dkms
    apt-mark hold flexiwan-ath10k-dkms

    log "Rebuilding Wifi dirvers..."
    kernel_latest_installed_version="$(ls /lib/modules | sort -rV | head -n 1)"
    wifi_drivers_list="ath10k ath9k"
    for driver in $wifi_drivers_list ; do
        wifi_drivers_name="$driver"
        wifi_drivers_version="5.10.16-1"
        wifi_drivers_src_dir="/usr/src/${wifi_drivers_name}-${wifi_drivers_version}"
        wifi_drivers_dkms_config="${wifi_drivers_src_dir}/dkms.conf"
        wifi_drivers_makefile="${wifi_drivers_src_dir}/Makefile"
        dkms_modules_build_dir="/var/lib/dkms/${wifi_drivers_name}/${wifi_drivers_version}/${kernel_latest_installed_version}/x86_64/module"
        dkms_modules_install_dir="/lib/modules/${kernel_latest_installed_version}/updates/dkms"
        if [ -d $wifi_drivers_src_dir ] ; then
            log "INFO: Re-building $wifi_drivers_name kernel module to match vermagic to the latest installed Linux headers ..."
            dkms remove $wifi_drivers_dkms_config -m $wifi_drivers_name -v $wifi_drivers_version -k $kernel_latest_installed_version
            cp $wifi_drivers_makefile ${wifi_drivers_makefile}.orig
            sed -i -e "s/^KLIB := .*/KLIB := \/lib\/modules\/${kernel_latest_installed_version}\//g" $wifi_drivers_makefile
            dkms build $wifi_drivers_dkms_config -m $wifi_drivers_name -v $wifi_drivers_version -k $kernel_latest_installed_version
            dkms install $wifi_drivers_dkms_config -m $wifi_drivers_name -v $wifi_drivers_version -k $kernel_latest_installed_version
            for i in $(ls $dkms_modules_build_dir) ; do
                vermagic="$(modinfo -F vermagic ${dkms_modules_install_dir}/$i | cut -d ' ' -f1)"
                if [ "$vermagic" == "$kernel_latest_installed_version" ] ; then
                    log "INFO: Kernel module ${dkms_modules_install_dir}/$i vermagic (${vermagic}) matches the latest installed Linux headers (${kernel_latest_installed_version})"
                else
                    log "WARN: Kernel module ${dkms_modules_install_dir}/$i vermagic (${vermagic}) does not match the latest installed Linux headers (${kernel_latest_installed_version})"
                    if [ ! -f ${wifi_drivers_makefile}.flexiwan_wifi_dirvers_re-build ] ; then
                        log "INFO: Saving Makefile used for re-building kernel module ${dkms_modules_install_dir}/$i at ${wifi_drivers_makefile}.flexiwan_wifi_dirvers_re-build"
                        cp $wifi_drivers_makefile ${wifi_drivers_makefile}.flexiwan_wifi_dirvers_re-build
                    fi
                fi
            done
            mv ${wifi_drivers_makefile}.orig $wifi_drivers_makefile
        fi
    done
}

flexiedge_install() {
    log "Installing new flexiAgent"
    install_cmd="apt-get -o Dpkg::Options::="--force-confold" -y install --allow-downgrades $1"
    out=$(${install_cmd} 2>&1); ret=${PIPESTATUS[0]}
    if [ ${ret} == 0 ]; then
        return 0   # return on success
    fi
}

# Upgrade process
log "Starting linux upgrade process..."

date_now=$(date "+%F %H:%M:%S")
log "Starting Ubuntu upgrade at ${date_now}"

# Update debian repositories
res=$(apt-get update)
if [ ${PIPESTATUS[0]} != 0 ]; then
    log "WARN: apt update failed. Trying to solve it by installing/upgrading ca-certificates package. res=${res}"
    res=$(apt-get install ca-certificates)
    if [ ${PIPESTATUS[0]} != 0 ]; then
        log "Error: failed upgrading ca-certificates package. res=${res}"
        handle_upgrade_failure 'update debian repositories' 'Failed to update debian repositores'
        exit 1
    fi
    log "Running apt-get update again"
    res=$(apt-get update)
    if [ ${PIPESTATUS[0]} != 0 ]; then
        log "Error: failed second apt-get update. res=${res}"
        handle_upgrade_failure 'update debian repositories' 'Failed to update debian repositores again'
        exit 1
    fi
fi

# Stop agent connection loop to the MGMT, to make sure the
# agent does not prcoess messages during the upgrade process.
log "Closing connection to MGMT..."
res=$(fwagent stop)
if [ ${PIPESTATUS[0]} != 0 ]; then
    log $res
    handle_upgrade_failure 'stop agent connection' 'Failed to stop agent connection to management'
    exit 1
fi

linux_upgrade

date_now=$(date "+%F %H:%M:%S")
log "Ubuntu upgrade finished at ${date_now}"

# Update debian repositories
res=$(apt-get update)
if [ ${PIPESTATUS[0]} != 0 ]; then
    log $res
    handle_upgrade_failure 'update debian repositories' 'Failed to update debian repositores'
    exit 1
fi

flexiedge_install "${AGENT_SERVICE}"
ret=${PIPESTATUS[0]}
if [ ${ret} != 0 ]; then
    handle_upgrade_failure 'install new flexiEdge version' 'failed to install new version'
    exit 1
fi

reboot

