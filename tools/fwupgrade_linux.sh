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
    exit 1
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

    # Mark wifi drivers packages as holded in apt,
    # in order to avoid installing new ones on systems running kernel 5.4.0
    apt-mark hold flexiwan-ath9k-dkms
    apt-mark hold flexiwan-ath10k-dkms

    apt upgrade -y
    apt dist-upgrade -y
    apt install -y update-manager-core
    do-release-upgrade -f DistUpgradeViewNonInteractive
    sed -i -e 's/^# //g' -e 's/#.*//g' /etc/apt/sources.list.d/flexiwan.testing.source.list
    sed -i -e 's/^# //g' -e 's/#.*//g' /etc/apt/sources.list.d/openvpn-aptrepo.list
    rm -rf /etc/apt/sources.list.d/*.distUpgrade /etc/apt/sources.list.distUpgrade
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
    log $res
    handle_upgrade_failure 'update debian repositories' 'Failed to update debian repositores'
    exit 1
fi

# Stop agent connection loop to the MGMT, to make sure the
# agent does not prcoess messages during the upgrade process.
log "Closing connection to MGMT..."
res=$(fwagent stop)
if [ ${PIPESTATUS[0]} != 0 ]; then
    log $res
    handle_upgrade_failure 'stop agent connection' 'Failed to stop agent connection to management'
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

# Reopen the connection loop in case it is closed
res=$(fwagent start)
if [ ${PIPESTATUS[0]} != 0 ]; then
    handle_upgrade_failure 'starting agent connection loop' 'failed to connect'
    exit 1
fi

reboot

