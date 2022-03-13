from netaddr import IPAddress
import os
import json
from scripts_logger import logger

# We need to save information between the script called when running (up)
# and the script called when the daemon goes down.
# For this purpose we create a file in the library of the application where we store the required information
app_db_path = '__APP_DB_FILE__'

def add_to_ospf(ifconfig_local_ip, ifconfig_netmask):
    mask = IPAddress(ifconfig_netmask).netmask_bits()
    vtysh_cmd = f'sudo /usr/bin/vtysh -c "configure" -c "router ospf" -c "network {ifconfig_local_ip}/{mask} area 0.0.0.0"'
    rc = os.system(vtysh_cmd)
    if rc:
        raise Exception('Failed to add openvpn network to ospf')

def remove_from_ospf(ifconfig_local_ip, ifconfig_netmask):
    try:
        mask = IPAddress(ifconfig_netmask).netmask_bits()
        vtysh_cmd = f'sudo /usr/bin/vtysh -c "configure" -c "router ospf" -c "no network {ifconfig_local_ip}/{mask} area 0.0.0.0"'
        os.system(vtysh_cmd)
    except:
        pass

def add_tc_commands(ifconfig_local_ip):
    tc_cmd = [
        # configure mirror ingress traffic from the tun interface created by vpp to the the openvpn tun interface
        'sudo tc qdisc add dev t_vpp_remotevpn handle ffff: ingress',
        'sudo tc filter add dev t_vpp_remotevpn parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev t_remotevpn',

        # configure mirror ingress traffic from vpn tun interace to the tun interface that created by vpp
        'sudo tc qdisc add dev t_remotevpn handle ffff: ingress',

        # don't mirror traffic that its destination address is the vpn server itself (traffic originated by linux).
        f'sudo tc filter add dev t_remotevpn parent ffff: protocol all priority 1 u32 match ip dst {ifconfig_local_ip}/32 action pass',
        'sudo tc filter add dev t_remotevpn parent ffff: protocol all priority 2 u32 match u32 0 0 action mirred egress mirror dev t_vpp_remotevpn',
    ]

    for cmd in tc_cmd:
        rc = os.system(cmd)
        if rc:
            logger(f'Failed to create traffic control command. reverting')
            raise Exception(f'Failed to create traffic control command: {cmd}')

def remove_tc_commands(vpn_tun_is_up):
    try:
        tc_cmd = ['sudo tc qdisc del dev t_vpp_remotevpn handle ffff: ingress']

        # This function can be called from the revert of the "up" script.
        # In such a case, the t_remotevpn interface exists.
        # Hence, we need to remove the traffic control commands we applied to this interface.
        # If the script is called from the "down" script,
        # it means that the t_remotevpn interface is already closed,
        # and traffic control settings were removed from this interface automatically.
        # Hence, we don't need to remove the traffic control commands we applied to this interface.
        if vpn_tun_is_up:
            tc_cmd.append('sudo tc qdisc del dev t_remotevpn handle ffff: ingress')

        for cmd in tc_cmd:
            os.system(cmd)
    except:
        pass

def create_tun_in_vpp(ifconfig_local_ip, ifconfig_netmask):
    mask = IPAddress(ifconfig_netmask).netmask_bits()

    # configure the vpp interface
    tun_vpp_if_name = os.popen('sudo vppctl create tap host-if-name t_vpp_remotevpn tun').read().strip()
    if not tun_vpp_if_name:
        raise Exception('Cannot create tun device in vpp')

    logger(f'TUN created in vpp. vpp_if_name={tun_vpp_if_name}')

    # store the vpp_if_name in application db
    data = { 'tun_vpp_if_name': tun_vpp_if_name }
    with open(app_db_path, 'w') as f:
        json.dump(data, f)

    vpp_cmd = [
        f'sudo vppctl set interface ip address {tun_vpp_if_name} {ifconfig_local_ip}/{mask}',
        f'sudo vppctl set interface state {tun_vpp_if_name} up'
    ]

    for cmd in vpp_cmd:
        rc = os.system(cmd)
        if rc:
            raise Exception(f'Failed to run vppctl command: {cmd}')

def remove_tun_from_vpp():
    try:
        data = None
        with open(app_db_path, 'r') as json_file:
            data = json.load(json_file)
            tun_vpp_if_name = data.get('tun_vpp_if_name')
            if tun_vpp_if_name:
                os.system(f'sudo vppctl delete tap {tun_vpp_if_name}')
                logger(f'TUN removed from vpp. vpp_if_name={tun_vpp_if_name}')
                del data['tun_vpp_if_name']

        # update
        with open(app_db_path, 'w+') as json_file:
            json.dump(data, json_file)
    except:
        pass