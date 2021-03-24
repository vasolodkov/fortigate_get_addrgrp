#!/usr/bin/env python3

#
# 'ssh_user': 'user'
# 'ssh_password': 'password'
# 'addr_group': 'bad_sites'
# 'source_forti': '10.10.10.1'
# 'dest_forti': '10.10.10.2'
#

import sys
import ipaddress
from netmiko import ConnectHandler
import ruamel.yaml as yaml

def generate_devices(device_ips, device_type):
    devices = [{'device_type': device_type,
                'ip': device,
                'username': ssh_user,
                'password': ssh_pass} for device in device_ips]
    return devices

with open('config.yaml') as stream:
    try:
        config = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        print(exc)

ssh_user = config['ssh_user']
ssh_pass = config['ssh_pass']
addr_group = contig['addr_group']
source_forti = contig['source_forti']
dest_forti = config['dest_forti']

source = generate_devices(source_forti, 'fortinet')
dest = generate_devices(dest_forti, 'fortinet')

conf = []
members = []
# get address and address group
for device in source:
	try:
		src_connect = ConnectHandler(**device)
		grp = src_connect.send_command(f'show firewall addrgrp {addr_group}')
		grp = grp.split('\n')[-4].split()[2::]
		for addr in grp:
			i = addr.strip('"')
			obj = src_connect.send_command(f'show firewall address {i}')
			a = obj.split('\n')
			a.pop(2)
			conf.append(a)
			members.append(a[1].split()[1])
		src_connect.disconnect()
    except Exception e:
		print(e)
		print(f"check {device['ip']}")
		pass

members_str = ' '.join(members)
grp_command = f'''config firewall addrgrp
edit "{addr_group}"
set member {members_str}
next
end
'''

# upload config
for device in dest:
	try:
		dst_connect = ConnectHandler(**device)
		for object in conf:
			for line in object:
				dst_addr = dst_connect.send_config_set(line)
				print(dst_addr)
		dst_grp = dst_connect.send_command(grp_command, cmd_verify=False)
		print(dst_grp)
		dst_connect.disconnect()
	except Exception as e:
		print(e)
		print(f"check {device['ip']}")
		pass
