


import httplib2 as http
import json
import xmltodict
import collections
import boto3
import re
import pexpect


## Instructions to run & pre-requisites for dCloud NAAS/NAAE demo
#  =============================================================
#
# ISE
# ---
# 1. Schedule dCloud demo for NAAS/NAAE
# 2. Enable ERS Service in ISE
# 3. Create ERSAdmin user with the appropriate credentials
# 4. Update Unknown->EmployeeSGT policy to PermitIP to ensure employee is able to connect to internet
#
# Environment
# -----------
# 1. Ensure Python libraries for this script are installed 
# 2. AWS CLI python package is installed 
# 3. "AWS-Configure" is executed for admin access to AWS
# 4. In script - Global parameters are updated: ISE IP, Switch IP, ISE Credentials, Switch Credentials
# 5. SSH key to switch is added to host-key list 
#


try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

# Global Variables 
base_uri = 'https://198.18.133.27:9060/ers/config'
auth_user = 'ersadmin'
auth_password = 'C1sco12345'

switch_ip = '198.19.10.1'
switch_user = 'admin'
switch_pass = 'C1sco12345'


ec2_resource = boto3.resource('ec2')
ec2_client = boto3.client('ec2')



def initialize():
	http_handler = http.Http(disable_ssl_certificate_validation=True)
	http_handler.add_credentials(auth_user, auth_password)
	return http_handler

def ssh_to_switch():
	SWITCH_PROMPT = '#'
	TERMINAL_PROMPT = '(?i)terminal type\?'
	TERMINAL_TYPE = 'vt100'
	SSH_NEWKEY = '(?i)are you sure you want to continue connecting'

	child = pexpect.spawn('ssh -l %s %s'%(switch_user, switch_ip))
	i = child.expect([pexpect.TIMEOUT, SSH_NEWKEY, SWITCH_PROMPT, '(?i)password'])

	if i == 0: # Timeout
		print('ERROR! could not login with SSH. Here is what SSH said:')
		print(child.before, child.after)
		print(str(child))
		sys.exit (1)
	if i == 1: # In this case SSH does not have the public key cached.
		child.sendline ('yes')
		child.expect ('(?i)password')
	if i == 2:
	# This may happen if a public key was setup to automatically login.
		pass
	if i == 3:
		child.sendline(switch_pass)
	# Now we are either at the command prompt or
	# the login process is asking for our terminal type.
		i = child.expect ([SWITCH_PROMPT, TERMINAL_PROMPT])
	if i == 1:
		child.sendline (TERMINAL_TYPE)
		child.expect (SWITCH_PROMPT)
	return child


def ise_sgt_version_get():
	path = '/sgt/versioninfo'
	target = urlparse(base_uri+path)
	method = 'GET'
	body = ''
	headers = {
    	'Accept': 'application/vnd.com.cisco.ise.trustsec.sgt.1.1+xml'
	}
	response, content = http_handler.request(target.geturl(), method, body, headers)
	if response['status'] != '200':
		print "Error in ise_sgt_version_get"
	doc = xmltodict.parse(content)
	return doc['ns3:versionInfo']['currentServerVersion']


def ise_ip_sgt_mapping_get_all():
	path = '/sgmapping'
	target = urlparse(base_uri+path)
	method = 'GET'
	body = ''
	headers = {
    	'Accept': 'application/vnd.com.cisco.ise.trustsec.sgmapping.1.0+xml'
	}	
	response, content = http_handler.request(target.geturl(), method, body, headers)
	return response, content

def ise_security_groups_get_all():
	path = '/sgt'
	target = urlparse(base_uri+path)
	method = 'GET'
	body = ''
	headers = {
    	'Accept': 'application/vnd.com.cisco.ise.trustsec.sgt.1.1+xml'
	}	
	response, content = http_handler.request(target.geturl(), method, body, headers)
	if response['status'] != '200':
		print "Error in ise_security_groups_get_all"
		pretty_print(response)
		pretty_print(content)
	doc = xmltodict.parse(content)
	return doc['ns3:searchResult']['resources']['resource']


def ise_security_groups_create(sgt_name, sgt_desc, sgt_number):
	path = '/sgt'
	target = urlparse(base_uri+path)
	method = 'POST'
	body = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ns4:sgt description="%s" name="%s" xmlns:ers="ers.ise.cisco.com" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:ns4="trustsec.ers.ise.cisco.com"><value>%d</value></ns4:sgt>' % (unicode(sgt_desc), unicode(sgt_name), sgt_number)
	headers = {
    	'Content-type': 'application/vnd.com.cisco.ise.trustsec.sgt.1.1+xml; charset=utf-8'
	}
	response, content = http_handler.request(target.geturl(), method, body, headers)	
	if response['status'] != '201':
		print "Error in ise_security_groups_create"
		pretty_print(response)
		pretty_print(content)
	else:
		print "Successfully created Group %s SGT %d Description %s in ISE"  % (sgt_name, sgt_number, sgt_desc)


def ise_get_sgt_id_by_name(sgt_name):
	list_groups = ise_security_groups_get_all()
	k = (item for item in list_groups if item["@name"] == sgt_name).next()
	return k['@id']


def ise_sxp_ip_sgt_bindings_get_by_id(id):
	path = '/sxplocalbindings/' + id
	target = urlparse(base_uri+path)
	method = 'GET'
	body = ''
	headers = {
    	'Accept': 'application/vnd.com.cisco.ise.sxp.sxplocalbindings.1.0+xml'
	}
	response, content = http_handler.request(target.geturl(), method, body, headers)
	doc = xmltodict.parse(content)
	return doc['ns4:sxplocalbindings']['bindingName'], doc['ns4:sxplocalbindings']['ipAddressOrHost']

def ise_sxp_ip_sgt_bindings_get_all():
	path = '/sxplocalbindings'
	target = urlparse(base_uri+path)
	method = 'GET'
	body = ''
	headers = {
    	'Accept': 'application/vnd.com.cisco.ise.sxp.sxplocalbindings.1.0+xml'
	}
	response, content = http_handler.request(target.geturl(), method, body, headers)
	if response['status'] != '200':
		print "Error in ise_sxp_ip_sgt_bindings_get_all"
	doc = xmltodict.parse(content)

	ip_sgt_list = []   # List of all IP-SGT Dicts

	for item in doc['ns3:searchResult']['resources']['resource']:
		ip_sgt_item = {}   # Dict for each item 
		ip_sgt_item['name'], ip_sgt_item['ip'] = ise_sxp_ip_sgt_bindings_get_by_id(item['@id'])
		ip_sgt_list.append(ip_sgt_item)

	return ip_sgt_list



def ise_sxp_ip_sgt_binding_create(description, bindingName, ipAddressOrHost, sgt_id, sxp_name):
	path = '/sxplocalbindings'
	target = urlparse(base_uri+path)
	method = 'POST'
	body = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ns4:sxplocalbindings description="des" xmlns:ers="ers.ise.cisco.com" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:ns4="sxp.ers.ise.cisco.com"><bindingName>bin</bindingName><ipAddressOrHost>10.10.10.1</ipAddressOrHost><sgt>10</sgt><sxpVpn>default</sxpVpn></ns4:sxplocalbindings>' 
	headers = {
    	'Accept': 'application/vnd.com.cisco.ise.sxp.sxplocalbindings.1.0+xml'
    	'Content-type': 'application/vnd.com.cisco.ise.sxp.sxplocalbindings.1.0+xml; charset=utf-8'
	}
	response, content = http_handler.request(target.geturl(), method, body, headers)
	pretty_print(response)
	pretty_print(content)


def ise_sgacl_get_all():
	path = '/sgacl'
	target = urlparse(base_uri+path)
	method = 'GET'
	body = ''
	headers = {
    	'Accept': 'application/vnd.com.cisco.ise.trustsec.sgacl.1.0+xml'
	}	
	response, content = http_handler.request(target.geturl(), method, body, headers)
	if response['status'] != '200':
		print "Error in ise_sgacl_get_all"
		pretty_print(response)
		pretty_print(content)
	doc = xmltodict.parse(content)
	return doc['ns3:searchResult']['resources']['resource']	


def switch_config_cts_ip_sgt_mappings(ssh_handler, mappings):
	SWITCH_PROMPT = '#'
	ssh_handler.sendline ('enable')
	ssh_handler.expect (SWITCH_PROMPT)
	ssh_handler.sendline ('conf t')
	ssh_handler.expect (SWITCH_PROMPT)
	print ('\nConfiguring IP-SGT Bindings on Switch')
	for i in mappings:
		cmd = "cts role-based sgt-map %s/32 sgt %d" % (i['ip'], i['sgt'])
		ssh_handler.sendline (cmd)
		ssh_handler.expect (SWITCH_PROMPT)
		print( "Done - IP: %s    SGT: %d") % (i['ip'], i['sgt']) 
#	print('exiting conf')
	ssh_handler.sendline ('exit')
	ssh_handler.expect (SWITCH_PROMPT)
#	print('writing')
	ssh_handler.sendline ('write')
	ssh_handler.expect (SWITCH_PROMPT)
#	print('refreshing env')
	ssh_handler.sendline ('cts refresh env')
	ssh_handler.expect (SWITCH_PROMPT)
#	print('refreshing policy')
	ssh_handler.sendline ('cts refresh policy')
	ssh_handler.expect (SWITCH_PROMPT)
#	print('exiting')
	ssh_handler.sendline ('exit')
	index = ssh_handler.expect([pexpect.EOF, 'closed.', '$'])


def aws_running_instances_get_all():
	# Check What Instances Are Running.
	aws_instances = ec2_resource.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
#	for i in instances:
#		print(i.id, i.public_ip_address, i.security_groups, i.vpc_id)
	return aws_instances


def aws_get_ip_group_mappings():
	aws_instances = aws_running_instances_get_all()
	ip_group_list = []
	for item in aws_instances:
		e = {}
		e['ip_addr'] = item.public_ip_address
		e['group'] = item.security_groups
		ip_group_list.append(e)
	return ip_group_list

def pretty_print(c):
	# assume that content is a json reply
	#data = json.loads(content)
	print(json.dumps(c, indent=4))




## Main module

http_handler = initialize()

## Get the version of current SGT groups in ISE
# ver = ise_sgt_version_get()
# print ('\nCurrent sgt version is ' + ver)

## List of current SGT Groups in ISE
# list_groups = ise_security_groups_get_all()
# print('\nListing Security Groups')
# for item in list_groups:
#	print(item['@id'] + ' - ' + item['@name'] + ' - ' + item['@description'] )


## Get all the ISE IP-SGT bindings 
# ip_sgt_list = ise_sxp_ip_sgt_bindings_get_all()
# print(ip_sgt_list)

## Create a new IP-SGT binding in ISE
# ise_sxp_ip_sgt_binding_create('DescSXPBin', 'NameSXP', '10.10.10.4/24', 10, 'default')


## Get all the current SGACLs in ISE
# list_sgacls = ise_sgacl_get_all()
# print('\nListing SGACLs')
# for item in list_sgacls:
#	print(item['@id'] + ' - ' + item['@name'] + ' - ' + item['@description'] )


## Get the current list of IP-Group mappings for instances in AWS
aws_ip_group_list = aws_get_ip_group_mappings()
print("\nList of AWS Instances")
for i in aws_ip_group_list:
	print( "IP: %s    GroupID: %s  GroupName: %s" ) % (i['ip_addr'], i['group'][0]['GroupId'], i['group'][0]['GroupName'])



## Create a Groups in ISE based on AWS discovered Groups, and the IP-SGT Mapping table
print('\nCreating SGT Groups in ISE')
ip_sgt_table = []   # IP-SGT Mapping table
sgt_id = 2000  # This is the starting SGT ID
pattern = re.compile(r"-")  ## ISE does not like "-" in SGT Names
for i in aws_ip_group_list:
	ip_sgt_table_item = {}
	sgt_name = "AWS_" + i['group'][0]['GroupName']
	sgt_desc = "AWS_" + i['group'][0]['GroupId']
	sgt_name = pattern.sub("_", sgt_name)  ## ISE does not like "-" in SGT Names
	ise_security_groups_create(sgt_name, sgt_desc, sgt_id)
	ip_sgt_table_item['ip'] = i['ip_addr']
	ip_sgt_table_item['sgt'] = sgt_id
	ip_sgt_table.append(ip_sgt_table_item)
	sgt_id = sgt_id + 1


print("\nNewly creating IP-SGT Mappings")
for i in ip_sgt_table:
	print( "IP: %s    SGT: %d") % (i['ip'], i['sgt']) 

ssh_handler = ssh_to_switch()
switch_config_cts_ip_sgt_mappings(ssh_handler, ip_sgt_table)    ## This i a hack since ISE APIs for IP-SGT in SXP were not functional

## Populate the IP-SGT Binding table in ISE for use in SXP -- ideally use this instead of Switch IP-SGT mappings




 




