#!/usr/bin/python

""" Configures new services and security rules to Palo Alto Firewall """

__author__ = 'apoorva.dornadula@berkeley.edu (Apoorva Dornadula)'

""" 
NOTE:
- command line arguments:
	- Palo Alto Firewall username
	- Palo Alto Firewall password
	- URL (ex: https://192.168.10.1/api/)
- reads services and security rules from a file called policy.xml 
  located in the same directory as this script
"""

import sys, urllib2, urllib
from xml.etree import ElementTree as etree


def updateFirewall(url="https://192.168.10.1/api/"):
	# Getting the username and password from the user
	username = sys.argv[1]
	password = sys.argv[2]
	if len(sys.argv) > 3:
		url = sys.argv[3]

	# Auth and getting key
	values = {"type":"keygen", "user":username, "password":password}

	data = urllib.urlencode(values)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	response_body = response.read()

	keyTree = etree.fromstring(response_body)
	key = keyTree.find(".//key").text	

	# reading the new policy file for appropriate code
	tree = etree.parse("policy.xml")

	services = tree.findall(".//devices/entry/vsys/entry/service")
	if len(services) > 0:
		servicesStr = etree.tostring(services[0], method="xml")
	else:
		servicesStr = ""
	security_rules = tree.find(".//devices/entry/vsys/entry/rulebase/security")
	if len(security_rules) > 0:
		security_rulesStr = etree.tostring(security_rules[0], method="xml")
	else:
		security_rulesStr = ""
	default_security_rules = tree.find(".//devices/entry/vsys/entry/rulebase/default-security-rules")
	if len(default_security_rules) > 0:
		default_security_rulesStr = etree.tostring(default_security_rules[0], method="xml")
	else:
		default_security_rulesStr = ""

	# adding services
	values1 = {"type":"config", "key":key, "action":"edit", "xpath":"/config/devices/entry/vsys/entry/service", "element":servicesStr}
	data1 = urllib.urlencode(values1)
	serviceResponse = urllib2.Request(url, data1)

	# adding the security rules
	values2 = {"type":"config", "key":key, "action":"edit", "xpath":"/config/devices/entry/vsys/entry/rulebase/security", "element":security_rulesStr}
	data2 = urllib.urlencode(values2)
	secRulesResonse = urllib2.Request(url, data2)

	# adding the default security rules
	values3 = {"type":"config", "key":key, "action":"edit", "xpath":"/config/devices/entry/vsys/entry/rulebase/default-security-rules", "element":default_security_rulesStr}
	data3 = urllib.urlencode(values3)
	secRulesResonse = urllib2.Request(url, data3)


updateFirewall()