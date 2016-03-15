#!/usr/bin/python

""" Configures new services and security rules to Palo Alto Firewall """

__author__ = 'apoorva.dornadula@berkeley.edu (Apoorva Dornadula)'

""" 
NOTE:
- command line arguments:
	- Policy File (ex: policy.pol)
	- URL (ex: https://192.168.10.1/api/)
- reads services and security rules from a file called policy.xml 
  located in the same directory as this script
"""

import sys, urllib2, urllib
from xml.etree import ElementTree as etree


def updateFirewall(url="https://192.168.10.1/api/"):
	# Checking command line arguments
	if len(sys.argv) < 2:
		print("You must enter the name of your policy file as a command line argument")
		return	

	# Getting the username and password from the user
	username = raw_input("Enter username: ")
	password = raw_input("Enter password: ")
	
	if len(sys.argv) == 2:
		polFile = sys.argv[1]
	elif len(sys.argv) == 3:
		polFile = sys.argv[1]
		url = sys.argv[2]
	
	# Auth and getting key
	values = {"type":"keygen", "user":username, "password":password}

	data = urllib.urlencode(values)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	response_body = response.read()

	keyTree = etree.fromstring(response_body)
	key = keyTree.find(".//key").text	

	# reading the new policy file for appropriate code
	tree = etree.parse(polFile)

	services = tree.find(".//devices/entry/vsys/entry/service")
	if services is not None:
		servicesStr = etree.tostring(services, method="xml")
	else:
		servicesStr = None
	security_rules = tree.find(".//devices/entry/vsys/entry/rulebase/security")
	if security_rules is not None:
		security_rulesStr = etree.tostring(security_rules, method="xml")
	else:
		security_rulesStr = None

	# adding services
	if servicesStr is not None:
		values = {"type":"config", "key":key, "action":"edit", "xpath":"/config/devices/entry/vsys/entry/service", "element":servicesStr}
		data = urllib.urlencode(values)
		req = urllib2.Request(url, data)
		serviceResponse = urllib2.urlopen(req)

	# adding the security rules
	if security_rulesStr is not None:
		values = {"type":"config", "key":key, "action":"edit", "xpath":"/config/devices/entry/vsys/entry/rulebase/security", "element":security_rulesStr}
		data = urllib.urlencode(values)
		req = urllib2.Request(url, data)
		secRulesResponse = urllib2.urlopen(req)

updateFirewall()
