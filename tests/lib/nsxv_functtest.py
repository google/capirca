# Copyright 2015 The Capirca Project Authors All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Functional test class for nsxv.py"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest
# system imports
import copy
from optparse import OptionParser
from xml.etree import ElementTree as ET

# compiler imports
from lib import naming
from lib import policy
from lib import nsxv
import nsxv_mocktest


class NsxvFunctionalTest(unittest.TestCase):
  """
  Reads the policy and the output has the xml formed correctly with the tags and values
  """

  def setUp(self):
    """Call before every test case
    """
    _parser = OptionParser()
    _parser.add_option('-d', '--def', dest='definitions',
                      help='definitions directory', default='../def')
    (FLAGS, args) = _parser.parse_args()
    self.defs = naming.Naming(FLAGS.definitions)

  def tearDown(self):
    pass

  def runTest(self):
    pass

  def test_nsxv_policy(self):
    pol = policy.ParsePolicy(nsxv_mocktest.POLICY, self.defs)
    exp_info = 2
    nsx = copy.deepcopy(pol)
    fw = nsxv.Nsxv(nsx, exp_info)
    output = str(fw)

    # parse the xml
    root = ET.fromstring(output)
     # check section name
    section_name = {'id': '1007', 'name': 'POLICY_NAME'}
    self.assertEqual(root.attrib, section_name)
    # check name and action
    self.assertEqual(root.find('./rule/name').text, 'reject-imap-requests')
    self.assertEqual(root.find('./rule/action').text, 'reject')

    #check IPV4 destination
    exp_destaddr = ['200.1.1.4/31']

    for destination in root.findall('./rule/destinations/destination'):
      self.assertEqual((destination.find('type').text), 'Ipv4Address')
      value = (destination.find('value').text)
      if value not in exp_destaddr:
        self.fail('IPv4Address destination not found in test_nsxv_str()')

    #check protocol
    protocol =  int(root.find('./rule/services/service/protocol').text)
    self.assertEqual(protocol, 6)

    # check destination port
    destination_port = root.find('./rule/services/service/destinationPort').text
    self.assertEqual(destination_port, '143')

  def test_nsxv_nosectiondid(self):
    pol = policy.ParsePolicy(nsxv_mocktest.POLICY_NO_SECTION_ID, self.defs)
    exp_info = 2
    nsx = copy.deepcopy(pol)
    fw = nsxv.Nsxv(nsx, exp_info)
    output = str(fw)
    # parse the xml
    root = ET.fromstring(output)
     # check section name
    section_name = {'name': 'POLICY_NO_SECTION_ID_NAME'}
    self.assertEqual(root.attrib, section_name)
    # check name and action
    self.assertEqual(root.find('./rule/name').text, 'accept-icmp')
    self.assertEqual(root.find('./rule/action').text, 'allow')

    #check protocol
    protocol =  int(root.find('./rule/services/service/protocol').text)
    self.assertEqual(protocol, 1)

  def test_nsxv_nofiltertype(self):
    def test_nofiltertype():
      pol = policy.ParsePolicy(nsxv_mocktest.POLICY_NO_FILTERTYPE, self.defs)
      exp_info = 2
      nsx = copy.deepcopy(pol)
      fw = nsxv.Nsxv(nsx, exp_info)
    self.assertRaises(nsxv.UnsupportedNsxvAccessListError, test_nofiltertype)

  def test_nsxv_incorrectfiltertype(self):
    def test_incorrectfiltertype():
      pol = policy.ParsePolicy(nsxv_mocktest.POLICY_INCORRECT_FILTERTYPE, self.defs)
      exp_info = 2
      nsx = copy.deepcopy(pol)
      fw = nsxv.Nsxv(nsx, exp_info)
    self.assertRaises(nsxv.UnsupportedNsxvAccessListError, test_incorrectfiltertype)

  def test_nsxv_optionkywd(self):
    def test_optionkywd():
      pol = policy.ParsePolicy(nsxv_mocktest.POLICY_OPTION_KYWD, self.defs)
      exp_info = 2
      nsx = copy.deepcopy(pol)
      fw = nsxv.Nsxv(nsx, exp_info)
      output = str(fw)
    self.assertRaises(nsxv.NsxvAclTermError, test_optionkywd)

  if __name__ == '__main__':
    unittest.main()
