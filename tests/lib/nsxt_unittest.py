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
"""UnitTest class for nsxt.py."""

import optparse
from absl.testing import absltest
from xml.etree import ElementTree as ET

from capirca.lib import naming
from capirca.lib import nsxt
from capirca.lib import policy
from capirca.tests.lib import nsxt_mocktest


class TermTest(absltest.TestCase):

  def setUp(self):
    """Call before every test case."""
    super().setUp()
    parser = optparse.OptionParser()
    parser.add_option(
        '-d',
        '--def',
        dest='definitions',
        help='definitions directory',
        default='../def')
    (FLAGS, args) = parser.parse_args()
    self.defs = naming.Naming(FLAGS.definitions)

  def tearDown(self):
    super().setUp()
    pass

  def runTest(self):
    pass

  def test_init_forinet(self):
    """Test for Term._init_."""
    inet_term = nsxt.Term(nsxt_mocktest.INET_TERM, 'inet')
    self.assertEqual(inet_term.af, 4)
    self.assertEqual(inet_term.filter_type, 'inet')

  def test_init_forinet6(self):
    """Test for Term._init_."""
    inet6_term = nsxt.Term(nsxt_mocktest.INET6_TERM, 'inet6', 6)
    self.assertEqual(inet6_term.af, 6)
    self.assertEqual(inet6_term.filter_type, 'inet6')

  def test_ServiceToStr(self):
    """Test for Term._ServiceToStr."""

    proto = 6
    icmp_types = []
    dports = [(1024, 65535)]
    spots = [(123, 123)]
    nsxt_term = nsxt.Term(nsxt_mocktest.INET_TERM, 'inet')
    service = nsxt_term._ServiceToString(proto, spots, dports, icmp_types)
    self.assertEqual(
        service, '<service><protocol>6</protocol><sourcePort>123'
        '</sourcePort><destinationPort>1024-65535'
        '</destinationPort></service>')

  def test_str_forinet(self):
    """Test for Term._str_."""
    pol = policy.ParsePolicy(nsxt_mocktest.INET_FILTER, self.defs, False)
    af = 4
    for _, terms in pol.filters:
      nsxt_term = nsxt.Term(terms[0], af)
      rule_str = nsxt.Term.__str__(nsxt_term)
    # parse xml rule and check if the values are correct
    root = ET.fromstring(rule_str)
    # check name and action
    self.assertEqual(root.find('name').text, 'allow-ntp-request')
    self.assertEqual(root.find('action').text, 'allow')

    # check source address
    exp_sourceaddr = ['10.0.0.1', '10.0.0.2']
    for destination in root.findall('./sources/source'):
      self.assertEqual((destination.find('type').text), 'Ipv4Address')
      value = (destination.find('value').text)
      if value not in exp_sourceaddr:
        self.fail('IPv4Address source address not found in test_str_forinet()')

    # check destination address
    exp_destaddr = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
    for destination in root.findall('./destinations/destination'):
      self.assertEqual((destination.find('type').text), 'Ipv4Address')
      value = (destination.find('value').text)
      if value not in exp_destaddr:
        self.fail('IPv4Address destination not found in test_str_forinet()')

    # check protocol
    protocol = int(root.find('./services/service/protocol').text)
    self.assertEqual(protocol, 17)

    # check source port
    source_port = root.find('./services/service/sourcePort').text
    self.assertEqual(source_port, '123')

    # check destination port
    destination_port = root.find('./services/service/destinationPort').text
    self.assertEqual(destination_port, '123')

    # check notes
    notes = root.find('notes').text
    self.assertEqual(notes, 'Allow ntp request')

  def test_str_forinet6(self):
    """Test for Term._str_."""
    pol = policy.ParsePolicy(nsxt_mocktest.INET6_FILTER, self.defs, False)
    af = 6
    filter_type = 'inet6'
    for _, terms in pol.filters:
      nsxt_term = nsxt.Term(terms[0], filter_type, af)
      rule_str = nsxt.Term.__str__(nsxt_term)

    # parse xml rule and check if the values are correct
    root = ET.fromstring(rule_str)
    # check name and action
    self.assertEqual(root.find('name').text, 'test-icmpv6')
    self.assertEqual(root.find('action').text, 'allow')

    # check protocol and sub protocol
    exp_subprotocol = [128, 129]
    for service in root.findall('./services/service'):
      protocol = int(service.find('protocol').text)
      self.assertEqual(protocol, 58)

      sub_protocol = int(service.find('subProtocol').text)
      if sub_protocol not in exp_subprotocol:
        self.fail('subProtocol not matched in test_str_forinet6()')

  def test_TranslatePolicy(self):
    """Test for Nsxt.test_TranslatePolicy."""
    # exp_info default is 2
    exp_info = 2
    pol = policy.ParsePolicy(nsxt_mocktest.INET_FILTER, self.defs, False)
    translate_pol = nsxt.Nsxt(pol, exp_info)
    nsxt_policies = translate_pol.nsxt_policies
    for (_, filter_name, filter_list, terms) in nsxt_policies:
      self.assertEqual(filter_name, 'inet')
      self.assertEqual(filter_list, ['inet'])
      self.assertEqual(len(terms), 1)

  def test_nsxt_str(self):
    """Test for Nsxt._str_."""
    # exp_info default is 2
    exp_info = 2
    pol = policy.ParsePolicy(nsxt_mocktest.MIXED_FILTER, self.defs, False)
    target = nsxt.Nsxt(pol, exp_info)

    # parse the xml and check the values
    root = ET.fromstring(str(target))
    # check section name
    section_name = {'id': '1009', 'name': 'MIXED_FILTER_NAME'}
    self.assertEqual(root.attrib, section_name)
    # check name and action
    self.assertEqual(root.find('./rule/name').text, 'accept-to-honestdns')
    self.assertEqual(root.find('./rule/action').text, 'allow')

    # check IPV4 and IPV6 destinations
    exp_ipv4dest = ['8.8.4.4', '8.8.8.8']
    exp_ipv6dest = ['2001:4860:4860::8844', '2001:4860:4860::8888']

    for destination in root.findall('./rule/destinations/destination'):
      obj_type = destination.find('type').text
      value = (destination.find('value').text)

      if 'Ipv4Address' in obj_type:
        if value not in exp_ipv4dest:
          self.fail('IPv4Address not found in test_nsxt_str()')
      else:
        if value not in exp_ipv6dest:
          self.fail('IPv6Address not found in test_nsxt_str()')

    # check protocol
    protocol = int(root.find('./rule/services/service/protocol').text)
    self.assertEqual(protocol, 17)

    # check destination port
    destination_port = root.find('./rule/services/service/destinationPort').text
    self.assertEqual(destination_port, '53')

    # check notes
    notes = root.find('./rule/notes').text
    self.assertEqual(notes, 'Allow name resolution using honestdns.')

  if __name__ == '__main__':
    absltest.main()
