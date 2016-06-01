# Copyright 2016 Google Inc. All Rights Reserved.
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
"""UnitTest class for nsxv.py."""

import unittest
from xml.etree import ElementTree as ET

from lib import nacaddr
from lib import naming
from lib import nsxv
from lib import policy
import mock


INET_TERM = """\
  term permit-mail-services {
    destination-address:: MAIL_SERVERS
    protocol:: tcp
    destination-port:: MAIL_SERVICES
    action:: accept
  }
  """

INET6_TERM = """\
  term test-icmpv6 {
    protocol:: icmpv6
    icmp-type:: echo-request echo-reply
    action:: accept
  }
  """

INET_FILTER = """\
  header {
    comment:: "Sample inet NSXV filter"
    target:: nsxv inet
  }

  term allow-ntp-request {
    comment::"Allow ntp request"
    source-address:: NTP_SERVERS
    source-port:: NTP
    destination-address:: INTERNAL
    destination-port:: NTP
    protocol:: udp
    action:: accept
  }
  """

INET6_FILTER = """\
  header {
    comment:: "Sample inet6 NSXV filter"
    target:: nsxv inet6
  }

  term test-icmpv6 {
    #destination-address:: WEB_SERVERS
    protocol:: icmpv6
    icmp-type:: echo-request echo-reply
    action:: accept
  }
  """

MIXED_FILTER = """\
  header {
    comment:: "Sample mixed NSXV filter"
    target:: nsxv mixed
  }

  term accept-to-honestdns {
    comment:: "Allow name resolution using honestdns."
    destination-address:: GOOGLE_DNS
    destination-port:: DNS
    protocol:: udp
    action:: accept
  }
  """

POLICY = """\
  header {
    comment:: "Sample NSXV filter"
    target:: nsxv inet
  }

  term reject-imap-requests {
    destination-address:: MAIL_SERVERS
    destination-port:: IMAP
    protocol:: tcp
    action:: reject-with-tcp-rst
  }
  """

POLICY_NO_ACTION = """\
  header {
    comment:: "Sample NSXV filter"
    target:: nsxv inet
  }
  term accept-icmp {
    protocol:: icmp
  }
  """


class TermTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testInitForinet(self):
    """Test for Term._init_."""
    inet_term = nsxv.Term(INET_TERM, 'inet')
    self.assertEqual(inet_term.af, 4)
    self.assertEqual(inet_term.filter_type, 'inet')

  def testInitForinet6(self):
    """Test for Term._init_."""
    inet6_term = nsxv.Term(INET6_TERM, 'inet6', 6)
    self.assertEqual(inet6_term.af, 6)
    self.assertEqual(inet6_term.filter_type, 'inet6')

  def testServiceToStr(self):
    """Test for Term._ServiceToStr."""

    proto = 6
    icmp_types = []
    dports = [(1024, 65535)]
    spots = [(123, 123)]
    nsxv_term = nsxv.Term(INET_TERM, 'inet')
    service = nsxv_term._ServiceToString(proto, spots, dports, icmp_types)
    self.assertEquals(service, '<service><protocol>6</protocol><sourcePort>'
                      '123</sourcePort><destinationPort>1024-65535'
                      '</destinationPort></service>')

  def testStrForinet(self):
    """Test for Term._str_."""
    self.naming.GetNetAddr('NTP_SERVERS').AndReturn([nacaddr.IP('10.0.0.1'),
                                                     nacaddr.IP('10.0.0.2')])
    self.naming.GetNetAddr('INTERNAL').AndReturn([nacaddr.IP('10.0.0.0/8'),
                                                  nacaddr.IP('172.16.0.0/12'),
                                                  nacaddr.IP('192.168.0.0/16')])
    self.naming.GetServiceByProto.return_value = ['123']

    pol = policy.ParsePolicy(INET_FILTER, self.naming, False)
    af = 4
    for _, terms in pol.filters:
      nsxv_term = nsxv.Term(terms[0], af)
      rule_str = nsxv.Term.__str__(nsxv_term)
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

    self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('NTP', 'udp')] * 2)

  def testStrForinet6(self):
    """Test for Term._str_."""
    pol = policy.ParsePolicy(INET6_FILTER, self.naming, False)
    af = 6
    filter_type = 'inet6'
    for _, terms in pol.filters:
      nsxv_term = nsxv.Term(terms[0], filter_type, af)
      rule_str = nsxv.Term.__str__(nsxv_term)

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

  def testTranslatePolicy(self):
    """Test for Nsxv.test_TranslatePolicy."""
    # exp_info default is 2
    self.naming.GetNetAddr('NTP_SERVERS').AndReturn([nacaddr.IP('10.0.0.1'),
                                                     nacaddr.IP('10.0.0.2')])
    self.naming.GetNetAddr('INTERNAL').AndReturn([nacaddr.IP('10.0.0.0/8'),
                                                  nacaddr.IP('172.16.0.0/12'),
                                                  nacaddr.IP('192.168.0.0/16')])
    self.naming.GetServiceByProto.return_value = ['123']

    exp_info = 2
    pol = policy.ParsePolicy(INET_FILTER, self.naming, False)
    translate_pol = nsxv.Nsxv(pol, exp_info)
    nsxv_policies = translate_pol.nsxv_policies
    for (_, filter_name, filter_list, terms) in nsxv_policies:
      self.assertEqual(filter_name, 'inet')
      self.assertEqual(filter_list, ['inet'])
      self.assertEqual(len(terms), 1)

    self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('NTP', 'udp')] * 2)

  def testNsxvStr(self):
    """Test for Nsxv._str_."""
    # exp_info default is 2
    self.naming.GetNetAddr('GOOGLE_DNS').AndReturn([
        nacaddr.IP('8.8.4.4'),
        nacaddr.IP('8.8.8.8'),
        nacaddr.IP('2001:4860:4860::8844'),
        nacaddr.IP('2001:4860:4860::8888')])
    self.naming.GetServiceByProto.return_value = ['53']

    exp_info = 2
    pol = policy.ParsePolicy(MIXED_FILTER, self.naming, False)
    target = nsxv.Nsxv(pol, exp_info)

    # parse the output and seperate sections and comment
    section_tokens = str(target).split('<section')
    sections = []

    for sec in section_tokens:
      section = sec.replace('name=', '<section name=')
      sections.append(section)
    # parse the xml
    # Checking comment tag
    comment = sections[0]
    if 'Id' not in comment:
      self.fail('Id missing in xml comment in test_nsxv_str()')
    if 'Date' not in comment:
      self.fail('Date missing in xml comment in test_nsxv_str()')
    if 'Revision' not in comment:
      self.fail('Revision missing in xml comment in test_nsxv_str()')

    root = ET.fromstring(sections[1])
    # check section name
    section_name = {'name': 'Sample mixed NSXV filter'}
    self.assertEqual(root.attrib, section_name)
    # check name and action
    self.assertEqual(root.find('./rule/name').text, 'accept-to-honestdns')
    self.assertEqual(root.find('./rule/action').text, 'allow')

    # check IPV4 and IPV6 destinations
    exp_ipv4dest = ['8.8.4.4', '8.8.8.8']
    exp_ipv6dest = ['2001:4860:4860::8844', '2001:4860:4860::8888']

    for destination in root.findall('./rule/destinations/destination'):
      addr_type = destination.find('type').text
      value = (destination.find('value').text)

      if 'Ipv4Address' in addr_type:
        if value not in exp_ipv4dest:
          self.fail('IPv4Address not found in test_nsxv_str()')
      else:
        if value not in exp_ipv6dest:
          self.fail('IPv6Address not found in test_nsxv_str()')

    # check protocol
    protocol = int(root.find('./rule/services/service/protocol').text)
    self.assertEqual(protocol, 17)

    # check destination port
    destination_port = root.find('./rule/services/service/destinationPort').text
    self.assertEqual(destination_port, '53')

    # check notes
    notes = root.find('./rule/notes').text
    self.assertEqual(notes, 'Allow name resolution using honestdns.')

    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'udp')


if __name__ == '__main__':
  unittest.main()
