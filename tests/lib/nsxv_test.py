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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

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
    target:: nsxv INET_FILTER_NAME inet
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

INET_FILTER_2 = """\
  header {
    comment:: "Sample inet NSXV filter"
    target:: nsxv INET_FILTER2_NAME inet
  }

  term allow-ntp-request {
    comment::"Allow ntp request"
    source-address:: NTP_SERVERS
    source-port:: NTP
    destination-address:: INTERNAL
    destination-port:: NTP
    protocol:: udp
    policer:: batman
    action:: accept
  }
  """

INET_FILTER_WITH_ESTABLISHED = """\
  header {
    comment:: "Sample inet NSXV filter"
    target:: nsxv INET_FILTER_WITH_ESTABLISHED_NAME inet
  }

  term allow-ntp-request {
    comment::"Allow ntp request"
    source-address:: NTP_SERVERS
    source-port:: NTP
    destination-address:: INTERNAL
    destination-port:: NTP
    protocol:: udp
    option:: tcp-established
    policer:: batman
    action:: accept
  }
  """
MIXED_HEADER = """\
  header {
    comment:: "Sample mixed NSXV filter"
    target:: nsxv MIXED_HEADER_NAME mixed
  }

"""

INET_HEADER = """\
  header {
    comment:: "Sample mixed NSXV filter"
    target:: nsxv INET_HEADER_NAME inet
  }

"""

MIXED_FILTER_INET_ONLY = MIXED_HEADER + INET_TERM

INET_FILTER_NO_SOURCE = INET_HEADER + INET_TERM

INET6_FILTER = """\
  header {
    comment:: "Sample inet6 NSXV filter"
    target:: nsxv INET6_FILTER_NAME inet6
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
    target:: nsxv MIXED_FILTER_NAME mixed
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
    target:: nsxv POLICY_NAME inet
  }

  term reject-imap-requests {
    destination-address:: MAIL_SERVERS
    destination-port:: IMAP
    protocol:: tcp
    action:: reject-with-tcp-rst
  }
  """

POLICY_WITH_SECURITY_GROUP = """\
  header {
    comment:: "Sample filter with Security Group"
    target:: nsxv POLICY_WITH_SECURITY_GROUP_NAME inet 1010 securitygroup \
    securitygroup-Id
  }

  term accept-icmp {
    protocol:: icmp
    action:: accept
  }
  """

HEADER_WITH_SECTIONID = """\
  header {
    comment:: "Sample NSXV filter1"
    target:: nsxv HEADER_WITH_SECTIONID_NAME inet 1009
  }
  """

HEADER_WITH_SECURITYGROUP = """\
  header {
    comment:: "Sample NSXV filter2"
    target:: nsxv HEADER_WITH_SECURITYGROUP_NAME inet6 securitygroup \
    securitygroup-Id1
  }
  """

BAD_HEADER = """\
  header {
    comment:: "Sample NSXV filter3"
    target:: nsxv BAD_HEADER_NAME inet 1011 securitygroup
  }
  """

BAD_HEADER_1 = """\
  header {
    comment:: "Sample NSXV filter4"
    target:: nsxv BAD_HEADER_1_NAME 1012
  }
  """

BAD_HEADER_2 = """\
  header {
    comment:: "Sample NSXV filter5"
    target:: nsxv BAD_HEADER_2_NAME inet securitygroup
  }
  """

BAD_HEADER_3 = """\
  header {
    comment:: "Sample NSXV filter6"
    target:: nsxv BAD_HEADER_3_NAME
  }
  """

BAD_HEADER_4 = """\
  header {
    comment:: "Sample NSXV filter7"
    target:: nsxv BAD_HEADER_3_NAME inet 1234 securitygroup securitygroup \
    securitygroupId1
  }
  """

TERM = """\
  term accept-icmp {
    protocol:: icmp
    action:: accept
  }
  """

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'expiration',
    'expiration',
    'icmp_type',
    'logging',
    'name',
    'protocol',
    'source_address',
    'source_address_exclude',
    'source_port',
    'option',
    'platform',
    'platform_exclude',
    'translated',
    'verbatim',
}

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny', 'reject', 'reject-with-tcp-rst'},
    'icmp_type': {
        'alternate-address',
        'certification-path-advertisement',
        'certification-path-solicitation',
        'conversion-error',
        'destination-unreachable',
        'echo-reply',
        'echo-request',
        'mobile-redirect',
        'home-agent-address-discovery-reply',
        'home-agent-address-discovery-request',
        'icmp-node-information-query',
        'icmp-node-information-response',
        'information-request',
        'inverse-neighbor-discovery-advertisement',
        'inverse-neighbor-discovery-solicitation',
        'mask-reply',
        'mask-request',
        'information-reply',
        'mobile-prefix-advertisement',
        'mobile-prefix-solicitation',
        'multicast-listener-done',
        'multicast-listener-query',
        'multicast-listener-report',
        'multicast-router-advertisement',
        'multicast-router-solicitation',
        'multicast-router-termination',
        'neighbor-advertisement',
        'neighbor-solicit',
        'packet-too-big',
        'parameter-problem',
        'redirect',
        'redirect-message',
        'router-advertisement',
        'router-renumbering',
        'router-solicit',
        'router-solicitation',
        'source-quench',
        'time-exceeded',
        'timestamp-reply',
        'timestamp-request',
        'unreachable',
        'version-2-multicast-listener-report',
    },
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2
_PLATFORM = 'nsxv'


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
    inet6_term = nsxv.Term(INET6_TERM, 'inet6', None, 6)
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
      nsxv_term = nsxv.Term(terms[0], filter_type, None, af)
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
    self.naming.GetNetAddr('NTP_SERVERS').AndReturn([nacaddr.IP('10.0.0.1'),
                                                     nacaddr.IP('10.0.0.2')])
    self.naming.GetNetAddr('INTERNAL').AndReturn([nacaddr.IP('10.0.0.0/8'),
                                                  nacaddr.IP('172.16.0.0/12'),
                                                  nacaddr.IP('192.168.0.0/16')])
    self.naming.GetServiceByProto.return_value = ['123']

    pol = policy.ParsePolicy(INET_FILTER, self.naming, False)
    translate_pol = nsxv.Nsxv(pol, EXP_INFO)
    nsxv_policies = translate_pol.nsxv_policies
    for (_, filter_name, filter_list, terms) in nsxv_policies:
      self.assertEqual(filter_name, 'inet')
      self.assertEqual(filter_list, ['inet'])
      self.assertEqual(len(terms), 1)

    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('NTP', 'udp')] * 2)

  def testTranslatePolicyMixedFilterInetOnly(self):
    """Test for Nsxv.test_TranslatePolicy. Testing Mixed filter with inet."""
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(MIXED_FILTER_INET_ONLY, self.naming, False)
    translate_pol = nsxv.Nsxv(pol, EXP_INFO)
    nsxv_policies = translate_pol.nsxv_policies
    for (_, filter_name, filter_list, terms) in nsxv_policies:
      self.assertEqual(filter_name, 'mixed')
      self.assertEqual(filter_list, ['mixed'])
      self.assertEqual(len(terms), 1)
      self.assertIn('10.0.0.0/8', str(terms[0]))

    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('MAIL_SERVICES', 'tcp')] * 1)

  def testTranslatePolicyMixedFilterInet6Only(self):
    """Test for Nsxv.test_TranslatePolicy. Testing Mixed filter with inet6."""
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2001:4860:4860::8844')]

    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(MIXED_FILTER_INET_ONLY, self.naming, False)
    translate_pol = nsxv.Nsxv(pol, EXP_INFO)
    nsxv_policies = translate_pol.nsxv_policies
    for (_, filter_name, filter_list, terms) in nsxv_policies:
      self.assertEqual(filter_name, 'mixed')
      self.assertEqual(filter_list, ['mixed'])
      self.assertEqual(len(terms), 1)
      self.assertIn('2001:4860:4860::8844', str(terms[0]))

    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('MAIL_SERVICES', 'tcp')] * 1)

  def testTranslatePolicyMixedFilterInetMixed(self):
    """Test for Nsxv.test_TranslatePolicy. Testing Mixed filter with mixed."""
    self.naming.GetNetAddr.return_value = [
        nacaddr.IP('2001:4860:4860::8844'),
        nacaddr.IP('10.0.0.0/8')
    ]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(MIXED_FILTER_INET_ONLY, self.naming, False)
    translate_pol = nsxv.Nsxv(pol, EXP_INFO)
    nsxv_policies = translate_pol.nsxv_policies
    for (_, filter_name, filter_list, terms) in nsxv_policies:
      self.assertEqual(filter_name, 'mixed')
      self.assertEqual(filter_list, ['mixed'])
      self.assertEqual(len(terms), 1)
      self.assertIn('2001:4860:4860::8844', str(terms[0]))
      self.assertIn('10.0.0.0/8', str(terms[0]))

    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('MAIL_SERVICES', 'tcp')] * 1)

  def testTranslatePolicyWithEstablished(self):
    """Test for Nsxv.test_TranslatePolicy."""
    # exp_info default is 2
    self.naming.GetNetAddr('NTP_SERVERS').AndReturn([nacaddr.IP('10.0.0.1'),
                                                     nacaddr.IP('10.0.0.2')])
    self.naming.GetNetAddr('INTERNAL').AndReturn([nacaddr.IP('10.0.0.0/8'),
                                                  nacaddr.IP('172.16.0.0/12'),
                                                  nacaddr.IP('192.168.0.0/16')])
    self.naming.GetServiceByProto.return_value = ['123']

    pol = policy.ParsePolicy(INET_FILTER_WITH_ESTABLISHED, self.naming, False)
    translate_pol = nsxv.Nsxv(pol, EXP_INFO)
    nsxv_policies = translate_pol.nsxv_policies
    for (_, filter_name, filter_list, terms) in nsxv_policies:
      self.assertEqual(filter_name, 'inet')
      self.assertEqual(filter_list, ['inet'])
      self.assertEqual(len(terms), 1)

      self.assertNotIn('<sourcePort>123</sourcePort><destinationPort>123',
                       str(terms[0]))

    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('NTP', 'udp')] * 2)

  def testNsxvStr(self):
    """Test for Nsxv._str_."""
    self.naming.GetNetAddr('GOOGLE_DNS').AndReturn([
        nacaddr.IP('8.8.4.4'),
        nacaddr.IP('8.8.8.8'),
        nacaddr.IP('2001:4860:4860::8844'),
        nacaddr.IP('2001:4860:4860::8888')])
    self.naming.GetServiceByProto.return_value = ['53']

    pol = policy.ParsePolicy(MIXED_FILTER, self.naming, False)
    target = nsxv.Nsxv(pol, EXP_INFO)

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
    section_name = {'name': 'MIXED_FILTER_NAME'}
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

  def testNsxvStrWithSecurityGroup(self):
    """Test for Nsxv._str_."""
    pol = policy.ParsePolicy(POLICY_WITH_SECURITY_GROUP, self.naming, False)
    target = nsxv.Nsxv(pol, EXP_INFO)

    # parse the output and seperate sections and comment
    section_tokens = str(target).split('<section')
    sections = []

    for sec in section_tokens:
      section = sec.replace('id=', '<section id=')
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
    section_name = {'id': '1010', 'name': 'POLICY_WITH_SECURITY_GROUP_NAME'}
    self.assertEqual(root.attrib, section_name)
    # check name and action
    self.assertEqual(root.find('./rule/name').text, 'accept-icmp')
    self.assertEqual(root.find('./rule/action').text, 'allow')

    # check protocol
    protocol = int(root.find('./rule/services/service/protocol').text)
    self.assertEqual(protocol, 1)

    # check appliedTo
    applied_to = root.find('./rule/appliedToList/appliedTo/value').text
    self.assertEqual(applied_to, 'securitygroup-Id')

  def testBuildTokens(self):
    self.naming.GetNetAddr('NTP_SERVERS').AndReturn([nacaddr.IP('10.0.0.1'),
                                                     nacaddr.IP('10.0.0.2')])
    self.naming.GetNetAddr('INTERNAL').AndReturn([nacaddr.IP('10.0.0.0/8'),
                                                  nacaddr.IP('172.16.0.0/12'),
                                                  nacaddr.IP('192.168.0.0/16')])
    self.naming.GetServiceByProto.return_value = ['123']
    pol1 = nsxv.Nsxv(policy.ParsePolicy(INET_FILTER, self.naming), 2)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    self.naming.GetNetAddr('NTP_SERVERS').AndReturn([nacaddr.IP('10.0.0.1'),
                                                     nacaddr.IP('10.0.0.2')])
    self.naming.GetNetAddr('INTERNAL').AndReturn([nacaddr.IP('10.0.0.0/8'),
                                                  nacaddr.IP('172.16.0.0/12'),
                                                  nacaddr.IP('192.168.0.0/16')])
    self.naming.GetServiceByProto.return_value = ['123']

    pol1 = nsxv.Nsxv(policy.ParsePolicy(INET_FILTER_2, self.naming), 2)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

  def testParseFilterOptionsCase1(self):
    pol = nsxv.Nsxv(policy.ParsePolicy(HEADER_WITH_SECTIONID + TERM,
                                       self.naming, False), EXP_INFO)
    for (header, _, _, _) in pol.nsxv_policies:
      filter_options = header.FilterOptions(_PLATFORM)
      pol._ParseFilterOptions(filter_options)
      self.assertEquals(nsxv.Nsxv._FILTER_OPTIONS_DICT['filter_type'], 'inet')
      self.assertEquals(nsxv.Nsxv._FILTER_OPTIONS_DICT['section_id'], '1009')
      self.assertEquals(nsxv.Nsxv._FILTER_OPTIONS_DICT['applied_to'], None)

  def testParseFilterOptionsCase2(self):
    pol = nsxv.Nsxv(policy.ParsePolicy(HEADER_WITH_SECURITYGROUP + INET6_TERM,
                                       self.naming, False), EXP_INFO)
    for (header, _, _, _) in pol.nsxv_policies:
      filter_options = header.FilterOptions(_PLATFORM)
      pol._ParseFilterOptions(filter_options)
      self.assertEquals(nsxv.Nsxv._FILTER_OPTIONS_DICT['filter_type'], 'inet6')
      self.assertEquals(nsxv.Nsxv._FILTER_OPTIONS_DICT['section_id'], 0)
      self.assertEquals(nsxv.Nsxv._FILTER_OPTIONS_DICT['applied_to'],
                        'securitygroup-Id1')

  def testBadHeaderCase(self):
    pol = policy.ParsePolicy(BAD_HEADER + INET6_TERM, self.naming, False)
    self.assertRaises(nsxv.UnsupportedNsxvAccessListError,
                      nsxv.Nsxv, pol, EXP_INFO)

  def testBadHeaderCase1(self):
    pol = policy.ParsePolicy(BAD_HEADER_1 + TERM, self.naming, False)
    self.assertRaises(nsxv.UnsupportedNsxvAccessListError,
                      nsxv.Nsxv, pol, EXP_INFO)

  def testBadHeaderCase2(self):
    pol = policy.ParsePolicy(BAD_HEADER_2 + INET6_TERM, self.naming, False)
    self.assertRaises(nsxv.UnsupportedNsxvAccessListError,
                      nsxv.Nsxv, pol, EXP_INFO)

  def testBadHeaderCase3(self):
    pol = policy.ParsePolicy(BAD_HEADER_3 + INET6_TERM, self.naming, False)
    self.assertRaises(nsxv.UnsupportedNsxvAccessListError,
                      nsxv.Nsxv, pol, EXP_INFO)

  def testBadHeaderCase4(self):
    pol = policy.ParsePolicy(BAD_HEADER_4 + INET6_TERM, self.naming, False)
    self.assertRaises(nsxv.UnsupportedNsxvAccessListError,
                      nsxv.Nsxv, pol, EXP_INFO)


if __name__ == '__main__':
  unittest.main()
