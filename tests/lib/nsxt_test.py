# Copyright 2023 The Capirca Project Authors All Rights Reserved.
# Copyright 2023 VMware, Inc. SPDX-License-Identifier: Apache-2.0
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
"""UnitTest class for nsxt.py."""

import json
from absl.testing import absltest
from unittest import mock

from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import nsxt
from capirca.lib import policy

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
    comment:: "Sample inet NSXT filter"
    target:: nsxt INET_FILTER_NAME inet
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
    comment:: "Sample inet NSXT filter"
    target:: nsxt INET_FILTER2_NAME inet
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
    comment:: "Sample inet NSXT filter"
    target:: nsxt INET_FILTER_WITH_ESTABLISHED_NAME inet
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
    comment:: "Sample mixed NSXT filter"
    target:: nsxt MIXED_HEADER_NAME mixed
  }

"""

INET_HEADER = """\
  header {
    comment:: "Sample mixed NSXT filter"
    target:: nsxt INET_HEADER_NAME inet
  }

"""

MIXED_FILTER_INET_ONLY = MIXED_HEADER + INET_TERM

INET_FILTER_NO_SOURCE = INET_HEADER + INET_TERM

INET6_FILTER = """\
  header {
    comment:: "Sample inet6 NSXT filter"
    target:: nsxt INET6_FILTER_NAME inet6
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
    comment:: "Sample mixed NSXT filter"
    target:: nsxt MIXED_FILTER_NAME mixed
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
    comment:: "Sample NSXT filter"
    target:: nsxt POLICY_NAME inet
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
    target:: nsxt POLICY_WITH_SECURITY_GROUP_NAME inet 1010 securitygroup \
    securitygroup-Id
  }

  term accept-icmp {
    protocol:: icmp
    action:: accept
  }
  """

HEADER_WITH_SECTIONID = """\
  header {
    comment:: "Sample NSXT filter1"
    target:: nsxt HEADER_WITH_SECTIONID_NAME inet 1009
  }
  """

HEADER_WITH_SECURITYGROUP = """\
  header {
    comment:: "Sample NSXT filter2"
    target:: nsxt HEADER_WITH_SECURITYGROUP_NAME inet6 securitygroup \
    securitygroup-Id1
  }
  """

BAD_HEADER = """\
  header {
    comment:: "Sample NSXT filter3"
    target:: nsxt BAD_HEADER_NAME inet 1011 securitygroup
  }
  """

BAD_HEADER_1 = """\
  header {
    comment:: "Sample NSXT filter4"
    target:: nsxt BAD_HEADER_1_NAME 1012
  }
  """

BAD_HEADER_2 = """\
  header {
    comment:: "Sample NSXT filter5"
    target:: nsxt BAD_HEADER_2_NAME inet securitygroup
  }
  """

BAD_HEADER_3 = """\
  header {
    comment:: "Sample NSXT filter6"
    target:: nsxt BAD_HEADER_3_NAME
  }
  """

BAD_HEADER_4 = """\
  header {
    comment:: "Sample NSXT filter7"
    target:: nsxt BAD_HEADER_3_NAME inet 1234 securitygroup securitygroup \
    securitygroupId1
  }
  """

TERM = """\
  term accept-icmp {
    protocol:: icmp
    action:: accept
  }
  """

MIXED_TO_V4 = """\
  term mixed_to_v4 {
    source-address:: GOOGLE_DNS
    destination-address:: INTERNAL
    protocol:: tcp udp
    action:: accept
  }
  """

V4_TO_MIXED = """\
  term v4_to_mixed {
    source-address:: INTERNAL
    destination-address:: GOOGLE_DNS
    protocol:: tcp udp
    action:: accept
  }
  """

MIXED_TO_V6 = """\
  term mixed_to_v6 {
    source-address:: GOOGLE_DNS
    destination-address:: SOME_HOST
    action:: accept
  }
  """

V6_TO_MIXED = """\
  term v6_to_mixed {
    source-address:: SOME_HOST
    destination-address:: GOOGLE_DNS
    action:: accept
  }
  """

MIXED_TO_MIXED = """\
  term mixed_to_mixed {
    source-address:: GOOGLE_DNS
    destination-address:: GOOGLE_DNS
    action:: accept
  }
  """

MIXED_TO_ANY = """\
  term mixed_to_any {
    source-address:: GOOGLE_DNS
    action:: accept
  }
  """

ANY_TO_MIXED = """\
  term any_to_mixed {
    destination-address:: GOOGLE_DNS
    action:: accept
  }
  """

V4_TO_V4 = """\
  term v4_to_v4 {
    source-address:: NTP_SERVERS
    destination-address:: INTERNAL
    action:: accept
  }
  """

V6_TO_V6 = """\
  term v6_to_v6 {
    source-address:: SOME_HOST
    destination-address:: SOME_HOST
    action:: accept
  }
  """

V4_TO_V6 = """\
  term v4_to_v6 {
    source-address:: INTERNAL
    destination-address:: SOME_HOST
    action:: accept
  }
  """

V6_TO_V4 = """\
  term v6_to_v4 {
    source-address:: SOME_HOST
    destination-address:: INTERNAL
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
    'stateless_reply',
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
    'action': {'next', 'accept', 'deny', 'reject', 'reject-with-tcp-rst'},
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
    'option': {'first-fragment', 'established', 'tcp-established', 'initial', 'sample', 'rst', 'is-fragment'}
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2
_PLATFORM = 'nsxt'


class TermTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def testInitForinet(self):
    """Test for Term._init_."""
    inet_term = nsxt.Term(INET_TERM, 'inet')
    self.assertEqual(inet_term.af, 4)
    self.assertEqual(inet_term.filter_type, 'inet')

  def testInitForinet6(self):
    """Test for Term._init_."""
    inet6_term = nsxt.Term(INET6_TERM, 'inet6', None, 6)
    self.assertEqual(inet6_term.af, 6)
    self.assertEqual(inet6_term.filter_type, 'inet6')

  def testStrForinet(self):
    """Test for Term._str_."""
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('10.0.0.1'), nacaddr.IP('10.0.0.2')],
        [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('172.16.0.0/12'),
         nacaddr.IP('192.168.0.0/16')]]
    self.naming.GetServiceByProto.return_value = ['123']

    pol = policy.ParsePolicy(INET_FILTER, self.naming, False)
    af = 4
    for _, terms in pol.filters:
      nsxt_term = nsxt.Term(terms[0], af)
      rule_str = nsxt.Term.__str__(nsxt_term)
    # parse xml rule and check if the values are correct
    rule = json.loads(rule_str)
    # check name and action
    self.assertEqual(rule["display_name"], 'allow-ntp-request')
    self.assertEqual(rule["action"][0], 'accept')

    # check source address
    exp_sourceaddr = ['10.0.0.1/32', '10.0.0.2/32']
    source_address = rule["source_groups"]
    self.assertNotEqual(len(source_address), 0)
    for source in source_address:
      if source not in exp_sourceaddr:
        self.fail('IPv4Address source address not found in test_str_forinet()')

    # check destination address
    exp_destaddr = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
    destination_address = rule["destination_groups"]
    self.assertNotEqual(len(destination_address), 0)
    for destination in destination_address:
      if destination not in exp_destaddr:
        self.fail('IPv4Address destination not found in test_str_forinet()')

    # check protocol
    protocol = rule["ip_protocol"]
    self.assertEqual(protocol, '')

    # check notes
    notes = rule["notes"]
    self.assertEqual(notes[0], 'Allow ntp request')

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('NTP_SERVERS'), mock.call('INTERNAL')])
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('NTP', 'udp')] * 2)

  def testStrForinet6(self):
    """Test for Term._str_."""
    pol = policy.ParsePolicy(INET6_FILTER, self.naming, False)
    af = 6
    filter_type = 'inet6'
    for _, terms in pol.filters:
      nsxt_term = nsxt.Term(terms[0], filter_type, None, af)
      rule_str = nsxt.Term.__str__(nsxt_term)

    # parse xml rule and check if the values are correct
    rule = json.loads(rule_str)
    # check name and action
    self.assertEqual(rule["display_name"], 'test-icmpv6')
    self.assertEqual(rule["action"][0], 'accept')

    # check protocol and sub protocol
    protocol = rule["ip_protocol"]
    self.assertEqual(protocol, '')

  def testTranslatePolicy(self):
    """Test for Nsxt.test_TranslatePolicy."""
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('10.0.0.1'), nacaddr.IP('10.0.0.2')],
        [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('172.16.0.0/12'),
         nacaddr.IP('192.168.0.0/16')]]
    self.naming.GetServiceByProto.return_value = ['123']

    pol = policy.ParsePolicy(INET_FILTER, self.naming, False)
    translate_pol = nsxt.Nsxt(pol, EXP_INFO)
    nsxt_policies = translate_pol.nsxt_policies
    for (_, filter_name, filter_list, terms) in nsxt_policies:
      self.assertEqual(filter_name, 'inet')
      self.assertEqual(filter_list, [''])
      self.assertEqual(len(terms), 1)

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('NTP_SERVERS'), mock.call('INTERNAL')])
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('NTP', 'udp')] * 2)

  def testTranslatePolicyMixedFilterInetOnly(self):
    """Test for Nsxt.test_TranslatePolicy. Testing Mixed filter with inet."""
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(MIXED_FILTER_INET_ONLY, self.naming, False)
    translate_pol = nsxt.Nsxt(pol, EXP_INFO)
    nsxt_policies = translate_pol.nsxt_policies
    for (_, filter_name, filter_list, terms) in nsxt_policies:
      self.assertEqual(filter_name, 'mixed')
      self.assertEqual(filter_list, [''])
      self.assertEqual(len(terms), 1)
      self.assertIn('10.0.0.0/8', str(terms[0]))

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('MAIL_SERVERS')])
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('MAIL_SERVICES', 'tcp')] * 1)

  def testTranslatePolicyMixedFilterInet6Only(self):
    """Test for Nsxt.test_TranslatePolicy. Testing Mixed filter with inet6."""
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2001:4860:4860::8844')]

    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(MIXED_FILTER_INET_ONLY, self.naming, False)
    translate_pol = nsxt.Nsxt(pol, EXP_INFO)
    nsxt_policies = translate_pol.nsxt_policies
    for (_, filter_name, filter_list, terms) in nsxt_policies:
      self.assertEqual(filter_name, 'mixed')
      self.assertEqual(filter_list, [''])
      self.assertEqual(len(terms), 1)
      self.assertIn('2001:4860:4860::8844', str(terms[0]))

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('MAIL_SERVERS')])
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('MAIL_SERVICES', 'tcp')] * 1)

  def testTranslatePolicyMixedFilterInetMixed(self):
    """Test for Nsxt.test_TranslatePolicy. Testing Mixed filter with mixed."""
    self.naming.GetNetAddr.return_value = [
        nacaddr.IP('2001:4860:4860::8844'),
        nacaddr.IP('10.0.0.0/8')
    ]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(MIXED_FILTER_INET_ONLY, self.naming, False)
    translate_pol = nsxt.Nsxt(pol, EXP_INFO)
    nsxt_policies = translate_pol.nsxt_policies
    for (_, filter_name, filter_list, terms) in nsxt_policies:
      self.assertEqual(filter_name, 'mixed')
      self.assertEqual(filter_list, [''])
      self.assertEqual(len(terms), 1)
      self.assertIn('2001:4860:4860::8844', str(terms[0]))
      self.assertIn('10.0.0.0/8', str(terms[0]))

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('MAIL_SERVERS')])
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('MAIL_SERVICES', 'tcp')] * 1)

  def testTranslatePolicyWithEstablished(self):
    """Test for Nsxt.test_TranslatePolicy."""
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('10.0.0.1'), nacaddr.IP('10.0.0.2')],
        [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('172.16.0.0/12'),
         nacaddr.IP('192.168.0.0/16')]]
    self.naming.GetServiceByProto.return_value = ['123']

    pol = policy.ParsePolicy(INET_FILTER_WITH_ESTABLISHED, self.naming, False)
    translate_pol = nsxt.Nsxt(pol, EXP_INFO)
    nsxt_policies = translate_pol.nsxt_policies
    for (_, filter_name, filter_list, terms) in nsxt_policies:
      self.assertEqual(filter_name, 'inet')
      self.assertEqual(filter_list, [''])
      self.assertEqual(len(terms), 1)

      self.assertNotIn('<sourcePort>123</sourcePort><destinationPort>123',
                       str(terms[0]))

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('NTP_SERVERS'), mock.call('INTERNAL')])
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('NTP', 'udp')] * 2)

  def testNsxtStr(self):
    """Test for Nsxt._str_."""
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('8.8.4.4'),
         nacaddr.IP('8.8.8.8'),
         nacaddr.IP('2001:4860:4860::8844'),
         nacaddr.IP('2001:4860:4860::8888')]]
    self.naming.GetServiceByProto.return_value = ['53']

    pol = policy.ParsePolicy(MIXED_FILTER, self.naming, False)
    target = nsxt.Nsxt(pol, EXP_INFO)

    # parse the output and seperate sections and comment
    target_json = json.loads(str(target))

    rule = target_json["rules"][0]
    # check name and action
    self.assertEqual(rule["display_name"], 'accept-to-honestdns')
    self.assertEqual(rule["action"][0], 'accept')

    # check IPV4 and IPV6 destinations
    exp_dest = ['8.8.4.4/32', '8.8.8.8/32', '2001:4860:4860::8844/128', '2001:4860:4860::8888/128']

    destination_groups = rule["destination_groups"]
    self.assertNotEqual(len(destination_groups), 0)
    for destination in destination_groups:
        if destination not in exp_dest:
          self.fail('Group not found in test_nsxt_str()')

    # check protocol
    protocol = rule["ip_protocol"]
    self.assertEqual(protocol, '')

    # check notes
    notes = rule["notes"]
    self.assertEqual(notes[0], 'Allow name resolution using honestdns.')

    self.naming.GetNetAddr.assert_called_once_with('GOOGLE_DNS')
    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'udp')

  def testNsxtStrWithSecurityGroup(self):
    """Test for Nsxt._str_."""
    pol = policy.ParsePolicy(POLICY_WITH_SECURITY_GROUP, self.naming, False)
    target = nsxt.Nsxt(pol, EXP_INFO)

    # parse the output and seperate sections and comment
    target_json = json.loads(str(target))

    rule = target_json["rules"][0]
    # check name and action
    self.assertEqual(rule["display_name"], 'accept-icmp')
    self.assertEqual(rule["action"][0], 'accept')

    # check protocol
    protocol = rule["ip_protocol"]
    self.assertEqual(protocol, '')

  def testBuildTokens(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('10.0.0.1'), nacaddr.IP('10.0.0.2')],
        [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('172.16.0.0/12'),
         nacaddr.IP('192.168.0.0/16')]]
    self.naming.GetServiceByProto.return_value = ['123']
    pol1 = nsxt.Nsxt(policy.ParsePolicy(INET_FILTER, self.naming), 2)
    st, sst = pol1._BuildTokens()
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('NTP_SERVERS'), mock.call('INTERNAL')])

  def testBuildWarningTokens(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('10.0.0.1'), nacaddr.IP('10.0.0.2')],
        [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('172.16.0.0/12'),
         nacaddr.IP('192.168.0.0/16')]]
    self.naming.GetServiceByProto.return_value = ['123']

    pol1 = nsxt.Nsxt(policy.ParsePolicy(INET_FILTER_2, self.naming), 2)
    st, sst = pol1._BuildTokens()
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)
    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('NTP_SERVERS'), mock.call('INTERNAL')])

  def testParseFilterOptionsCase1(self):
    pol = nsxt.Nsxt(policy.ParsePolicy(HEADER_WITH_SECTIONID + TERM,
                                       self.naming, False), EXP_INFO)
    for (header, _, _, _) in pol.nsxt_policies:
      filter_options = header.FilterOptions(_PLATFORM)
      pol._ParseFilterOptions(filter_options)
      self.assertEqual(nsxt.Nsxt._FILTER_OPTIONS_DICT['filter_type'], 'inet')
      self.assertEqual(nsxt.Nsxt._FILTER_OPTIONS_DICT['section_id'], '1009')
      self.assertIsNone(nsxt.Nsxt._FILTER_OPTIONS_DICT['applied_to'])

  def testParseFilterOptionsCase2(self):
    pol = nsxt.Nsxt(policy.ParsePolicy(HEADER_WITH_SECURITYGROUP + INET6_TERM,
                                       self.naming, False), EXP_INFO)
    for (header, _, _, _) in pol.nsxt_policies:
      filter_options = header.FilterOptions(_PLATFORM)
      pol._ParseFilterOptions(filter_options)
      self.assertEqual(nsxt.Nsxt._FILTER_OPTIONS_DICT['filter_type'], 'inet6')
      self.assertEqual(nsxt.Nsxt._FILTER_OPTIONS_DICT['section_id'], 0)
      self.assertEqual(nsxt.Nsxt._FILTER_OPTIONS_DICT['applied_to'],
                       'securitygroup-Id1')

  def testBadHeaderCase(self):
    pol = policy.ParsePolicy(BAD_HEADER + INET6_TERM, self.naming, False)
    self.assertRaises(nsxt.UnsupportedNsxtAccessListError,
                      nsxt.Nsxt, pol, EXP_INFO)

  def testBadHeaderCase1(self):
    pol = policy.ParsePolicy(BAD_HEADER_1 + TERM, self.naming, False)
    self.assertRaises(nsxt.UnsupportedNsxtAccessListError,
                      nsxt.Nsxt, pol, EXP_INFO)

  def testBadHeaderCase2(self):
    pol = policy.ParsePolicy(BAD_HEADER_2 + INET6_TERM, self.naming, False)
    self.assertRaises(nsxt.UnsupportedNsxtAccessListError,
                      nsxt.Nsxt, pol, EXP_INFO)

  def testBadHeaderCase3(self):
    pol = policy.ParsePolicy(BAD_HEADER_3 + INET6_TERM, self.naming, False)
    self.assertRaises(nsxt.UnsupportedNsxtAccessListError,
                      nsxt.Nsxt, pol, EXP_INFO)

  def testBadHeaderCase4(self):
    pol = policy.ParsePolicy(BAD_HEADER_4 + INET6_TERM, self.naming, False)
    self.assertRaises(nsxt.UnsupportedNsxtAccessListError,
                      nsxt.Nsxt, pol, EXP_INFO)

  def testMixedToV4(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8'),
         nacaddr.IP('2001:4860:4860::8844'),
         nacaddr.IP('2001:4860:4860::8888')],
        [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('172.16.0.0/12'),
         nacaddr.IP('192.168.0.0/16')]]

    source_addr, dest_addr = self.get_source_dest_addresses(MIXED_HEADER +
                                                            MIXED_TO_V4)
    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('GOOGLE_DNS'), mock.call('INTERNAL')])

  def testV4ToMixed(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('172.16.0.0/12'),
         nacaddr.IP('192.168.0.0/16')],
        [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8'),
         nacaddr.IP('2001:4860:4860::8844'),
         nacaddr.IP('2001:4860:4860::8888')]]

    source_addr, dest_addr = self.get_source_dest_addresses(MIXED_HEADER +
                                                            V4_TO_MIXED)
    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('INTERNAL'), mock.call('GOOGLE_DNS')])

  def testMixedToV6(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8'),
         nacaddr.IP('2001:4860:4860::8844'),
         nacaddr.IP('2001:4860:4860::8888')],
        [nacaddr.IP('2001:4860:8000::/33')]]

    source_addr, dest_addr = self.get_source_dest_addresses(MIXED_HEADER +
                                                            MIXED_TO_V6)
    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('GOOGLE_DNS'), mock.call('SOME_HOST')])

  def testV6ToMixed(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('2001:4860:8000::/33')],
        [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8'),
         nacaddr.IP('2001:4860:4860::8844'),
         nacaddr.IP('2001:4860:4860::8888')]]

    source_addr, dest_addr = self.get_source_dest_addresses(MIXED_HEADER +
                                                            V6_TO_MIXED)
    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('SOME_HOST'), mock.call('GOOGLE_DNS')])

  def testMixedToMixed(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8'),
         nacaddr.IP('2001:4860:4860::8844'),
         nacaddr.IP('2001:4860:4860::8888')],
        [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8'),
         nacaddr.IP('2001:4860:4860::8844'),
         nacaddr.IP('2001:4860:4860::8888')]]

    source_addr, dest_addr = self.get_source_dest_addresses(MIXED_HEADER +
                                                            MIXED_TO_MIXED)

    self.naming.GetNetAddr.assert_has_calls([mock.call('GOOGLE_DNS')] * 2)

  def testMixedToAny(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8'),
         nacaddr.IP('2001:4860:4860::8844'),
         nacaddr.IP('2001:4860:4860::8888')]]

    source_addr, dest_addr = self.get_source_dest_addresses(MIXED_HEADER +
                                                            MIXED_TO_ANY)

    self.naming.GetNetAddr.assert_has_calls([mock.call('GOOGLE_DNS')])

  def testAnyToMixed(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8'),
         nacaddr.IP('2001:4860:4860::8844'),
         nacaddr.IP('2001:4860:4860::8888')]]

    source_addr, dest_addr = self.get_source_dest_addresses(MIXED_HEADER +
                                                            ANY_TO_MIXED)
    self.assertEqual(len(source_addr), 3)

    self.naming.GetNetAddr.assert_has_calls([mock.call('GOOGLE_DNS')])

  def testV4ToV4(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('10.0.0.1'), nacaddr.IP('10.0.0.2')],
        [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('172.16.0.0/12'),
         nacaddr.IP('192.168.0.0/16')]]

    source_addr, dest_addr = self.get_source_dest_addresses(MIXED_HEADER +
                                                            V4_TO_V4)
    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('NTP_SERVERS'), mock.call('INTERNAL')])

  def testV6ToV6(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('2001:4860:8000::/33')],
        [nacaddr.IP('2001:4860:8000::/33')]]

    source_addr, dest_addr = self.get_source_dest_addresses(MIXED_HEADER +
                                                            V6_TO_V6)
    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('SOME_HOST')] * 2)

  def testV4ToV6(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('172.16.0.0/12'),
         nacaddr.IP('192.168.0.0/16')],
        [nacaddr.IP('2001:4860:8000::/33')]]

    root = self.get_json_object(MIXED_HEADER + V4_TO_V6)
    rule = root["rules"]
    # No term(rule) will be rendered in this case
    self.assertEqual(len(rule), 1)
    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('INTERNAL'), mock.call('SOME_HOST')])

  def testV6ToV4(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('2001:4860:8000::/33')],
        [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('172.16.0.0/12'),
         nacaddr.IP('192.168.0.0/16')]]

    root = self.get_json_object(MIXED_HEADER + V6_TO_V4)
    rule = root["rules"]
    # No term(rule) will be rendered in this case
    self.assertEqual(len(rule), 1)
    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('SOME_HOST'), mock.call('INTERNAL')])

  def get_json_object(self, data):
    pol = policy.ParsePolicy(data, self.naming, False)
    target = nsxt.Nsxt(pol, EXP_INFO)
    return json.loads(str(target))

  def get_source_dest_addresses(self, data):
    root = self.get_json_object(data)
    rule = root["rules"][0]
    source_addr = rule["source_groups"]
    dest_addr = rule["destination_groups"]

    return source_addr, dest_addr

    self.assertTrue(ipv4_address)
    self.assertTrue(ipv6_address)


if __name__ == '__main__':
  absltest.main()
