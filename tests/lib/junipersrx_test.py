# Copyright 2012 Google Inc. All Rights Reserved.
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

"""Unit test for Juniper SRX acl rendering module."""

import copy
import datetime
import re
from absl.testing import absltest
from unittest import mock

from capirca.lib import aclgenerator
from capirca.lib import junipersrx
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy


GOOD_HEADER = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone untrust
}
"""
GOOD_HEADER_2 = """
header {
  comment:: "This is a header from untrust to trust"
  target:: srx from-zone untrust to-zone trust
}
"""
GOOD_HEADER_3 = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone untrust inet
}
"""
GOOD_HEADER_4 = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone untrust inet6
}
"""
GOOD_HEADER_5 = """
header {
  target:: srx from-zone trust to-zone untrust inet
  apply-groups:: tcp-test1 tcp-test2
}
"""
GOOD_HEADER_6 = """
header {
  target:: srx from-zone trust to-zone untrust inet
  apply-groups-except:: tcp-test1 tcp-test2
}
"""
GOOD_HEADER_7 = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone untrust address-book-zone inet
}
"""

GOOD_HEADER_8 = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone untrust address-book-zone inet6
}
"""

GOOD_HEADER_9 = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone untrust address-book-zone
}
"""

GOOD_HEADER_10 = """
header {
  comment:: "This is a test acl with a global policy"
  target:: srx from-zone all to-zone all address-book-global
}
"""

GOOD_HEADER_11 = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone dmz
}
"""

GOOD_HEADER_12 = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone untrust to-zone trust address-book-zone inet
}
"""

GOOD_HEADER_13 = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone untrust inet expresspath
}
"""

GOOD_HEADER_14 = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone untrust expresspath inet
}
"""

GOOD_HEADER_NOVERBOSE = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone untrust noverbose
}
"""

BAD_HEADER = """
header {
  target:: srx something
}
"""

BAD_HEADER_1 = """
header {
  comment:: "This header has two address families"
  target:: srx from-zone trust to-zone untrust inet6 mixed
}
"""

BAD_HEADER_3 = """
header {
  comment:: "This is a test acl with a global policy"
  target:: srx from-zone all to-zone all address-book-zone
}
"""

BAD_HEADER_4 = """
header {
  comment:: "This is a test acl with a global policy"
  target:: srx from-zone test to-zone all
}
"""

GOOD_TERM_1 = """
term good-term-1 {
  comment:: "This header is very very very very very very very very very very very very very very very very very very very very large"
  destination-address:: SOME_HOST
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_2 = """
term good-term-2 {
  destination-address:: SOME_HOST
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_3 = """
term good-term-3 {
  destination-address:: SOME_HOST
  protocol:: tcp
  action:: accept
  vpn:: good-vpn-3
}
"""

GOOD_TERM_4 = """
term good-term-4 {
  destination-address:: SOME_HOST
  protocol:: tcp
  action:: accept
  vpn:: good-vpn-4 policy-4
}
"""

GOOD_TERM_LOG_1 = """
term good-term-5 {
  action:: accept
  logging:: log-both
}
"""
GOOD_TERM_LOG_2 = """
term good-term-5 {
  action:: deny
  logging:: log-both
}
"""

GOOD_TERM_LOG_3 = """
term good-term-5 {
  action:: accept
  logging:: true
}
"""
GOOD_TERM_LOG_4 = """
term good-term-5 {
  action:: deny
  logging:: true
}
"""

GOOD_TERM_10 = """
term good-term-10 {
  destination-address:: SOME_HOST
  action:: accept
  dscp-set:: b111000
}
"""

GOOD_TERM_11 = """
term good-term-11 {
  destination-address:: SOME_HOST
  action:: accept
  dscp-set:: af42
  dscp-match:: af41-af42 5
  dscp-except:: be
}
"""

GOOD_TERM_12 = """
term dup-of-term-1 {
  destination-address:: FOOBAR
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_13 = """
term dup-of-term-1 {
  destination-address:: FOOBAR SOME_HOST
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_14 = """
term term_to_split {
  source-address:: FOOBAR
  destination-address:: SOME_HOST
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_15 = """
term good-term-15 {
  destination-address:: SOME_HOST
  destination-port:: SMTP
  protocol:: tcp
  policer:: batman
  action:: accept
}
"""

GOOD_TERM_16 = """
term good-term-16 {
  destination-address:: BAZ
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_17 = """
term term_to_split {
  destination-address:: FOOBAR SOME_HOST
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_18 = """
term good_term_18 {
  source-exclude:: SMALL
  protocol:: tcp
  action:: accept
}
"""
GOOD_TERM_19 = """
term good_term_19 {
  source-address:: LARGE
  source-exclude:: SMALL
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_20 = """
term good_term_20 {
  destination-address:: FOO
  destination-port:: HTTP
  protocol:: tcp
  action:: accept
}
"""
GOOD_TERM_21 = """
term good_term_21 {
  destination-address:: UDON
  destination-port:: HTTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_21 = """
term good_term_21 {
  destination-address:: FOO
  destination-port:: QUIC
  protocol:: udp
  action:: accept
}
"""

GOOD_TERM_23 = """
term good_term_23 {
  action:: accept
}
"""

BAD_TERM_1 = """
term bad-term-1 {
  destination-address:: SOME_HOST
  protocol:: tcp
  action:: deny
  vpn:: good-vpn-4 policy-4
}
"""

TCP_ESTABLISHED_TERM = """
term tcp-established-term {
  source-address:: SOME_HOST
  source-port:: SMTP
  protocol:: tcp
  option:: tcp-established
  action:: accept
}
"""

UDP_ESTABLISHED_TERM = """
term udp-established-term {
  source-address:: FOO
  source-port:: QUIC
  protocol:: udp
  option:: established
  action:: accept
}
"""

ICMP_RESPONSE_TERM = """
term icmp_response-term {
  protocol:: icmp
  icmp-type:: echo-reply
  action:: accept
}
"""

EXPIRED_TERM_1 = """
term expired_test {
  expiration:: 2000-1-1
  action:: deny
}
"""

EXPIRING_TERM = """
term is_expiring {
  expiration:: %s
  action:: accept
}
"""

ICMP_TYPE_TERM_1 = """
term test-icmp {
  protocol:: icmp
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

# For testing when the number of terms is at the 8 term application limit
LONG_IPV6_ICMP_TERM = """
term accept-icmpv6-types {
  protocol:: icmpv6
  icmp-type:: echo-request echo-reply neighbor-solicit
  icmp-type:: neighbor-advertisement router-advertisement packet-too-big
  icmp-type:: parameter-problem time-exceeded
  action:: accept
}
"""

# For testing when the number of terms goes over the 8 term application limit
LONG_IPV6_ICMP_TERM2 = """
term accept-icmpv6-types {
  protocol:: icmpv6
  icmp-type:: echo-request echo-reply neighbor-solicit
  icmp-type:: neighbor-advertisement router-advertisement packet-too-big
  icmp-type:: parameter-problem time-exceeded destination-unreachable
  action:: accept
}
"""

ICMP_ALL_TERM = """
term accept-icmp-types {
  protocol:: icmp
  icmp-type:: echo-reply unreachable source-quench redirect alternate-address
  icmp-type:: echo-request router-advertisement router-solicitation
  icmp-type:: time-exceeded parameter-problem timestamp-request
  icmp-type:: timestamp-reply information-request information-reply
  icmp-type:: mask-request mask-reply conversion-error mobile-redirect
  action:: accept
}
"""

ICMP6_ALL_TERM = """
term accept-icmpv6-types {
  protocol:: icmpv6
  icmp-type:: destination-unreachable packet-too-big time-exceeded
  icmp-type:: parameter-problem echo-request echo-reply
  icmp-type:: multicast-listener-query multicast-listener-report
  icmp-type:: multicast-listener-done router-solicit router-advertisement
  icmp-type:: neighbor-solicit neighbor-advertisement redirect-message
  icmp-type:: router-renumbering icmp-node-information-query
  icmp-type:: icmp-node-information-response
  icmp-type:: inverse-neighbor-discovery-solicitation
  icmp-type:: inverse-neighbor-discovery-advertisement
  icmp-type:: version-2-multicast-listener-report
  icmp-type:: home-agent-address-discovery-request
  icmp-type:: home-agent-address-discovery-reply mobile-prefix-solicitation
  icmp-type:: mobile-prefix-advertisement certification-path-solicitation
  icmp-type:: certification-path-advertisement multicast-router-advertisement
  icmp-type:: multicast-router-solicitation multicast-router-termination
  action:: accept
}
"""

IPV6_ICMP_TERM = """
term test-ipv6_icmp {
  protocol:: icmpv6
  icmp-type:: destination-unreachable packet-too-big
  icmp-type:: time-exceeded time-exceeded
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

BAD_ICMP_TERM_1 = """
term test-icmp {
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

ICMP_ONLY_TERM_1 = """
term test-icmp {
  protocol:: icmp
  action:: accept
}
"""

OWNER_TERM = """
term owner-test {
  owner:: foo@google.com
  action:: accept
}
"""

MULTIPLE_PROTOCOLS_TERM = """
term multi-proto {
  protocol:: tcp udp icmp
  action:: accept
}
"""

DEFAULT_TERM_1 = """
term default-term-1 {
  action:: deny
}
"""

TIMEOUT_TERM = """
term timeout-term {
  protocol:: icmp
  icmp-type:: echo-request
  timeout:: 77
  action:: accept
}
"""

PLATFORM_EXCLUDE_TERM = """
term platform-exclude-term {
  protocol:: tcp udp
  platform-exclude:: srx
  action:: accept
}
"""

PLATFORM_TERM = """
term platform-term {
  protocol:: tcp udp
  platform:: srx juniper
  action:: accept
}
"""

PLATFORM_EXCLUDE_ADDRESS_TERM = """
term platform-exclude-term {
  protocol:: tcp udp
  source-address:: FOO
  platform-exclude:: srx
  action:: accept
}
"""

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'dscp_except',
    'dscp_match',
    'dscp_set',
    'expiration',
    'icmp_type',
    'stateless_reply',
    'logging',
    'name',
    'option',
    'owner',
    'platform',
    'platform_exclude',
    'protocol',
    'source_address',
    'source_address_exclude',
    'source_port',
    'timeout',
    'translated',
    'verbatim',
    'vpn'
}

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny', 'reject', 'count', 'log', 'dscp'},
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

_IPSET = [nacaddr.IP('10.0.0.0/8'),
          nacaddr.IP('2001:4860:8000::/33')]
_IPSET2 = [nacaddr.IP('10.23.0.0/22'), nacaddr.IP('10.23.0.6/23', strict=False)]
_IPSET3 = [nacaddr.IP('10.23.0.0/23')]
_IPSET4 = [nacaddr.IP('10.0.0.0/20')]
_IPSET5 = [nacaddr.IP('10.0.0.0/24')]


class JuniperSRXTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def testHeaderComment(self):
    pol = policy.ParsePolicy(GOOD_HEADER + ICMP_TYPE_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('This is a test acl with a comment', output, output)

  def testHeaderApplyGroups(self):
    pol = policy.ParsePolicy(GOOD_HEADER_5 + ICMP_TYPE_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('apply-groups [ tcp-test1 tcp-test2 ]', output,
                  output)

  def testHeaderApplyGroupsExcept(self):
    pol = policy.ParsePolicy(GOOD_HEADER_6 + ICMP_TYPE_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('apply-groups-except [ tcp-test1 tcp-test2 ]', output,
                  output)

  def testLongComment(self):
    expected_output = """
            /*
            This header is very very very very very very very very very very
            very very very very very very very very very very large
            */"""
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']
    srx = junipersrx.JuniperSRX(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.assertIn(expected_output, output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testTermAndFilterName(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    srx = junipersrx.JuniperSRX(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.assertIn('policy good-term-1 {', output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testVpnWithoutPolicy(self):
    self.naming.GetNetAddr.return_value = _IPSET

    srx = junipersrx.JuniperSRX(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_3,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.assertIn('ipsec-vpn good-vpn-3;', output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testVpnWithPolicy(self):
    self.naming.GetNetAddr.return_value = _IPSET

    srx = junipersrx.JuniperSRX(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_4,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.assertIn('ipsec-vpn good-vpn-4;', output, output)
    self.assertIn('pair-policy policy-4;', output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testVpnWithDrop(self):
    self.naming.GetNetAddr.return_value = _IPSET

    srx = junipersrx.JuniperSRX(policy.ParsePolicy(GOOD_HEADER + BAD_TERM_1,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.assertNotIn('ipsec-vpn good-vpn-4;', output, output)
    self.assertNotIn('pair-policy policy-4;', output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testDefaultDeny(self):
    srx = junipersrx.JuniperSRX(policy.ParsePolicy(GOOD_HEADER + DEFAULT_TERM_1,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.assertIn('deny;', output, output)

  def testIcmpTypes(self):
    pol = policy.ParsePolicy(GOOD_HEADER + ICMP_TYPE_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('application test-icmp-app;', output, output)
    self.assertIn('application test-icmp-app {', output, output)
    self.assertIn('term t1 protocol icmp icmp-type 0 inactivity-timeout 60',
                  output, output)
    self.assertIn('term t2 protocol icmp icmp-type 8 inactivity-timeout 60',
                  output, output)

  def testLongIcmpTypes(self):
    pol = policy.ParsePolicy(GOOD_HEADER + LONG_IPV6_ICMP_TERM, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))

    # Make sure that the application isn't split into an application set
    # due to ICMP term usage up to 8 terms.
    self.assertNotIn('application-set accept-icmpv6-types-app', output)
    self.assertIn('application accept-icmpv6-types-app;', output)

    # Use regex to check for there being a single application with exactly 8
    # terms in it.
    pattern = re.compile(
        r'application accept-icmpv6-types-app \{\s+(term t\d protocol icmp6 icmp6-type \d{1,3} inactivity-timeout 60;\s+){8}\}'
    )
    self.assertTrue(pattern.search(output), output)

  def testLongSplitIcmpTypes(self):
    pol = policy.ParsePolicy(GOOD_HEADER + LONG_IPV6_ICMP_TERM2, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))

    # Check the application was split into a set of many applications; 9 terms.
    pattern = re.compile(
        r'application-set accept-icmpv6-types-app \{\s+(application accept-icmpv6-types-app\d;\s+){9}\}')
    self.assertTrue(pattern.search(output), output)

    # Check that each of the 9 applications with 1 term each.
    pattern = re.compile(
        r'(application accept-icmpv6-types-app\d \{\s+(term t1 protocol icmp6 icmp6-type \d{1,3} inactivity-timeout 60;\s+)\}\s+){9}'
    )
    self.assertTrue(pattern.search(output), output)

  def testAllIcmpTypes(self):
    pol = policy.ParsePolicy(GOOD_HEADER + ICMP_ALL_TERM, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))

    # Check for split into application set of many applications; 18 terms.
    pattern = re.compile(
        r'application-set accept-icmp-types-app \{\s+(application accept-icmp-types-app\d{1,2};\s+){18}\}')
    self.assertTrue(pattern.search(output), output)

    # Check that each of the 18 applications have 1 term each.
    pattern = re.compile(
        r'(application accept-icmp-types-app\d{1,2} \{\s+(term t1 protocol icmp icmp-type \d{1,3} inactivity-timeout 60;\s+)\}\s+){18}'
    )
    self.assertTrue(pattern.search(output), output)

  def testAllIcmp6Types(self):
    pol = policy.ParsePolicy(GOOD_HEADER + ICMP6_ALL_TERM, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    # Check for 29 applications.
    pattern = re.compile(
        r'application-set accept-icmpv6-types-app \{\s+(application accept-icmpv6-types-app\d{1,2};\s+){29}\}'
    )
    self.assertTrue(pattern.search(output), output)

    # Check that each of the 4 applications have between 1 and 8 terms.
    pattern = re.compile(
        r'(application accept-icmpv6-types-app\d{1,2} \{\s+(term t1 protocol icmp6 icmp6-type \d{1,3} inactivity-timeout 60;\s+)\}\s+){29}'
    )
    self.assertTrue(pattern.search(output), output)

  def testLoggingBothAccept(self):
    srx = junipersrx.JuniperSRX(policy.ParsePolicy(GOOD_HEADER
                                                   + GOOD_TERM_LOG_1,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.assertIn('session-init;', output)
    self.assertIn('session-close;', output)

  def testLoggingBothDeny(self):
    srx = junipersrx.JuniperSRX(policy.ParsePolicy(GOOD_HEADER
                                                   + GOOD_TERM_LOG_2,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.assertIn('session-init;', output)
    self.assertIn('session-close;', output)

  def testLoggingTrueAccept(self):
    srx = junipersrx.JuniperSRX(policy.ParsePolicy(GOOD_HEADER
                                                   + GOOD_TERM_LOG_3,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.assertIn('session-close;', output)
    self.assertNotIn('session-init;', output)

  def testLoggingTrueDeny(self):
    srx = junipersrx.JuniperSRX(policy.ParsePolicy(GOOD_HEADER
                                                   + GOOD_TERM_LOG_4,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.assertIn('session-init;', output)
    self.assertNotIn('session-close;', output)

  def testOwnerTerm(self):
    pol = policy.ParsePolicy(GOOD_HEADER + OWNER_TERM, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('            /*\n'
                  '            Owner: foo@google.com\n'
                  '            */', output, output)

  def testBadICMP(self):
    pol = policy.ParsePolicy(GOOD_HEADER + BAD_ICMP_TERM_1, self.naming)
    self.assertRaises(aclgenerator.UnsupportedFilterError,
                      junipersrx.JuniperSRX, pol, EXP_INFO)

  def testICMPProtocolOnly(self):
    pol = policy.ParsePolicy(GOOD_HEADER + ICMP_ONLY_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('protocol icmp;', output, output)

  def testMultipleProtocolGrouping(self):
    pol = policy.ParsePolicy(GOOD_HEADER + MULTIPLE_PROTOCOLS_TERM, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('application-set multi-proto-app {', output, output)
    self.assertIn('application multi-proto-app1;', output, output)
    self.assertIn('application multi-proto-app2;', output, output)
    self.assertIn('application multi-proto-app3;', output, output)
    self.assertIn('application multi-proto-app1 {', output, output)
    self.assertIn('term t1 protocol tcp;', output, output)
    self.assertIn('application multi-proto-app2 {', output, output)
    self.assertIn('term t2 protocol udp;', output, output)
    self.assertIn('application multi-proto-app3 {', output, output)
    self.assertIn('term t3 protocol icmp;', output, output)

  def testGlobalPolicyHeader(self):
    pol = policy.ParsePolicy(GOOD_HEADER_10 + MULTIPLE_PROTOCOLS_TERM,
                             self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertEqual(output.count('global {'), 2)
    self.assertNotIn('from-zone all to-zone all {', output)

  def testBadGlobalPolicyHeaderZoneBook(self):
    pol = policy.ParsePolicy(BAD_HEADER_3 + MULTIPLE_PROTOCOLS_TERM,
                             self.naming)
    self.assertRaises(junipersrx.UnsupportedFilterError, junipersrx.JuniperSRX,
                      pol, EXP_INFO)

  def testBadGlobalPolicyHeaderNameAll(self):
    pol = policy.ParsePolicy(BAD_HEADER_4 + MULTIPLE_PROTOCOLS_TERM,
                             self.naming)
    self.assertRaises(junipersrx.UnsupportedFilterError, junipersrx.JuniperSRX,
                      pol, EXP_INFO)

  def testBadHeaderType(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(BAD_HEADER + GOOD_TERM_1, self.naming)
    self.assertRaises(junipersrx.UnsupportedFilterError, junipersrx.JuniperSRX,
                      pol, EXP_INFO)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testBadHeaderMultiAF(self):
    # test for multiple address faimilies in header
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(BAD_HEADER_1 + GOOD_TERM_1, self.naming)
    self.assertRaises(junipersrx.ConflictingTargetOptionsError,
                      junipersrx.JuniperSRX,
                      pol, EXP_INFO)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  @mock.patch.object(junipersrx.logging, 'warning')
  def testExpiredTerm(self, mock_warn):
    _ = junipersrx.JuniperSRX(policy.ParsePolicy(GOOD_HEADER + EXPIRED_TERM_1,
                                                 self.naming), EXP_INFO)

    mock_warn.assert_called_once_with(
        'WARNING: Term %s in policy %s>%s is expired.',
        'expired_test', 'trust', 'untrust')

  @mock.patch.object(junipersrx.logging, 'info')
  def testExpiringTerm(self, mock_info):
    exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
    _ = junipersrx.JuniperSRX(policy.ParsePolicy(GOOD_HEADER + EXPIRING_TERM %
                                                 exp_date.strftime('%Y-%m-%d'),
                                                 self.naming), EXP_INFO)

    mock_info.assert_called_once_with(
        'INFO: Term %s in policy %s>%s expires in '
        'less than two weeks.', 'is_expiring',
        'trust', 'untrust')

  def testTimeout(self):
    pol = policy.ParsePolicy(GOOD_HEADER + TIMEOUT_TERM, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('timeout 77', output, output)

  def testIcmpV6(self):
    pol = policy.ParsePolicy(GOOD_HEADER + IPV6_ICMP_TERM, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('protocol icmp6', output, output)
    self.assertIn('icmp6-type', output, output)

  def testReplaceStatement(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('replace: address-book', output, output)
    self.assertIn('replace: policies', output, output)
    self.assertIn('replace: applications', output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testAdressBookBothAFs(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('replace: address-book {', output, output)
    self.assertIn('global {', output, output)
    self.assertIn('2001:4860:8000::/33', output, output)
    self.assertIn('10.0.0.0/8', output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testAdressBookIPv4(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('replace: address-book {', output, output)
    self.assertIn('global {', output, output)
    self.assertNotIn('2001:4860:8000::/33', output, output)
    self.assertIn('10.0.0.0/8', output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testAdressBookIPv6(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(GOOD_HEADER_4 + GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('replace: address-book {', output, output)
    self.assertIn('global {', output, output)
    self.assertIn('2001:4860:8000::/33', output, output)
    self.assertNotIn('10.0.0.0/8', output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testAddressBookContainsSmallerPrefix(self):
    _IPSET2[0].parent_token = 'FOOBAR'
    _IPSET2[1].parent_token = 'SOME_HOST'
    _IPSET3[0].parent_token = 'FOOBAR'
    self.naming.GetNetAddr.side_effect = [_IPSET2, _IPSET3]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1 + GOOD_HEADER_2 +
                             GOOD_TERM_12, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('address FOOBAR_0 10.23.0.0/22;', output, output)

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('SOME_HOST'),
        mock.call('FOOBAR')])
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('SMTP', 'tcp')] * 2)

  def testAddressBookContainsLargerPrefix(self):
    _IPSET2[0].parent_token = 'FOOBAR'
    _IPSET2[1].parent_token = 'SOME_HOST'
    _IPSET3[0].parent_token = 'FOOBAR'
    self.naming.GetNetAddr.side_effect = [_IPSET3, _IPSET2]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(GOOD_HEADER_2 + GOOD_TERM_12 + GOOD_HEADER +
                             GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('address FOOBAR_0 10.23.0.0/22;', output, output)

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('FOOBAR'),
        mock.call('SOME_HOST')])
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('SMTP', 'tcp')] * 2)

  def testZoneAdressBookBothAFs(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(GOOD_HEADER_9 + GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('security-zone untrust {', output, output)
    self.assertIn('replace: address-book {', output, output)
    self.assertIn('2001:4860:8000::/33', output, output)
    self.assertIn('10.0.0.0/8', output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testZoneAdressBookIPv4(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(GOOD_HEADER_7 + GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('security-zone untrust {', output, output)
    self.assertIn('replace: address-book {', output, output)
    self.assertNotIn('2001:4860:8000::/33', output, output)
    self.assertIn('10.0.0.0/8', output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testZoneAdressBookIPv6(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(GOOD_HEADER_8 + GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('security-zone untrust {', output, output)
    self.assertIn('replace: address-book {', output, output)
    self.assertIn('2001:4860:8000::/33', output, output)
    self.assertNotIn('10.0.0.0/8', output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def assertFalseUnorderedAddressBook(self, address_book):
    # This is very naive check that expects addresses to be exact as returned
    # from _OutOfOrderAddresses method. If you modify one please modify this one
    # as well.
    for line in address_book:
      if '10.0.0.0/8' in line:
        self.fail('Addresses in address book are out of order.')
      elif '1.0.0.0/8' in line:
        break

  def _OutOfOrderAddresses(self):
    x = nacaddr.IP('10.0.0.0/8')
    x.parent_token = 'test'
    y = nacaddr.IP('1.0.0.0/8')
    y.parent_token = 'out_of_order'

    return x, y

  def testAddressBookOrderingSuccess(self):
    self.naming.GetNetAddr.return_value = self._OutOfOrderAddresses()
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_2, self.naming)
    p = junipersrx.JuniperSRX(pol, EXP_INFO)

    self.assertFalseUnorderedAddressBook(p._GenerateAddressBook())

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testAddressBookOrderingAlreadyOrdered(self):
    y, x = self._OutOfOrderAddresses()
    self.naming.GetNetAddr.return_value = [x, y]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_2, self.naming)
    p = junipersrx.JuniperSRX(pol, EXP_INFO)

    self.assertFalseUnorderedAddressBook(p._GenerateAddressBook())

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def _AssertOrder(self, strings, expected_order):
    order = copy.copy(expected_order)
    matcher = order.pop(0)
    for line in strings:
      if matcher in line:
        if not order:
          return
        matcher = order.pop(0)

    self.fail('Strings weren\'t in expected order.\nExpected:\n  %s\n\nGot:\n%s'
              % ('\n  '.join(expected_order), '\n'.join(strings)))

  def testApplicationsOrderingSuccess(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.side_effect = [['80', '80'], ['25', '25']]

    pol = policy.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_2 + GOOD_TERM_1,
                             self.naming)
    p = junipersrx.JuniperSRX(pol, EXP_INFO)
    self._AssertOrder(p._GenerateApplications(),
                      ['application good-term-1-app1',
                       'application good-term-2-app1',
                       'application-set good-term-1-app',
                       'application-set good-term-2-app'])

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('SOME_HOST')] * 2)
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('SMTP', 'tcp')] * 2)

  def testApplicationsOrderingAlreadyOrdered(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.side_effect = [['25', '25'], ['80', '80']]

    pol = policy.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_1 + GOOD_TERM_2,
                             self.naming)
    p = junipersrx.JuniperSRX(pol, EXP_INFO)
    self._AssertOrder(p._GenerateApplications(),
                      ['application good-term-1-app1',
                       'application good-term-2-app1',
                       'application-set good-term-1-app',
                       'application-set good-term-2-app'])

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('SOME_HOST')] * 2)
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('SMTP', 'tcp')] * 2)

  def testDscpWithByte(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    srx = junipersrx.JuniperSRX(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_10,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.assertIn('dscp b111000;', output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testDscpWithClass(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]

    srx = junipersrx.JuniperSRX(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_11,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.assertIn('dscp af42;', output, output)
    self.assertIn('dscp [ af41-af42 5 ];', output, output)
    self.assertIn('dscp-except [ be ];', output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testLargeTermSplitting(self):
    ips = list(nacaddr.IP('10.0.8.0/21').subnets(new_prefix=32))
    mo_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        mo_ips.append(nacaddr.IP(ip))
      counter += 1

    ips = list(nacaddr.IP('10.0.0.0/21').subnets(new_prefix=32))
    prodcolos_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        prodcolos_ips.append(nacaddr.IP(ip))
      counter += 1

    self.naming.GetNetAddr.side_effect = [mo_ips, prodcolos_ips]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(GOOD_HEADER_2 + GOOD_TERM_14, self.naming)
    srx = junipersrx.JuniperSRX(pol, EXP_INFO)
    self.assertEqual(len(srx.policy.filters[0][1]), 4)

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('FOOBAR'),
        mock.call('SOME_HOST')])
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testLargeTermSplittingV6(self):
    ips = list(nacaddr.IP('2620:0:1000:3103:eca0:2c09:6b32:e000/119'
                          ).subnets(new_prefix=128))
    mo_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        mo_ips.append(nacaddr.IP(ip))
      counter += 1

    ips = list(nacaddr.IP('2720:0:1000:3103:eca0:2c09:6b32:e000/119'
                          ).subnets(new_prefix=128))
    prodcolos_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        prodcolos_ips.append(nacaddr.IP(ip))
      counter += 1

    self.naming.GetNetAddr.side_effect = [mo_ips, prodcolos_ips]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(GOOD_HEADER_2 + GOOD_TERM_14, self.naming)
    srx = junipersrx.JuniperSRX(pol, EXP_INFO)
    self.assertEqual(len(srx.policy.filters[0][1]), 4)

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('FOOBAR'),
        mock.call('SOME_HOST')])
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testLargeTermSplitIgnoreV6(self):
    ips = list(nacaddr.IP('2620:0:1000:3103:eca0:2c09:6b32:e000/119'
                          ).subnets(new_prefix=128))
    mo_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        mo_ips.append(nacaddr.IP(ip))
      counter += 1

    ips = list(nacaddr.IP('2720:0:1000:3103:eca0:2c09:6b32:e000/119'
                          ).subnets(new_prefix=128))
    ips.append(nacaddr.IPv4('10.0.0.1/32'))
    prodcolos_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        prodcolos_ips.append(nacaddr.IP(ip))
      counter += 1

    self.naming.GetNetAddr.side_effect = [mo_ips, prodcolos_ips]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_14, self.naming)
    srx = junipersrx.JuniperSRX(pol, EXP_INFO)
    self.assertEqual(len(srx.policy.filters[0][1]), 1)

  def testDuplicateTermsInDifferentZones(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.side_effect = [['25'], ['26']]

    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_2 + GOOD_HEADER_11 +
                             GOOD_TERM_2, self.naming)
    self.assertRaises(junipersrx.ConflictingApplicationSetsError,
                      junipersrx.JuniperSRX, pol, EXP_INFO)

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('SOME_HOST')] * 2)
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('SMTP', 'tcp')] * 2)

  def testBuildTokens(self):
    self.naming.GetServiceByProto.side_effect = [['25'], ['26']]
    pol1 = junipersrx.JuniperSRX(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_2,
                                                    self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    self.naming.GetServiceByProto.side_effect = [['25'], ['26']]

    pol1 = junipersrx.JuniperSRX(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_15, self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

  def testOptimizedGlobalAddressBook(self):
    foobar_ips = [nacaddr.IP('172.16.0.0/16', token='FOOBAR'),
                  nacaddr.IP('172.17.0.0/16', token='FOOBAR'),
                  nacaddr.IP('172.18.0.0/16', token='FOOBAR'),
                  nacaddr.IP('172.19.0.0/16', token='FOOBAR'),
                  nacaddr.IP('172.22.0.0/16', token='FOOBAR'),
                  nacaddr.IP('172.23.0.0/16', token='FOOBAR'),
                  nacaddr.IP('172.24.0.0/16', token='FOOBAR'),
                  nacaddr.IP('172.25.0.0/16', token='FOOBAR'),
                  nacaddr.IP('172.26.0.0/16', token='FOOBAR'),
                  nacaddr.IP('172.27.0.0/16', token='FOOBAR'),
                  nacaddr.IP('172.28.0.0/16', token='FOOBAR'),
                  nacaddr.IP('172.29.0.0/16', token='FOOBAR'),
                  nacaddr.IP('172.30.0.0/16', token='FOOBAR'),
                  nacaddr.IP('172.31.0.0/16', token='FOOBAR')]
    some_host_ips = [nacaddr.IP('172.20.0.0/16', token='SOME_HOST'),
                     nacaddr.IP('172.21.0.0/16', token='SOME_HOST'),
                     nacaddr.IP('10.0.0.0/8', token='SOME_HOST')]

    self.naming.GetNetAddr.side_effect = [foobar_ips, some_host_ips,
                                          some_host_ips]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_17 + GOOD_HEADER_2 +
                             GOOD_TERM_15, self.naming)
    srx = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('address FOOBAR_0 172.16.0.0/14', srx, srx)
    self.assertIn('address FOOBAR_1 172.22.0.0/15;', srx, srx)
    self.assertIn('address FOOBAR_2 172.24.0.0/13;', srx, srx)
    self.assertIn('address SOME_HOST_0 10.0.0.0/8;', srx, srx)
    self.assertIn('address SOME_HOST_1 172.20.0.0/15;', srx, srx)
    self.assertNotIn('/16', srx, srx)

  def testNakedExclude(self):
    small = [nacaddr.IP('10.0.0.0/24', 'SMALL', 'SMALL')]
    self.naming.GetNetAddr.side_effect = [small]

    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_18, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn(
        'address GOOD_TERM_18_SRC_EXCLUDE_2 10.0.1.0/24;', output, output)
    self.assertIn(
        'address GOOD_TERM_18_SRC_EXCLUDE_3 10.0.2.0/23;', output, output)
    self.assertIn(
        'address GOOD_TERM_18_SRC_EXCLUDE_4 10.0.4.0/22;', output, output)
    self.assertIn(
        'address GOOD_TERM_18_SRC_EXCLUDE_5 10.0.8.0/21;', output, output)
    self.assertNotIn('10.0.0.0', output)

  def testSourceExclude(self):
    large = [nacaddr.IP('10.0.0.0/20', 'LARGE', 'LARGE')]
    small = [nacaddr.IP('10.0.0.0/24', 'SMALL', 'SMALL')]
    self.naming.GetNetAddr.side_effect = [large, small]

    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_19, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn(
        'address GOOD_TERM_19_SRC_EXCLUDE_0 10.0.1.0/24;', output, output)
    self.assertIn(
        'address GOOD_TERM_19_SRC_EXCLUDE_1 10.0.2.0/23;', output, output)
    self.assertIn(
        'address GOOD_TERM_19_SRC_EXCLUDE_2 10.0.4.0/22;', output, output)
    self.assertIn(
        'address GOOD_TERM_19_SRC_EXCLUDE_3 10.0.8.0/21;', output, output)
    self.assertNotIn('10.0.0.0/24', output)

  def testPlatformExclude(self):
    large = [nacaddr.IP('10.0.0.0/20', 'LARGE', 'LARGE')]
    small = [nacaddr.IP('10.0.0.0/24', 'SMALL', 'SMALL')]
    self.naming.GetNetAddr.side_effect = [large, small]

    pol = policy.ParsePolicy(GOOD_HEADER + PLATFORM_EXCLUDE_TERM + GOOD_TERM_19,
                             self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('good_term_19', output,
                  output)
    self.assertNotIn('platform-exclude-term', output)

  def testPlatformTerm(self):
    large = [nacaddr.IP('10.0.0.0/20', 'LARGE', 'LARGE')]
    small = [nacaddr.IP('10.0.0.0/24', 'SMALL', 'SMALL')]
    self.naming.GetNetAddr.side_effect = [large, small]

    pol = policy.ParsePolicy(GOOD_HEADER + PLATFORM_TERM + GOOD_TERM_19,
                             self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('good_term_19', output,
                  output)
    self.assertIn('platform-term', output, output)

  def testPlatformExcludeWithSourceExclude(self):
    foo = [nacaddr.IP('192.1.0.0/20', 'FOO', 'FOO')]
    large = [nacaddr.IP('10.0.0.0/20', 'LARGE', 'LARGE')]
    small = [nacaddr.IP('10.0.0.0/24', 'SMALL', 'SMALL')]
    self.naming.GetNetAddr.side_effect = [foo, large, small]

    pol = policy.ParsePolicy(
        GOOD_HEADER + PLATFORM_EXCLUDE_ADDRESS_TERM + GOOD_TERM_19, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('address GOOD_TERM_19_SRC_EXCLUDE_0 10.0.1.0/24;', output,
                  output)
    self.assertIn('address GOOD_TERM_19_SRC_EXCLUDE_1 10.0.2.0/23;', output,
                  output)
    self.assertIn('address GOOD_TERM_19_SRC_EXCLUDE_2 10.0.4.0/22;', output,
                  output)
    self.assertIn('address GOOD_TERM_19_SRC_EXCLUDE_3 10.0.8.0/21;', output,
                  output)
    self.assertNotIn('10.0.0.0/24', output)
    self.assertNotIn('192.1.0.0/20', output)
    self.assertNotIn('platform-exclude-term', output)

  def testMixedVersionIcmp(self):
    pol = policy.ParsePolicy(GOOD_HEADER + ICMP_TYPE_TERM_1 + IPV6_ICMP_TERM,
                             self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('term t6 protocol icmp6 icmp6-type 129 '
                  'inactivity-timeout 60;', output)
    self.assertIn('term t1 protocol icmp icmp-type 0 '
                  'inactivity-timeout 60;', output)

  def testOptimizedApplicationset(self):
    some_host = [nacaddr.IP('10.0.0.1/32', token='SOMEHOST')]
    foo = [nacaddr.IP('10.0.0.2/32', token='FOO')]
    foobar = [nacaddr.IP('10.0.0.3/32', token='FOOBAR')]
    self.naming.GetNetAddr.side_effect = [some_host, foo, foobar,
                                          foobar, some_host]

    self.naming.GetServiceByProto.side_effect = [['25', '25'], ['80', '80'],
                                                 ['25', '25'], ['25', '25']]

    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_2 + GOOD_TERM_20 +
                             GOOD_TERM_12 + GOOD_HEADER_2 + GOOD_TERM_14,
                             self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertNotIn('dup-of-term-1-app', output)

  def testExpressPath(self):
    some_host = [nacaddr.IP('10.0.0.1/32', token='SOMEHOST')]
    self.naming.GetNetAddr.side_effect = [some_host, some_host]

    self.naming.GetServiceByProto.side_effect = [['25', '25'], ['25', '25']]

    pol = policy.ParsePolicy(GOOD_HEADER_14 + GOOD_TERM_2 + DEFAULT_TERM_1 +
                             GOOD_HEADER + GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertIn('services-offload;', output)
    self.assertIn('deny;', output)
    self.assertIn('permit;', output)

  def testDropEstablished(self):
    some_host = [nacaddr.IP('10.0.0.1/32', token='FOO')]
    self.naming.GetServiceByProto.side_effect = [['25', '25'], ['443', '443'],
                                                 ['25', '25'], ['443', '443']]
    self.naming.GetNetAddr.side_effect = [some_host, some_host, some_host,
                                          some_host]
    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1 + GOOD_TERM_21 +
                             DEFAULT_TERM_1 + GOOD_HEADER_2 +
                             TCP_ESTABLISHED_TERM + UDP_ESTABLISHED_TERM +
                             DEFAULT_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertNotIn('udp-established-term', output)
    self.assertNotIn('tcp-established-term', output)

  def testStatelessReply(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    ret = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1 + ICMP_RESPONSE_TERM,
                             self.naming)

    _, terms = ret.filters[0]
    for term in terms:
      if term.protocol[0] == 'icmp':
        term.stateless_reply = True

    srx = junipersrx.JuniperSRX(ret, EXP_INFO)

    output = str(srx)
    self.assertIn('policy good-term-1 {', output, output)
    self.assertNotIn('policy icmp_response-term {', output, output)

  def testNoVerbose(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']
    pol = policy.ParsePolicy(GOOD_HEADER_NOVERBOSE + GOOD_TERM_1, self.naming)
    srx = junipersrx.JuniperSRX(pol, EXP_INFO)
    self.assertNotIn('This is a test acl with a comment', str(srx))
    self.assertNotIn('very very very', str(srx))

  def testDropUndefinedAddressbookTermsV4ForV6Render(self):
    # V4-only term should be dropped when rendering ACL as V6 - b/172933068
    udon = [nacaddr.IP('10.0.0.2/32', token='UDON')]
    self.naming.GetServiceByProto.side_effect = [['25', '25']]
    self.naming.GetNetAddr.side_effect = [udon]

    # GOOD_HEADER_4 specifies V6 rendering
    pol = policy.ParsePolicy(GOOD_HEADER_4 + GOOD_TERM_21, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertNotIn('good_term_21', output)

  def testDeleteV4AddressEntriesForV6Render(self):
    # Confirm V4 address book entries are not generated when rendering as V6
    udon = [nacaddr.IP('10.0.0.2/32', token='UDON')]
    self.naming.GetServiceByProto.side_effect = [['25', '25']]
    self.naming.GetNetAddr.side_effect = [udon]

    # GOOD_HEADER_4 specifies V6 rendering
    pol = policy.ParsePolicy(GOOD_HEADER_4 + GOOD_TERM_21, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertNotIn('10.0.0.2/32', output)

  def testDropUndefinedAddressbookTermsV6ForV4Render(self):
    # V6-only term should be dropped when rendering ACL as V4 - b/172933068
    udon = [nacaddr.IP('2001:4860:8000::5/128', token='UDON')]
    self.naming.GetServiceByProto.side_effect = [['25', '25']]
    self.naming.GetNetAddr.side_effect = [udon]

    # GOOD_HEADER_3 specifies V4 rendering
    pol = policy.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_21, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertNotIn('good_term_21', output)

  def testDeleteV6AddressEntriesForV4Render(self):
    # Confirm V6 address book entries are not generated when rendering as V4
    udon = [nacaddr.IP('2001:4860:8000::5/128', token='UDON')]
    self.naming.GetServiceByProto.side_effect = [['25', '25']]
    self.naming.GetNetAddr.side_effect = [udon]

    # GOOD_HEADER_3 specifies V4 rendering
    pol = policy.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_21, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertNotIn('2001:4860:8000::5/128', output)

  def testCreateV6AddressEntriesForMixedRender(self):
    # V6-only 1024+ IPs; MIXED rendering
    # Confirm that address set names used in policy are also created in
    # address book

    # TODO(nitb) Move multiple IP networks generation logic to separate method
    # and reuse in other tests
    overflow_ips = [
        nacaddr.IP('2001:4860:8000::5/128'),
        nacaddr.IP('3051:abd2:5400::9/128'),
        nacaddr.IP('aee2:37ba:3cc0::3/128'),
        nacaddr.IP('6f5d:abd2:1403::1/128'),
        nacaddr.IP('577e:5400:3051::6/128'),
        nacaddr.IP('af22:32d2:3f00::2/128')
    ]

    ips = list(
        nacaddr.IP('2620:0:1000:3103:eca0:2c09:6b32:e000/117').subnets(
            new_prefix=128))
    mo_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        mo_ips.append(nacaddr.IP(ip))
      counter += 1

    self.naming.GetServiceByProto.side_effect = [['25', '25']]
    self.naming.GetNetAddr.side_effect = [overflow_ips+mo_ips]

    # GOOD_HEADER = MIXED rendering
    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_21, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))

    # extract address-set-names referenced in policy blocks
    partial_pruned_acl = output.split('replace: policies')[1].split(
        'destination-address [ ')[1:]

    # verify that there are exactly 9 terms in the ACL by checking if
    # partial_pruned_acl contains exactly 9 elements
    self.assertEqual(len(partial_pruned_acl), 9)

    for text in partial_pruned_acl:
      address_set_name = text.split(' ];')[0]

      if address_set_name:
        address_set_count = output.count(address_set_name)
        # check if each addresssetname referenced in policy occurs more than
        # once i.e. is defined in the address book
        self.assertGreater(address_set_count, 1)

  def testCreateV6AddressEntriesForV6Render(self):
    # V6-only 1024+ IPs; V6 rendering
    overflow_ips = [
        nacaddr.IP('2001:4860:8000::5/128'),
        nacaddr.IP('3051:abd2:5400::9/128'),
        nacaddr.IP('aee2:37ba:3cc0::3/128'),
        nacaddr.IP('6f5d:abd2:1403::1/128'),
        nacaddr.IP('577e:5400:3051::6/128'),
        nacaddr.IP('af22:32d2:3f00::2/128')
    ]

    ips = list(
        nacaddr.IP('2620:0:1000:3103:eca0:2c09:6b32:e000/117').subnets(
            new_prefix=128))
    mo_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        mo_ips.append(nacaddr.IP(ip))
      counter += 1

    self.naming.GetServiceByProto.side_effect = [['25', '25']]
    self.naming.GetNetAddr.side_effect = [overflow_ips+mo_ips]

    # GOOD_HEADER_4 = V6 rendering
    pol = policy.ParsePolicy(GOOD_HEADER_4 + GOOD_TERM_21, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))

    # extract address-set-names referenced in policy blocks
    partial_pruned_acl = output.split('replace: policies')[1].split(
        'destination-address [ ')[1:]

    # verify that there are exactly 9 terms in the ACL by checking if
    # partial_pruned_acl contains exactly 9 elements
    self.assertEqual(len(partial_pruned_acl), 9)

    for text in partial_pruned_acl:
      address_set_name = text.split(' ];')[0]

      if address_set_name:
        address_set_count = output.count(address_set_name)
        # check if each addresssetname referenced in policy occurs more than
        # once i.e. is defined in the address book
        self.assertGreater(address_set_count, 1)

  def testEmptyACLEmptyAddressBookV6IpsV4Render(self):
    # V6-only 1024+ IPs; V4 rendering
    overflow_ips = [
        nacaddr.IP('2001:4860:8000::5/128'),
        nacaddr.IP('3051:abd2:5400::9/128'),
        nacaddr.IP('aee2:37ba:3cc0::3/128'),
        nacaddr.IP('6f5d:abd2:1403::1/128'),
        nacaddr.IP('577e:5400:3051::6/128'),
        nacaddr.IP('af22:32d2:3f00::2/128')
    ]

    ips = list(
        nacaddr.IP('2620:0:1000:3103:eca0:2c09:6b32:e000/117').subnets(
            new_prefix=128))
    mo_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        mo_ips.append(nacaddr.IP(ip))
      counter += 1

    self.naming.GetServiceByProto.side_effect = [['25', '25']]
    self.naming.GetNetAddr.side_effect = [overflow_ips+mo_ips]

    # GOOD_HEADER_3 = V4 rendering
    pol = policy.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_21, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    address_set_count = output.count('address')

    # verify acl is empty
    self.assertNotIn('policy', output)

    # verify address book is empty
    self.assertEqual(address_set_count, 1)

  def testCreateV4AddressEntriesForMixedRender(self):
    # V4-only 1024+ IPs; MIXED rendering
    overflow_ips = [
        nacaddr.IP('23.2.3.3/32'),
        nacaddr.IP('54.2.3.4/32'),
        nacaddr.IP('76.2.3.5/32'),
        nacaddr.IP('132.2.3.6/32'),
        nacaddr.IP('197.2.3.7/32')
    ]

    ips = list(nacaddr.IP('10.0.8.0/21').subnets(new_prefix=32))
    mo_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        mo_ips.append(nacaddr.IP(ip))
      counter += 1

    self.naming.GetServiceByProto.side_effect = [['25', '25']]
    self.naming.GetNetAddr.side_effect = [overflow_ips+mo_ips]

    # GOOD_HEADER = MIXED rendering
    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_21, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))

    # extract address-set-names referenced in policy blocks
    partial_pruned_acl = output.split('replace: policies')[1].split(
        'destination-address [ ')[1:]

    # verify that there are exactly 3 terms in the ACL by checking if
    # partial_pruned_acl contains exactly 3 elements
    self.assertEqual(len(partial_pruned_acl), 3)

    for text in partial_pruned_acl:
      address_set_name = text.split(' ];')[0]

      if address_set_name:
        address_set_count = output.count(address_set_name)
        # check if each addresssetname referenced in policy occurs more than
        # once i.e. is defined in the address book
        self.assertGreater(address_set_count, 1)

  def testEmptyACLEmptyAddressBookV4IpsV6Render(self):
    # V4-only 1024+ IPs; V6 rendering
    overflow_ips = [
        nacaddr.IP('23.2.3.3/32'),
        nacaddr.IP('54.2.3.4/32'),
        nacaddr.IP('76.2.3.5/32'),
        nacaddr.IP('132.2.3.6/32'),
        nacaddr.IP('197.2.3.7/32')
    ]

    ips = list(nacaddr.IP('10.0.8.0/21').subnets(new_prefix=32))
    mo_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        mo_ips.append(nacaddr.IP(ip))
      counter += 1

    self.naming.GetServiceByProto.side_effect = [['25', '25']]
    self.naming.GetNetAddr.side_effect = [overflow_ips+mo_ips]

    # GOOD_HEADER_4 = V6 rendering
    pol = policy.ParsePolicy(GOOD_HEADER_4 + GOOD_TERM_21, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    address_set_count = output.count('address')

    # verify acl is empty
    self.assertNotIn('policy', output)

    # verify address book is empty
    self.assertEqual(address_set_count, 1)

  def testCreateV4AddressEntriesForV4Render(self):
    # V4-only 1024+ IPs; V4 rendering
    overflow_ips = [
        nacaddr.IP('23.2.3.3/32'),
        nacaddr.IP('54.2.3.4/32'),
        nacaddr.IP('76.2.3.5/32'),
        nacaddr.IP('132.2.3.6/32'),
        nacaddr.IP('197.2.3.7/32')
    ]

    ips = list(nacaddr.IP('10.0.8.0/21').subnets(new_prefix=32))
    mo_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        mo_ips.append(nacaddr.IP(ip))
      counter += 1

    self.naming.GetServiceByProto.side_effect = [['25', '25']]
    self.naming.GetNetAddr.side_effect = [overflow_ips+mo_ips]

    # GOOD_HEADER_3 = V4 rendering
    pol = policy.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_21, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))

    # extract address-set-names referenced in policy blocks
    partial_pruned_acl = output.split('replace: policies')[1].split(
        'destination-address [ ')[1:]

    # verify that there are exactly 3 terms in the ACL by checking if
    # partial_pruned_acl contains exactly 3 elements
    self.assertEqual(len(partial_pruned_acl), 3)

    for text in partial_pruned_acl:
      address_set_name = text.split(' ];')[0]

      if address_set_name:
        address_set_count = output.count(address_set_name)
        # check if each addresssetname referenced in policy occurs more than
        # once i.e. is defined in the address book
        self.assertGreater(address_set_count, 1)

  def testCreateMixedAddressEntriesForMixedRender(self):
    # 513V6 and 512V4 IPs; MIXED rendering
    overflow_ips = [
        nacaddr.IP('2001:4860:8000::5/128')
    ]

    ips = list(nacaddr.IP('10.0.8.0/22').subnets(new_prefix=32))
    v4_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        v4_ips.append(nacaddr.IP(ip))
      counter += 1

    ips = list(
        nacaddr.IP('2620:0:1000:3103:eca0:2c09:6b32:e000/118').subnets(
            new_prefix=128))
    v6_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        v6_ips.append(nacaddr.IP(ip))
      counter += 1

    self.naming.GetServiceByProto.side_effect = [['25', '25']]
    self.naming.GetNetAddr.side_effect = [overflow_ips + v4_ips + v6_ips]

    # GOOD_HEADER = MIXED rendering
    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_21, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))

    # extract address-set-names referenced in policy blocks
    partial_pruned_acl = output.split('replace: policies')[1].split(
        'destination-address [ ')[1:]

    # verify that there are exactly 6 terms in the ACL by checking if
    # partial_pruned_acl contains exactly 6 elements
    self.assertEqual(len(partial_pruned_acl), 6)

    for text in partial_pruned_acl:
      address_set_name = text.split(' ];')[0]

      if address_set_name:
        address_set_count = output.count(address_set_name)
        # check if each addresssetname referenced in policy occurs more than
        # once i.e. is defined in the address book
        self.assertGreater(address_set_count, 1)

  def testCreateV6AddressEntriesForV6Render2(self):
    # 513V6 and 512V4 IPs; V6 rendering
    overflow_ips = [
        nacaddr.IP('2001:4860:8000::5/128')
    ]

    ips = list(nacaddr.IP('10.0.8.0/22').subnets(new_prefix=32))
    v4_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        v4_ips.append(nacaddr.IP(ip))
      counter += 1

    ips = list(nacaddr.IP('2620:0:1000:3103:eca0:2c09:6b32:e000/118').subnets(new_prefix=128))
    v6_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        v6_ips.append(nacaddr.IP(ip))
      counter += 1

    self.naming.GetServiceByProto.side_effect = [['25', '25']]
    self.naming.GetNetAddr.side_effect = [overflow_ips + v4_ips + v6_ips]

    # GOOD_HEADER_4 = V6 rendering
    pol = policy.ParsePolicy(GOOD_HEADER_4 + GOOD_TERM_21, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))

    # extract address-set-names referenced in policy blocks
    partial_pruned_acl = output.split('replace: policies')[1].split(
        'destination-address [ ')[1:]

    # verify that there are exactly 5 terms in the ACL by checking if
    # partial_pruned_acl contains exactly 5 elements
    self.assertEqual(len(partial_pruned_acl), 5)

    for text in partial_pruned_acl:
      address_set_name = text.split(' ];')[0]

      if address_set_name:
        address_set_count = output.count(address_set_name)
        # check if each addresssetname referenced in policy occurs more than
        # once i.e. is defined in the address book
        self.assertGreater(address_set_count, 1)

  def testCreateV4AddressEntriesForV4Render2(self):
    # 513V6 and 512V4 IPs; V4 rendering
    overflow_ips = [
        nacaddr.IP('2001:4860:8000::5/128')
    ]

    ips = list(nacaddr.IP('10.0.8.0/22').subnets(new_prefix=32))
    v4_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        v4_ips.append(nacaddr.IP(ip))
      counter += 1

    ips = list(nacaddr.IP('2620:0:1000:3103:eca0:2c09:6b32:e000/118').subnets(new_prefix=128))
    v6_ips = []
    counter = 0
    for ip in ips:
      if counter % 2 == 0:
        v6_ips.append(nacaddr.IP(ip))
      counter += 1

    self.naming.GetServiceByProto.side_effect = [['25', '25']]
    self.naming.GetNetAddr.side_effect = [overflow_ips + v4_ips + v6_ips]

    # GOOD_HEADER_3 = V4 rendering
    pol = policy.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_21, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))

    # extract address-set-names referenced in policy blocks

    partial_pruned_acl = output.split('replace: policies')[1].split(
        'destination-address [ ')[1:]

    # verify that there is only one term in the ACL by checking if
    # partial_pruned_acl contains only one element
    self.assertEqual(len(partial_pruned_acl), 1)

    for text in partial_pruned_acl:
      address_set_name = text.split(' ];')[0]

      if address_set_name:
        address_set_count = output.count(address_set_name)
        # check if each addresssetname referenced in policy occurs more than
        # once i.e. is defined in the address book
        self.assertGreater(address_set_count, 1)

  def testEmptyApplications(self):
    self.naming.GetNetAddr.return_value = _IPSET

    # GOOD_HEADER_3 doesn't matter, any valid header should do
    pol = policy.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_23,
                             self.naming)
    p = junipersrx.JuniperSRX(pol, EXP_INFO)
    output = p._GenerateApplications()

    pattern = re.compile(r'delete: applications;')
    self.assertTrue(pattern.search(str(''.join(output))), ''.join(output))


if __name__ == '__main__':
  absltest.main()
