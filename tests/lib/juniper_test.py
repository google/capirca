# Copyright 2007 Google Inc. All Rights Reserved.
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

"""Unittest for juniper acl rendering module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import datetime
import re
import unittest

from lib import aclgenerator
from lib import juniper
from lib import nacaddr
from lib import naming
from lib import policy
import mock

import gflags as flags
import logging

FLAGS = flags.FLAGS

GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: juniper test-filter
}
"""
GOOD_HEADER_2 = """
header {
  target:: juniper test-filter bridge
}
"""
GOOD_HEADER_V6 = """
header {
  target:: juniper test-filter inet6
}
"""
GOOD_HEADER_BRIDGE = """
header {
  target:: juniper test-filter bridge
}
"""
GOOD_DSMO_HEADER = """
header {
  target:: juniper test-filter enable_dsmo
}
"""
GOOD_NOVERBOSE_V4_HEADER = """
header {
  target:: juniper test-filter inet noverbose
}
"""
GOOD_NOVERBOSE_V6_HEADER = """
header {
  target:: juniper test-filter inet6 noverbose
}
"""
GOOD_HEADER_NOT_INTERFACE_SPECIFIC = """
header {
  target:: juniper test-filter bridge not-interface-specific
}
"""
BAD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: cisco test-filter
}
"""
BAD_HEADER_2 = """
header {
  target:: juniper test-filter inetpoop
}
"""
EXPIRED_TERM = """
term is_expired {
  expiration:: 2001-01-01
  action:: accept
}
"""
EXPIRING_TERM = """
term is_expiring {
  expiration:: %s
  action:: accept
}
"""
GOOD_TERM_1 = """
term good-term-1 {
  protocol:: icmp
  action:: accept
}

term good-term-2 {
  protocol:: tcp
  destination-port:: SMTP
  destination-address:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_1_V6 = """
term good-term-1 {
  protocol:: icmpv6
  action:: accept
}

term good-term-2 {
  protocol:: tcp
  destination-port:: SMTP
  destination-address:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_2 = """
term good-term-3 {
  protocol:: tcp
  destination-address:: SOME_HOST
  source-port:: HTTP
  option:: established tcp-established
  action:: accept
}
"""
GOOD_TERM_3 = """
term good-term-3 {
  protocol:: icmp
  icmp-type:: echo-reply information-reply information-request
  icmp-type:: router-solicitation timestamp-request
  action:: accept
}
"""
GOOD_TERM_5 = """
term good-term-5 {
  protocol:: icmp
  protocol:: tcp
  action:: accept
}
"""
GOOD_TERM_7 = """
term good-term-7 {
  protocol-except:: tcp
  action:: accept
}
"""
GOOD_TERM_8 = """
term good-term-8 {
  source-prefix:: foo_prefix_list
  destination-prefix:: bar_prefix_list baz_prefix_list
  action:: accept
}
"""
GOOD_TERM_9 = """
term good-term-9 {
  ether-type:: arp
  action:: accept
}
"""
GOOD_TERM_10 = """
term good-term-10 {
  traffic-type:: unknown-unicast
  action:: accept
}
"""
GOOD_TERM_11 = """
term good-term-11 {
  verbatim:: juniper "mary had a little lamb"
  verbatim:: iptables "mary had a second lamb"
  verbatim:: cisco "mary had a third lamb"
}
"""
GOOD_TERM_12 = """
term good-term-12 {
  source-address:: LOCALHOST
  action:: accept
}
"""
GOOD_TERM_13 = """
term routing-instance-setting {
  protocol:: tcp
  routing-instance:: EXTERNAL-NAT
}
"""
GOOD_TERM_14 = """
term loss-priority-setting {
  protocol:: tcp
  loss-priority:: low
  action:: accept
}
"""
GOOD_TERM_15 = """
term precedence-setting {
  protocol:: tcp
  destination-port:: SSH
  precedence:: 7
  action:: accept
}
"""
GOOD_TERM_16 = """
term precedence-setting {
  protocol:: tcp
  destination-port:: SSH
  precedence:: 5 7
  action:: accept
}
"""
GOOD_TERM_17 = """
term owner-term {
  owner:: foo@google.com
  action:: accept
}
"""
GOOD_TERM_18_SRC = """
term address-exclusions {
  source-address:: INTERNAL
  source-exclude:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_18_DST = """
term address-exclusions {
  destination-address:: INTERNAL
  destination-exclude:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_19 = """
term minimize-prefix-list {
  source-address:: INCLUDES
  source-exclude:: EXCLUDES
  action:: accept
}
"""
GOOD_TERM_V6_HOP_LIMIT = """
term good-term-v6-hl {
  hop-limit:: 25
  action:: accept
}
"""
GOOD_TERM_20_V6 = """
term good-term-20-v6 {
  protocol-except:: icmpv6
  action:: accept
}
"""
GOOD_TERM_22 = """
term good_term_22 {
  protocol:: tcp
  source-port:: DNS
  dscp-set:: b111000
  action:: accept
}
"""
GOOD_TERM_23 = """
term good_term_23 {
  protocol:: tcp
  source-port:: DNS
  dscp-set:: af42
  dscp-match:: af41-af42 5
  dscp-except:: be
  action:: accept
}
"""
GOOD_TERM_24 = """
term good_term_24 {
  protocol:: tcp
  source-port:: DNS
  qos:: af1
  action:: accept
}
"""
GOOD_TERM_25 = """
term good_term_25 {
  protocol:: tcp
  source-port:: DNS
  action:: accept
}
"""
GOOD_TERM_26 = """
term good_term_26 {
  protocol:: tcp
  source-port:: DNS
  action:: deny
}
"""
GOOD_TERM_26_V6 = """
term good_term_26-v6 {
  protocol:: tcp
  source-port:: DNS
  action:: deny
}
"""
GOOD_TERM_26_V6_REJECT = """
term good_term_26-v6 {
  protocol:: tcp
  source-port:: DNS
  action:: reject
}
"""
GOOD_TERM_27 = """
term good_term_27 {
  forwarding-class:: floop
  action:: deny
}
"""
GOOD_TERM_28 = """
term good_term_28 {
  next-ip:: TEST_NEXT
}
"""
GOOD_TERM_29 = """
term multiple-forwarding-class {
  forwarding-class:: floop fluup fleep
  action:: deny
}
"""
GOOD_TERM_30 = """
term good-term-30 {
  source-prefix-except:: foo_prefix_list
  destination-prefix-except:: bar_prefix_list
  action:: accept
}
"""
GOOD_TERM_31 = """
term good-term-31 {
  source-prefix:: foo_prefix
  source-prefix-except:: foo_except
  destination-prefix:: bar_prefix
  destination-prefix-except:: bar_except
  action:: accept
}
"""
GOOD_TERM_32 = """
term good_term_32 {
  forwarding-class-except:: floop
  action:: deny
}
"""
GOOD_TERM_33 = """
term multiple-forwarding-class-except {
  forwarding-class-except:: floop fluup fleep
  action:: deny
}
"""
GOOD_TERM_34 = """
term good_term_34 {
  traffic-class-count:: floop
  action:: deny
}
"""
GOOD_TERM_35 = """
term good_term_35 {
  protocol:: icmp
  icmp-type:: unreachable
  icmp-code:: 3 4
  action:: accept
}
"""
GOOD_TERM_COMMENT = """
term good-term-comment {
  comment:: "This is a COMMENT"
  action:: accept
}
"""
BAD_TERM_1 = """
term bad-term-1 {
  protocol:: tcp udp
  source-port:: DNS
  option:: tcp-established
  action:: accept
}
"""
ESTABLISHED_TERM_1 = """
term established-term-1 {
  protocol:: tcp
  source-port:: DNS
  option:: established
  action:: accept
}
"""
OPTION_TERM_1 = """
term option-term {
  protocol:: tcp
  source-port:: SSH
  option:: is-fragment
  action:: accept
}
"""
BAD_ICMPTYPE_TERM_1 = """
term icmptype-mismatch {
  comment:: "error when icmpv6 paired with inet filter"
  protocol:: icmpv6
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""
BAD_ICMPTYPE_TERM_2 = """
term icmptype-mismatch {
  comment:: "error when icmp paired with inet6 filter"
  protocol:: icmp
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""
DEFAULT_TERM_1 = """
term default-term-1 {
  action:: deny
}
"""
LONG_COMMENT_TERM_1 = """
term long-comment-term-1 {
  comment:: "this is very very very very very very very very very very very
  comment:: "very very very very very very very long."
  action:: deny
}
"""
LONG_POLICER_TERM_1 = """
term long-policer-term-1 {
  policer:: this-is-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-long
  action:: deny
}
"""
HOPOPT_TERM = """
term good-term-1 {
  protocol:: hopopt
  action:: accept
}
"""
GOOD_FLEX_MATCH_TERM = """
term flex-match-term-1 {
  protocol:: tcp
  flexible-match-range:: bit-length 8
  flexible-match-range:: range 0x08
  flexible-match-range:: match-start payload
  flexible-match-range:: byte-offset 16
  flexible-match-range:: bit-offset 7
  action:: deny
}
"""
BAD_FLEX_MATCH_TERM_1 = """
term flex-match-term-1 {
  protocol:: tcp
  flexible-match-range:: bit-length 36
  flexible-match-range:: range 0x08
  flexible-match-range:: match-start payload
  flexible-match-range:: byte-offset 16
  flexible-match-range:: bit-offset 7
  action:: deny
}
"""
BAD_FLEX_MATCH_TERM_2 = """
term flex-match-term-1 {
  protocol:: tcp
  flexible-match-range:: bit-length 8
  flexible-match-range:: range 0x08
  flexible-match-range:: match-start wrong
  flexible-match-range:: byte-offset 16
  flexible-match-range:: bit-offset 7
  action:: deny
}
"""
BAD_FLEX_MATCH_TERM_3 = """
term flex-match-term-1 {
  protocol:: tcp
  flexible-match-range:: bit-length 8
  flexible-match-range:: range 0x08
  flexible-match-range:: match-start payload
  flexible-match-range:: byte-offset 260
  flexible-match-range:: bit-offset 7
  action:: deny
}
"""
BAD_FLEX_MATCH_TERM_4 = """
term flex-match-term-1 {
  protocol:: tcp
  flexible-match-range:: bit-length 8
  flexible-match-range:: range 0x08
  flexible-match-range:: match-start payload
  flexible-match-range:: byte-offset 16
  flexible-match-range:: bit-offset 8
  action:: deny
}
"""

SUPPORTED_TOKENS = {
    'action',
    'address',
    'comment',
    'counter',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'destination_prefix',
    'destination_prefix_except',
    'dscp_except',
    'dscp_match',
    'dscp_set',
    'ether_type',
    'expiration',
    'flexible_match_range',
    'forwarding_class',
    'forwarding_class_except',
    'fragment_offset',
    'hop_limit',
    'icmp_code',
    'icmp_type',
    'logging',
    'loss_priority',
    'name',
    'next_ip',
    'option',
    'owner',
    'packet_length',
    'platform',
    'platform_exclude',
    'policer',
    'port',
    'precedence',
    'protocol',
    'protocol_except',
    'qos',
    'routing_instance',
    'source_address',
    'source_address_exclude',
    'source_port',
    'source_prefix',
    'source_prefix_except',
    'traffic_class_count',
    'traffic_type',
    'translated',
    'verbatim',
}

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny', 'reject', 'next', 'reject-with-tcp-rst'},
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
    'option': {'established',
               'first-fragment',
               '.*',   # not actually a lex token!
               'sample',
               'tcp-established',
               'tcp-initial'}
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class JuniperTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testOptions(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['80']

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_2,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('destination-port 1024-65535;' in output, output)
    # Verify that tcp-established; doesn't get duplicated if both 'established'
    # and 'tcp-established' options are included in term
    self.assertEquals(output.count('tcp-established;'), 1)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('HTTP', 'tcp')

  def testTermAndFilterName(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('term good-term-1 {' in output, output)
    self.failUnless('filter test-filter {' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testBadFilterType(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(BAD_HEADER_2 + GOOD_TERM_1, self.naming)
    self.assertRaises(aclgenerator.UnsupportedAF, juniper.Juniper,
                      pol, EXP_INFO)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testBridgeFilterType(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER_2 + GOOD_TERM_1,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('ip-protocol tcp;' in output, output)
    self.failIf(' destination-address {' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testCommentShrinking(self):
    long_comment = ' this is a very descriptive comment ' * 10
    expected = (
        ' ' * 24 + '/* this is a very descriptive comment  this is a\n' +
        ' ' * 24 + '** very descriptive comment  this is a very\n' +
        ' ' * 24 + '** descriptive comment  this is a very descript */'
        )
    self.naming.GetNetAddr.return_value = (
            [nacaddr.IPv4('10.0.0.0/8', comment=long_comment)])
    self.naming.GetServiceByProto.return_value = ['25']

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless(expected in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testDefaultDeny(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + DEFAULT_TERM_1,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failIf('from {' in output, output)

  def testIcmpType(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_3,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    # verify proper translation from policy icmp-type text to juniper-esque
    self.failUnless(' icmp-type [' in output, output)
    self.failUnless(' 0 ' in output, output)
    self.failUnless(' 15 ' in output, output)
    self.failUnless(' 10 ' in output, output)
    self.failUnless(' 13 ' in output, output)
    self.failUnless(' 16 ' in output, output)
    self.failUnless('];' in output, output)

  def testIcmpCode(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_35,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('icmp-code [ 3 4 ];' in output, output)

  def testInet6(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2001::/33')]
    self.naming.GetServiceByProto.return_value = ['25']

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER_V6 + GOOD_TERM_1_V6,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('next-header icmpv6;' in output and
                    'next-header tcp;' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testNotInterfaceSpecificHeader(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    jcl = juniper.Juniper(
        policy.ParsePolicy(GOOD_HEADER_NOT_INTERFACE_SPECIFIC + GOOD_TERM_1,
                           self.naming), EXP_INFO)
    output = str(jcl)
    self.failIf('interface-specific;' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testInterfaceSpecificHeader(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('interface-specific;' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testHopLimit(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER_V6 +
                                             GOOD_TERM_V6_HOP_LIMIT,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('hop-limit 25;' in output, output)

  def testProtocolExcept(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER_V6 + GOOD_TERM_7,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('next-header-except tcp;' in output, output)

  def testIcmpv6Except(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER_V6 + GOOD_TERM_20_V6,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('next-header-except icmpv6;' in output, output)

  def testProtocolCase(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_5,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('protocol [ icmp tcp ];' in output, output)

  def testPrefixList(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_8,
                                             self.naming), EXP_INFO)
    spfx_re = re.compile('source-prefix-list {\W+foo_prefix_list;\W+}')
    dpfx_re = re.compile(
        'destination-prefix-list {\W+bar_prefix_list;\W+baz_prefix_list;\W+}')
    output = str(jcl)
    self.failUnless(spfx_re.search(output), output)
    self.failUnless(dpfx_re.search(output), output)

  def testPrefixListExcept(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_30,
                                             self.naming), EXP_INFO)
    spfx_re = re.compile('source-prefix-list {\W+foo_prefix_list except;\W+}')
    dpfx_re = re.compile(
        'destination-prefix-list {\W+bar_prefix_list except;\W+}')
    output = str(jcl)
    self.failUnless(spfx_re.search(output), output)
    self.failUnless(dpfx_re.search(output), output)

  def testPrefixListMixed(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_31,
                                             self.naming), EXP_INFO)
    spfx_re = re.compile('source-prefix-list {\W+foo_prefix;\W+'
                         'foo_except except;\W+}')
    dpfx_re = re.compile('destination-prefix-list {\W+bar_prefix;\W+'
                         'bar_except except;\W+}')
    output = str(jcl)
    self.failUnless(spfx_re.search(output), output)
    self.failUnless(dpfx_re.search(output), output)

  def testEtherType(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_9,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('ether-type arp;' in output, output)

  def testTrafficType(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_10,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('traffic-type unknown-unicast;' in output, output)

  def testVerbatimTerm(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_11,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('mary had a little lamb' in output, output)
    # check if other platforms verbatim shows up in output
    self.failIf('mary had a second lamb' in output, output)
    self.failIf('mary had a third lamb' in output, output)

  def testDscpByte(self):
    self.naming.GetServiceByProto.return_value = ['53']

    policy_text = GOOD_HEADER + GOOD_TERM_22
    jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming),
                          EXP_INFO)
    output = str(jcl)
    self.failUnless('dscp b111000;' in output, output)

    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')

  def testDscpClass(self):
    self.naming.GetServiceByProto.return_value = ['53']

    policy_text = GOOD_HEADER + GOOD_TERM_23
    jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming),
                          EXP_INFO)
    output = str(jcl)
    self.failUnless('dscp af42;' in output, output)
    self.failUnless('dscp [ af41-af42 5 ];' in output, output)
    self.failUnless('dscp-except [ be ];' in output, output)

    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')

  def testDscpIPv6(self):
    self.naming.GetServiceByProto.return_value = ['53']

    policy_text = GOOD_HEADER_V6 + GOOD_TERM_23
    jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming),
                          EXP_INFO)
    output = str(jcl)
    self.failUnless('traffic-class af42;' in output, output)
    self.failUnless('traffic-class [ af41-af42 5 ];' in output, output)
    self.failUnless('traffic-class-except [ be ];' in output, output)
    self.failIf('dscp' in output, output)

    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')

  def testSimplifiedThenStatement(self):
    self.naming.GetServiceByProto.return_value = ['53']

    policy_text = GOOD_HEADER + GOOD_TERM_24
    jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming),
                          EXP_INFO)
    output = str(jcl)
    self.failUnless('forwarding-class af1' in output, output)
    self.failUnless('accept' in output, output)

    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')

  def testSimplifiedThenStatementWithSingleAction(self):
    self.naming.GetServiceByProto.return_value = ['53']

    policy_text = GOOD_HEADER + GOOD_TERM_25
    jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming),
                          EXP_INFO)
    output = str(jcl)
    self.failUnless('then accept;' in output, output)

    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')

  def testSimplifiedThenStatementWithSingleActionDiscardIPv4(self):
    self.naming.GetServiceByProto.return_value = ['53']

    policy_text = GOOD_HEADER + GOOD_TERM_26
    jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming),
                          EXP_INFO)
    output = str(jcl)
    self.failUnless('then {' in  output, output)
    self.failUnless('discard;' in output, output)

    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')

  def testSimplifiedThenStatementWithSingleActionDiscardIPv6(self):
    self.naming.GetServiceByProto.return_value = ['53']

    policy_text = GOOD_HEADER_V6 + GOOD_TERM_26_V6
    jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming),
                          EXP_INFO)
    output = str(jcl)
    self.failUnless('then discard;' in output, output)

    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')

  def testSimplifiedThenStatementWithSingleActionRejectIPv6(self):
    self.naming.GetServiceByProto.return_value = ['53']

    policy_text = GOOD_HEADER_V6 + GOOD_TERM_26_V6_REJECT
    jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming),
                          EXP_INFO)
    output = str(jcl)
    self.failUnless('then {' in output, output)
    self.failUnless('reject;' in output, output)

    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')

  def testTcpEstablished(self):
    self.naming.GetServiceByProto.return_value = ['53']

    policy_text = GOOD_HEADER + ESTABLISHED_TERM_1
    jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming),
                          EXP_INFO)
    output = str(jcl)
    self.failUnless('tcp-established' in output, output)

    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')

  def testNonTcpWithTcpEstablished(self):
    self.naming.GetServiceByProto.return_value = ['53']

    policy_text = GOOD_HEADER + BAD_TERM_1
    pol_obj = policy.ParsePolicy(policy_text, self.naming)
    jcl = juniper.Juniper(pol_obj, EXP_INFO)
    self.assertRaises(juniper.TcpEstablishedWithNonTcp, str, jcl)

    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('DNS', 'tcp'), mock.call('DNS', 'udp')])

  def testBridgeFilterInetType(self):
    self.naming.GetNetAddr.return_value = [
            nacaddr.IPv4('127.0.0.1'), nacaddr.IPv6('::1/128')]

    jcl = juniper.Juniper(policy.ParsePolicy(
        GOOD_HEADER_BRIDGE + GOOD_TERM_12, self.naming), EXP_INFO)
    output = str(jcl)
    self.failIf('::1/128' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('LOCALHOST')

  def testNoVerboseV4(self):
    addr_list = list()
    for octet in range(0, 256):
      net = nacaddr.IP('192.168.' + str(octet) + '.64/27')
      addr_list.append(net)
    self.naming.GetNetAddr.return_value = addr_list
    self.naming.GetServiceByProto.return_value = ['25']

    jcl = juniper.Juniper(
        policy.ParsePolicy(
            GOOD_NOVERBOSE_V4_HEADER + GOOD_TERM_1 + GOOD_TERM_COMMENT,
            self.naming), EXP_INFO)
    self.failUnless('192.168.0.64/27;' in str(jcl))
    self.failUnless('COMMENT' not in str(jcl))
    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testNoVerboseV6(self):
    addr_list = list()
    for octet in range(0, 256):
      net = nacaddr.IPv6('2001:db8:1010:' + str(octet) + '::64/64')
      addr_list.append(net)
    self.naming.GetNetAddr.return_value = addr_list
    self.naming.GetServiceByProto.return_value = ['25']

    jcl = juniper.Juniper(
        policy.ParsePolicy(
            GOOD_NOVERBOSE_V6_HEADER + GOOD_TERM_1 + GOOD_TERM_COMMENT,
            self.naming), EXP_INFO)
    self.failUnless('2001:db8:1010:90::/61;' in str(jcl))
    self.failUnless('COMMENT' not in str(jcl))
    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testDsmo(self):
    addr_list = list()
    for octet in range(0, 256):
      net = nacaddr.IP('192.168.' + str(octet) + '.64/27')
      addr_list.append(net)
    self.naming.GetNetAddr.return_value = addr_list
    self.naming.GetServiceByProto.return_value = ['25']

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_DSMO_HEADER + GOOD_TERM_1,
                                             self.naming), EXP_INFO)
    self.failUnless('192.168.0.64/255.255.0.224;' in str(jcl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testDsmoJuniperFriendly(self):
    addr_list = [nacaddr.IP('192.168.%d.0/24' % octet) for octet in range(256)]
    self.naming.GetNetAddr.return_value = addr_list
    self.naming.GetServiceByProto.return_value = ['25']

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_DSMO_HEADER + GOOD_TERM_1,
                                             self.naming), EXP_INFO)
    self.failUnless('192.168.0.0/16;' in str(jcl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testDsmoExclude(self):
    big = nacaddr.IPv4('0.0.0.0/1')
    ip1 = nacaddr.IPv4('192.168.0.64/27')
    ip2 = nacaddr.IPv4('192.168.1.64/27')
    terms = (GOOD_TERM_18_SRC, GOOD_TERM_18_DST)
    self.naming.GetNetAddr.side_effect = [[big], [ip1, ip2]] * len(terms)

    mock_calls = []
    for term in terms:
      jcl = juniper.Juniper(
          policy.ParsePolicy(GOOD_DSMO_HEADER + term, self.naming),
          EXP_INFO)
      self.failUnless('192.168.0.64/255.255.254.224 except;' in str(jcl))
      mock_calls.append(mock.call('INTERNAL'))
      mock_calls.append(mock.call('SOME_HOST'))

    self.naming.GetNetAddr.assert_has_calls(mock_calls)

  def testTermTypeIndexKeys(self):
    # ensure an _INET entry for each _TERM_TYPE entry
    self.assertEquals(sorted(juniper.Term._TERM_TYPE.keys()),
                      sorted(juniper.Term.AF_MAP.keys()))

  def testRoutingInstance(self):
    jcl = juniper.Juniper(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_13, self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('routing-instance EXTERNAL-NAT;' in output, output)

  def testLossPriority(self):
    jcl = juniper.Juniper(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_14, self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('loss-priority low;' in output, output)

  def testPrecedence(self):
    self.naming.GetServiceByProto.return_value = ['22']

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_15,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('precedence 7;' in output, output)

    self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

  def testMultiplePrecedence(self):
    self.naming.GetServiceByProto.return_value = ['22']

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_16,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('precedence [ 5 7 ];' in output, output)

    self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

  def testArbitraryOptions(self):
    self.naming.GetServiceByProto.return_value = ['22']

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + OPTION_TERM_1,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('is-fragment;' in output, output)

    self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

  @mock.patch.object(juniper.logging, 'debug')
  def testIcmpv6InetMismatch(self, mock_debug):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + BAD_ICMPTYPE_TERM_1,
                                             self.naming), EXP_INFO)
    # output happens in __str_
    str(jcl)

    mock_debug.assert_called_once_with(
        'Term icmptype-mismatch will not be rendered,'
        ' as it has [u\'icmpv6\'] match specified but '
        'the ACL is of inet address family.')

  @mock.patch.object(juniper.logging, 'debug')
  def testIcmpInet6Mismatch(self, mock_debug):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER_V6 +
                                             BAD_ICMPTYPE_TERM_2,
                                             self.naming), EXP_INFO)
    # output happens in __str_
    str(jcl)

    mock_debug.assert_called_once_with(
            'Term icmptype-mismatch will not be rendered,'
            ' as it has [u\'icmp\'] match specified but '
            'the ACL is of inet6 address family.')

  @mock.patch.object(juniper.logging, 'warn')
  def testExpiredTerm(self, mock_warn):
    _ = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + EXPIRED_TERM,
                                           self.naming), EXP_INFO)

    mock_warn.assert_called_once_with(
        'WARNING: Term %s in policy %s is expired and will '
        'not be rendered.', 'is_expired', 'test-filter')

  @mock.patch.object(juniper.logging, 'info')
  def testExpiringTerm(self, mock_info):
    exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
    _ = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + EXPIRING_TERM %
                                           exp_date.strftime('%Y-%m-%d'),
                                           self.naming), EXP_INFO)

    mock_info.assert_called_once_with(
        'INFO: Term %s in policy %s expires in '
        'less than two weeks.', 'is_expiring', 'test-filter')

  def testOwnerTerm(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_17,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('            /*\n'
                    '            ** Owner: foo@google.com\n'
                    '            */' in output, output)

  def testAddressExclude(self):
    big = nacaddr.IPv4('0.0.0.0/1')
    ip1 = nacaddr.IPv4('10.0.0.0/8')
    ip2 = nacaddr.IPv4('172.16.0.0/12')
    terms = (GOOD_TERM_18_SRC, GOOD_TERM_18_DST)
    self.naming.GetNetAddr.side_effect = [[big, ip1, ip2], [ip1]] * len(terms)

    mock_calls = []
    for term in terms:
      jcl = juniper.Juniper(
          policy.ParsePolicy(GOOD_HEADER + term, self.naming),
          EXP_INFO)
      output = str(jcl)
      self.failUnless('10.0.0.0/8 except;' in output, output)
      self.failIf('10.0.0.0/8;' in output, output)
      self.failUnless('172.16.0.0/12;' in output, output)
      self.failIf('172.16.0.0/12 except;' in output, output)
      mock_calls.append(mock.call('INTERNAL'))
      mock_calls.append(mock.call('SOME_HOST'))

    self.naming.GetNetAddr.assert_has_calls(mock_calls)

  def testMinimizePrefixes(self):
    includes = ['1.0.0.0/8', '2.0.0.0/8']
    excludes = ['1.1.1.1/32', '2.0.0.0/8', '3.3.3.3/32']

    expected = ['1.0.0.0/8;',
                '1.1.1.1/32 except;']
    unexpected = ['2.0.0.0/8;',
                  '2.0.0.0/8 except;',
                  '3.3.3.3/32']

    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4(ip) for ip in includes],
        [nacaddr.IPv4(ip) for ip in excludes]]

    jcl = juniper.Juniper(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_19, self.naming),
        EXP_INFO)
    output = str(jcl)
    for result in expected:
      self.failUnless(result in output,
                      'expected "%s" in %s' % (result, output))
    for result in unexpected:
      self.failIf(result in output,
                  'unexpected "%s" in %s' % (result, output))

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('INCLUDES'), mock.call('EXCLUDES')])

  def testConfigHelper(self):
    config = juniper.Config()
    config.Append('test {')
    config.Append('blah {')
    config.Append('foo;')
    config.Append('bar;')
    config.Append('}')  # close blah{}
    config.Append(' Mr. T Pities the fool!', verbatim=True)

    # haven't closed everything yet
    self.assertRaises(juniper.JuniperIndentationError, lambda: str(config))

    config.Append('}')  # close test{}
    self.assertMultiLineEqual(str(config),
                              'test {\n'
                              '    blah {\n'
                              '        foo;\n'
                              '        bar;\n'
                              '    }\n'
                              ' Mr. T Pities the fool!\n'
                              '}')

    # one too many '}'
    self.assertRaises(juniper.JuniperIndentationError,
                      lambda: config.Append('}'))

  def testForwardingClass(self):
    policy_text = GOOD_HEADER + GOOD_TERM_27
    jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming),
                          EXP_INFO)
    output = str(jcl)
    self.failUnless('forwarding-class floop;' in output, output)

  def testForwardingClassExcept(self):
    policy_text = GOOD_HEADER + GOOD_TERM_32
    jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming),
                          EXP_INFO)
    output = str(jcl)
    self.failUnless('forwarding-class-except floop;' in output, output)

  def testTrafficClassCount(self):
    policy_text = GOOD_HEADER + GOOD_TERM_34
    jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming),
                          EXP_INFO)
    output = str(jcl)
    self.failUnless('traffic-class-count floop;' in output, output)

  def testMultipleForwardingClass(self):
    policy_text = GOOD_HEADER + GOOD_TERM_29
    jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming),
                          EXP_INFO)
    output = str(jcl)
    self.failUnless('forwarding-class [ floop fluup fleep ];' in output,
                    output)

  def testMultipleForwardingClassExcept(self):
    policy_text = GOOD_HEADER + GOOD_TERM_33
    jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming),
                          EXP_INFO)
    output = str(jcl)
    self.failUnless('forwarding-class-except [ floop fluup fleep ];' in output,
                    output)

  def testLongPolicer(self):
    with mock.patch.object(juniper.logging, 'warn', spec=logging.warn) as warn:
      policy_text = GOOD_HEADER + LONG_POLICER_TERM_1
      jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming),
                            EXP_INFO)
      _ = str(jcl)
      warn.assert_called_with('WARNING: %s is longer than %d bytes. Due to'
                              ' limitation in JUNOS, OIDs longer than %dB'
                              ' can cause SNMP timeout issues.', 'this-is-very'
                              '-very-very-very-very-very-very-very-very-very'
                              '-very-very-very-very-very-very-very-very-very'
                              '-very-very-very-very-very-very-very-very-very'
                              '-very-very-long', 128, 128)

  def testNextIp(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless(
        ('next-ip 10.1.1.1/32') in output)

    self.naming.GetNetAddr.assert_called_once_with('TEST_NEXT')

  def testNextIpFormat(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless(
        ('                then {\n'
         '                    next-ip 10.1.1.1/32;\n'
         '                }') in output)

    self.naming.GetNetAddr.assert_called_once_with('TEST_NEXT')

  def testNextIpv6(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2001::/128')]

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless(
        ('next-ip6 2001::/128;') in output)

    self.naming.GetNetAddr.assert_called_once_with('TEST_NEXT')

  def testFailNextIpMultipleIP(self):
    self.naming.GetNetAddr.return_value = [
        nacaddr.IP('10.1.1.1/32'), nacaddr.IP('192.168.1.1/32')]
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28,
                                             self.naming), EXP_INFO)
    self.assertRaises(juniper.JuniperNextIpError, str, jcl)

    self.naming.GetNetAddr.assert_called_once_with('TEST_NEXT')

  def testFailNextIpNetworkIP(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/26')]

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28,
                                             self.naming), EXP_INFO)
    self.assertRaises(juniper.JuniperNextIpError, str, jcl)

    self.naming.GetNetAddr.assert_called_once_with('TEST_NEXT')

  def testBuildTokens(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/26')]

    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28,
                                             self.naming), EXP_INFO)
    st, sst = jcl._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28,
                                             self.naming), EXP_INFO)
    st, sst = jcl._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

  def testHopOptProtocol(self):
    jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + HOPOPT_TERM,
                                             self.naming), EXP_INFO)
    output = str(jcl)
    self.failUnless('protocol hop-by-hop;' in output, output)

  def testFlexibleMatch(self):
    jcl = juniper.Juniper(policy.ParsePolicy(
        GOOD_HEADER + GOOD_FLEX_MATCH_TERM, self.naming), EXP_INFO)

    output = str(jcl)

    flexible_match_expected = [
        'flexible-match-range {',
        'bit-length 8;',
        'range 0x08;',
        'match-start payload;',
        'byte-offset 16;',
        'bit-offset 7;'
    ]

    self.assertEquals(all([x in output for x in flexible_match_expected]), True)

  def testFlexibleMatchIPv6(self):
    jcl = juniper.Juniper(policy.ParsePolicy(
        GOOD_HEADER_V6 + GOOD_FLEX_MATCH_TERM, self.naming), EXP_INFO)
    output = str(jcl)

    flexible_match_expected = [
        'flexible-match-range {',
        'bit-length 8;',
        'range 0x08;',
        'match-start payload;',
        'byte-offset 16;',
        'bit-offset 7;'
    ]

    self.assertEquals(all([x in output for x in flexible_match_expected]), True)

  def testFailFlexibleMatch(self):

    # bad bit-length
    self.assertRaises(policy.FlexibleMatchError,
                      policy.ParsePolicy,
                      GOOD_HEADER + BAD_FLEX_MATCH_TERM_1,
                      self.naming)
    self.assertRaises(policy.FlexibleMatchError,
                      policy.ParsePolicy,
                      GOOD_HEADER_V6 + BAD_FLEX_MATCH_TERM_1,
                      self.naming)

    # bad match-start
    self.assertRaises(policy.FlexibleMatchError,
                      policy.ParsePolicy,
                      GOOD_HEADER + BAD_FLEX_MATCH_TERM_2,
                      self.naming)
    self.assertRaises(policy.FlexibleMatchError,
                      policy.ParsePolicy,
                      GOOD_HEADER_V6 + BAD_FLEX_MATCH_TERM_2,
                      self.naming)

    # bad byte-offset
    self.assertRaises(policy.FlexibleMatchError,
                      policy.ParsePolicy,
                      GOOD_HEADER + BAD_FLEX_MATCH_TERM_3,
                      self.naming)
    self.assertRaises(policy.FlexibleMatchError,
                      policy.ParsePolicy,
                      GOOD_HEADER_V6 + BAD_FLEX_MATCH_TERM_3,
                      self.naming)

    # bad bit-offset
    self.assertRaises(policy.FlexibleMatchError,
                      policy.ParsePolicy,
                      GOOD_HEADER + BAD_FLEX_MATCH_TERM_4,
                      self.naming)
    self.assertRaises(policy.FlexibleMatchError,
                      policy.ParsePolicy,
                      GOOD_HEADER_V6 + BAD_FLEX_MATCH_TERM_4,
                      self.naming)


if __name__ == '__main__':
  unittest.main()
