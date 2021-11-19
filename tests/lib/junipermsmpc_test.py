# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Unittest for junipermsmpc acl rendering module."""

import datetime
import re
from absl.testing import absltest
from unittest import mock

from absl.testing import parameterized
from capirca.lib import junipermsmpc
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy

GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: msmpc test-filter inet
}
"""
GOOD_HEADER_V6 = """
header {
  target:: msmpc test-filter inet6
}
"""
GOOD_HEADER_MIXED = """
header {
  target:: msmpc test-filter mixed
}
"""
GOOD_HEADER_MIXED_IMPLICIT = """
header {
  target:: msmpc test-filter
}
"""
GOOD_NOVERBOSE_V4_HEADER = """
header {
  target:: msmpc test-filter noverbose inet
}
"""
GOOD_NOVERBOSE_V6_HEADER = """
header {
  target:: msmpc test-filter inet6 noverbose
}
"""
GOOD_HEADER_INGRESS = """
header {
  comment:: "this is a test acl"
  target:: msmpc test-filter ingress inet
}
"""
GOOD_HEADER_EGRESS = """
header {
  comment:: "this is a test acl"
  target:: msmpc test-filter egress inet
}
"""
BAD_HEADER_DIRECTION = """
header {
  comment:: "this is a test acl"
  target:: msmpc test-filter ingress egress inet
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
  target:: msmpc test-filter inetpoop
}
"""
BAD_HEADER_3 = """
header {
  target:: msmpc test-filter inet inet6
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
GOOD_TERM_8 = """
term good-term-8 {
  source-prefix:: foo_prefix_list
  destination-prefix:: bar_prefix_list baz_prefix_list
  action:: accept
}
"""
GOOD_TERM_11 = """
term good-term-11 {
  verbatim:: msmpc "mary had a little lamb"
  verbatim:: iptables "mary had a second lamb"
  verbatim:: cisco "mary had a third lamb"
  verbatim:: juniper "mary had a fourth lamb"
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
GOOD_TERM_35 = """
term good_term_35 {
  protocol:: icmp
  icmp-type:: unreachable
  icmp-code:: 3 4
  action:: accept
}
"""
GOOD_TERM_36 = """
term good-term-36 {
  protocol:: tcp
  destination-address:: SOME_HOST
  destination-address:: SOME_HOST
  option:: inactive
  action:: accept
}
"""
GOOD_TERM_NUMERIC_PROTOCOL = """
term good-term-numeric {
  protocol:: %s
  action:: accept
}
"""
GOOD_TERM_COMMENT = """
term good-term-comment {
  comment:: "This is a COMMENT"
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
RANGE_PORTS_TERM = """
term ranged-ports-1 {
  protocol:: udp
  destination-port:: BOOTPS
  destination-port:: BOOTPC
  action:: accept
}
"""
MIXED_TESTING_TERM = """
term good-term {
  protocol:: tcp
  source-address:: SOME_HOST
  destination-port:: SMTP
  destination-address:: SOME_OTHER_HOST
  action:: accept
}
"""

MIXED_TESTING_TERM_ICMP = """
term good-term-icmp {
  protocol:: icmp
  source-address:: SOME_HOST
  destination-address:: SOME_OTHER_HOST
  action:: accept
}

term good-term-icmp-2 {
  protocol:: icmp
  action:: accept
}

term good-term-icmpv6 {
  protocol:: icmpv6
  source-address:: SOME_HOST
  destination-address:: SOME_OTHER_HOST
  action:: accept
}

term good-term-icmpv6-2 {
  protocol:: icmpv6
  action:: accept
}

term good-term-both-icmp-and-icmpv6 {
  protocol:: icmp
  protocol:: icmpv6
  source-address:: SOME_HOST
  destination-address:: SOME_OTHER_HOST
  action:: accept
}

term good-term-both-icmp-and-icmpv6-2 {
  protocol:: icmp
  protocol:: icmpv6
  source-address:: SOME_HOST
  destination-address:: SOME_OTHER_HOST
  action:: accept
}

"""
LOGGING_TERM = """
term good-term-1 {
  protocol:: icmp
  action:: accept
  logging:: %s
}
"""
TERM_NAME_COLLISION = """
term good-term-1%s {
  protocol:: icmp
  action:: accept
}

term hood-term-1%s {
  protocol:: tcp
  action:: accept
}
"""

SUPPORTED_TOKENS = frozenset([
    'action', 'comment', 'destination_address', 'destination_address_exclude',
    'destination_port', 'destination_prefix', 'destination_prefix_except',
    'expiration', 'icmp_code', 'icmp_type', 'stateless_reply', 'logging',
    'name', 'option', 'owner', 'platform', 'platform_exclude', 'protocol',
    'source_address', 'source_address_exclude', 'source_port', 'source_prefix',
    'source_prefix_except', 'translated', 'verbatim'
])

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
    'option': {
        'established',
        'inactive',
        '.*',  # not actually a lex token!
        'tcp-established',
    }
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class JuniperMSMPCTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def testTermAndFilterName(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1, self.naming), EXP_INFO)
    output = str(msmpc)
    self.assertIn('term good-term-1 {', output, output)
    self.assertIn('rule test-filter {', output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testBadFilterType(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(BAD_HEADER_2 + GOOD_TERM_1, self.naming)
    self.assertRaises(junipermsmpc.UnsupportedHeaderError,
                      junipermsmpc.JuniperMSMPC, pol, EXP_INFO)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testMultipleFilterType(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policy.ParsePolicy(BAD_HEADER_3 + GOOD_TERM_1, self.naming)
    self.assertRaises(junipermsmpc.ConflictingTargetOptionsError,
                      junipermsmpc.JuniperMSMPC, pol, EXP_INFO)

  def testMixedv4(self):
    self.naming.GetNetAddr.return_value = ([nacaddr.IPv4('192.168.0.0/24')])
    self.naming.GetServiceByProto.return_value = ['25']
    expected = ('                    term good-term-2 {\n' +
                '                        from {\n' +
                '                            destination-address {\n' +
                '                                192.168.0.0/24;\n' +
                '                            }')

    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM_1, self.naming),
        EXP_INFO)
    output = str(msmpc)
    self.assertIn(expected, output, output)

  def testMixedv6(self):
    self.naming.GetNetAddr.return_value = ([nacaddr.IPv6('2001::/33')])
    self.naming.GetServiceByProto.return_value = ['25']
    expected = ('                    term good-term-2 {\n' +
                '                        from {\n' +
                '                            destination-address {\n' +
                '                                2001::/33;\n' +
                '                            }')

    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM_1, self.naming),
        EXP_INFO)
    output = str(msmpc)
    self.assertIn(expected, output, output)

  def testMixedBoth(self):
    self.naming.GetNetAddr.return_value = ([
        nacaddr.IPv4('192.168.0.0/24'),
        nacaddr.IPv6('2001::/33')
    ])
    self.naming.GetServiceByProto.return_value = ['25']
    expectedv4 = ('                    term good-term-2-inet {\n' +
                  '                        from {\n' +
                  '                            destination-address {\n' +
                  '                                192.168.0.0/24;\n' +
                  '                            }')
    expectedv6 = ('                    term good-term-2-inet6 {\n' +
                  '                        from {\n' +
                  '                            destination-address {\n' +
                  '                                2001::/33;\n' +
                  '                            }')

    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM_1, self.naming),
        EXP_INFO)
    output = str(msmpc)
    self.assertIn(expectedv4, output, output)
    self.assertIn(expectedv6, output, output)

  def testCommentShrinking(self):
    long_comment = ' this is a very descriptive comment ' * 10
    expected = (' ' * 32 + '/* this is a very descriptive comment  this\n' +
                ' ' * 33 + '** is a very descriptive comment  this is a\n' +
                ' ' * 33 + '** very descriptive comment  this is a very\n' +
                ' ' * 33 + '** descript */')
    self.naming.GetNetAddr.return_value = ([
        nacaddr.IPv4('10.0.0.0/8', comment=long_comment)
    ])
    self.naming.GetServiceByProto.return_value = ['25']

    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1, self.naming), EXP_INFO)
    output = str(msmpc)
    self.assertIn(expected, output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testDefaultDeny(self):
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + DEFAULT_TERM_1, self.naming), EXP_INFO)
    output = str(msmpc)
    self.assertNotIn('from {', output, output)
    self.assertIn('discard;', output, output)

  def testIcmpType(self):
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_3, self.naming), EXP_INFO)
    output = str(msmpc)
    # verify proper translation from policy icmp-type text to juniper-esque
    self.assertIn('icmp-type 0;', output, output)
    self.assertIn('icmp-type 15;', output, output)
    self.assertIn('icmp-type 10;', output, output)
    self.assertIn('icmp-type 13;', output, output)
    self.assertIn('icmp-type 16;', output, output)

  def testIcmpCode(self):
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_35, self.naming), EXP_INFO)
    output = str(msmpc)
    self.assertIn('icmp-code [ 3 4 ];', output, output)

  def testInactiveTerm(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_36, self.naming), EXP_INFO)
    output = str(msmpc)
    self.assertIn('inactive: term good-term-36 {', output)

  def testInet6(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2001::/33')]
    self.naming.GetServiceByProto.return_value = ['25']

    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER_V6 + GOOD_TERM_1_V6, self.naming),
        EXP_INFO)
    output = str(msmpc)
    self.assertTrue('protocol icmp6;' in output and 'protocol tcp;' in output,
                    output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testProtocolCase(self):
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_5, self.naming), EXP_INFO)
    output = str(msmpc)
    expected_output = (
        '            application test-filtergood-term-5-app1 {\n' +
        '                protocol icmp;\n' + '            }\n' +
        '            application test-filtergood-term-5-app2 {\n' +
        '                protocol tcp;\n' +
        '                destination-port 1-65535;\n' + '            }')

    self.assertIn(expected_output, output, output)

  def testPrefixList(self):
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_8, self.naming), EXP_INFO)
    spfx_re = re.compile(r'source-prefix-list foo_prefix_list;')
    dpfx_re = re.compile(
        r'destination-prefix-list bar_prefix_list;\W+destination-prefix-list baz_prefix_list;'
    )
    output = str(msmpc)
    self.assertTrue(spfx_re.search(output), output)
    self.assertTrue(dpfx_re.search(output), output)

  def testPrefixListExcept(self):
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_30, self.naming), EXP_INFO)
    spfx_re = re.compile(r'source-prefix-list foo_prefix_list except;')
    dpfx_re = re.compile(r'destination-prefix-list bar_prefix_list except;')
    output = str(msmpc)
    self.assertTrue(spfx_re.search(output), output)
    self.assertTrue(dpfx_re.search(output), output)

  def testPrefixListMixed(self):
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_31, self.naming), EXP_INFO)
    spfx_re = re.compile(r'source-prefix-list foo_prefix;\W+'
                         r'source-prefix-list foo_except except;')
    dpfx_re = re.compile(r'destination-prefix-list bar_prefix;\W+'
                         r'destination-prefix-list bar_except except;')
    output = str(msmpc)
    self.assertTrue(spfx_re.search(output), output)
    self.assertTrue(dpfx_re.search(output), output)

  def testVerbatimTerm(self):
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_11, self.naming), EXP_INFO)
    output = str(msmpc)
    self.assertIn('mary had a little lamb', output, output)
    # check if other platforms verbatim shows up in output
    self.assertNotIn('mary had a second lamb', output, output)
    self.assertNotIn('mary had a third lamb', output, output)
    self.assertNotIn('mary had a fourth lamb', output, output)

  def testAccept(self):
    self.naming.GetServiceByProto.return_value = ['53']

    policy_text = GOOD_HEADER + GOOD_TERM_25
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
    output = str(msmpc)
    self.assertIn('then {', output, output)
    self.assertIn('accept;', output, output)

    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')

  def testDiscardIPv4(self):
    self.naming.GetServiceByProto.return_value = ['53']

    policy_text = GOOD_HEADER + GOOD_TERM_26
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
    output = str(msmpc)
    self.assertIn('then {', output, output)
    self.assertIn('discard;', output, output)

    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')

  def testDiscardIPv6(self):
    self.naming.GetServiceByProto.return_value = ['53']

    policy_text = GOOD_HEADER_V6 + GOOD_TERM_26_V6
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
    output = str(msmpc)
    self.assertIn('then {', output, output)
    self.assertIn('discard;', output, output)

    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')

  def testRejectIPv6(self):
    self.naming.GetServiceByProto.return_value = ['53']

    policy_text = GOOD_HEADER_V6 + GOOD_TERM_26_V6_REJECT
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
    output = str(msmpc)
    self.assertIn('then {', output, output)
    self.assertIn('reject;', output, output)

    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')

  def testTcpEstablished(self):
    self.naming.GetServiceByProto.return_value = ['53']

    policy_text = GOOD_HEADER + ESTABLISHED_TERM_1
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
    output = str(msmpc)
    self.assertNotIn('term established-term-1', output, output)
    self.assertNotIn('tcp-established', output, output)

    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')

  def testStatelessReply(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.1/32')]
    self.naming.GetServiceByProto.return_value = ['25']

    ret = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1, self.naming)

    _, terms = ret.filters[0]
    for term in terms:
      if term.protocol[0] == 'icmp':
        term.stateless_reply = True

    msmpc = junipermsmpc.JuniperMSMPC(ret, EXP_INFO)

    output = str(msmpc)
    self.assertNotIn('term good-term-1 {', output, output)
    self.assertIn('term good-term-2 {', output, output)

  def testNoVerboseV4(self):
    addr_list = list()
    for octet in range(0, 256):
      net = nacaddr.IP('192.168.' + str(octet) + '.64/27')
      addr_list.append(net)
    self.naming.GetNetAddr.return_value = addr_list
    self.naming.GetServiceByProto.return_value = ['25']

    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(
            GOOD_NOVERBOSE_V4_HEADER + GOOD_TERM_1 + GOOD_TERM_COMMENT,
            self.naming), EXP_INFO)
    self.assertIn('192.168.0.64/27;', str(msmpc))
    self.assertNotIn('COMMENT', str(msmpc))
    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testNoVerboseV6(self):
    addr_list = list()
    for octet in range(0, 256):
      net = nacaddr.IPv6(
          '2001:db8:1010:' + str(octet) + '::64/64', strict=False)
      addr_list.append(net)
    self.naming.GetNetAddr.return_value = addr_list
    self.naming.GetServiceByProto.return_value = ['25']

    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(
            GOOD_NOVERBOSE_V6_HEADER + GOOD_TERM_1 + GOOD_TERM_COMMENT,
            self.naming), EXP_INFO)
    self.assertIn('2001:db8:1010:90::/61;', str(msmpc))
    self.assertNotIn('COMMENT', str(msmpc))
    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testTermTypeIndexKeys(self):
    # ensure an _INET entry for each _TERM_TYPE entry
    self.assertCountEqual(junipermsmpc.Term._TERM_TYPE.keys(),
                          junipermsmpc.Term.AF_MAP.keys())

  @mock.patch.object(junipermsmpc.logging, 'debug')
  def testIcmpv6InetMismatch(self, mock_debug):
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + BAD_ICMPTYPE_TERM_1, self.naming),
        EXP_INFO)
    # output happens in __str_
    str(msmpc)

    mock_debug.assert_called_once_with(
        'Term icmptype-mismatch will not be rendered,'
        ' as it has icmpv6 match specified but '
        'the ACL is of inet address family.')

  @mock.patch.object(junipermsmpc.logging, 'debug')
  def testIcmpInet6Mismatch(self, mock_debug):
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER_V6 + BAD_ICMPTYPE_TERM_2, self.naming),
        EXP_INFO)
    # output happens in __str_
    str(msmpc)

    mock_debug.assert_called_once_with(
        'Term icmptype-mismatch will not be rendered,'
        ' as it has icmp match specified but '
        'the ACL is of inet6 address family.')

  @mock.patch.object(junipermsmpc.logging, 'warning')
  def testExpiredTerm(self, mock_warn):
    _ = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + EXPIRED_TERM, self.naming), EXP_INFO)

    mock_warn.assert_called_once_with(
        'WARNING: Term %s in policy %s is expired and will '
        'not be rendered.', 'is_expired', 'test-filter')

  @mock.patch.object(junipermsmpc.logging, 'info')
  def testExpiringTerm(self, mock_info):
    exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
    _ = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(
            GOOD_HEADER + EXPIRING_TERM % exp_date.strftime('%Y-%m-%d'),
            self.naming), EXP_INFO)

    mock_info.assert_called_once_with(
        'INFO: Term %s in policy %s expires in '
        'less than two weeks.', 'is_expiring', 'test-filter')

  def testOwnerTerm(self):
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_17, self.naming), EXP_INFO)
    output = str(msmpc)
    self.assertIn(
        '                    /*\n'
        '                     ** Owner: foo@google.com\n'
        '                     */', output, output)

  def testOwnerNoVerboseTerm(self):
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_NOVERBOSE_V4_HEADER + GOOD_TERM_17,
                           self.naming), EXP_INFO)
    output = str(msmpc)
    self.assertNotIn('** Owner: ', output, output)

  def testAddressExclude(self):
    big = nacaddr.IPv4('0.0.0.0/1', comment='half of everything')
    ip1 = nacaddr.IPv4('10.0.0.0/8', comment='RFC1918 10-net')
    ip2 = nacaddr.IPv4('172.16.0.0/12', comment='RFC1918 172-net')
    terms = (GOOD_TERM_18_SRC, GOOD_TERM_18_DST)
    self.naming.GetNetAddr.side_effect = [[big, ip1, ip2], [ip1]] * len(terms)

    mock_calls = []
    for term in terms:
      msmpc = junipermsmpc.JuniperMSMPC(
          policy.ParsePolicy(GOOD_HEADER + term, self.naming), EXP_INFO)
      output = str(msmpc)
      expected_output = (
          '                            ' +
          ('source' if term == GOOD_TERM_18_SRC else 'destination') +
          '-address {\n' +
          '                                /* half of everything, RFC1918 '
          '10-net */\n' + '                                0.0.0.0/1;\n' +
          '                                /* RFC1918 172-net */\n' +
          '                                172.16.0.0/12;\n' +
          '                                /* RFC1918 10-net */\n' +
          '                                10.0.0.0/8 except;\n' +
          '                            }')
      self.assertIn(expected_output, output, output)
      self.assertNotIn('10.0.0.0/8;', output, output)
      self.assertNotIn('172.16.0.0/12 except;', output, output)
      mock_calls.append(mock.call('INTERNAL'))
      mock_calls.append(mock.call('SOME_HOST'))

    self.naming.GetNetAddr.assert_has_calls(mock_calls)

  def testMinimizePrefixes(self):
    includes = ['1.0.0.0/8', '2.0.0.0/8']
    excludes = ['1.1.1.1/32', '2.0.0.0/8', '3.3.3.3/32']

    expected = ['1.0.0.0/8;', '1.1.1.1/32 except;']
    unexpected = ['2.0.0.0/8;', '2.0.0.0/8 except;', '3.3.3.3/32']

    self.naming.GetNetAddr.side_effect = [[nacaddr.IPv4(ip) for ip in includes],
                                          [nacaddr.IPv4(ip) for ip in excludes]]

    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_19, self.naming), EXP_INFO)
    output = str(msmpc)
    for result in expected:
      self.assertIn(result, output, 'expected "%s" in %s' % (result, output))
    for result in unexpected:
      self.assertNotIn(result, output,
                       'unexpected "%s" in %s' % (result, output))

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('INCLUDES'), mock.call('EXCLUDES')])

  def testNoMatchReversal(self):
    includes = ['10.0.0.0/8', '10.0.0.0/10']
    excludes = ['10.0.0.0/9']

    expected = ['10.0.0.0/8;', '10.0.0.0/10;', '10.0.0.0/9 except;']

    self.naming.GetNetAddr.side_effect = [[nacaddr.IPv4(ip) for ip in includes],
                                          [nacaddr.IPv4(ip) for ip in excludes]]

    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_19, self.naming), EXP_INFO)
    output = str(msmpc)
    for result in expected:
      self.assertIn(result, output)

  def testBuildTokens(self):
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_35, self.naming), EXP_INFO)
    st, sst = msmpc._BuildTokens()
    self.assertSetEqual(st, SUPPORTED_TOKENS)
    self.assertDictEqual(sst, SUPPORTED_SUB_TOKENS)

  def testRangedPorts(self):
    self.naming.GetServiceByProto.side_effect = [['67'], ['68']]
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + RANGE_PORTS_TERM, self.naming),
        EXP_INFO)
    self.assertIn('destination-port 67-68;', str(msmpc))

  def testNotRangedPorts(self):
    self.naming.GetServiceByProto.side_effect = [['67'], ['69']]
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + RANGE_PORTS_TERM, self.naming),
        EXP_INFO)
    self.assertNotIn('destination-port 67-68;', str(msmpc))
    self.assertIn('destination-port 67;', str(msmpc))
    self.assertIn('destination-port 69;', str(msmpc))

  def testApplicationSets(self):
    self.naming.GetServiceByProto.side_effect = [['67'], ['69']]
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + RANGE_PORTS_TERM, self.naming),
        EXP_INFO)
    expected = ('        applications {\n'
                '            application test-filterranged-ports-1-app1 {\n'
                '                protocol udp;\n'
                '                destination-port 67;\n'
                '            }\n'
                '            application test-filterranged-ports-1-app2 {\n'
                '                protocol udp;\n'
                '                destination-port 69;\n'
                '            }\n'
                '            application-set test-filterranged-ports-1-app {\n'
                '                application test-filterranged-ports-1-app1;\n'
                '                application test-filterranged-ports-1-app2;\n'
                '            }\n'
                '        }\n')
    self.assertIn(expected, str(msmpc))

  def testGroup(self):
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + DEFAULT_TERM_1, self.naming), EXP_INFO)
    self.assertEqual('b;', msmpc._Group(['B']))
    self.assertEqual('B;', msmpc._Group(['B'], lc=False))
    self.assertEqual('b;', msmpc._Group(['B'], lc=True))
    self.assertEqual('100;', msmpc._Group([100]))
    self.assertEqual('100-200;', msmpc._Group([(100, 200)]))
    self.assertEqual('[ b a ];', msmpc._Group(['b', 'A']))
    self.assertEqual('[ 99 101-199 ];', msmpc._Group([99, (101, 199)]))
    self.assertEqual('[ 99 101-199 ];', msmpc._Group([99, (101, 199)]))

  @parameterized.named_parameters(
      dict(
          testcase_name='MIXED_TO_V4',
          addresses=[[nacaddr.IPv4('0.0.0.0/1'),
                      nacaddr.IPv6('2001::/33')],
                     [nacaddr.IPv4('192.168.0.0/24')]],
          expected=[
              '                    term good-term-inet {\n' +
              '                        from {\n' +
              '                            source-address {\n' +
              '                                0.0.0.0/1;\n' +
              '                            }\n' +
              '                            destination-address {\n' +
              '                                192.168.0.0/24;\n' +
              '                            }'
          ],
          notexpected=['2001::/33']),
      dict(
          testcase_name='V4_TO_MIXED',
          addresses=[
              [nacaddr.IPv4('192.168.0.0/24')],
              [nacaddr.IPv4('0.0.0.0/1'),
               nacaddr.IPv6('2001::/33')],
          ],
          expected=[
              '                    term good-term-inet {\n' +
              '                        from {\n' +
              '                            source-address {\n' +
              '                                192.168.0.0/24;\n' +
              '                            }\n' +
              '                            destination-address {\n' +
              '                                0.0.0.0/1;\n' +
              '                            }'
          ],
          notexpected=['2001::/33']),
      dict(
          testcase_name='MIXED_TO_V6',
          addresses=[[nacaddr.IPv4('0.0.0.0/1'),
                      nacaddr.IPv6('2001::/33')], [nacaddr.IPv6('2201::/48')]],
          expected=[
              '                    term good-term-inet6 {\n' +
              '                        from {\n' +
              '                            source-address {\n' +
              '                                2001::/33;\n' +
              '                            }\n' +
              '                            destination-address {\n' +
              '                                2201::/48;\n' +
              '                            }'
          ],
          notexpected=['0.0.0.0/1']),
      dict(
          testcase_name='V6_TO_MIXED',
          addresses=[[nacaddr.IPv6('2201::/48')],
                     [nacaddr.IPv4('0.0.0.0/1'),
                      nacaddr.IPv6('2001::/33')]],
          expected=[
              '                    term good-term-inet6 {\n' +
              '                        from {\n' +
              '                            source-address {\n' +
              '                                2201::/48;\n' +
              '                            }\n' +
              '                            destination-address {\n' +
              '                                2001::/33;\n' +
              '                            }'
          ],
          notexpected=['0.0.0.0/1']),
      dict(
          testcase_name='MIXED_TO_MIXED',
          addresses=[[nacaddr.IPv4('0.0.0.0/1'),
                      nacaddr.IPv6('2001::/33')],
                     [
                         nacaddr.IPv4('192.168.0.0/24'),
                         nacaddr.IPv6('2201::/48')
                     ]],
          expected=[
              '                    term good-term-inet {\n' +
              '                        from {\n' +
              '                            source-address {\n' +
              '                                0.0.0.0/1;\n' +
              '                            }\n' +
              '                            destination-address {\n' +
              '                                192.168.0.0/24;\n' +
              '                            }',
              '                    term good-term-inet6 {\n' +
              '                        from {\n' +
              '                            source-address {\n' +
              '                                2001::/33;\n' +
              '                            }\n' +
              '                            destination-address {\n' +
              '                                2201::/48;\n' +
              '                            }'
          ],
          notexpected=[]),
      dict(
          testcase_name='V4_TO_V4',
          addresses=[[nacaddr.IPv4('0.0.0.0/1')],
                     [nacaddr.IPv4('192.168.0.0/24')]],
          expected=[
              '                    term good-term {\n' +
              '                        from {\n' +
              '                            source-address {\n' +
              '                                0.0.0.0/1;\n' +
              '                            }\n' +
              '                            destination-address {\n' +
              '                                192.168.0.0/24;\n' +
              '                            }'
          ],
          notexpected=[]),
      dict(
          testcase_name='V6_TO_V6',
          addresses=[[nacaddr.IPv6('2001::/33')], [nacaddr.IPv6('2201::/48')]],
          expected=[
              '                    term good-term {\n' +
              '                        from {\n' +
              '                            source-address {\n' +
              '                                2001::/33;\n' +
              '                            }\n' +
              '                            destination-address {\n' +
              '                                2201::/48;\n' +
              '                            }'
          ],
          notexpected=[]),
      dict(
          testcase_name='V4_TO_V6',
          addresses=[[nacaddr.IPv4('0.0.0.0/1')], [nacaddr.IPv6('2201::/48')]],
          expected=[],
          notexpected=['0.0.0.0/1', '192.168.0.0/24', '2001::/33', '2201::/48'],
      ),
      dict(
          testcase_name='V6_TO_V4',
          addresses=[[nacaddr.IPv6('2001::/33')],
                     [nacaddr.IPv4('192.168.0.0/24')]],
          expected=[],
          notexpected=['0.0.0.0/1', '192.168.0.0/24', '2001::/33', '2201::/48'],
      ),
      dict(
          testcase_name='PARTLY_UNSPECIFIED',
          addresses=[[nacaddr.IPv6('2001::/33')],
                     [nacaddr.IPv4('192.168.0.0/24')]],
          expected=['term good_term_25 '],
          notexpected=[
              '0.0.0.0/1', '192.168.0.0/24', '2001::/33', '2201::/48',
              'term good-term-both-icmp-and-icmpv6-'
          ],
      ),
  )
  def testMixed(self, addresses, expected, notexpected):
    self.naming.GetNetAddr.side_effect = addresses
    self.naming.GetServiceByProto.return_value = ['25']
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(
            GOOD_HEADER_MIXED + MIXED_TESTING_TERM + GOOD_TERM_25, self.naming),
        EXP_INFO)
    output = str(msmpc)
    for expect in expected:
      self.assertIn(expect, output, output)
    for notexpect in notexpected:
      self.assertNotIn(notexpect, output, output)

  @parameterized.named_parameters(
      dict(
          testcase_name='MIXED_TO_V4',
          addresses=[[nacaddr.IPv4('0.0.0.0/1'),
                      nacaddr.IPv6('2001::/33')],
                     [nacaddr.IPv4('192.168.0.0/24')]],
          expected=[
              '                    term good-term-icmp-inet {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                0.0.0.0/1;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                192.168.0.0/24;\n'
              '                            }\n'
              '                            application-sets test-filtergood-term-icmp-app;\n'
              '                        }',
              '                    term good-term-icmp-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmp-app;\n'
              '                        }',
              '                    term good-term-icmpv6-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6-inet {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                0.0.0.0/1;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                192.168.0.0/24;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6-2-inet {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                0.0.0.0/1;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                192.168.0.0/24;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
          ],
          notexpected=['2001::/33']),
      dict(
          testcase_name='V4_TO_MIXED',
          addresses=[
              [nacaddr.IPv4('192.168.0.0/24')],
              [nacaddr.IPv4('0.0.0.0/1'),
               nacaddr.IPv6('2001::/33')],
          ],
          expected=[
              '                    term good-term-icmp-inet {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                192.168.0.0/24;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                0.0.0.0/1;\n'
              '                            }\n'
              '                            application-sets test-filtergood-term-icmp-app;\n'
              '                        }',
              '                    term good-term-icmp-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmp-app;\n'
              '                        }',
              '                    term good-term-icmpv6-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6-inet {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                192.168.0.0/24;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                0.0.0.0/1;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6-2-inet {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                192.168.0.0/24;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                0.0.0.0/1;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
          ],
          notexpected=['2001::/33']),
      dict(
          testcase_name='MIXED_TO_V6',
          addresses=[[nacaddr.IPv4('0.0.0.0/1'),
                      nacaddr.IPv6('2001::/33')], [nacaddr.IPv6('2201::/48')]],
          expected=[
              '                    term good-term-icmp-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmp-app;\n'
              '                        }',
              '                    term good-term-icmpv6-inet6 {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                2001::/33;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                2201::/48;\n'
              '                            }\n'
              '                            application-sets test-filtergood-term-icmpv6-app;\n'
              '                        }',
              '                    term good-term-icmpv6-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6-inet6 {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                2001::/33;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                2201::/48;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6-2-inet6 {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                2001::/33;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                2201::/48;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
          ],
          notexpected=['0.0.0.0/1']),
      dict(
          testcase_name='V6_TO_MIXED',
          addresses=[[nacaddr.IPv6('2201::/48')],
                     [nacaddr.IPv4('0.0.0.0/1'),
                      nacaddr.IPv6('2001::/33')]],
          expected=[
              '                    term good-term-icmp-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmp-app;\n'
              '                        }',
              '                    term good-term-icmpv6-inet6 {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                2201::/48;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                2001::/33;\n'
              '                            }\n'
              '                            application-sets test-filtergood-term-icmpv6-app;\n'
              '                        }',
              '                    term good-term-icmpv6-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6-inet6 {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                2201::/48;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                2001::/33;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6-2-inet6 {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                2201::/48;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                2001::/33;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
          ],
          notexpected=['0.0.0.0/1']),
      dict(
          testcase_name='MIXED_TO_MIXED',
          addresses=[[nacaddr.IPv4('0.0.0.0/1'),
                      nacaddr.IPv6('2001::/33')],
                     [
                         nacaddr.IPv4('192.168.0.0/24'),
                         nacaddr.IPv6('2201::/48')
                     ]],
          expected=[
              '                    term good-term-icmp-inet {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                0.0.0.0/1;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                192.168.0.0/24;\n'
              '                            }\n'
              '                            application-sets test-filtergood-term-icmp-app;\n'
              '                        }',
              '                    term good-term-icmp-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmp-app;\n'
              '                        }',
              '                    term good-term-icmpv6-inet6 {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                2001::/33;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                2201::/48;\n'
              '                            }\n'
              '                            application-sets test-filtergood-term-icmpv6-app;\n'
              '                        }',
              '                    term good-term-icmpv6-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6-inet {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                0.0.0.0/1;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                192.168.0.0/24;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6-inet6 {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                2001::/33;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                2201::/48;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6-2-inet {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                0.0.0.0/1;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                192.168.0.0/24;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6-2-inet6 {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                2001::/33;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                2201::/48;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
          ],
          notexpected=[]),
      dict(
          testcase_name='V4_TO_V4',
          addresses=[[nacaddr.IPv4('0.0.0.0/1')],
                     [nacaddr.IPv4('192.168.0.0/24')]],
          expected=[
              '                    term good-term-icmp {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                0.0.0.0/1;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                192.168.0.0/24;\n'
              '                            }\n'
              '                            application-sets test-filtergood-term-icmp-app;\n'
              '                        }',
              '                    term good-term-icmp-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmp-app;\n'
              '                        }',
              '                    term good-term-icmpv6-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6 {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                0.0.0.0/1;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                192.168.0.0/24;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6-2 {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                0.0.0.0/1;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                192.168.0.0/24;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
          ],
          notexpected=[]),
      dict(
          testcase_name='V6_TO_V6',
          addresses=[[nacaddr.IPv6('2001::/33')], [nacaddr.IPv6('2201::/48')]],
          expected=[
              '                    term good-term-icmp-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmp-app;\n'
              '                        }',
              '                    term good-term-icmpv6 {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                2001::/33;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                2201::/48;\n'
              '                            }\n'
              '                            application-sets test-filtergood-term-icmpv6-app;\n'
              '                        }',
              '                    term good-term-icmpv6-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6 {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                2001::/33;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                2201::/48;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
              '                    term good-term-both-icmp-and-icmpv6-2 {\n'
              '                        from {\n'
              '                            source-address {\n'
              '                                2001::/33;\n'
              '                            }\n'
              '                            destination-address {\n'
              '                                2201::/48;\n'
              '                            }\n'
              '                            application-sets test-filterd-term-both-icmp-and-icmpv6-app;\n'
              '                        }',
          ],
          notexpected=[]),
      dict(
          testcase_name='V4_TO_V6',
          addresses=[[nacaddr.IPv4('0.0.0.0/1')], [nacaddr.IPv6('2201::/48')]],
          expected=[
              '                    term good-term-icmp-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmp-app;\n'
              '                        }',
              '                    term good-term-icmpv6-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmpv6-app;\n'
              '                        }',
          ],
          notexpected=['0.0.0.0/1', '192.168.0.0/24', '2001::/33', '2201::/48'],
      ),
      dict(
          testcase_name='V6_TO_V4',
          addresses=[[nacaddr.IPv6('2001::/33')],
                     [nacaddr.IPv4('192.168.0.0/24')]],
          expected=[
              '                    term good-term-icmp-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmp-app;\n'
              '                        }',
              '                    term good-term-icmpv6-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmpv6-app;\n'
              '                        }',
          ],
          notexpected=['0.0.0.0/1', '192.168.0.0/24', '2001::/33', '2201::/48'],
      ),
      dict(
          testcase_name='PARTLY_UNSPECIFIED',
          addresses=[[nacaddr.IPv6('2001::/33')],
                     [nacaddr.IPv4('192.168.0.0/24')]],
          expected=[
              '                    term good-term-icmp-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmp-app;\n'
              '                        }',
              '                    term good-term-icmpv6-2 {\n'
              '                        from {\n'
              '                            application-sets test-filtergood-term-icmpv6-app;\n'
              '                        }',
          ],
          notexpected=[
              '0.0.0.0/1', '192.168.0.0/24', '2001::/33', '2201::/48',
              'term good-term-icmp-i', 'term good-term-icmpv6-i',
              'term good-term-both-icmp-and-icmpv6-'
          ],
      ),
  )
  def testMixedICMP(self, addresses, expected, notexpected):
    self.naming.GetNetAddr.side_effect = addresses * 4
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER_MIXED + MIXED_TESTING_TERM_ICMP,
                           self.naming), EXP_INFO)
    output = str(msmpc)
    for expect in expected:
      self.assertIn(expect, output, output)
    for notexpect in notexpected:
      self.assertNotIn(notexpect, output, output)

  @parameterized.named_parameters(
      dict(testcase_name='true', option='true', want_logging=True),
      dict(testcase_name='True', option='True', want_logging=True),
      dict(testcase_name='syslog', option='syslog', want_logging=True),
      dict(testcase_name='local', option='local', want_logging=True),
      dict(testcase_name='disable', option='disable', want_logging=False),
      dict(testcase_name='log-both', option='log-both', want_logging=True),
  )
  def testLogging(self, option, want_logging):
    self.naming.GetNetAddr.return_value = [nacaddr.IPv4('192.168.0.0/24')]
    self.naming.GetServiceByProto.return_value = ['25']
    expected_output = (
        '    test-filter {\n' + '        services {\n' +
        '            stateful-firewall {\n' +
        '                rule test-filter {\n' +
        '                    match-direction input-output;\n' +
        '                    term good-term-1 {\n' +
        '                        from {\n' +
        '                            application-sets '
        'test-filtergood-term-1-app;\n' + '                        }\n' +
        '                        then {\n' +
        '                            accept;\n' +
        ('                            syslog;\n' if want_logging else '') +
        '                        }\n' + '                    }\n' +
        '                }\n' + '            }\n' + '        }\n' +
        '        applications {\n' +
        '            application test-filtergood-term-1-app1 {\n' +
        '                protocol icmp;\n' + '            }\n' +
        '            application-set test-filtergood-term-1-app {\n' +
        '                application test-filtergood-term-1-app1;\n' +
        '            }\n' + '        }\n' + '    }\n' + '}\n' +
        'apply-groups test-filter;')
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER_MIXED_IMPLICIT + (LOGGING_TERM % option),
                           self.naming), EXP_INFO)
    output = str(msmpc)
    self.assertIn(expected_output, output, output)

  @parameterized.named_parameters(
      dict(
          testcase_name='default', header=GOOD_HEADER,
          direction='input-output'),
      dict(
          testcase_name='ingress',
          header=GOOD_HEADER_INGRESS,
          direction='input'),
      dict(
          testcase_name='egress', header=GOOD_HEADER_EGRESS,
          direction='output'))
  def testDirection(self, header, direction):
    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(header + GOOD_TERM_3, self.naming), EXP_INFO)
    output = str(msmpc)
    expected_output = ('                rule test-filter {\n' +
                       '                    match-direction %s;')
    self.assertIn(expected_output % direction, output, output)

  def testBadDirectionCombo(self):
    pol = policy.ParsePolicy(BAD_HEADER_DIRECTION + GOOD_TERM_3, self.naming)
    self.assertRaises(junipermsmpc.ConflictingTargetOptionsError,
                      junipermsmpc.JuniperMSMPC, pol, EXP_INFO)

  def testTermNameCollision(self):
    short_append = '1' * (
        junipermsmpc.MAX_IDENTIFIER_LEN // 2 - len('?ood-term-1'))
    long_append = short_append + '1'
    not_too_long_name = (TERM_NAME_COLLISION % (short_append, short_append))
    too_long_name = (TERM_NAME_COLLISION % (long_append, long_append))
    pol = policy.ParsePolicy(GOOD_HEADER + too_long_name, self.naming)
    self.assertRaises(junipermsmpc.ConflictingApplicationSetsError,
                      junipermsmpc.JuniperMSMPC, pol, EXP_INFO)
    _ = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER + not_too_long_name, self.naming),
        EXP_INFO)

  def testSlashZeroReplacement(self):
    self.naming.GetNetAddr.return_value = ([
        nacaddr.IPv4('0.0.0.0/0'),
        nacaddr.IPv6('::/0')
    ])
    self.naming.GetServiceByProto.return_value = ['25']
    expectedv4 = ('                    term good-term-2-inet {\n' +
                  '                        from {\n' +
                  '                            destination-address {\n' +
                  '                                any-ipv4;\n' +
                  '                            }')
    expectedv6 = ('                    term good-term-2-inet6 {\n' +
                  '                        from {\n' +
                  '                            destination-address {\n' +
                  '                                any-ipv6;\n' +
                  '                            }')

    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM_1, self.naming),
        EXP_INFO)
    output = str(msmpc)
    self.assertIn(expectedv4, output, output)
    self.assertIn(expectedv6, output, output)

  def testV6SlashFourteenReplacement(self):
    self.naming.GetNetAddr.return_value = ([
        nacaddr.IPv4('0.0.0.0/1'),
        nacaddr.IPv6('::/14')
    ])
    self.naming.GetServiceByProto.return_value = ['25']
    expectedv4 = ('                    term good-term-2-inet {\n' +
                  '                        from {\n' +
                  '                            destination-address {\n' +
                  '                                0.0.0.0/1;\n' +
                  '                            }')
    expectedv6 = ('                    term good-term-2-inet6 {\n' +
                  '                        from {\n' +
                  '                            destination-address {\n' +
                  '                                ::/16;\n' +
                  '                                1::/16;\n' +
                  '                                2::/16;\n' +
                  '                                3::/16;\n' +
                  '                            }')

    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM_1, self.naming),
        EXP_INFO)
    output = str(msmpc)
    self.assertIn(expectedv4, output, output)
    self.assertIn(expectedv6, output, output)

  @parameterized.named_parameters(
      dict(testcase_name='tcp', protoname='tcp', protonum='tcp'),
      dict(testcase_name='hopopt', protoname='hopopt', protonum='0'),
      dict(testcase_name='vrrp', protoname='vrrp', protonum='112'),
  )
  def testProtocolAsNumber(self, protoname, protonum):
    expected = ('            application test-filtergood-term-numeric-app1 {\n'
                + '                protocol %s;') % protonum

    msmpc = junipermsmpc.JuniperMSMPC(
        policy.ParsePolicy(
            GOOD_HEADER_MIXED + GOOD_TERM_NUMERIC_PROTOCOL % protoname,
            self.naming), EXP_INFO)
    output = str(msmpc)
    self.assertIn(expected, output, output)


if __name__ == '__main__':
  absltest.main()
