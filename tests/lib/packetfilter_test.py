# Copyright 2013 Google Inc. All Rights Reserved.
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

"""Unittest for packetfilter rendering module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import datetime
import unittest


from lib import aclgenerator
from lib import nacaddr
from lib import naming
from lib import packetfilter
from lib import policy
import mock


GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: packetfilter test-filter mixed
}
"""

GOOD_HEADER_STATELESS = """
header {
  comment:: "this is a stateless test acl"
  target:: packetfilter test-filter mixed nostate
}
"""

GOOD_HEADER_INET4 = """
header {
  comment:: "this is a test acl"
  target:: packetfilter test-filter
}
"""

GOOD_HEADER_INET6 = """
header {
  comment:: "this is a test acl"
  target:: packetfilter test-filter inet6
}
"""

GOOD_HEADER_DIRECTIONAL = """
header {
  comment:: "this is a test acl"
  target:: packetfilter test-filter out mixed
}
"""

GOOD_HEADER_DIRECTIONAL_STATELESS = """
header {
  comment:: "this is a test acl"
  target:: packetfilter test-filter out mixed nostate
}
"""

GOOD_TERM_ICMP = """
term good-term-icmp {
  protocol:: icmp
  action:: accept
}
"""

GOOD_TERM_ICMP_TYPES = """
term good-term-icmp-types {
  protocol:: icmp
  icmp-type:: echo-reply unreachable time-exceeded
  action:: deny
}
"""

GOOD_TERM_ICMPV6 = """
term good-term-icmpv6 {
  protocol:: icmpv6
  action:: accept
}
"""

BAD_TERM_ICMP = """
term test-icmp {
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

BAD_TERM_ACTION = """
term bad-term-action {
  protocol:: icmp
  action:: reject-with-tcp-rst
}
"""

GOOD_TERM_TCP = """
term good-term-tcp {
  comment:: "Test term 1"
  destination-address:: PROD_NETWORK
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

DENY_TERM_TCP = """
term deny-term-tcp {
  protocol:: tcp
  action:: deny
}
"""

GOOD_TERM_LOG = """
term good-term-log {
  protocol:: tcp
  logging:: true
  action:: accept
}
"""

EXPIRED_TERM = """
term expired_test {
  expiration:: 2000-1-1
  action:: deny
}
"""

EXPIRED_TERM2 = """
term expired_test2 {
  expiration:: 2015-01-01
  action:: deny
}
"""

EXPIRING_TERM = """
term is_expiring {
  expiration:: %s
  action:: accept
}
"""

MULTIPLE_PROTOCOLS_TERM = """
term multi-proto {
  protocol:: tcp udp icmp
  action:: accept
}
"""

NEXT_TERM = """
term next {
  action:: next
}
"""

NEXT_LOG_TERM = """
term next-log {
  logging:: true
  action:: next
}
"""

PORTRANGE_TERM = """
term portrange {
  protocol:: tcp
  action:: accept
  destination-port:: HIGH_PORTS
}
"""

FLAGS_TERM = """
term flags {
  protocol:: tcp
  action:: accept
  option:: syn fin
}
"""

INVALID_FLAGS_TERM = """
term invalid-flags {
  protocol:: udp
  action:: accept
  option:: syn fin
}
"""

MULTILINE_COMMENT = """
term multiline-comment {
  comment:: "This is a
multiline comment"
  protocol:: tcp
  action:: accept
}
"""

TCP_STATE_TERM = """
term tcp-established-only {
  protocol:: tcp
  option:: established
  action:: accept
}
"""

TCP_GOOD_ESTABLISHED_TERM = """
term tcp-established-good {
  protocol:: tcp
  option:: established
  action:: accept
}
"""

TCP_BAD_ESTABLISHED_TERM = """
term tcp-established-bad {
  protocol:: tcp
  option:: established syn
  action:: accept
}
"""

UDP_ESTABLISHED_TERM = """
term udp-established {
  protocol:: udp
  option:: established
  action:: accept
}
"""

MULTIPLE_NAME_TERM = """
term multiple-name {
  protocol:: tcp
  destination-address:: PROD_NETWORK
  destination-port:: SMTP
  source-address:: CORP_INTERNAL
  action:: accept
}
"""

LONG_NAME_TERM_DNS_TCP = """
term multiple-name-dns-tcp {
  protocol:: tcp
  destination-address:: PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME
  destination-port:: DNS
  action:: accept
}
"""

LONG_NAME_TERM_DNS_UDP = """
term multiple-name-dns-udp {
  protocol:: udp
  destination-address:: PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME
  destination-port:: DNS
  action:: accept
}
"""

NON_SHORTENED_LONG_NAME_TERM_DNS_UDP = """
term multiple-name-dns-udp {
  protocol:: udp
  destination-address:: PROD_NETWORK_EXTREAMLY_LONG_VER
  destination-port:: DNS
  action:: accept
}
"""

DUPLICATE_DIFFERENT_LONG_NAME_TERM = """
term multiple-name {
  protocol:: tcp
  destination-address:: PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME
  destination-port:: SMTP
  source-address:: PROD_NETWORK_EXTREAMLY_LONG_VERY_GOOD_NAME
  action:: accept
}
"""

BAD_PROTO_TERM = """
term bad-proto {
  protocol:: hopopt
  action:: accept
}
"""

GOOD_WARNING_TERM = """
term good-warning {
  protocol:: tcp
  policer:: batman
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
    'icmp_type',
    'logging',
    'name',
    'option',
    'platform',
    'platform_exclude',
    'protocol',
    'source_address',
    'source_address_exclude',
    'source_port',
    'translated',
    'verbatim',
}

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny', 'reject', 'next'},
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
    'option': {'syn',
               'ack',
               'fin',
               'rst',
               'urg',
               'psh',
               'all',
               'established',
               'tcp-established'}
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class PacketFilterTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testTcp(self):
    ip = nacaddr.IP('10.0.0.0/8')
    ip.parent_token = 'PROD_NETWORK'
    self.naming.GetNetAddr.return_value = [ip]
    self.naming.GetServiceByProto.return_value = ['25']

    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_TCP, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term good-term-tcp' in result,
                    'did not find comment for good-term-tcp')
    self.failUnless(
        'pass quick proto { tcp } from { any } to { <PROD_NETWORK> } port '
        '{ 25 }' in result,
        'did not find actual term for good-term-tcp')

    self.naming.GetNetAddr.assert_called_once_with('PROD_NETWORK')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testLog(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_LOG, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term good-term-log' in result,
                    'did not find comment for good-term-log')
    self.failUnless(
        'pass quick log proto { tcp } from { any } to { any } flags S/SA '
        'keep state\n'
        in result,
        'did not find actual term for good-term-log')

  def testIcmp(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_ICMP, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term good-term-icmp' in result,
                    'did not find comment for good-term-icmp')
    self.failUnless(
        'pass quick proto { icmp } from { any } to { any } keep state\n'
        in result,
        'did not find actual term for good-term-icmp')

  def testIcmpTypes(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_ICMP_TYPES, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term good-term-icmp-types' in result,
                    'did not find comment for good-term-icmp-types')
    self.failUnless(
        'block drop quick proto { icmp } from { any } to { any } '
        'icmp-type { 0, 3, 11 }' in result,
        'did not find actual term for good-term-icmp-types')

  def testIcmpv6(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_ICMPV6, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term good-term-icmpv6' in result,
                    'did not find comment for good-term-icmpv6')
    self.failUnless(
        'pass quick proto { ipv6-icmp } from { any } to { any } keep state\n'
        in result,
        'did not find actual term for good-term-icmpv6')

  def testBadIcmp(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + BAD_TERM_ICMP, self.naming), EXP_INFO)
    self.assertRaises(aclgenerator.UnsupportedFilterError, str, acl)

  @mock.patch.object(packetfilter.logging, 'warn')
  def testExpiredTerm(self, mock_warn):
    packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + EXPIRED_TERM, self.naming), EXP_INFO)

    mock_warn.assert_called_once_with(
        'WARNING: Term %s in policy %s is expired and '
        'will not be rendered.', 'expired_test',
        'test-filter')

  @mock.patch.object(packetfilter.logging, 'warn')
  def testExpiredTerm2(self, mock_warn):
    packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + EXPIRED_TERM2, self.naming), EXP_INFO)

    mock_warn.assert_called_once_with(
        'WARNING: Term %s in policy %s is expired and '
        'will not be rendered.', 'expired_test2',
        'test-filter')

  @mock.patch.object(packetfilter.logging, 'info')
  def testExpiringTerm(self, mock_info):
    exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
    packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + EXPIRING_TERM % exp_date.strftime('%Y-%m-%d'),
        self.naming), EXP_INFO)

    mock_info.assert_called_once_with(
        'INFO: Term %s in policy %s expires in '
        'less than two weeks.', 'is_expiring',
        'test-filter')

  def testMultiprotocol(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + MULTIPLE_PROTOCOLS_TERM, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term multi-proto' in result,
                    'did not find comment for multi-proto')
    self.failUnless(
        'pass quick proto { tcp udp icmp } from { any } to { any } keep state\n'
        in result,
        'did not find actual term for multi-proto')

  def testNextTerm(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + NEXT_TERM, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term next' in result,
                    'did not find comment for next')
    self.failUnless(
        'pass from { any } to { any } flags S/SA keep state\n' in result,
        'did not find actual term for next-term')

  def testNextLogTerm(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + NEXT_LOG_TERM, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term next-log' in result,
                    'did not find comment for next-log')
    self.failUnless(
        'pass log from { any } to { any } flags S/SA keep state\n' in result,
        'did not find actual term for next-log-term')

  def testPortRange(self):
    self.naming.GetServiceByProto.return_value = ['12345-12354']

    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + PORTRANGE_TERM, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term portrange' in result,
                    'did not find comment for portrange')
    self.failUnless(
        'pass quick proto { tcp } from { any } to { any } '
        'port { 12345:12354 }' in result,
        'did not find actual term for portrange')

    self.naming.GetServiceByProto.assert_called_once_with(
        'HIGH_PORTS', 'tcp')

  def testFlags(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + FLAGS_TERM, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term flags' in result,
                    'did not find comment for flags')
    self.failUnless(
        'pass quick proto { tcp } from { any } to { any } '
        'flags SF/SF' in result,
        'did not find actual term for flags')

  def testInvalidFlags(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + INVALID_FLAGS_TERM, self.naming), EXP_INFO)
    self.assertRaises(aclgenerator.UnsupportedFilterError, str, acl)

  def testMultilineComment(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + MULTILINE_COMMENT, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term multiline-comment' in result,
                    'did not find comment for multiline-comment')
    self.failUnless('# This is a\n# multiline comment' in result,
                    'did not find multiline comment for multiline-comment')

  def testStateless(self):
    ip = nacaddr.IP('10.0.0.0/8')
    ip.parent_token = 'PROD_NETWORK'
    self.naming.GetNetAddr.return_value = [ip]
    self.naming.GetServiceByProto.return_value = ['25']

    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER_STATELESS + GOOD_TERM_TCP, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term good-term-tcp' in result,
                    'did not find comment for good-term-tcp')
    self.failUnless(
        'pass quick proto { tcp } from { any } to { <PROD_NETWORK> } port '
        '{ 25 } no state' in result,
        'did not find actual term for good-term-tcp')

    self.naming.GetNetAddr.assert_called_once_with('PROD_NETWORK')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testInet4(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER_INET4 + GOOD_TERM_LOG, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term good-term-log' in result,
                    'did not find comment for good-term-log')
    self.failUnless(
        'pass quick log inet proto { tcp } from { any } to { any } flags S/SA '
        'keep state\n'
        in result,
        'did not find actual term for good-term-log')

  def testInet6(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER_INET6 + GOOD_TERM_LOG, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term good-term-log' in result,
                    'did not find comment for good-term-log')
    self.failUnless(
        'pass quick log inet6 proto { tcp } from { any } to { any } flags S/SA '
        'keep state\n'
        in result,
        'did not find actual term for good-term-log')

  def testDirectional(self):
    ip = nacaddr.IP('10.0.0.0/8')
    ip.parent_token = 'PROD_NETWORK'
    self.naming.GetNetAddr.return_value = [ip]
    self.naming.GetServiceByProto.return_value = ['25']

    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER_DIRECTIONAL + GOOD_TERM_TCP, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term good-term-tcp' in result,
                    'did not find comment for good-term-tcp')
    self.failUnless(
        'pass out quick proto { tcp } from { any } to { <PROD_NETWORK> } port '
        '{ 25 }' in result,
        'did not find actual term for good-term-tcp')

    self.naming.GetNetAddr.assert_called_once_with('PROD_NETWORK')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testMultipleHeader(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER_STATELESS + GOOD_TERM_LOG + GOOD_HEADER_INET6
        + GOOD_TERM_ICMP,
        self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        'pass quick log proto { tcp } from { any } to { any } no state'
        in result,
        'did not find actual term for good-term-log')
    self.failUnless(
        'pass quick inet6 proto { icmp } from { any } to { any } no state'
        in result,
        'did not find actual term for good-term-icmp')

  def testDirectionalStateless(self):
    ip = nacaddr.IP('10.0.0.0/8')
    ip.parent_token = 'PROD_NETWORK'
    self.naming.GetNetAddr.return_value = [ip]
    self.naming.GetServiceByProto.return_value = ['25']

    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER_DIRECTIONAL_STATELESS + GOOD_TERM_TCP, self.naming),
                                    EXP_INFO)
    result = str(acl)
    self.failUnless('# term good-term-tcp' in result,
                    'did not find comment for good-term-tcp')
    self.failUnless(
        'pass out quick proto { tcp } from { any } to { <PROD_NETWORK> } port '
        '{ 25 } no state' in result,
        'did not find actual term for good-term-tcp')

    self.naming.GetNetAddr.assert_called_once_with('PROD_NETWORK')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testStatelessEstablished(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER_STATELESS + TCP_STATE_TERM, self.naming),
                                    EXP_INFO)
    result = str(acl)
    self.failUnless('# term tcp-established-only' in result,
                    'did not find comment for tcp-established-only')
    self.failUnless(
        'pass quick proto { tcp } from { any } to { any } flags A/A no state'
        in result,
        'did not find actual term for tcp-established-only')

  def testBadFlags(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + TCP_BAD_ESTABLISHED_TERM, self.naming), EXP_INFO)
    self.assertRaises(aclgenerator.UnsupportedFilterError, str, acl)

  # While "UDP stateless established" seems to be a strange combination it
  # actually makes sense:  e.g., the state or nostate header is a global
  # header directive and indicates whether we do matching on established by
  # flags or proper connection tracking, and pf's permissiveness allows things
  # like:
  #   proto { udp, tcp } flags A/A no state'
  # whereby the flags only apply to TCP protocol matches.  However, the
  # following is invalid:
  #   proto { udp } flags A/A no state'
  # check to make sure we don't output the latter for things like:
  #   target:: packetfilter nostate
  #   term foo { protocol:: udp option:: established }
  def testUdpStatelessEstablished(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER_STATELESS + UDP_ESTABLISHED_TERM, self.naming),
                                    EXP_INFO)
    result = str(acl)
    self.failUnless('# term udp-established' in result,
                    'did not find comment for udp-established')
    self.failUnless(
        'pass quick proto { udp } from { any } to { any } no state'
        in result,
        'did not find actual term for udp-established')

  def testStatefulBlock(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + DENY_TERM_TCP, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('# term deny-term-tcp' in result,
                    'did not find comment for udp-established')
    self.failUnless(
        'block drop quick proto { tcp } from { any } to { any } flags S/SA'
        in result,
        'did not find actual term for deny-term-tcp')

  def testTcpEstablished(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + TCP_GOOD_ESTABLISHED_TERM, self.naming),
                                    EXP_INFO)
    result = str(acl)
    self.failUnless('# term tcp-established-good' in result,
                    'did not find comment for tcp-established-good')
    self.failUnless(
        'pass quick proto { tcp } from { any } to { any } flags A/A keep state'
        in result,
        'did not find actual term for udp-established')

  def testTableCreation(self):
    prod_network = nacaddr.IP('10.0.0.0/8')
    prod_network.parent_token = 'PROD_NETWORK'
    corp_internal_one = nacaddr.IP('100.96.0.1/11')
    corp_internal_one.parent_token = 'CORP_INTERNAL'
    corp_internal_two = nacaddr.IP('172.16.0.0/16')
    corp_internal_two.parent_token = 'CORP_INTERNAL'
    self.naming.GetNetAddr.side_effect = [
        [prod_network],
        [corp_internal_one, corp_internal_two]]
    self.naming.GetServiceByProto.return_value = ['25']

    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + MULTIPLE_NAME_TERM, self.naming),
                                    EXP_INFO)
    result = str(acl)
    self.failUnless(
        'table <PROD_NETWORK> {10.0.0.0/8}' in result,
        'did not find PROD_NETWORKtable in header')
    self.failUnless(
        'table <CORP_INTERNAL> {100.96.0.1/11,\\\n'
        '172.16.0.0/16}' in result,
        'did not find CORP_INTERNAL table in header')
    self.failUnless(
        'pass quick proto { tcp } from { <CORP_INTERNAL> } to '
        '{ <PROD_NETWORK> } port { 25 } flags S/SA keep state'
        in result,
        'did not find actual term for multiple-name')

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWORK'),
        mock.call('CORP_INTERNAL')])
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testTableNameShortened(self):
    prod_network = nacaddr.IP('10.0.0.0/8')
    prod_network.parent_token = 'PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME'
    self.naming.GetNetAddr.return_value = [prod_network]
    self.naming.GetServiceByProto.return_value = ['53']

    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER_DIRECTIONAL + LONG_NAME_TERM_DNS_TCP, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        'table <PROD_NETWORK_EXTREAMLY_LONG_VER> {10.0.0.0/8}' in result,
        'did not find shortened name in header.')
    self.failUnless(
        'pass out quick proto { tcp } from { any } to '
        '{ <PROD_NETWORK_EXTREAMLY_LONG_VER> } '
        'port { 53 } flags S/SA keep state'
        in result,
        'did not find actual term for multiple-name')

    self.naming.GetNetAddr.assert_called_once_with(
        'PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME')
    self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')

  def testTableDuplicateShortNameError(self):
    prod_network = nacaddr.IP('10.0.0.0/8')
    prod_network.parent_token = 'PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME'
    prod_network_two = nacaddr.IP('172.0.0.1/8')
    prod_network_two.parent_token = 'PROD_NETWORK_EXTREAMLY_LONG_VERY_GOOD_NAME'
    self.naming.GetNetAddr.side_effect = [
        [prod_network], [prod_network_two]]
    self.naming.GetServiceByProto.return_value = ['25']

    self.assertRaises(
        packetfilter.DuplicateShortenedTableName,
        packetfilter.PacketFilter.__init__,
        packetfilter.PacketFilter.__new__(packetfilter.PacketFilter),
        policy.ParsePolicy(
            GOOD_HEADER_DIRECTIONAL + DUPLICATE_DIFFERENT_LONG_NAME_TERM,
            self.naming),
        EXP_INFO)
    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME'),
        mock.call('PROD_NETWORK_EXTREAMLY_LONG_VERY_GOOD_NAME')])
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testTableSameLongNameSameFilter(self):
    prod_network = nacaddr.IP('10.0.0.0/8')
    prod_network.parent_token = 'PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME'
    self.naming.GetNetAddr.return_value = [prod_network]
    self.naming.GetServiceByProto.return_value = ['53']

    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER_DIRECTIONAL + LONG_NAME_TERM_DNS_TCP + LONG_NAME_TERM_DNS_UDP,
        self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        'table <PROD_NETWORK_EXTREAMLY_LONG_VER> {10.0.0.0/8}' in result,
        'did not find shortened name in header.')
    self.failUnless(
        'pass out quick proto { tcp } from { any } to '
        '{ <PROD_NETWORK_EXTREAMLY_LONG_VER> } '
        'port { 53 } flags S/SA keep state'
        in result,
        'did not find actual TCP term for multiple-name')
    self.failUnless(
        'pass out quick proto { udp } from { any } to '
        '{ <PROD_NETWORK_EXTREAMLY_LONG_VER> } '
        'port { 53 } keep state'
        in result,
        'did not find actual UDP for multiple-name')

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME'),
        mock.call('PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME')])
    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('DNS', 'tcp'),
        mock.call('DNS', 'udp')])

  def testTableSameLongNameDiffFilter(self):
    prod_network = nacaddr.IP('10.0.0.0/8')
    prod_network.parent_token = 'PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME'
    self.naming.GetNetAddr.return_value = [prod_network]
    self.naming.GetServiceByProto.return_value = ['53']

    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER_DIRECTIONAL + LONG_NAME_TERM_DNS_TCP +
        GOOD_HEADER_DIRECTIONAL + LONG_NAME_TERM_DNS_UDP,
        self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        'table <PROD_NETWORK_EXTREAMLY_LONG_VER> {10.0.0.0/8}' in result,
        'did not find shortened name in header.')
    self.failUnless(
        'pass out quick proto { tcp } from { any } to '
        '{ <PROD_NETWORK_EXTREAMLY_LONG_VER> } '
        'port { 53 } flags S/SA keep state'
        in result,
        'did not find actual TCP term for multiple-name')
    self.failUnless(
        'pass out quick proto { udp } from { any } to '
        '{ <PROD_NETWORK_EXTREAMLY_LONG_VER> } '
        'port { 53 } keep state'
        in result,
        'did not find actual UDP for multiple-name')

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME'),
        mock.call('PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME')])
    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('DNS', 'tcp'),
        mock.call('DNS', 'udp')])

  def testTableDiffObjectsShortenedAndNonShortened(self):
    prod_network = nacaddr.IP('10.0.0.0/8')
    prod_network.parent_token = 'PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME'
    prod_network_two = nacaddr.IP('172.0.0.1/8')
    prod_network_two.parent_token = 'PROD_NETWORK_EXTREAMLY_LONG_VER'
    self.naming.GetNetAddr.side_effect = [
        [prod_network], [prod_network_two]]
    self.naming.GetServiceByProto.return_value = ['53']

    self.assertRaises(
        packetfilter.DuplicateShortenedTableName,
        packetfilter.PacketFilter.__init__,
        packetfilter.PacketFilter.__new__(packetfilter.PacketFilter),
        policy.ParsePolicy(
            GOOD_HEADER_DIRECTIONAL + LONG_NAME_TERM_DNS_TCP +
            NON_SHORTENED_LONG_NAME_TERM_DNS_UDP,
            self.naming),
        EXP_INFO)
    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME'),
        mock.call('PROD_NETWORK_EXTREAMLY_LONG_VER')])
    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('DNS', 'tcp'),
        mock.call('DNS', 'udp')])

  def testTableDuplicateShortNameErrorDiffFilter(self):
    prod_network = nacaddr.IP('10.0.0.0/8')
    prod_network.parent_token = 'PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME'
    prod_network_two = nacaddr.IP('172.0.0.1/8')
    prod_network_two.parent_token = 'PROD_NETWORK_EXTREAMLY_LONG_VER'
    self.naming.GetNetAddr.side_effect = [
        [prod_network], [prod_network_two]]
    self.naming.GetServiceByProto.return_value = ['53']

    self.assertRaises(
        packetfilter.DuplicateShortenedTableName,
        packetfilter.PacketFilter.__init__,
        packetfilter.PacketFilter.__new__(packetfilter.PacketFilter),
        policy.ParsePolicy(
            GOOD_HEADER_DIRECTIONAL + LONG_NAME_TERM_DNS_TCP +
            GOOD_HEADER_DIRECTIONAL + NON_SHORTENED_LONG_NAME_TERM_DNS_UDP,
            self.naming),
        EXP_INFO)
    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWORK_EXTREAMLY_LONG_VERY_NO_GOOD_NAME'),
        mock.call('PROD_NETWORK_EXTREAMLY_LONG_VER')])
    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('DNS', 'tcp'),
        mock.call('DNS', 'udp')])

  def testTermNameConflict(self):
    self.assertRaises(
        packetfilter.DuplicateTermError,
        packetfilter.PacketFilter.__init__,
        packetfilter.PacketFilter.__new__(packetfilter.PacketFilter),
        policy.ParsePolicy(
            GOOD_HEADER_DIRECTIONAL + GOOD_TERM_ICMP + GOOD_TERM_ICMP,
            self.naming),
        EXP_INFO)

  def testBadProtoError(self):
    acl = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + BAD_PROTO_TERM, self.naming), EXP_INFO)
    self.assertRaises(packetfilter.UnsupportedProtoError, str, acl)

  def testBuildTokens(self):
    ip = nacaddr.IP('10.0.0.0/8')
    ip.parent_token = 'PROD_NETWORK'
    self.naming.GetNetAddr.return_value = [ip]
    self.naming.GetServiceByProto.return_value = ['25']

    pol1 = packetfilter.PacketFilter(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_TCP, self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    pol1 = packetfilter.PacketFilter(
        policy.ParsePolicy(GOOD_HEADER + GOOD_WARNING_TERM,
                           self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)


if __name__ == '__main__':
  unittest.main()
