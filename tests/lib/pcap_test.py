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
"""Unittest for pcap rendering module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import datetime
import unittest


from lib import aclgenerator
from lib import nacaddr
from lib import naming
from lib import pcap
from lib import policy
import mock


GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: pcap test-filter
}
"""

GOOD_HEADER_IN = """
header {
  comment:: "this is a test acl"
  target:: pcap test-filter in
}
"""

GOOD_HEADER_OUT = """
header {
  comment:: "this is a test acl"
  target:: pcap test-filter out
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
  action:: undefined
}
"""

GOOD_TERM_TCP = """
term good-term-tcp {
  comment:: "Test term 1"
  destination-address:: PROD_NETWRK
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_WARNING_TERM = """
term good-warning-term {
  comment:: "Test term 1"
  destination-address:: PROD_NETWRK
  destination-port:: SMTP
  protocol:: tcp
  policer:: batman
  action:: accept
}
"""

GOOD_TERM_LOG = """
term good-term-log {
  protocol:: tcp
  logging:: true
  action:: accept
}
"""
GOOD_ICMP_CODE = """
term good_term {
  protocol:: icmp
  icmp-type:: unreachable
  icmp-code:: 3 4
  action:: accept
}
"""
EXPIRED_TERM = """
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

ESTABLISHED_TERM = """
term accept-established {
  protocol:: tcp
  option:: tcp-established
  action:: accept
}
"""

VRRP_TERM = """
term vrrp-term {
  protocol:: vrrp
  action:: accept
}
"""

UNICAST_TERM = """
term unicast-term {
  destination-address:: ANY
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_HBH = """
term good-term-hbh {
  protocol:: hopopt
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
    'icmp_code',
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
               'none',
               'established',
               'tcp-established'}
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class PcapFilter(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testTcp(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    acl = pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_TCP, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        '(dst net 10.0.0.0/8) and (proto \\tcp) and (dst port 25)' in result,
        'did not find actual term for good-term-tcp')

    self.naming.GetNetAddr.assert_called_once_with('PROD_NETWRK')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testLog(self):
    acl = pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_LOG, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        'proto \\tcp' in result,
        'did not find actual term for good-term-log')

  def testIcmp(self):
    acl = pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_ICMP, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        'proto \\icmp' in result,
        'did not find actual term for good-term-icmp')

  def testIcmpCode(self):
    acl = pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER + GOOD_ICMP_CODE, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('and icmp[icmpcode] == 3' in result, result)
    self.failUnless('and icmp[icmpcode] == 4' in result, result)

  def testIcmpTypes(self):
    acl = pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_ICMP_TYPES, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        '(proto \\icmp) and (icmp[icmptype] == 0 or icmp[icmptype] == 3'
        ' or icmp[icmptype] == 11)' in result,
        'did not find actual term for good-term-icmp-types')

  def testIcmpv6(self):
    acl = pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_ICMPV6, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        'icmp6' in result,
        'did not find actual term for good-term-icmpv6')

  def testBadIcmp(self):
    acl = pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER + BAD_TERM_ICMP, self.naming), EXP_INFO)
    self.assertRaises(aclgenerator.UnsupportedFilterError,
                      str, acl)

  @mock.patch.object(pcap.logging, 'warn')
  def testExpiredTerm(self, mock_warn):
    pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER + EXPIRED_TERM, self.naming), EXP_INFO)

    mock_warn.assert_called_once_with(
        'WARNING: Term %s in policy %s is expired and '
        'will not be rendered.', 'expired_test', 'test-filter')

  @mock.patch.object(pcap.logging, 'info')
  def testExpiringTerm(self, mock_info):
    exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
    pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER + EXPIRING_TERM % exp_date.strftime('%Y-%m-%d'),
        self.naming), EXP_INFO)

    mock_info.assert_called_once_with(
        'INFO: Term %s in policy %s expires in '
        'less than two weeks.', 'is_expiring', 'test-filter')

  def testMultiprotocol(self):
    acl = pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER + MULTIPLE_PROTOCOLS_TERM, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        '(proto \\tcp or proto \\udp or proto \\icmp)' in result,
        'did not find actual term for multi-proto')

  def testNextTerm(self):
    acl = pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER + NEXT_TERM, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless('' in result,
                    'did not find actual term for good-term-icmpv6')

  def testTcpOptions(self):
    acl = pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER + ESTABLISHED_TERM, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        '(tcp[tcpflags] & (tcp-ack) == (tcp-ack)' in result,
        'did not find actual term for established')

  def testVrrpTerm(self):
    acl = pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER + VRRP_TERM, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        '(proto 112)' in result,
        'did not find actual term for vrrp')

  def testMultiHeader(self):
    acl = pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_LOG + GOOD_HEADER + GOOD_TERM_ICMP,
        self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        '((((proto \\tcp))\n))\nor\n((((proto \\icmp))\n))' in result,
        'did not find actual terms for multi-header')

  def testDirectional(self):
    acl = pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER_IN + GOOD_TERM_LOG + GOOD_HEADER_OUT + GOOD_TERM_ICMP,
        self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        '(((dst net localhost and ((proto \\tcp)))\n))\nor\n'
        '(((src net localhost and ((proto \\icmp)))\n))' in result,
        'did not find actual terms for directional')

  def testUnicastIPv6(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('::/0')]

    acl = pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER_IN + UNICAST_TERM, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        '(dst net localhost and ((proto \\tcp)))' in result,
        'did not find actual terms for unicast-term')

    self.naming.GetNetAddr.assert_called_once_with('ANY')

  def testHbh(self):
    acl = pcap.PcapFilter(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_HBH, self.naming), EXP_INFO)
    result = str(acl)

    self.failUnless(
        '(ip6 protochain 0)' in result,
        'did not find actual terms for unicast-term')

  def testBuildTokens(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']
    pol1 = pcap.PcapFilter(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_TCP,
                                              self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    pol1 = pcap.PcapFilter(
        policy.ParsePolicy(GOOD_HEADER + GOOD_WARNING_TERM,
                           self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)


if __name__ == '__main__':
  unittest.main()
