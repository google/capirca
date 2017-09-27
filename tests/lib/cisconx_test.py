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
"""Unittest for Cisco NX acl rendering module."""

import unittest

from lib import cisconx
from lib import naming
from lib import policy
import mock
import ipaddr


GOOD_HEADER_1 = """
header {
  comment:: "this is a test acl"
  target:: cisconx test-filter
}
"""

GOOD_HEADER_2 = """
header {
  comment:: "this is a test ipv6 acl"
  target:: cisconx ipv6-test-filter inet6
}
"""

GOOD_HEADER_3 = """
header {
  comment:: "this is a ipv4 network acl"
  target:: cisconx ipv4-net-test-filter
}
"""

GOOD_TERM_1 = """
term good-term-1 {
  source-address:: SOME_HOST
  protocol:: icmp
  action:: accept
}
"""

GOOD_TERM_2 = """
term good-term-2 {
  protocol:: tcp
  destination-address:: SOME_HOST2
  source-port:: HTTP
  action:: accept
}
"""

GOOD_TERM_3 = """
term good-term-3 {
  protocol:: tcp
  destination-address:: SOME_HOST2
  source-port:: HTTP
  policer:: batman
  action:: accept
}
"""

GOOD_TERM_4 = """
term network-test-4 {
  source-address:: SOME_HOST
  action:: accept
}
"""

EXPIRED_TERM = """
term is_expired {
  expiration:: 2001-01-01
  action:: accept
}
"""

SUPPORTED_TOKENS = {
    'action',
    'address',
    'comment',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'dscp_match',
    'expiration',
    'icmp_type',
    'icmp_code',
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
    'stateless_reply',
    'translated',
    'verbatim',
}

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny', 'reject', 'next',
               'reject-with-tcp-rst'},
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
               'tcp-established'}
}

EXP_INFO = 2


class CiscoNXTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testStandardTermHost(self):
    self.naming.GetNetAddr.return_value = [ipaddr.IPv4Network('10.1.1.1/32')]

    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1,
                             self.naming)
    acl = cisconx.CiscoNX(pol, EXP_INFO)
    expected = 'ip access-list test-filter'
    self.failUnless(expected in str(acl), '[%s]' % str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testStandardTermHostIPv6(self):
    self.naming.GetNetAddr.return_value = [ipaddr.IPv6Network('2001::3/128')]
    self.naming.GetServiceByProto.return_value = ['80']

    pol = policy.ParsePolicy(GOOD_HEADER_2 + GOOD_TERM_2,
                             self.naming)
    acl = cisconx.CiscoNX(pol, EXP_INFO)
    expected = 'ipv6 access-list ipv6-test-filter'
    self.failUnless(expected in str(acl), '[%s]' % str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST2')
    self.naming.GetServiceByProto.assert_called_once_with('HTTP', 'tcp')

  def testStandardTermNet(self):
    self.naming.GetNetAddr.return_value = [ipaddr.IPv4Network('10.0.0.0/8')]

    pol = policy.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_4,
                             self.naming)
    acl = cisconx.CiscoNX(pol, EXP_INFO)
    expected = 'permit ip 10.0.0.0/8 any'
    self.failUnless(expected in str(acl), '[%s]' % str(acl))

  def testBuildTokens(self):
    pol1 = cisconx.CiscoNX(policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1,
                                              self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    self.naming.GetNetAddr.return_value = [ipaddr.IPv6Network('2001::3/128')]
    self.naming.GetServiceByProto.return_value = ['80']

    pol1 = cisconx.CiscoNX(policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_3,
                                              self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)


if __name__ == '__main__':
  unittest.main()
