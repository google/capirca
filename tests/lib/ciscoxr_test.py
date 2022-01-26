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
"""Unittest for Cisco XR acl rendering module."""

from absl.testing import absltest
from unittest import mock

from capirca.lib import ciscoxr
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy


GOOD_HEADER_1 = """
header {
  comment:: "this is a test acl"
  target:: ciscoxr test-filter
}
"""

GOOD_HEADER_2 = """
header {
  comment:: "this is a test ipv6 acl"
  target:: ciscoxr ipv6-test-filter inet6
}
"""

OBJECT_GROUP_HEADER_1 = """
header {
  target:: ciscoxr foo object-group
}
"""

OBJECT_GROUP_HEADER_2 = """
header {
  target:: ciscoxr foo object-group-inet6
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
term good-term-4 {
  source-address:: SOME_HOST2
  action:: accept
}
"""

GOOD_TERM_5 = """
term good-term-5 {
  next-ip:: TEST_NEXT
}
"""

GOOD_TERM_6 = """
term good-term-6 {
  action:: accept
  next-ip:: TEST_NEXT
}
"""

VERBATIM_TERM = """
term verb_term {
  verbatim:: ciscoxr " permit tcp any"
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
    'icmp_code',
    'icmp_type',
    'next_ip',
    'stateless_reply',
    'logging',
    'name',
    'option',
    'owner',
    'platform',
    'platform_exclude',
    'protocol',
    'restrict_address_family',
    'source_address',
    'source_address_exclude',
    'source_port',
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
               'tcp-established',
               'is-fragment',
               'fragments'}
}

EXP_INFO = 2


class CiscoXRTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def testRemark(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]

    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1,
                             self.naming)
    acl = ciscoxr.CiscoXR(pol, EXP_INFO)
    expected = 'remark this is a test acl'
    self.assertIn(expected, str(acl), '[%s]' % str(acl))
    expected = 'remark good-term-1'
    self.assertIn(expected, str(acl), str(acl))
    expected = 'test-filter remark'
    self.assertNotIn(expected, str(acl), str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testStandardTermHost(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]

    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1 + GOOD_TERM_4,
                             self.naming)
    acl = ciscoxr.CiscoXR(pol, EXP_INFO)
    expected = 'ipv4 access-list test-filter'
    self.assertIn(expected, str(acl), '[%s]' % str(acl))
    expected = ' permit icmp host 10.1.1.1 any'
    self.assertIn(expected, str(acl), str(acl))
    expected = ' permit ipv4 host 10.1.1.1 any'
    self.assertIn(expected, str(acl), str(acl))

    self.naming.GetNetAddr.assert_has_calls([mock.call('SOME_HOST'),
                                             mock.call('SOME_HOST2')])

  def testStandardTermHostIPv6(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2001::3/128')]
    self.naming.GetServiceByProto.return_value = ['80']

    pol = policy.ParsePolicy(GOOD_HEADER_2 + GOOD_TERM_2 + GOOD_TERM_4,
                             self.naming)
    acl = ciscoxr.CiscoXR(pol, EXP_INFO)
    expected = 'ipv6 access-list ipv6-test-filter'
    self.assertIn(expected, str(acl), '[%s]' % str(acl))
    expected = ' permit tcp any eq 80 host 2001::3'
    self.assertIn(expected, str(acl), str(acl))
    expected = ' permit ipv6 host 2001::3 any'
    self.assertIn(expected, str(acl), str(acl))

    self.naming.GetNetAddr.assert_has_calls([mock.call('SOME_HOST2'),
                                             mock.call('SOME_HOST2')])
    self.naming.GetServiceByProto.assert_called_once_with('HTTP', 'tcp')

  def testAclBasedForwardingIPv4(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]

    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_5, self.naming)
    acl = ciscoxr.CiscoXR(pol, EXP_INFO)
    expected = 'ipv4 access-list test-filter'
    self.assertIn(expected, str(acl), '[%s]' % str(acl))
    expected = ' permit ipv4 any any nexthop1 ipv4 10.1.1.1'
    self.assertIn(expected, str(acl), str(acl))

    self.naming.GetNetAddr.assert_has_calls([mock.call('TEST_NEXT')])

  def testAclBasedForwardingIPv6(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2001::3/128')]

    pol = policy.ParsePolicy(GOOD_HEADER_2 + GOOD_TERM_5, self.naming)
    acl = ciscoxr.CiscoXR(pol, EXP_INFO)
    expected = 'ipv6 access-list ipv6-test-filter'
    self.assertIn(expected, str(acl), '[%s]' % str(acl))
    expected = ' permit ipv6 any any nexthop1 ipv6 2001::3'
    self.assertIn(expected, str(acl), str(acl))

    self.naming.GetNetAddr.assert_has_calls([mock.call('TEST_NEXT')])

  def testAclBasedForwardingMultipleIP(self):
    self.naming.GetNetAddr.return_value = [
        nacaddr.IP('10.1.1.0/32'),
        nacaddr.IP('10.1.1.1/32')
    ]

    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_5, self.naming)
    acl = ciscoxr.CiscoXR(pol, EXP_INFO)
    self.assertRaises(ciscoxr.cisco.CiscoNextIpError, str, acl)

    self.naming.GetNetAddr.assert_has_calls([mock.call('TEST_NEXT')])

  def testAclBasedForwardingNetworkIP(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.0/31')]

    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_5, self.naming)
    acl = ciscoxr.CiscoXR(pol, EXP_INFO)
    self.assertRaises(ciscoxr.cisco.CiscoNextIpError, str, acl)

    self.naming.GetNetAddr.assert_has_calls([mock.call('TEST_NEXT')])

  def testAclBasedForwardingNotIP(self):
    self.naming.GetNetAddr.return_value = ['not_ip_address']

    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_5, self.naming)
    acl = ciscoxr.CiscoXR(pol, EXP_INFO)
    self.assertRaises(ciscoxr.cisco.CiscoNextIpError, str, acl)

    self.naming.GetNetAddr.assert_has_calls([mock.call('TEST_NEXT')])

  def testAclBasedForwardingActionAcceptNextIpIgnored(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]

    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_6, self.naming)
    acl = ciscoxr.CiscoXR(pol, EXP_INFO)
    expected = 'ipv4 access-list test-filter'
    self.assertIn(expected, str(acl), '[%s]' % str(acl))
    expected = ' permit ipv4 any any'
    self.assertIn(expected, str(acl), str(acl))
    expected = 'nexthop1'
    self.assertNotIn(expected, str(acl), str(acl))

  def testBuildTokens(self):
    pol1 = ciscoxr.CiscoXR(policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1,
                                              self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2001::3/128')]
    self.naming.GetServiceByProto.return_value = ['80']

    pol1 = ciscoxr.CiscoXR(policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_3,
                                              self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

  def testVerbatimObjectGroup(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]
    pol = policy.ParsePolicy(OBJECT_GROUP_HEADER_1 + VERBATIM_TERM, self.naming)
    acl = ciscoxr.CiscoXR(pol, EXP_INFO)
    self.assertIn('permit tcp any', str(acl))


  def testVerbatimObjectGroupIPv6(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2001::3/128')]
    pol = policy.ParsePolicy(OBJECT_GROUP_HEADER_2 + VERBATIM_TERM, self.naming)
    acl = ciscoxr.CiscoXR(pol, EXP_INFO)
    self.assertIn('permit tcp any', str(acl))
    self.assertIn('ipv6 access-list foo', str(acl))


if __name__ == '__main__':
  absltest.main()
