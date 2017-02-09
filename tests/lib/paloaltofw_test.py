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

"""Unit test for Palo Alto Firewalls acl rendering module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

from lib import aclgenerator
from lib import nacaddr
from lib import naming
from lib import paloaltofw
from lib import policy
import mock


GOOD_HEADER_1 = """
header {
  comment:: "This is a test acl with a comment"
  target:: paloalto from-zone trust to-zone untrust
}
"""

GOOD_HEADER_2 = """
header {
  comment:: "This is a test acl with a comment"
  target:: paloalto from-zone all to-zone all
}
"""
BAD_HEADER_1 = """
header {
  comment:: "This header has two address families"
  target:: paloalto from-zone trust to-zone untrust inet6 mixed
}
"""

GOOD_TERM_1 = """
term good-term-1 {
  comment:: "This header is very very very very very very very very very very very very very very very very very very very very large"
  destination-address:: FOOBAR
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""
GOOD_TERM_2 = """
term good-term-4 {
  destination-address:: SOME_HOST
  protocol:: tcp
  pan-application:: ssl http
  action:: accept
}
"""
GOOD_TERM_3 = """
term only-pan-app {
  pan-application:: ssl
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

IPV6_ICMP_TERM = """
term test-ipv6_icmp {
  protocol:: icmpv6
  action:: accept
}
"""

BAD_ICMP_TERM_1 = """
term test-icmp-type {
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

ICMP_ONLY_TERM_1 = """
term test-icmp-only {
  protocol:: icmp
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

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'destination_address',
    'destination_port',
    'expiration',
    'icmp_type',
    'logging',
    'name',
    'owner',
    'platform',
    'protocol',
    'source_address',
    'source_port',
    'timeout',
    'pan_application',
    'translated'
}

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny', 'reject', 'count', 'log'},
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
_IPSET2 = [nacaddr.IP('10.23.0.0/22'), nacaddr.IP('10.23.0.6/23')]
_IPSET3 = [nacaddr.IP('10.23.0.0/23')]


class PaloAltoFWTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testTermAndFilterName(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    paloalto = paloaltofw.PaloAltoFW(
        policy.ParsePolicy(GOOD_HEADER_1 +GOOD_TERM_1,
                           self.naming), EXP_INFO)
    output = str(paloalto)
    self.failUnless('<entry name="good-term-1">' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('FOOBAR')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testDefaultDeny(self):
    paloalto = paloaltofw.PaloAltoFW(
        policy.ParsePolicy(GOOD_HEADER_1 + DEFAULT_TERM_1,
                           self.naming), EXP_INFO)
    output = str(paloalto)
    self.failUnless('<action>deny</action>' in output, output)

  def testIcmpTypes(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + ICMP_TYPE_TERM_1, self.naming)
    output = str(paloaltofw.PaloAltoFW(pol, EXP_INFO))
    self.failUnless('<member>ping</member>' in output, output)

  def testBadICMP(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + BAD_ICMP_TERM_1, self.naming)
    self.assertRaises(aclgenerator.UnsupportedFilterError,
                      paloaltofw.PaloAltoFW, pol, EXP_INFO)

  def testICMPProtocolOnly(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + ICMP_ONLY_TERM_1, self.naming)
    output = str(paloaltofw.PaloAltoFW(pol, EXP_INFO))
    self.failUnless('<member>ping</member>' in output, output)

  def testBuildTokens(self):
    self.naming.GetServiceByProto.side_effect = [['25'], ['26']]
    pol1 = paloaltofw.PaloAltoFW(policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_2,
                                                    self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

if __name__ == '__main__':
  unittest.main()
