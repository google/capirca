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

"""Unit test for Versa acl rendering module."""

import copy
import datetime
import re
from absl.testing import absltest
from unittest import mock
from capirca.lib import aclgenerator
from capirca.lib import versa
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy


GOOD_HEADER = """
header {
  comment:: "This is a test acl with a comment"
  target:: versa from-zone trust to-zone untrust template test tenant tenant1
}
"""
GOOD_HEADER_1 = """
header {
  comment:: "This is a test acl with a comment"
  target:: versa from-zone trust to-zone untrust
}
"""
GOOD_HEADER_2 = """
header {
  comment:: "This is a test acl with a comment"
  target:: versa from-zone trust to-zone untrust template test
}
"""

GOOD_HEADER_3 = """
header {
  comment:: "This is a test acl with a comment"
  target:: versa from-zone trust to-zone untrust template test tenant tenant1
}
"""

GOOD_HEADER_4 = """
header {
  comment:: "This is a test acl with a comment"
  target:: versa from-zone trust to-zone untrust template test tenant tenant1 policy Default-Policy
}
"""

GOOD_HEADER_NOVERBOSE = """
header {
  comment:: "This is a test acl with a comment"
  target:: versa from-zone trust to-zone untrust template test tenant tenant1 policy Default-Policy noverbose
}
"""

BAD_HEADER = """
header {
  target:: versa something
}
"""

BAD_HEADER_1 = """
header {
  comment:: "This header has two address families"
  target:: versa from-zone trust to-zone untrust inet6 mixed
}
"""

BAD_HEADER_3 = """
header {
  comment:: "This is a test acl with a global policy"
  target:: versa from-zone all to-zone all address-book-zone
}
"""

BAD_HEADER_4 = """
header {
  comment:: "This is a test acl with a global policy"
  target:: versa from-zone test to-zone all
}
"""

BAD_HEADER_5 = """
header {
  comment:: "This header has address-book-global in from zone"
  target:: versa from-zone address-book-global to-zone any
}
"""

GOOD_TERM_1 = """
term good-term-1 {
  comment:: "Term allow source dest"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: accept
}
"""

GOOD_TERM_2 = """
term good-term-1 {
  comment:: "Term reject source dest"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: reject
}
"""
GOOD_TERM_3 = """
term good-term-1 {
  comment:: "Term deny source dest"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: deny
}
"""

GOOD_TERM_4 = """
term good-term-1 {
  comment:: "Add a service"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  destination-port:: SMTP
  protocol:: tcp udp
  action:: accept
}
"""

GOOD_TERM_5 = """
term good-term-1 {
  comment:: "Add a pre-defined service"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: accept
  versa-application:: ssh
}
"""

GOOD_TERM_6 = """
term good-term-1 {
  comment:: "Add both service and pre-defined service"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  destination-port:: SMTP
  protocol:: tcp udp
  action:: accept
  versa-application:: ssh who
}
"""

GOOD_TERM_7 = """
term good-term-1 {
  comment:: "Add a source zone in term"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: accept
  source-zone:: gen
}
"""

GOOD_TERM_8 = """
term good-term-1 {
  comment:: "Add a dest zone in term"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: accept
  destination-zone:: gen
}
"""

GOOD_TERM_9 = """
term good-term-1 {
  comment:: "Add source and  dest zone in term"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: accept
  source-zone:: gen
  destination-zone:: untrust
}
"""

GOOD_TERM_10 = """
term good-term-1 {
  comment:: "Add dscp match"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: accept
  source-zone:: gen
  destination-zone:: untrust
  dscp-match:: 40 41
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

ICMP_TYPE_TERM_0 = """
term test-icmp {
  comment:: "Add icmp "
  protocol:: icmp
  action:: accept
}
"""

ICMP_TYPE_TERM_1 = """
term test-icmp {
  comment:: "Add icmp type not supported"
  protocol:: icmp
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

ICMP_TYPE_TERM_2 = """
term test-icmp {
  comment:: "Add icmpv6 not supported"
  protocol:: icmpv6
  action:: accept
}
"""

SUPPORTED_TOKENS = frozenset({
    'action',
    'comment',
    'counter',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'destination_zone',
    'dscp_except',
    'dscp_match',
    'dscp_set',
    'source_zone',
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
})

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


class VersaTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def testHeaderComment(self):
    pol = policy.ParsePolicy(GOOD_HEADER + ICMP_TYPE_TERM_0 , self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('This is a test acl with a comment', output, output)

  def testHeaderWithoutVersaHeader(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + ICMP_TYPE_TERM_0 , self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('template _templatename', output, output)
    self.assertIn('org-services _tenantname', output, output)
    self.assertIn('access-policy-group _policyname', output, output)

  def testHeaderWithoutVersaHeaderTemplate(self):
    pol = policy.ParsePolicy(GOOD_HEADER_2 + ICMP_TYPE_TERM_0 , self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('template test', output, output)

  def testHeaderWithoutVersaHeaderTenant(self):
    pol = policy.ParsePolicy(GOOD_HEADER_3 + ICMP_TYPE_TERM_0 , self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('org-services tenant1', output, output)

  def testHeaderWithNoVerbose(self):
    pol = policy.ParsePolicy(GOOD_HEADER_NOVERBOSE+ ICMP_TYPE_TERM_0,
                                            self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertNotIn('/*', output, output)
    self.assertNotIn('*/', output, output)

  def testHeaderWithoutVersaHeaderPolicy(self):
    pol = policy.ParsePolicy(GOOD_HEADER_4 + ICMP_TYPE_TERM_0 , self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('access-policy-group Default-Policy', output, output)

  def testIcmpV4(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + ICMP_TYPE_TERM_0 , self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn(' predefined-services-list [ ICMP ]', output, output)

  def testIcmpType(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + ICMP_TYPE_TERM_1 , self.naming)
    self.assertRaises(versa.VersaUnsupportedTerm, versa.Versa, pol, EXP_INFO)

  def testIcmpV6(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + ICMP_TYPE_TERM_2 , self.naming)
    self.assertRaises(versa.VersaUnsupportedTerm, versa.Versa, pol, EXP_INFO)

  def testSourceDestAllow(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('action allow', output, output)

  def testSourceDestReject(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_2, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('action reject', output, output)

  def testSourceDestDeny(self):
    self.naming.GetServiceByProto.return_value = ['25']
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_3, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('action deny', output, output)

  def testAddingService(self):
    self.naming.GetServiceByProto.return_value = ['25']
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_4, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('services-list [ good-term-1-app1 good-term-1-app2 ]',
                                          output, output)


  def testAddingApplication(self):
    self.naming.GetServiceByProto.return_value = ['25']
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_5, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn(' predefined-services-list [ ssh ]', output, output)


  def testAddingServiceApplication(self):
    self.naming.GetServiceByProto.return_value = ['25']
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_6, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('services-list [ good-term-1-app1 good-term-1-app2 ]',
                                                    output, output)
    self.assertIn(' predefined-services-list [ ssh who ]', output, output)

  def testSourceZone(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_7, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('zone-list [ gen ]', output, output)

  def testDestZone(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_8, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('zone-list [ gen ]', output, output)

  def testSourceDestZone(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_9, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('zone-list [ untrust ]', output, output)
    self.assertIn('zone-list [ gen ]', output, output)

  def testDscpMatch(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_10, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('dscp [ 40 41 ]', output, output)

  def testBadHeaderSupportedTargetOption(self):
    pol = policy.ParsePolicy(BAD_HEADER_5 + GOOD_TERM_10, self.naming)
    self.assertRaises(versa.UnsupportedFilterError, versa.Versa, pol, EXP_INFO)

  def testAdressBookIPv4(self):
    ipsetx = [nacaddr.IP('10.23.0.0/24'), nacaddr.IP('10.24.0.0/24')]
    self.naming.GetNetAddr.return_value = ipsetx
    self.naming.GetServiceByProto.return_value = ['25']
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_2, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('10.23.0.0/24', output, output)
    self.assertIn('10.24.0.0/24', output, output)

if __name__ == '__main__':
  absltest.main()
