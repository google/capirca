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
term good-term-2 {
  comment:: "Term reject source dest"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: reject
}
"""

GOOD_TERM_3 = """
term good-term-3 {
  comment:: "Term deny source dest"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: deny
}
"""

GOOD_TERM_4 = """
term good-term-4 {
  comment:: "Add a service"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  destination-port:: SMTP
  protocol:: tcp udp
  action:: accept
}
"""

GOOD_TERM_5 = """
term good-term-5 {
  comment:: "Add a pre-defined service"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: accept
  versa-application:: ssh
}
"""

GOOD_TERM_6 = """
term good-term-6 {
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
term good-term-7 {
  comment:: "Add a source zone in term"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: accept
  source-zone:: gen
}
"""

GOOD_TERM_8 = """
term good-term-8 {
  comment:: "Add a dest zone in term"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: accept
  destination-zone:: gen
}
"""

GOOD_TERM_9 = """
term good-term-9 {
  comment:: "Add source and  dest zone in term"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: accept
  source-zone:: gen
  destination-zone:: untrust
}
"""

GOOD_TERM_10 = """
term good-term-10 {
  comment:: "Add dscp match"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: accept
  source-zone:: gen
  destination-zone:: untrust
  dscp-match:: 40 41
}
"""

GOOD_TERM_11 = """
term good-term-11 {
  comment:: "This header is very very very very very very very very very very very very very very very very very very very very large"
  destination-address:: SOME_HOST
  source-address:: INTERNAL
  action:: accept
  source-zone:: gen
  destination-zone:: untrust
  dscp-match:: 40 41
}
"""

GOOD_TERM_12 = """
term good-term-12 {
  comment:: "Source address exclude"
  source-address:: INCLUDES
  source-exclude:: EXCLUDES
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_13 = """
term good-term-13 {
  comment:: "Destination address exclude"
  destination-address:: INCLUDES
  destination-exclude:: EXCLUDES
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_14 = """
term good-term-14 {
  destination-address:: DSTADDRS
  source-address:: SRCADDRS
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_LOG_1 = """
term good-term-log-1 {
  action:: accept
  logging:: log-both
}
"""

GOOD_TERM_LOG_2 = """
term good-term-log-2 {
  action:: accept
  logging:: true
}
"""

GOOD_TERM_LOG_3 = """
term good-term-log-3 {
  action:: deny
  logging:: disable
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
term test-icmp-1 {
  comment:: "Add icmp type not supported"
  protocol:: icmp
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

ICMP_TYPE_TERM_2 = """
term test-icmp-2 {
  comment:: "Add icmpv6 not supported"
  protocol:: icmpv6
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
  protocol:: icmp
}
"""

PLATFORM_TERM = """
term platform-term {
  protocol:: tcp udp
  platform:: versa
  action:: accept
}
"""

PLATFORM_EXCLUDE_TERM = """
term platform-exclude-term {
  protocol:: tcp udp
  platform-exclude:: versa
  action:: accept
}
"""


BAD_TERM_COUNT_1 = """
term bad-term-count-1 {
  counter:: good-counter
  action:: accept
}
"""

BAD_TERM_DSCP_SET = """
term bad-term-11 {
  destination-address:: SOME_HOST
  action:: accept
  dscp-set:: af42
}
"""

BAD_TERM_DSCP_EXCEPT = """
term bad-term-11 {
  destination-address:: SOME_HOST
  action:: accept
  dscp-except:: be
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

  def testLongComment(self):
    out1 = 'This header is very very very very very very very very very'
    out2 = 'very very very very very very very very very very very large'

    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_11, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))


    self.assertIn(out1, output, output)
    self.assertIn(out2, output, output)


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

  def testLoggingBoth(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_LOG_1, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('event both', output, output)

  def testLoggingTrue(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_LOG_2, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('event start', output, output)

  def testLoggingNever(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_LOG_3, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('event never', output, output)

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
    self.assertIn('services-list [ good-term-4-app1 good-term-4-app2 ]',
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
    self.assertIn('services-list [ good-term-6-app1 good-term-6-app2 ]',
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


  @mock.patch.object(versa.logging, 'warning')
  def testExpiredTerm(self, mock_warn):
    _ = versa.Versa(policy.ParsePolicy(GOOD_HEADER + EXPIRED_TERM_1,
                                                 self.naming), EXP_INFO)

    mock_warn.assert_called_once_with(
        'WARNING: Term %s in policy %s>%s is expired.',
        'expired_test', 'trust', 'untrust')

  @mock.patch.object(versa.logging, 'info')
  def testExpiringTerm(self, mock_info):
    exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
    pol = policy.ParsePolicy(GOOD_HEADER + EXPIRING_TERM %
                                                 exp_date.strftime('%Y-%m-%d'),
                                                 self.naming)

    _ = str(versa.Versa(pol, EXP_INFO))
    mock_info.assert_called_once_with(
        'INFO: Term %s in policy %s>%s expires in '
        'less than two weeks.', 'is_expiring',
        'trust', 'untrust')

  def testCounterAccept(self):
    pol = policy.ParsePolicy(GOOD_HEADER + BAD_TERM_COUNT_1,
                                                   self.naming)
    self.assertRaises(versa.VersaUnsupportedTerm,
                         versa.Versa, pol, EXP_INFO)

  def testDscpSet(self):
    pol = policy.ParsePolicy(GOOD_HEADER + BAD_TERM_DSCP_SET,
                                                   self.naming)
    self.assertRaises(aclgenerator.UnsupportedFilterError,
                      versa.Versa, pol, EXP_INFO)


  def testDscpExcept(self):
    pol = policy.ParsePolicy(GOOD_HEADER + BAD_TERM_DSCP_EXCEPT,
                                                   self.naming)
    self.assertRaises(aclgenerator.UnsupportedFilterError,
                      versa.Versa, pol, EXP_INFO)

  def testSourceAddressExclude(self):
    includes = ['1.0.0.0/8']
    excludes = ['1.0.0.0/8']
    self.naming.GetNetAddr.side_effect = [[nacaddr.IPv4(ip) for ip in includes],
                                          [nacaddr.IPv4(ip) for ip in excludes]]

    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_12,
                                                   self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('negate', output, output)

  def testDestinationAddressExclude(self):
    includes = ['1.0.0.0/8', '2.0.0.0/16' ]
    excludes = ['1.0.0.0/8', '2.0.0.0/16' ]
    self.naming.GetNetAddr.side_effect = [[nacaddr.IPv4(ip) for ip in includes],
                                          [nacaddr.IPv4(ip) for ip in excludes]]

    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_13,
                                                   self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('negate', output, output)

  @mock.patch.object(versa.logging, 'warning')
  def testDestinationAddresssNotMatching(self, mock_warn):
    includes = ['1.0.0.0/8', '2.0.0.0/16' ]
    excludes = ['1.0.0.0/8', '2.0.0.1/32' ]
    self.naming.GetNetAddr.side_effect = [[nacaddr.IPv4(ip) for ip in includes],
                                          [nacaddr.IPv4(ip) for ip in excludes]]

    _ = str(versa.Versa(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_13,
                                                 self.naming), EXP_INFO))
    mock_warn.assert_called_once_with(
        'WARNING: Term good-term-13 in policy ' +
        'has source or destination addresses that does not match '+
        'address list')

  def testAdressBookIPv4(self):
    srcaddrs = ['10.23.0.0/24', '10.24.0.0/24' ]
    dstaddrs = ['10.25.0.0/24', '10.26.0.0/24' ]
    self.naming.GetNetAddr.side_effect = [
                          [nacaddr.IPv4(ip) for ip in srcaddrs ],
                          [nacaddr.IPv4(ip) for ip in dstaddrs ]]

    self.naming.GetServiceByProto.return_value = ['25']
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_14, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('10.23.0.0/24', output, output)
    self.assertIn('10.24.0.0/24', output, output)
    self.assertIn('10.25.0.0/24', output, output)
    self.assertIn('10.26.0.0/24', output, output)

  def testAdressBookIPv6(self):
    srcaddrs = ['2620:15c:2c4:202:b0e7:158f:6a7a:3188/128',
                  '2620:15c:2c4:202:b0e7:158a:6a7a:3188/128' ]
    dstaddrs = ['2620:15c:2c4:202:b0e7:158b:6a7a:3188/128',
                  '2620:15c:2c4:202:b0e7:158c:6a7a:3188/128' ]
    self.naming.GetNetAddr.side_effect =[
                         [nacaddr.IPv6(ip) for ip in srcaddrs ],
                         [nacaddr.IPv6(ip) for ip in dstaddrs ]]

    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_14, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('2620:15c:2c4:202:b0e7:158f:6a7a:3188/128', output, output)
    self.assertIn('2620:15c:2c4:202:b0e7:158a:6a7a:3188/128', output, output)
    self.assertIn('2620:15c:2c4:202:b0e7:158b:6a7a:3188/128', output, output)
    self.assertIn('2620:15c:2c4:202:b0e7:158c:6a7a:3188/128', output, output)

  def testPlatformTerm(self):
    srcaddrs = ['10.23.0.0/24', '10.24.0.0/24' ]
    dstaddrs = ['10.25.0.0/24', '10.26.0.0/24' ]
    self.naming.GetNetAddr.side_effect = [
                          [nacaddr.IPv4(ip) for ip in srcaddrs ],
                          [nacaddr.IPv4(ip) for ip in dstaddrs ]]

    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_14 + PLATFORM_TERM, 
                                      self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('good-term-14', output, output)
    self.assertIn('platform-term', output, output)

  def testPlatformExcludeTerm(self):
    srcaddrs = ['10.23.0.0/24', '10.24.0.0/24' ]
    dstaddrs = ['10.25.0.0/24', '10.26.0.0/24' ]
    self.naming.GetNetAddr.side_effect = [
                          [nacaddr.IPv4(ip) for ip in srcaddrs ],
                          [nacaddr.IPv4(ip) for ip in dstaddrs ]]

    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_14, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('good-term-14', output, output)
    self.assertNotIn('platform-exclude-term', output)

  def testAdressBookMixedIPs(self):
    srcaddrs = [nacaddr.IPv4('10.23.0.0/24'),
                nacaddr.IPv6('2620:15c:2c4:202:b0e7:158a:6a7a:3188/128') ]
    dstaddrs = [nacaddr.IPv6('2620:15c:2c4:202:b0e7:158b:6a7a:3188/128'),
                   nacaddr.IPv4('10.24.0.0/24') ]
    self.naming.GetNetAddr.side_effect = [srcaddrs ,dstaddrs ]

    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_14, self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('10.23.0.0/24', output, output)
    self.assertIn('2620:15c:2c4:202:b0e7:158a:6a7a:3188/128', output, output)
    self.assertIn('2620:15c:2c4:202:b0e7:158b:6a7a:3188/128', output, output)
    self.assertIn('10.24.0.0/24', output, output)

  def testMultipleTerms1(self):
    self.naming.GetServiceByProto.return_value = ['25']
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_10 + GOOD_TERM_6,
                                                self.naming)
    output = str(versa.Versa(pol, EXP_INFO))
    self.assertIn('access-policy good-term-10', output, output)
    self.assertIn('access-policy good-term-6', output, output)

if __name__ == '__main__':
  absltest.main()
