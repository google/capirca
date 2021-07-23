# Copyright 2008 Google Inc. All Rights Reserved.
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

"""Unittest for cisco acl rendering module."""

import datetime
import re
from absl.testing import absltest
from unittest import mock

from capirca.lib import aclgenerator
from capirca.lib import cisco
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy


GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: cisco test-filter
}
"""
GOOD_STANDARD_HEADER_1 = """
header {
  comment:: "this is a standard acl"
  target:: cisco 99 standard
}
"""
GOOD_STANDARD_HEADER_2 = """
header {
  comment:: "this is a standard acl"
  target:: cisco FOO standard
}
"""
GOOD_STANDARD_NUMBERED_HEADER = """
header {
  comment:: "numbered standard"
  target:: cisco 50 standard
}
"""
GOOD_OBJGRP_HEADER = """
header {
  comment:: "obj group header test"
  target:: cisco objgroupheader object-group
}
"""
GOOD_INET6_HEADER = """
header {
  comment:: "inet6 header test"
  target:: cisco inet6_acl inet6
}
"""
GOOD_MIXED_HEADER = """
header {
  comment:: "mixed inet/inet6 header test"
  target:: cisco mixed_acl mixed
}
"""
GOOD_DSMO_HEADER = """
header {
  comment:: "this is a dsmo test acl"
  target:: cisco dsmo_acl extended enable_dsmo
}
"""
GOOD_EXTENDED_NUMBERED_HEADER = """
header {
  comment:: "numbered extended"
  target:: cisco 150 extended
}
"""
GOOD_NOVERBOSE_HEADER = """
header {
  comment:: "should not see me"
  target:: cisco test-filter noverbose
}
"""

GOOD_NOVERBOSE_STANDARD_HEADER = """
header {
  comment:: "should not see me"
  target:: cisco 99 standard noverbose
}
"""
GOOD_NOVERBOSE_OBJGRP_HEADER = """
header {
  comment:: "should not see me"
  target:: cisco objgroupheader object-group noverbose
}
"""
GOOD_NOVERBOSE_INET6_HEADER = """
header {
  comment:: "should not see me"
  target:: cisco inet6_acl inet6 noverbose
}
"""
BAD_STANDARD_HEADER_1 = """
header {
  comment:: "this is a standard acl"
  target:: cisco 2001 standard
}
"""
BAD_STANDARD_HEADER_2 = """
header {
  comment:: "this is a standard acl"
  target:: cisco 101 standard
}
"""
BAD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: juniper test-filter
}
"""
BAD_HEADER_2 = """
header {
  target:: cisco 1300
}
"""
LONG_VERSION_HEADER = """
header {
  comment:: "This long header should be split even on a looooooooooooooooooooooooooonnnnnnnnnnnnnnnnnngggggggggg string. https://www.google.com/maps/place/1600+Amphitheatre+Parkway,+Mountain+View,+CA/@37.507491,-122.2540443,15z/data=!4m5!3m4!1s0x808fb99f8c51e885:0x169ef02a512c5b28!8m2!3d37.4220579!4d-122.0840897"
  target:: cisco test-filter
}
"""
GOOD_STANDARD_TERM_1 = """
term standard-term-1 {
  address:: SOME_HOST
  action:: accept
}
"""
GOOD_STANDARD_TERM_2 = """
term standard-term-2 {
  address:: SOME_HOST
  action:: accept
}
"""
BAD_STANDARD_TERM_1 = """
term bad-standard-term-1 {
  destination-address:: SOME_HOST
  protocol:: tcp
  action:: accept
}
"""
UNSUPPORTED_TERM_1 = """
term protocol_except_term {
  protocol-except:: tcp udp icmp
  action:: reject
}
"""
UNSUPPORTED_TERM_2 = """
term protocol_except_term {
  source-prefix:: configured-neighbors-only
  action:: reject
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
"""
GOOD_TERM_2 = """
term good-term-2 {
  protocol:: tcp
  destination-address:: SOME_HOST
  source-port:: HTTP
  option:: established
  action:: accept
}
"""
GOOD_TERM_3 = """
term good-term-3 {
  protocol:: tcp
  option:: tcp-established
  action:: accept
}
"""
GOOD_TERM_4 = """
term good-term-4 {
  protocol:: tcp
  logging:: true
  action:: accept
}
"""
GOOD_TERM_5 = """
term good-term-5 {
  verbatim:: cisco "mary had a little lamb"
  verbatim:: iptables "mary had second lamb"
  verbatim:: juniper "mary had third lamb"
}
"""
GOOD_TERM_6 = """
term good-term-6 {
  destination-address:: ANY
  action:: accept
}
"""
GOOD_TERM_7 = """
term good-term {
  protocol:: vrrp
  action:: accept
}
"""
GOOD_TERM_8 = """
term good-term {
  protocol:: tcp
  destination-address:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_9 = """
term good-term-9 {
  protocol:: tcp udp
  option:: established
  action:: accept
}
"""
GOOD_TERM_10 = """
term good-term-10 {
  protocol:: icmp
  icmp-type:: echo-reply unreachable time-exceeded
  action:: accept
}
"""
GOOD_TERM_11 = """
term good-term-11 {
  protocol:: icmpv6
  icmp-type:: echo-reply destination-unreachable time-exceeded
  action:: accept
}
"""
GOOD_TERM_12 = """
term good-term-12 {
  action:: accept
}
"""

GOOD_TERM_13 = """
term good-term-13 {
  owner:: foo@google.com
  action:: accept
}
"""
GOOD_TERM_14 = """
term good-term-14 {
  protocol:: tcp
  destination-address:: SOME_HOST
  destination-port:: CONSECUTIVE_PORTS
  action:: accept
}
"""
GOOD_TERM_15 = """
term good-term-15 {
  protocol:: hopopt
  action:: accept
}
"""
GOOD_TERM_16 = """
term good-term-16 {
  protocol:: tcp
  action:: accept
  dscp-match:: 42
}
"""
GOOD_TERM_17 = """
term good-term-17 {
  protocol:: tcp udp
  policer:: batman
  option:: established
  action:: accept
}
"""
GOOD_TERM_18 = """
term good-term-18 {
  source-address:: SOME_HOST
  destination-address:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_19 = """
term good_term_19 {
  protocol:: icmp
  icmp-type:: unreachable
  icmp-code:: 3 4
  action:: accept
}
"""
GOOD_TERM_20 = """
term good_term_20 {
  source-address:: SOME_HOST
  destination-address:: SOME_HOST
  option:: fragments
  action:: accept
}
"""
GOOD_TERM_21 = """
term good_term_21 {
  source-address:: cs4-valid_network_name
  destination-address:: cs4-valid_network_name
  action:: accept
}
"""
GOOD_TERM_22 = """
term good_term_22 {
  source-address:: SOME_HOST
  destination-address:: SOME_HOST
  option:: is-fragment
  action:: accept
}
"""
LONG_COMMENT_TERM = """
term long-comment-term {
  comment:: "%s "
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

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class CiscoTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def testIPVersion(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('0.0.0.0/0'),
                                           nacaddr.IP('::/0')]

    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_6, self.naming)
    acl = cisco.Cisco(pol, EXP_INFO)
    # check if we've got a v6 address in there.
    self.assertNotIn('::', str(acl), str(acl))

    self.naming.GetNetAddr.assert_called_once_with('ANY')

  def testOptions(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['80']

    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_2,
                                         self.naming), EXP_INFO)
    # this is a hacky sort of way to test that 'established' maps to HIGH_PORTS
    # in the destination port section.
    range_test = 'permit tcp any eq 80 10.0.0.0 0.255.255.255 range 1024 65535'
    self.assertIn(range_test, str(acl), '[%s]' % str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('HTTP', 'tcp')

  def testExpandingConsequtivePorts(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['80', '81']

    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_14,
                                         self.naming), EXP_INFO)
    first_string = 'permit tcp any 10.0.0.0 0.255.255.255 eq 80'
    second_string = 'permit tcp any 10.0.0.0 0.255.255.255 eq 81'
    self.assertIn(first_string, str(acl), '[%s]' % str(acl))
    self.assertIn(second_string, str(acl), '[%s]' % str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with(
        'CONSECUTIVE_PORTS', 'tcp')

  def testDSCP(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_16,
                                         self.naming), EXP_INFO)
    self.assertTrue(re.search('permit tcp any any dscp 42', str(acl)),
                    str(acl))

  def testTermAndFilterName(self):
    acl = cisco.Cisco(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_1 + GOOD_TERM_6, self.naming), EXP_INFO)
    self.assertIn('ip access-list extended test-filter', str(acl), str(acl))
    self.assertIn(' remark good-term-1', str(acl), str(acl))
    self.assertIn(' permit ip any any', str(acl), str(acl))

  def testRemark(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]

    # Extended ACLs should have extended remark style.
    acl = cisco.Cisco(policy.ParsePolicy(
        GOOD_EXTENDED_NUMBERED_HEADER + GOOD_TERM_1, self.naming), EXP_INFO)
    self.assertIn('ip access-list extended 150', str(acl), str(acl))
    self.assertIn(' remark numbered extended', str(acl), str(acl))
    self.assertNotIn('150 remark', str(acl), str(acl))
    # Standard ACLs should have standard remark style.
    acl = cisco.Cisco(policy.ParsePolicy(
        GOOD_STANDARD_NUMBERED_HEADER + GOOD_STANDARD_TERM_1, self.naming),
                      EXP_INFO)
    self.assertIn('access-list 50 remark numbered standard', str(acl),
                  str(acl))
    self.assertIn('access-list 50 remark standard-term-1', str(acl),
                  str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testTcpEstablished(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_3,
                                         self.naming), EXP_INFO)
    self.assertTrue(re.search('permit tcp any any established\n',
                              str(acl)), str(acl))

  def testLogging(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_4,
                                         self.naming), EXP_INFO)
    self.assertTrue(re.search('permit tcp any any log\n',
                              str(acl)), str(acl))

  def testVerbatimTerm(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_5,
                                         self.naming), EXP_INFO)
    self.assertIn('mary had a little lamb', str(acl), str(acl))
    # check if other platforms verbatim shows up in ouput
    self.assertNotIn('mary had a second lamb', str(acl), str(acl))
    self.assertNotIn('mary had a third lamb', str(acl), str(acl))

  def testDuplicateTermNames(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/24')]
    pol = policy.ParsePolicy(GOOD_STANDARD_HEADER_1 + GOOD_STANDARD_TERM_1 +
                             GOOD_STANDARD_TERM_1, self.naming)
    self.assertRaises(cisco.CiscoDuplicateTermError, cisco.Cisco, pol, EXP_INFO)

  def testBadStandardTerm(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]

    pol = policy.ParsePolicy(GOOD_STANDARD_HEADER_1 + BAD_STANDARD_TERM_1,
                             self.naming)
    self.assertRaises(cisco.StandardAclTermError, cisco.Cisco, pol, EXP_INFO)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testStandardTermHost(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]

    pol = policy.ParsePolicy(GOOD_STANDARD_HEADER_1 + GOOD_STANDARD_TERM_1,
                             self.naming)
    acl = cisco.Cisco(pol, EXP_INFO)
    expected = 'access-list 99 permit 10.1.1.1'
    self.assertIn(expected, str(acl), '[%s]' % str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testStandardTermNet(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]

    pol = policy.ParsePolicy(GOOD_STANDARD_HEADER_1 + GOOD_STANDARD_TERM_2,
                             self.naming)
    acl = cisco.Cisco(pol, EXP_INFO)
    expected = 'access-list 99 permit 10.0.0.0 0.255.255.255'
    self.assertIn(expected, str(acl), '[%s]' % str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testNamedStandard(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]

    pol = policy.ParsePolicy(GOOD_STANDARD_HEADER_2 + GOOD_STANDARD_TERM_2,
                             self.naming)
    acl = cisco.Cisco(pol, EXP_INFO)
    expected = 'ip access-list standard FOO'
    self.assertIn(expected, str(acl), '[%s]' % str(acl))
    expected = ' permit 10.0.0.0 0.255.255.255\n'
    self.assertIn(expected, str(acl), '[%s]' % str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testNoIPv6InOutput(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2620:0:1000::/40')]

    pol = policy.ParsePolicy(GOOD_STANDARD_HEADER_1 + GOOD_STANDARD_TERM_2,
                             self.naming)
    acl = cisco.Cisco(pol, EXP_INFO)
    self.assertNotIn('::', str(acl), '[%s]' % str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testStandardFilterName(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]

    pol = policy.ParsePolicy(BAD_STANDARD_HEADER_1 + GOOD_STANDARD_TERM_2,
                             self.naming)
    self.assertRaises(cisco.UnsupportedCiscoAccessListError,
                      cisco.Cisco, pol, EXP_INFO)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testStandardFilterRange(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]

    pol = policy.ParsePolicy(BAD_STANDARD_HEADER_2 + GOOD_STANDARD_TERM_2,
                             self.naming)
    self.assertRaises(cisco.UnsupportedCiscoAccessListError,
                      cisco.Cisco, pol, EXP_INFO)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testObjectGroup(self):
    ip_grp = ['object-group network ipv4 SOME_HOST']
    ip_grp.append(' 10.0.0.0/8')
    ip_grp.append('exit')
    port_grp1 = ['object-group port 80-80']
    port_grp1.append(' eq 80')
    port_grp1.append('exit')
    port_grp2 = ['object-group port 1024-65535']
    port_grp2.append(' range 1024 65535')
    port_grp2.append('exit')

    self.naming.GetNetAddr.return_value = [
        nacaddr.IP('10.0.0.0/8', token='SOME_HOST')]
    self.naming.GetServiceByProto.return_value = ['80']

    pol = policy.ParsePolicy(
        GOOD_OBJGRP_HEADER + GOOD_TERM_2 + GOOD_TERM_18, self.naming)
    acl = cisco.Cisco(pol, EXP_INFO)

    self.assertIn('\n'.join(ip_grp), str(acl), '%s %s' % (
        '\n'.join(ip_grp), str(acl)))
    self.assertIn('\n'.join(port_grp1), str(acl), '%s %s' % (
        '\n'.join(port_grp1), str(acl)))
    self.assertIn('\n'.join(port_grp2), str(acl), '%s %s' % (
        '\n'.join(port_grp2), str(acl)))

    # Object-group terms should use the object groups created.
    self.assertIn(
        ' permit tcp any port-group 80-80 net-group SOME_HOST port-group'
        ' 1024-65535', str(acl), str(acl))
    self.assertIn(
        ' permit ip net-group SOME_HOST net-group SOME_HOST', str(acl),
        str(acl))

    # There should be no addrgroups that look like IP addresses.
    for addrgroup in re.findall(r'net-group ([a-f0-9.:/]+)', str(acl)):
      self.assertRaises(ValueError, nacaddr.IP(addrgroup))

    self.naming.GetNetAddr.assert_has_calls([mock.call('SOME_HOST'),
                                             mock.call('SOME_HOST')])
    self.naming.GetServiceByProto.assert_called_once_with('HTTP', 'tcp')

  def testInet6(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8'),
                                           nacaddr.IP('2001:4860:8000::/33')]

    acl = cisco.Cisco(policy.ParsePolicy(GOOD_INET6_HEADER + GOOD_TERM_8,
                                         self.naming), EXP_INFO)
    inet6_test1 = 'no ipv6 access-list inet6_acl'
    inet6_test2 = 'ipv6 access-list inet6_acl'
    inet6_test3 = 'permit tcp any 2001:4860:8000::/33'
    self.assertIn(inet6_test1, str(acl), '[%s]' % str(acl))
    self.assertIn(inet6_test2, str(acl), '[%s]' % str(acl))
    self.assertTrue(re.search(inet6_test3, str(acl)), str(acl))
    self.assertNotIn('10.0.0.0', str(acl), str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testMixed(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8'),
                                           nacaddr.IP('2001:4860:8000::/33')]

    acl = cisco.Cisco(policy.ParsePolicy(GOOD_MIXED_HEADER + GOOD_TERM_8,
                                         self.naming), EXP_INFO)
    inet6_test1 = 'no ip access-list extended mixed_acl'
    inet6_test2 = 'ip access-list extended mixed_acl'
    inet6_test3 = 'permit tcp any 10.0.0.0 0.255.255.255'
    inet6_test4 = 'no ipv6 access-list ipv6-mixed_acl'
    inet6_test5 = 'ipv6 access-list ipv6-mixed_acl'
    inet6_test6 = 'permit tcp any 2001:4860:8000::/33'
    aclout = str(acl)
    self.assertIn(inet6_test1, aclout, '[%s]' % aclout)
    self.assertIn(inet6_test2, aclout, '[%s]' % aclout)
    self.assertTrue(re.search(inet6_test3, aclout), aclout)
    self.assertIn(inet6_test4, aclout, '[%s]' % aclout)
    self.assertIn(inet6_test5, aclout, '[%s]' % aclout)
    self.assertTrue(re.search(inet6_test6, aclout), aclout)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testDsmo(self):
    addr_list = list()
    for octet in range(0, 256):
      net = nacaddr.IP('192.168.' + str(octet) + '.64/27')
      addr_list.append(net)
    self.naming.GetNetAddr.return_value = addr_list

    acl = cisco.Cisco(policy.ParsePolicy(GOOD_DSMO_HEADER + GOOD_TERM_8,
                                         self.naming), EXP_INFO)
    self.assertIn('permit tcp any 192.168.0.64 0.0.255.31', str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testUdpEstablished(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_9,
                                         self.naming), EXP_INFO)
    self.assertFalse(re.search('permit 17 any any established',
                               str(acl)), str(acl))

  def testIcmpTypes(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_10,
                                         self.naming), EXP_INFO)
    # echo-reply = 0
    self.assertTrue(re.search('permit icmp any any 0',
                              str(acl)), str(acl))
    # unreachable = 3
    self.assertTrue(re.search('permit icmp any any 3',
                              str(acl)), str(acl))
    # time-exceeded = 11
    self.assertTrue(re.search('permit icmp any any 11',
                              str(acl)), str(acl))

  def testIcmpCode(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_19,
                                         self.naming), EXP_INFO)
    output = str(acl)
    self.assertIn(' permit icmp any any 3 3', output, output)
    self.assertIn(' permit icmp any any 3 4', output, output)

  def testIpv6IcmpTypes(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_INET6_HEADER + GOOD_TERM_11,
                                         self.naming), EXP_INFO)
    # echo-reply = icmp-type code 129
    self.assertTrue(re.search('permit 58 any any 129',
                              str(acl)), str(acl))
    # destination-unreachable = icmp-type code 1
    self.assertTrue(re.search('permit 58 any any 1',
                              str(acl)), str(acl))
    # time-exceeded = icmp-type code 3
    self.assertTrue(re.search('permit 58 any any 3',
                              str(acl)), str(acl))

  @mock.patch.object(cisco.logging, 'debug')
  def testIcmpv6InetMismatch(self, mock_debug):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_11,
                                         self.naming), EXP_INFO)
    # output happens in __str_
    str(acl)

    mock_debug.assert_called_once_with(
        'Term good-term-11 will not be rendered,'
        ' as it has icmpv6 match specified but '
        'the ACL is of inet address family.')

  @mock.patch.object(cisco.logging, 'debug')
  def testIcmpInet6Mismatch(self, mock_debug):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_INET6_HEADER + GOOD_TERM_1,
                                         self.naming), EXP_INFO)
    # output happens in __str_
    str(acl)

    mock_debug.assert_called_once_with(
        'Term good-term-1 will not be rendered,'
        ' as it has icmp match specified but '
        'the ACL is of inet6 address family.')

  def testUnsupportedKeywordsError(self):
    pol1 = policy.ParsePolicy(GOOD_HEADER + UNSUPPORTED_TERM_1, self.naming)
    pol2 = policy.ParsePolicy(GOOD_HEADER + UNSUPPORTED_TERM_1, self.naming)
    # protocol-except
    self.assertRaises(aclgenerator.UnsupportedFilterError,
                      cisco.Cisco, pol1, EXP_INFO)
    # source-prefix
    self.assertRaises(aclgenerator.UnsupportedFilterError,
                      cisco.Cisco, pol2, EXP_INFO)

  def testDefaultInet6Protocol(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_INET6_HEADER + GOOD_TERM_12,
                                         self.naming), EXP_INFO)
    self.assertTrue(re.search('permit ipv6 any any', str(acl)), str(acl))

  @mock.patch.object(cisco.logging, 'warning')
  def testExpiredTerm(self, mock_warn):
    _ = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + EXPIRED_TERM,
                                       self.naming), EXP_INFO)

    mock_warn.assert_called_once_with(
        'WARNING: Term %s in policy %s is expired and will not '
        'be rendered.', 'is_expired', 'test-filter')

  @mock.patch.object(cisco.logging, 'info')
  def testExpiringTerm(self, mock_info):
    exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
    _ = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + EXPIRING_TERM %
                                       exp_date.strftime('%Y-%m-%d'),
                                       self.naming), EXP_INFO)

    mock_info.assert_called_once_with(
        'INFO: Term %s in policy %s expires in '
        'less than two weeks.', 'is_expiring', 'test-filter')

  def testTermHopByHop(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_15,
                                         self.naming), EXP_INFO)
    self.assertIn('permit hbh any any', str(acl), str(acl))

  def testOwnerTerm(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER +
                                         GOOD_TERM_13, self.naming), EXP_INFO)
    self.assertTrue(re.search(' remark Owner: foo@google.com',
                              str(acl)), str(acl))

  def testBuildTokens(self):
    pol1 = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_5,
                                          self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    pol1 = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_17,
                                          self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

  def testProtoInts(self):
    pol = policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_7 + GOOD_TERM_9,
        self.naming)
    acl = cisco.Cisco(pol, EXP_INFO)
    self.assertIn('permit 112 any any', str(acl), str(acl))
    self.assertIn('permit tcp any any range 1024 65535 '
                  'established', str(acl), str(acl))
    self.assertIn('permit udp any any range 1024 65535', str(acl),
                  str(acl))

  def testFragments01(self):
    """Test policy term using 'fragments' (ref Github issue #187)."""
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/24')]
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_20,
                                         self.naming), EXP_INFO)
    expected = 'permit ip 10.0.0.0 0.0.0.255 10.0.0.0 0.0.0.255 fragments'
    self.assertIn(expected, str(acl), str(acl))

    self.naming.GetNetAddr.assert_has_calls([mock.call('SOME_HOST'),
                                             mock.call('SOME_HOST')])

  def testFragments02(self):
    """Test policy term using 'is-fragment' (ref Github issue #187)."""
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/24')]
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_22,
                                         self.naming), EXP_INFO)
    expected = 'permit ip 10.0.0.0 0.0.0.255 10.0.0.0 0.0.0.255 fragments'
    self.assertIn(expected, str(acl))

  def testTermDSCPMarker(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/24')]
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_21,
                                         self.naming), EXP_INFO)
    expected = 'permit ip 10.0.0.0 0.0.0.255 10.0.0.0 0.0.0.255'
    self.assertIn(expected, str(acl))

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('cs4-valid_network_name'),
         mock.call('cs4-valid_network_name')])

  def testNoVerbose(self):
    for i in [GOOD_NOVERBOSE_HEADER, GOOD_NOVERBOSE_STANDARD_HEADER,
              GOOD_NOVERBOSE_OBJGRP_HEADER, GOOD_NOVERBOSE_INET6_HEADER]:
      self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/24')]
      acl = cisco.Cisco(policy.ParsePolicy(i+GOOD_STANDARD_TERM_1, self.naming),
                        EXP_INFO)
      self.assertNotIn('remark', str(acl), str(acl))

  def testLongHeader(self):
    pol = policy.ParsePolicy(
        LONG_VERSION_HEADER + GOOD_TERM_7,
        self.naming)
    acl = cisco.Cisco(pol, EXP_INFO)
    print(acl)
    self.assertIn('remark This long header should be split even on a', str(acl))
    self.assertIn(('remark looooooooooooooooooooooooooonnnnnnnnnnnnnnnnnn'
                   'gggggggggg string.'), str(acl))
    self.assertIn(('remark https://www.google.com/maps/place/1600+Amphitheatr'
                   'e+Parkway,+Mountain+'), str(acl))
    self.assertIn(('remark View,+CA/@37.507491,-122.2540443,15z/data=!4m5!3m4!'
                   '1s0x808fb99f8c51e88'), str(acl))
    self.assertIn(('remark 5:0x169ef02a512c5b28!8m2!3d37.4220579!4d-122.084'
                   '0897'), str(acl))


if __name__ == '__main__':
  absltest.main()
