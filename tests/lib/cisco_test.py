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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import datetime
import re
import unittest

from lib import aclgenerator
from lib import cisco
from lib import nacaddr
from lib import naming
from lib import policy
import mock


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
               'tcp-established'}
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class CiscoTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testIPVersion(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('0.0.0.0/0'),
                                           nacaddr.IP('::/0')]

    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_6, self.naming)
    acl = cisco.Cisco(pol, EXP_INFO)
    # check if we've got a v6 address in there.
    self.failIf('::' in str(acl), str(acl))

    self.naming.GetNetAddr.assert_called_once_with('ANY')

  def testOptions(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['80']

    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_2,
                                         self.naming), EXP_INFO)
    # this is a hacky sort of way to test that 'established' maps to HIGH_PORTS
    # in the destination port section.
    range_test = 'permit tcp any eq 80 10.0.0.0 0.255.255.255 range 1024 65535'
    self.failUnless(range_test in str(acl), '[%s]' % str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('HTTP', 'tcp')

  def testExpandingConsequtivePorts(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['80', '81']

    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_14,
                                         self.naming), EXP_INFO)
    first_string = 'permit tcp any 10.0.0.0 0.255.255.255 eq 80'
    second_string = 'permit tcp any 10.0.0.0 0.255.255.255 eq 81'
    self.failUnless(first_string in str(acl), '[%s]' % str(acl))
    self.failUnless(second_string in str(acl), '[%s]' % str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with(
            'CONSECUTIVE_PORTS', 'tcp')

  def testDSCP(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_16,
                                         self.naming), EXP_INFO)
    self.failUnless(re.search('permit tcp any any dscp 42', str(acl)),
                    str(acl))

  def testTermAndFilterName(self):
    acl = cisco.Cisco(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_1 + GOOD_TERM_6, self.naming), EXP_INFO)
    self.failUnless('ip access-list extended test-filter' in str(acl), str(acl))
    self.failUnless(' remark good-term-1' in str(acl), str(acl))
    self.failUnless(' permit ip any any' in str(acl), str(acl))

  def testRemark(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]

    # Extended ACLs should have extended remark style.
    acl = cisco.Cisco(policy.ParsePolicy(
        GOOD_EXTENDED_NUMBERED_HEADER + GOOD_TERM_1, self.naming), EXP_INFO)
    self.failUnless('ip access-list extended 150' in str(acl), str(acl))
    self.failUnless(' remark numbered extended' in str(acl), str(acl))
    self.failIf('150 remark' in str(acl), str(acl))
    # Extended ACLs should have extended remark style.
    acl = cisco.Cisco(policy.ParsePolicy(
        GOOD_STANDARD_NUMBERED_HEADER + GOOD_STANDARD_TERM_1, self.naming),
                      EXP_INFO)
    self.failUnless('access-list 50 remark' in str(acl), str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testTcpEstablished(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_3,
                                         self.naming), EXP_INFO)
    self.failUnless(re.search('permit tcp any any established\n',
                              str(acl)), str(acl))

  def testLogging(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_4,
                                         self.naming), EXP_INFO)
    self.failUnless(re.search('permit tcp any any log\n',
                              str(acl)), str(acl))

  def testVerbatimTerm(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_5,
                                         self.naming), EXP_INFO)
    self.failUnless('mary had a little lamb' in str(acl), str(acl))
    # check if other platforms verbatim shows up in ouput
    self.failIf('mary had a second lamb' in str(acl), str(acl))
    self.failIf('mary had a third lamb' in str(acl), str(acl))

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
    self.failUnless(expected in str(acl), '[%s]' % str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testStandardTermNet(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]

    pol = policy.ParsePolicy(GOOD_STANDARD_HEADER_1 + GOOD_STANDARD_TERM_2,
                             self.naming)
    acl = cisco.Cisco(pol, EXP_INFO)
    expected = 'access-list 99 permit 10.0.0.0 0.255.255.255'
    self.failUnless(expected in str(acl), '[%s]' % str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testNamedStandard(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]

    pol = policy.ParsePolicy(GOOD_STANDARD_HEADER_2 + GOOD_STANDARD_TERM_2,
                             self.naming)
    acl = cisco.Cisco(pol, EXP_INFO)
    expected = 'ip access-list standard FOO'
    self.failUnless(expected in str(acl), '[%s]' % str(acl))
    expected = ' permit 10.0.0.0 0.255.255.255'
    self.failUnless(expected in str(acl), '[%s]' % str(acl))

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testNoIPv6InOutput(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2620:0:1000::/40')]

    pol = policy.ParsePolicy(GOOD_STANDARD_HEADER_1 + GOOD_STANDARD_TERM_2,
                             self.naming)
    acl = cisco.Cisco(pol, EXP_INFO)
    self.failIf('::' in str(acl), '[%s]' % str(acl))

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

    self.failUnless('\n'.join(ip_grp) in str(acl), '%s %s' % (
        '\n'.join(ip_grp), str(acl)))
    self.failUnless('\n'.join(port_grp1) in str(acl), '%s %s' % (
        '\n'.join(port_grp1), str(acl)))
    self.failUnless('\n'.join(port_grp2) in str(acl), '%s %s' % (
        '\n'.join(port_grp2), str(acl)))

    # Object-group terms should use the object groups created.
    self.failUnless(
        ' permit tcp any port-group 80-80 net-group SOME_HOST port-group'
        ' 1024-65535' in str(acl), str(acl))
    self.failUnless(
        ' permit ip net-group SOME_HOST net-group SOME_HOST' in str(acl),
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
    self.failUnless(inet6_test1 in str(acl), '[%s]' % str(acl))
    self.failUnless(inet6_test2 in str(acl), '[%s]' % str(acl))
    self.failUnless(re.search(inet6_test3, str(acl)), str(acl))
    self.failIf('10.0.0.0' in str(acl), str(acl))

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
    self.failUnless(inet6_test1 in aclout, '[%s]' % aclout)
    self.failUnless(inet6_test2 in aclout, '[%s]' % aclout)
    self.failUnless(re.search(inet6_test3, aclout), aclout)
    self.failUnless(inet6_test4 in aclout, '[%s]' % aclout)
    self.failUnless(inet6_test5 in aclout, '[%s]' % aclout)
    self.failUnless(re.search(inet6_test6, aclout), aclout)

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
    self.failIf(re.search('permit 17 any any established',
                          str(acl)), str(acl))

  def testIcmpTypes(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_10,
                                         self.naming), EXP_INFO)
    # echo-reply = 0
    self.failUnless(re.search('permit icmp any any 0',
                              str(acl)), str(acl))
    # unreachable = 3
    self.failUnless(re.search('permit icmp any any 3',
                              str(acl)), str(acl))
    # time-exceeded = 11
    self.failUnless(re.search('permit icmp any any 11',
                              str(acl)), str(acl))

  def testIcmpCode(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_19,
                                         self.naming), EXP_INFO)
    output = str(acl)
    self.failUnless(' permit icmp any any 3 3' in output, output)
    self.failUnless(' permit icmp any any 3 4' in output, output)

  def testIpv6IcmpTypes(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_INET6_HEADER + GOOD_TERM_11,
                                         self.naming), EXP_INFO)
    # echo-reply = icmp-type code 129
    self.failUnless(re.search('permit 58 any any 129',
                              str(acl)), str(acl))
    # destination-unreachable = icmp-type code 1
    self.failUnless(re.search('permit 58 any any 1',
                              str(acl)), str(acl))
    # time-exceeded = icmp-type code 3
    self.failUnless(re.search('permit 58 any any 3',
                              str(acl)), str(acl))

  @mock.patch.object(cisco.logging, 'debug')
  def testIcmpv6InetMismatch(self, mock_debug):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_11,
                                         self.naming), EXP_INFO)
    # output happens in __str_
    str(acl)

    mock_debug.assert_called_once_with(
        'Term good-term-11 will not be rendered,'
        ' as it has [u\'icmpv6\'] match specified but '
        'the ACL is of inet address family.')

  @mock.patch.object(cisco.logging, 'debug')
  def testIcmpInet6Mismatch(self, mock_debug):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_INET6_HEADER + GOOD_TERM_1,
                                         self.naming), EXP_INFO)
    # output happens in __str_
    str(acl)

    mock_debug.assert_called_once_with(
        'Term good-term-1 will not be rendered,'
        ' as it has [u\'icmp\'] match specified but '
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
    self.failUnless(re.search('permit ipv6 any any', str(acl)), str(acl))

  @mock.patch.object(cisco.logging, 'warn')
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
    self.failUnless('permit hbh any any' in str(acl), str(acl))

  def testOwnerTerm(self):
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER +
                                         GOOD_TERM_13, self.naming), EXP_INFO)
    self.failUnless(re.search(' remark Owner: foo@google.com',
                              str(acl)), str(acl))

  def testRemoveTrailingCommentWhitespace(self):
    term = LONG_COMMENT_TERM%'a'*99
    acl = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + term,
                                         self.naming), EXP_INFO)

  def testBuildTokens(self):
    pol1 = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_5,
                                          self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    pol1 = cisco.Cisco(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_17,
                                          self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

  def testProtoInts(self):
    pol = policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_7 + GOOD_TERM_9,
        self.naming)
    acl = cisco.Cisco(pol, EXP_INFO)
    self.failUnless('permit 112 any any' in str(acl), str(acl))
    self.failUnless('permit tcp any any range 1024 65535 '
                    'established' in str(acl), str(acl))
    self.failUnless('permit udp any any range 1024 65535' in str(acl),
                    str(acl))

if __name__ == '__main__':
  unittest.main()
