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

"""Unit test for Juniper SRX acl rendering module."""

import copy
import datetime
import unittest


from lib import aclgenerator
from lib import junipersrx
from lib import nacaddr
from lib import naming
from lib import policy
from lib import policyparser
import mock


GOOD_HEADER = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone untrust
}
"""
GOOD_HEADER_2 = """
header {
  comment:: "This is a header from untrust to trust"
  target:: srx from-zone untrust to-zone trust
}
"""
GOOD_HEADER_3 = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone untrust inet
}
"""
GOOD_HEADER_4 = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone untrust inet6
}
"""
GOOD_HEADER_5 = """
header {
  target:: srx from-zone trust to-zone untrust inet
  apply-groups:: tcp-test1 tcp-test2
}
"""
GOOD_HEADER_6 = """
header {
  target:: srx from-zone trust to-zone untrust inet
  apply-groups-except:: tcp-test1 tcp-test2
}
"""
GOOD_HEADER_7 = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone untrust address-book-zone inet
}
"""

GOOD_HEADER_8 = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone untrust address-book-zone inet6
}
"""

GOOD_HEADER_9 = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone untrust address-book-zone
}
"""

GOOD_HEADER_10 = """
header {
  comment:: "This is a test acl with a global policy"
  target:: srx from-zone all to-zone all address-book-global
}
"""

GOOD_HEADER_11 = """
header {
  comment:: "This is a test acl with a comment"
  target:: srx from-zone trust to-zone dmz
}
"""

BAD_HEADER = """
header {
  target:: srx something
}
"""

BAD_HEADER_1 = """
header {
  comment:: "This header has two address families"
  target:: srx from-zone trust to-zone untrust inet6 mixed
}
"""

BAD_HEADER_2 = """
header {
  comment:: "This header has two address-book-types"
  target:: srx from-zone trust to-zone untrust address-book-zone address-book-zone
}
"""

BAD_HEADER_3 = """
header {
  comment:: "This is a test acl with a global policy"
  target:: srx from-zone all to-zone all address-book-zone
}
"""

BAD_HEADER_4 = """
header {
  comment:: "This is a test acl with a global policy"
  target:: srx from-zone test to-zone all
}
"""

GOOD_TERM_1 = """
term good-term-1 {
  comment:: "This header is very very very very very very very very very very very very very very very very very very very very large"
  destination-address:: SOME_HOST
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_2 = """
term good-term-2 {
  destination-address:: SOME_HOST
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_3 = """
term good-term-3 {
  destination-address:: SOME_HOST
  protocol:: tcp
  action:: accept
  vpn:: good-vpn-3
}
"""

GOOD_TERM_4 = """
term good-term-4 {
  destination-address:: SOME_HOST
  protocol:: tcp
  action:: accept
  vpn:: good-vpn-4 policy-4
}
"""
GOOD_TERM_5 = '''
term good-term-5 {
  action:: accept
  logging:: log-both
}
'''
GOOD_TERM_10 = """
term good-term-10 {
  destination-address:: SOME_HOST
  action:: accept
  dscp-set:: b111000
}
"""
GOOD_TERM_11 = """
term good-term-11 {
  destination-address:: SOME_HOST
  action:: accept
  dscp-set:: af42
  dscp-match:: af41-af42 5
  dscp-except:: be
}
"""

GOOD_TERM_12 = """
term dup-of-term-1 {
  destination-address:: FOOBAR
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_13 = """
term dup-of-term-1 {
  destination-address:: FOOBAR SOME_HOST
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""


GOOD_TERM_14 = """
term term_to_split {
  source-address:: FOOBAR
  destination-address:: SOME_HOST
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

BAD_TERM_1 = """
term bad-term-1 {
  destination-address:: SOME_HOST
  protocol:: tcp
  action:: deny
  vpn:: good-vpn-4 policy-4
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
term test-icmp {
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

ICMP_ONLY_TERM_1 = """
term test-icmp {
  protocol:: icmp
  action:: accept
}
"""

OWNER_TERM = """
term owner-test {
  owner:: foo@google.com
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

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2

_IPSET = [nacaddr.IP('10.0.0.0/8'),
          nacaddr.IP('2001:4860:8000::/33')]
_IPSET2 = [nacaddr.IP('10.23.0.0/22'), nacaddr.IP('10.23.0.6/23')]
_IPSET3 = [nacaddr.IP('10.23.0.0/23')]


class JuniperSRXTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testHeaderComment(self):
    pol = policyparser.ParsePolicy(GOOD_HEADER + ICMP_TYPE_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('This is a test acl with a comment' in output, output)

  def testHeaderApplyGroups(self):
    pol = policyparser.ParsePolicy(GOOD_HEADER_5 + ICMP_TYPE_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('apply-groups [ tcp-test1 tcp-test2 ]' in output,
                    output)

  def testHeaderApplyGroupsExcept(self):
    pol = policyparser.ParsePolicy(GOOD_HEADER_6 + ICMP_TYPE_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('apply-groups-except [ tcp-test1 tcp-test2 ]' in output,
                    output)

  def testLongComment(self):
    expected_output = """
            /*
            This header is very very very very very very very very very very
            very very very very very very very very very very large
            */"""
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    srx = junipersrx.JuniperSRX(policyparser.ParsePolicy(GOOD_HEADER + GOOD_TERM_1,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.failUnless(expected_output in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testTermAndFilterName(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    srx = junipersrx.JuniperSRX(policyparser.ParsePolicy(GOOD_HEADER + GOOD_TERM_1,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.failUnless('policy good-term-1 {' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testVpnWithoutPolicy(self):
    self.naming.GetNetAddr.return_value = _IPSET

    srx = junipersrx.JuniperSRX(policyparser.ParsePolicy(GOOD_HEADER + GOOD_TERM_3,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.failUnless('ipsec-vpn good-vpn-3;' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testVpnWithPolicy(self):
    self.naming.GetNetAddr.return_value = _IPSET

    srx = junipersrx.JuniperSRX(policyparser.ParsePolicy(GOOD_HEADER + GOOD_TERM_4,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.failUnless('ipsec-vpn good-vpn-4;' in output, output)
    self.failUnless('pair-policy policy-4;' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testVpnWithDrop(self):
    self.naming.GetNetAddr.return_value = _IPSET

    srx = junipersrx.JuniperSRX(policyparser.ParsePolicy(GOOD_HEADER + BAD_TERM_1,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.failUnless('ipsec-vpn good-vpn-4;' not in output, output)
    self.failUnless('pair-policy policy-4;' not in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testDefaultDeny(self):
    srx = junipersrx.JuniperSRX(policyparser.ParsePolicy(GOOD_HEADER + DEFAULT_TERM_1,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.failUnless('deny;' in output, output)

  def testIcmpTypes(self):
    pol = policyparser.ParsePolicy(GOOD_HEADER + ICMP_TYPE_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('application test-icmp-app;' in output, output)
    self.failUnless('application test-icmp-app {' in output, output)
    self.failUnless('term t1 protocol icmp icmp-type 0 inactivity-timeout 60'
                    in output, output)
    self.failUnless('term t2 protocol icmp icmp-type 8 inactivity-timeout 60'
                    in output, output)

  def testLoggingBoth(self):
    srx = junipersrx.JuniperSRX(policyparser.ParsePolicy(GOOD_HEADER + GOOD_TERM_5,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.failUnless('session-init;' in output, output)
    self.failUnless('session-close;' in output, output)

  def testOwnerTerm(self):
    pol = policyparser.ParsePolicy(GOOD_HEADER + OWNER_TERM, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('            /*\n'
                    '            Owner: foo@google.com\n'
                    '            */' in output, output)

  def testBadICMP(self):
    pol = policyparser.ParsePolicy(GOOD_HEADER + BAD_ICMP_TERM_1, self.naming)
    self.assertRaises(aclgenerator.UnsupportedFilterError,
                      junipersrx.JuniperSRX, pol, EXP_INFO)

  def testICMPProtocolOnly(self):
    pol = policyparser.ParsePolicy(GOOD_HEADER + ICMP_ONLY_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('protocol icmp;' in output, output)

  def testMultipleProtocolGrouping(self):
    pol = policyparser.ParsePolicy(GOOD_HEADER + MULTIPLE_PROTOCOLS_TERM, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('application-set multi-proto-app {' in output, output)
    self.failUnless('application multi-proto-app1;' in output, output)
    self.failUnless('application multi-proto-app2;' in output, output)
    self.failUnless('application multi-proto-app3;' in output, output)
    self.failUnless('application multi-proto-app1 {' in output, output)
    self.failUnless('term t1 protocol tcp;' in output, output)
    self.failUnless('application multi-proto-app2 {' in output, output)
    self.failUnless('term t2 protocol udp;' in output, output)
    self.failUnless('application multi-proto-app3 {' in output, output)
    self.failUnless('term t3 protocol icmp;' in output, output)

  def testGlobalPolicyHeader(self):
    pol = policyparser.ParsePolicy(GOOD_HEADER_10 + MULTIPLE_PROTOCOLS_TERM,
                             self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.assertEqual(output.count('global {'), 2)
    self.assertFalse('from-zone all to-zone all {' in output)

  def testBadGlobalPolicyHeaderZoneBook(self):
    pol = policyparser.ParsePolicy(BAD_HEADER_3 + MULTIPLE_PROTOCOLS_TERM,
                             self.naming)
    self.assertRaises(junipersrx.UnsupportedFilterError, junipersrx.JuniperSRX,
                      pol, EXP_INFO)

  def testBadGlobalPolicyHeaderNameAll(self):
    pol = policyparser.ParsePolicy(BAD_HEADER_4 + MULTIPLE_PROTOCOLS_TERM,
                             self.naming)
    self.assertRaises(junipersrx.UnsupportedFilterError, junipersrx.JuniperSRX,
                      pol, EXP_INFO)

  def testBadHeaderType(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(BAD_HEADER + GOOD_TERM_1, self.naming)
    self.assertRaises(junipersrx.UnsupportedFilterError, junipersrx.JuniperSRX,
                      pol, EXP_INFO)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testBadHeaderMultiAF(self):
    # test for multiple address faimilies in header
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(BAD_HEADER_1 + GOOD_TERM_1, self.naming)
    self.assertRaises(junipersrx.ConflictingTargetOptions,
                      junipersrx.JuniperSRX,
                      pol, EXP_INFO)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testBadHeaderMultiAB(self):
    # test for multiple address-book-types in header
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(BAD_HEADER_2 + GOOD_TERM_1, self.naming)
    self.assertRaises(junipersrx.ConflictingTargetOptions,
                      junipersrx.JuniperSRX,
                      pol, EXP_INFO)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  @mock.patch.object(junipersrx.logging, 'warn')
  def testExpiredTerm(self, mock_warn):
    _ = junipersrx.JuniperSRX(policyparser.ParsePolicy(GOOD_HEADER + EXPIRED_TERM_1,
                                                 self.naming), EXP_INFO)

    mock_warn.assert_called_once_with(
        'WARNING: Term %s in policy %s>%s is expired.',
        'expired_test', 'trust', 'untrust')

  @mock.patch.object(junipersrx.logging, 'info')
  def testExpiringTerm(self, mock_info):
    exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
    _ = junipersrx.JuniperSRX(policyparser.ParsePolicy(GOOD_HEADER + EXPIRING_TERM %
                                                 exp_date.strftime('%Y-%m-%d'),
                                                 self.naming), EXP_INFO)

    mock_info.assert_called_once_with(
        'INFO: Term %s in policy %s>%s expires in '
        'less than two weeks.', 'is_expiring',
        'trust', 'untrust')

  def testTimeout(self):
    pol = policyparser.ParsePolicy(GOOD_HEADER + TIMEOUT_TERM, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('timeout 77' in output, output)

  def testIcmpV6(self):
    pol = policyparser.ParsePolicy(GOOD_HEADER + IPV6_ICMP_TERM, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('protocol icmp6' in output, output)

  def testReplaceStatement(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(GOOD_HEADER + GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('replace: address-book' in output, output)
    self.failUnless('replace: policies' in output, output)
    self.failUnless('replace: applications' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testAdressBookBothAFs(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(GOOD_HEADER + GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('replace: address-book {' in output, output)
    self.failUnless('global {' in output, output)
    self.failUnless('2001:4860:8000::/33' in output, output)
    self.failUnless('10.0.0.0/8' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testAdressBookIPv4(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('replace: address-book {' in output, output)
    self.failUnless('global {' in output, output)
    self.failUnless('2001:4860:8000::/33' not in output, output)
    self.failUnless('10.0.0.0/8' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testAdressBookIPv6(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(GOOD_HEADER_4 + GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('replace: address-book {' in output, output)
    self.failUnless('global {' in output, output)
    self.failUnless('2001:4860:8000::/33' in output, output)
    self.failUnless('10.0.0.0/8' not in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testAddressBookContainsSmallerPrefix(self):
    _IPSET2[0].parent_token = 'FOOBAR'
    _IPSET2[1].parent_token = 'SOME_HOST'
    _IPSET3[0].parent_token = 'FOOBAR'
    self.naming.GetNetAddr.side_effect = [_IPSET2, _IPSET3]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(GOOD_HEADER + GOOD_TERM_1 + GOOD_HEADER_2 +
                             GOOD_TERM_12, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('address FOOBAR_0 10.23.0.0/22;' in output, output)

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('SOME_HOST'),
        mock.call('FOOBAR')])
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('SMTP', 'tcp')] * 2)

  def testAddressBookContainsLargerPrefix(self):
    _IPSET2[0].parent_token = 'FOOBAR'
    _IPSET2[1].parent_token = 'SOME_HOST'
    _IPSET3[0].parent_token = 'FOOBAR'
    self.naming.GetNetAddr.side_effect = [_IPSET3, _IPSET2]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(GOOD_HEADER_2 + GOOD_TERM_12 + GOOD_HEADER +
                             GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('address FOOBAR_0 10.23.0.0/22;' in output, output)

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('FOOBAR'),
        mock.call('SOME_HOST')])
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('SMTP', 'tcp')] * 2)

  def testZoneAdressBookBothAFs(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(GOOD_HEADER_9 + GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('security-zone untrust {' in output, output)
    self.failUnless('replace: address-book {' in output, output)
    self.failUnless('2001:4860:8000::/33' in output, output)
    self.failUnless('10.0.0.0/8' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testZoneAdressBookIPv4(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(GOOD_HEADER_7 + GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('security-zone untrust {' in output, output)
    self.failUnless('replace: address-book {' in output, output)
    self.failUnless('2001:4860:8000::/33' not in output, output)
    self.failUnless('10.0.0.0/8' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testZoneAdressBookIPv6(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(GOOD_HEADER_8 + GOOD_TERM_1, self.naming)
    output = str(junipersrx.JuniperSRX(pol, EXP_INFO))
    self.failUnless('security-zone untrust {' in output, output)
    self.failUnless('replace: address-book {' in output, output)
    self.failUnless('2001:4860:8000::/33' in output, output)
    self.failUnless('10.0.0.0/8' not in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def _FailIfUnorderedAddressBook(self, address_book):
    # This is very naive check that expects addresses to be exact as returned
    # from _OutOfOrderAddresses method. If you modify one please modify this one
    # as well.
    for line in address_book:
      if '10.0.0.0/8' in line:
        self.fail('Addresses in address book are out of order.')
      elif '1.0.0.0/8' in line:
        break

  def _OutOfOrderAddresses(self):
    x = nacaddr.IP('10.0.0.0/8')
    x.parent_token = 'test'
    y = nacaddr.IP('1.0.0.0/8')
    y.parent_token = 'out_of_order'

    return x, y

  def testAddressBookOrderingSuccess(self):
    self.naming.GetNetAddr.return_value = self._OutOfOrderAddresses()
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_2, self.naming)
    p = junipersrx.JuniperSRX(pol, EXP_INFO)

    self._FailIfUnorderedAddressBook(p._GenerateAddressBook())

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testAddressBookOrderingAlreadyOrdered(self):
    y, x = self._OutOfOrderAddresses()
    self.naming.GetNetAddr.return_value = [x, y]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_2, self.naming)
    p = junipersrx.JuniperSRX(pol, EXP_INFO)

    self._FailIfUnorderedAddressBook(p._GenerateAddressBook())

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def _AssertOrder(self, strings, expected_order):
    order = copy.copy(expected_order)
    matcher = order.pop(0)
    for line in strings:
      if matcher in line:
        if not order:
          return
        matcher = order.pop(0)

    self.fail('Strings weren\'t in expected order.\nExpected:\n  %s\n\nGot:\n%s'
              % ('\n  '.join(expected_order), '\n'.join(strings)))

  def testApplicationsOrderingSuccess(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_2 + GOOD_TERM_1,
                             self.naming)
    p = junipersrx.JuniperSRX(pol, EXP_INFO)
    self._AssertOrder(p._GenerateApplications(),
                      ['application good-term-1-app1',
                       'application good-term-2-app1',
                       'application-set good-term-1-app',
                       'application-set good-term-2-app'])

    self.naming.GetNetAddr.assert_has_calls(
            [mock.call('SOME_HOST')] * 2)
    self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('SMTP', 'tcp')] * 2)

  def testApplicationsOrderingAlreadyOrdered(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_1 + GOOD_TERM_2,
                             self.naming)
    p = junipersrx.JuniperSRX(pol, EXP_INFO)
    self._AssertOrder(p._GenerateApplications(),
                      ['application good-term-1-app1',
                       'application good-term-2-app1',
                       'application-set good-term-1-app',
                       'application-set good-term-2-app'])

    self.naming.GetNetAddr.assert_has_calls(
            [mock.call('SOME_HOST')] * 2)
    self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('SMTP', 'tcp')] * 2)

  def testDscpWithByte(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    srx = junipersrx.JuniperSRX(policyparser.ParsePolicy(GOOD_HEADER + GOOD_TERM_10,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.failUnless('dscp b111000;' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testDscpWithClass(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]

    srx = junipersrx.JuniperSRX(policyparser.ParsePolicy(GOOD_HEADER + GOOD_TERM_11,
                                                   self.naming), EXP_INFO)
    output = str(srx)
    self.failUnless('dscp af42;' in output, output)
    self.failUnless('dscp [ af41-af42 5 ];' in output, output)
    self.failUnless('dscp-except [ be ];' in output, output)

    self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')

  def testLargeTermSplitting(self):
    ips = list(nacaddr.IP('10.0.8.0/21').iter_subnets(new_prefix=32))
    mo_ips = []
    counter = 0
    for ip in ips:
      if counter%2 == 0:
        mo_ips.append(nacaddr.IP(ip))
      counter += 1

    ips = list(nacaddr.IP('10.0.0.0/21').iter_subnets(new_prefix=32))
    prodcolos_ips = []
    counter = 0
    for ip in ips:
      if counter%2 == 0:
        prodcolos_ips.append(nacaddr.IP(ip))
      counter += 1

    self.naming.GetNetAddr.side_effect = [mo_ips, prodcolos_ips]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(GOOD_HEADER_2 + GOOD_TERM_14, self.naming)
    srx = junipersrx.JuniperSRX(pol, EXP_INFO)
    self.assertEqual(len(srx.policy.filters[0][1]), 4)

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('FOOBAR'),
        mock.call('SOME_HOST')])
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testLargeTermSplittingV6(self):
    ips = list(nacaddr.IP('2620:0:1000:3103:eca0:2c09:6b32:e000/119'
                         ).iter_subnets(new_prefix=128))
    mo_ips = []
    counter = 0
    for ip in ips:
      if counter%2 == 0:
        mo_ips.append(nacaddr.IP(ip))
      counter += 1

    ips = list(nacaddr.IP('2720:0:1000:3103:eca0:2c09:6b32:e000/119'
                         ).iter_subnets(new_prefix=128))
    prodcolos_ips = []
    counter = 0
    for ip in ips:
      if counter%2 == 0:
        prodcolos_ips.append(nacaddr.IP(ip))
      counter += 1

    self.naming.GetNetAddr.side_effect = [mo_ips, prodcolos_ips]
    self.naming.GetServiceByProto.return_value = ['25']

    pol = policyparser.ParsePolicy(GOOD_HEADER_2 + GOOD_TERM_14, self.naming)
    srx = junipersrx.JuniperSRX(pol, EXP_INFO)
    self.assertEqual(len(srx.policy.filters[0][1]), 4)

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('FOOBAR'),
        mock.call('SOME_HOST')])
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testDuplicateTermsInDifferentZones(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.side_effect = [['25'], ['26']]

    pol = policyparser.ParsePolicy(GOOD_HEADER + GOOD_TERM_2 + GOOD_HEADER_11 +
                             GOOD_TERM_2, self.naming)
    self.assertRaises(junipersrx.ConflictingApplicationSets,
                      junipersrx.JuniperSRX, pol, EXP_INFO)

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('SOME_HOST')] * 2)
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('SMTP', 'tcp')] * 2)


if __name__ == '__main__':
  unittest.main()
