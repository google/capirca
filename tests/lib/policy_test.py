# Copyright 2011 Google Inc. All Rights Reserved.
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

"""Unit tests for policy.py library."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'watson@google.com (Tony Watson)'

import unittest

from lib import nacaddr
from lib import naming
from lib import policy
import mock
import logging


HEADER = """
header {
  comment:: "this is a test acl"
  comment:: "this is another comment"
  target:: juniper test-filter
}
"""
HEADER_2 = """
header {
  comment:: "this goes in the other direction"
  target:: juniper test-filter-outbound
}
"""
HEADER_3 = """
header {
  comment:: "test header 3"
  target:: cisco 50 standard
}
"""
HEADER_4 = """
header {
  comment:: "test header 4"
  target:: iptables
}
"""
HEADER_5 = """
header {
  comment:: "test header 5"
  target:: gce global/networks/default
}
"""
HEADER_6 = """
header {
  comment:: "this is a test nftable acl"
  target::  nftables chain_name input 0 inet
}
"""
HEADER_V6 = """
header {
  comment:: "this is a test inet6 acl"
  comment:: "this is another comment"
  target:: juniper test-filter inet6
}
"""
INCLUDE_STATEMENT = """
#include "/tmp/y.inc"
"""
INCLUDED_Y_FILE = """
term included-term-1 {
  protocol:: tcp
  action:: accept
}
#include "/tmp/z.inc"
"""
GOOD_TERM_0 = """
term good-term-0 {
  protocol:: icmp
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
  source-address:: PROD_NETWRK
  action:: accept
}
"""
GOOD_TERM_3 = """
term good-term-3 {
  protocol:: tcp
  source-address:: PROD_NETWRK
  destination-port:: SMTP
  action:: accept
}
"""
GOOD_TERM_4 = """
term good-term-4 {
  protocol:: 1
  action:: accept
}
"""
GOOD_TERM_5 = """
term good-term-5 {
  action:: accept
}
"""
GOOD_TERM_6 = """
term good-term-6 {
  protocol:: tcp
  destination-port:: MYSQL HIGH_PORTS
  action:: accept
}
"""
GOOD_TERM_7 = """
term good-term-7 {
  protocol:: tcp
  destination-address:: PROD_NETWRK
  destination-exclude:: PROD_EH
  action:: accept
}
"""
GOOD_TERM_8 = """
term good-term-8 {
  protocol:: tcp udp
  destination-port:: DNS
  action:: accept
}
"""
GOOD_TERM_9 = """
term good-term-9 {
  comment:: "first comment"
  comment:: "second comment"
  action:: accept
}
"""
GOOD_TERM_10 = """
term good-term-10 {
  logging:: true
  action:: accept
}
"""
GOOD_TERM_11 = """
term good-term-11 {
  protocol:: icmp
  icmp-type:: echo-reply echo-request unreachable
  action:: accept
}
"""
GOOD_TERM_12 = """
term qos-good-term-12 {
  action:: accept
  qos:: af4
}
"""
GOOD_TERM_13 = """
term good-term-13 {
  source-port:: GOOGLE_PUBLIC
  source-port:: SNMP
  protocol:: udp
  action:: accept
}
"""
GOOD_TERM_14 = """
term good-term-14 {
  source-prefix:: foo_prefix_list
  action:: accept
}
"""
GOOD_TERM_15 = """
term good-term-15 {
  destination-prefix:: bar_prefix_list baz_prefix_list
  action:: accept
}
"""
GOOD_TERM_16 = """
term good-term-16 {
  ether-type:: arp ipv4
  ether-type:: vlan
  action:: accept
}
"""
GOOD_TERM_17 = """
term good-term-17 {
  traffic-type:: broadcast unknown-unicast
  traffic-type:: multicast
  action:: accept
}
"""
GOOD_TERM_18 = """
term good-term-18 {
  comment:: "test verbatim output"
  verbatim:: iptables "mary had a little lamb"
  verbatim:: juniper "mary had another lamb"
}
"""
GOOD_TERM_19 = """
term good-term-19 {
  source-port:: HTTP MYSQL
  destination-address:: PROD_EXTERNAL_SUPER PROD_NETWRK
  protocol:: tcp
  action:: accept
}
"""
GOOD_TERM_20 = """
term good-term-20 {
  source-port:: MYSQL HTTP
  destination-address:: PROD_NETWRK PROD_EXTERNAL_SUPER
  protocol:: tcp
  action:: accept
}
"""
GOOD_TERM_21 = """
term good-term-21 {
  source-port:: MYSQL HTTPS
  destination-address:: PROD_NETWRK PROD_EXTERNAL_SUPER
  protocol:: tcp
  action:: accept
}
"""
GOOD_TERM_22 = """
term precedence-term {
  protocol:: icmp
  precedence:: 1
  action:: accept
}
"""
GOOD_TERM_23 = """
term loss-priority-term {
  source-port:: SSH
  protocol:: tcp
  loss-priority:: low
  action:: accept
}
"""
GOOD_TERM_24 = """
term routing-instance-term {
  source-port:: SSH
  protocol:: tcp
  routing-instance:: foobar-router
}
"""
GOOD_TERM_25 = """
term source-interface-term {
  source-port:: SSH
  protocol:: tcp
  source-interface:: foo0
  action:: accept
}
"""
GOOD_TERM_26 = """
term good-term-26 {
  protocol:: tcp
  source-address:: PROD_NETWRK
  source-exclude:: PROD_EH
  action:: accept
}
"""
GOOD_TERM_27 = """
term good-term-27 {
  protocol:: tcp
  address:: PROD_NETWRK
  address-exclude:: PROD_EH
  action:: accept
}
"""
GOOD_TERM_28 = """
term good-term-28 {
  protocol:: tcp
  source-address:: PROD_NETWRK
  source-exclude:: BOTTOM_HALF
  action:: accept
}
"""
GOOD_TERM_29 = """
term good-term-29 {
  protocol:: tcp
  option:: tcp-established
  source-address:: PROD_NETWRK
  action:: accept
}
"""
GOOD_TERM_30 = """
term good-term-30 {
  protocol:: tcp
  action:: accept
  vpn:: special-30
}
"""
GOOD_TERM_31 = """
term good-term-31 {
  protocol:: tcp
  action:: accept
  vpn:: special-31 policy-11
}
"""
GOOD_TERM_32 = """
term good-term-32 {
  forwarding-class:: fritzy
  action:: accept
}
"""
GOOD_TERM_33 = """
term good-term-33 {
  forwarding-class:: flashy
  action:: accept
}
"""
GOOD_TERM_34 = """
term good-term-34 {
  source-tag:: src-tag
  destination-tag:: dest-tag
  action:: accept
}
"""
GOOD_TERM_35 = """
term good-term-35 {
  source-address:: PROD_NETWRK
  next-ip:: NEXT_IP
}
"""
GOOD_TERM_36 = """
term good-term-36 {
  forwarding-class:: flashy fritzy
  action:: accept
}
"""
GOOD_TERM_37 = """
term good-term-37 {
  protocol:: icmp
  action:: accept
  log_name:: "my special prefix"
}
"""
GOOD_TERM_38 = """
term good-term-38 {
  source-prefix-except:: foo_prefix_list
  action:: accept
}
"""
GOOD_TERM_39 = """
term good-term-39 {
  destination-prefix-except:: bar_prefix_list baz_prefix_list
  action:: accept
}
"""
GOOD_TERM_40 = """
term good-term-38 {
  source-prefix:: foo_prefix_list
  source-prefix-except:: foo_prefix_list_except
  action:: accept
}
"""
GOOD_TERM_41 = """
term good-term-39 {
  destination-prefix:: bar_prefix_list
  destination-prefix-except:: bar_prefix_list_except
  action:: accept
}
"""
GOOD_TERM_42 = """
term good-term-42 {
  protocol:: icmp
  icmp-type:: unreachable
  icmp-code:: 3 4
  action:: accept
}
"""
GOOD_TERM_V6_1 = """
term good-term-v6-1 {
  hop-limit:: 5
  action:: accept
}
"""
GOOD_TERM_V6_2 = """
term good-term-v6-1 {
  hop-limit:: 5-7
  action:: accept
}
"""
TERM_SUPER_1 = """
term term-super {
  source-address:: PROD
  protocol:: tcp
  destination-port:: SSH HTTP
  action:: accept
  }
"""
TERM_SUPER_2 = """
term term-super {
  address:: PROD
  action:: accept
}
"""
TERM_SUPER_3 = """
term term-super {
  protocol-except:: tcp udp icmpv6
  counter:: stuff_and_things
  action:: reject
}
"""
TERM_SUB_1 = """
term term-sub {
  source-address:: RANDOM_PROD
  protocol:: tcp
  destination-port:: SSH
  action:: accept
}
"""
TERM_SUB_2 = """
term term-sub {
  protocol:: icmp
  action:: accept
}
"""
BAD_TERM_1 = """
term bad-term- 1 {
  protocol:: tcp
  action:: reject
}
"""
BAD_TERM_2 = """
term bad-term-2 {
  prootocol:: tcp
  action:: accept
}
"""
BAD_TERM_3 = """
term bad-term-3 {
  protocol:: tcp
  source-port:: SNMP
  action:: accept
}
"""
BAD_TERM_4 = """
term bad-term-4 {
  source-port:: SMTP
  action:: accept
}
"""
BAD_TERM_5 = """
term bad-term-5 {
  protocol:: tcp
  destination-address:: PROD_EH
  destination-exclude:: PROD_NETWRK
  action:: accept
}
"""
BAD_TERM_6 = """
term bad-term-6 {
  logging:: unvalidloggingoption
  action:: accept
}
"""
BAD_TERM_7 = """
term bad-term-7 {
  action:: discard
}
"""
BAD_TERM_8 = """
term bad-term-8 {
  akshun:: accept
}
"""
BAD_TERM_9 = """
term bad-term-9 {
  ether-type:: arp
  protocol:: udp
  action:: accept
}
"""
BAD_TERM_10 = """
term bad-term-10 {
  verbatim:: cisco "mary had a little lamb"

  action:: accept
}
"""
BAD_TERM_12 = """
term bad-term-12 {
  protocol:: icmp
  icmp-type:: echo-foo packet-too-beaucoups
  action:: accept
}
"""
BAD_TERM_13 = """
term bad-term-13 {
  protocol:: icmp
  icmp-type:: unreachable
  icmp-code:: 99
  action:: accept
}
"""
BAD_TERM_14 = """
term bad-term-14 {
  protocol:: icmp
  icmp-type:: unreachable redirect
  icmp-code:: 3
  action:: accept
}
"""

# pylint: disable=maybe-no-member


class PolicyTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  @mock.patch.object(policy, '_ReadFile')
  def testIncludes(self, mock_file):
    """Ensure includes work, as well as nested included."""
    mock_file.side_effect = [INCLUDED_Y_FILE, GOOD_TERM_5]

    # contents of our base policy (which has an included file)
    pol = HEADER + INCLUDE_STATEMENT + GOOD_TERM_1
    p = policy.ParsePolicy(pol, self.naming)
    _, terms = p.filters[0]
    # ensure include worked and we now have 3 terms in this policy
    self.assertEquals(len(terms), 3)
    # ensure included_term_1 is included as first term
    self.assertEquals(terms[0].name, 'included-term-1')
    # ensure good-term-5 is included as second term
    self.assertEquals(terms[1].name, 'good-term-5')
    # ensure good-term-1 shows up as the second term
    self.assertEquals(terms[2].name, 'good-term-1')

    mock_file.assert_has_calls([
        mock.call('/tmp/y.inc'),
        mock.call('/tmp/z.inc')])

  def testGoodPol(self):
    pol = HEADER + GOOD_TERM_1 + GOOD_TERM_2
    self.naming.GetNetAddr.return_value = [nacaddr.IPv4('10.0.0.0/8')]

    ret = policy.ParsePolicy(pol, self.naming)
    # we should only have one filter from that
    self.assertEquals(len(ret.filters), 1)
    header, terms = ret.filters[0]
    self.assertEquals(type(ret), policy.Policy)
    self.assertEquals(str(terms[0].protocol[0]), 'icmp')
    self.assertEquals(len(terms), 2)
    # the comment is stored as a double quoted string, complete with double
    # quotes.
    self.assertEqual(str(header.comment[0]), 'this is a test acl')
    self.assertEqual(str(header.comment[1]), 'this is another comment')
    self.assertEqual(str(header.target[0]), 'juniper')

    self.naming.GetNetAddr.assert_called_once_with('PROD_NETWRK')

  def testBadPol(self):
    pol = HEADER + BAD_TERM_1
    self.assertRaises(policy.ParseError, policy.ParsePolicy, pol, self.naming)

  def testMissingHeader(self):
    pol = GOOD_TERM_1 + GOOD_TERM_2
    self.assertRaises(policy.ParseError, policy.ParsePolicy, pol, self.naming)

  def testService(self):
    pol = HEADER + GOOD_TERM_1 + GOOD_TERM_3
    self.naming.GetNetAddr.return_value = [nacaddr.IPv4('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(len(terms), 2)
    self.assertEquals(str(terms[1].protocol[0]), 'tcp')
    self.assertEqual(terms[1].destination_port[0], (25, 25))

    self.naming.GetNetAddr.assert_called_once_with('PROD_NETWRK')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testInvalidKeyword(self):
    pol = HEADER + BAD_TERM_2
    self.assertRaises(policy.ParseError, policy.ParsePolicy, pol, self.naming)

  def testNumericProtocol(self):
    pol = HEADER + GOOD_TERM_4
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEquals(str(terms[0].protocol[0]), '1')

  def testHopLimitSingle(self):
    pol = HEADER_V6 + GOOD_TERM_V6_1
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEquals(str(terms[0].hop_limit[0]), '5')

  def testHopLimitRange(self):
    pol = HEADER_V6 + GOOD_TERM_V6_2
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEquals(str(terms[0].hop_limit[2]), '7')

  def testBadPortProtocols(self):
    pol = HEADER + BAD_TERM_3
    self.naming.GetServiceByProto('SNMP', 'tcp').AndReturn([])
    self.assertRaises(policy.TermPortProtocolError, policy.ParsePolicy, pol,
                      self.naming)

  def testBadPortProtocols2(self):
    pol = HEADER + BAD_TERM_4
    self.assertRaises(policy.TermPortProtocolError, policy.ParsePolicy, pol,
                      self.naming)

  def testMinimumTerm(self):
    pol = HEADER + GOOD_TERM_5
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEquals(len(terms), 1)
    self.assertEquals(str(terms[0].action[0]), 'accept')

  def testPortCollapsing(self):
    pol = HEADER + GOOD_TERM_6
    self.naming.GetServiceByProto.return_value = ['3306']
    self.naming.GetServiceByProto.return_value = ['1024-65535']

    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertSequenceEqual(terms[0].destination_port, [(1024, 65535)])

    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('MYSQL', 'tcp'),
        mock.call('HIGH_PORTS', 'tcp')], any_order=True)

  def testPortCollapsing2(self):
    pol = HEADER + GOOD_TERM_8
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertSequenceEqual(terms[0].destination_port, [(53, 53)])

    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('DNS', 'tcp'),
        mock.call('DNS', 'udp')], any_order=True)

  def testMinimumTerm2(self):
    pol = HEADER + GOOD_TERM_9
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(str(terms[0].comment[0]), 'first comment')
    self.assertEqual(str(terms[0].comment[1]), 'second comment')

  def testLogNameTerm(self):
    pol = HEADER_6 + GOOD_TERM_37
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(str(terms[0].log_name), 'my special prefix')

  def testTermEquality(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('64.233.160.0/19'), nacaddr.IPv4('66.102.0.0/20'),
         nacaddr.IPv4('66.249.80.0/20'), nacaddr.IPv4('72.14.192.0/18'),
         nacaddr.IPv4('72.14.224.0/20'), nacaddr.IPv4('216.239.32.0/19')],
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('64.233.160.0/19'), nacaddr.IPv4('66.102.0.0/20'),
         nacaddr.IPv4('66.249.80.0/20'), nacaddr.IPv4('72.14.192.0/18'),
         nacaddr.IPv4('72.14.224.0/20'), nacaddr.IPv4('216.239.32.0/19')],
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('64.233.160.0/19'), nacaddr.IPv4('66.102.0.0/20'),
         nacaddr.IPv4('66.249.80.0/20'), nacaddr.IPv4('72.14.192.0/18'),
         nacaddr.IPv4('72.14.224.0/20'), nacaddr.IPv4('216.239.32.0/19')]]
    self.naming.GetServiceByProto.side_effect = [
        ['80'], ['3306'], ['3306'], ['80'], ['3306'], ['443']]

    pol_text = HEADER + GOOD_TERM_19 + GOOD_TERM_20 + GOOD_TERM_21
    ret = policy.ParsePolicy(pol_text, self.naming, shade_check=False)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(len(terms), 3)
    self.assertEqual(terms[0], terms[1])
    self.assertNotEqual(terms[0], terms[2])

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_EXTERNAL_SUPER'),
        mock.call('PROD_NETWRK'),
        mock.call('PROD_NETWRK'),
        mock.call('PROD_EXTERNAL_SUPER'),
        mock.call('PROD_NETWRK'),
        mock.call('PROD_EXTERNAL_SUPER')], any_order=True)
    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('HTTP', 'tcp'),
        mock.call('MYSQL', 'tcp'),
        mock.call('MYSQL', 'tcp'),
        mock.call('HTTP', 'tcp'),
        mock.call('MYSQL', 'tcp'),
        mock.call('HTTPS', 'tcp')], any_order=True)

  def testIpAndPortContains(self):
    pol = HEADER + TERM_SUPER_1 + TERM_SUB_1
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.1.1.1/32')]]
    self.naming.GetServiceByProto.side_effect = [['22'], ['80'], ['22']]

    ret = policy.ParsePolicy(pol, self.naming, shade_check=False)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertTrue(terms[1] in terms[0], '\n' + str(terms[0]) + '\n' +
                    str(terms[1]))
    self.assertFalse(terms[0] in terms[1], '\n' + str(terms[0]) + '\n' +
                     str(terms[1]))

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD'),
        mock.call('RANDOM_PROD')])
    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('SSH', 'tcp'),
        mock.call('HTTP', 'tcp'),
        mock.call('SSH', 'tcp')], any_order=True)

  def testEmptyIpContains(self):
    # testTermContains2 differs from testTermContains in that TERM_SUPER_2
    # only defines a source addres. it's meant to catch the case where
    # the containing term has less detail (and is hence, less restrictive)
    # than the contained term
    pol = HEADER + TERM_SUPER_2 + TERM_SUB_1
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.1.1.1/32')]]
    self.naming.GetServiceByProto.return_value = ['22']

    ret = policy.ParsePolicy(pol, self.naming, shade_check=False)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertTrue(terms[1] in terms[0], '\n' + str(terms[0]) + '\n' +
                    str(terms[1]))
    self.assertFalse(terms[0] in terms[1], '\n' + str(terms[0]) + '\n' +
                     str(terms[1]))

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD'), mock.call('RANDOM_PROD')], any_order=True)
    self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

  def testIpExcludeContains(self):
    # This "contains" test kicks the tires on source-address and
    # source-address-exclude.
    pol = HEADER + GOOD_TERM_2 + GOOD_TERM_26
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.62.0.0/15')]]

    ret = policy.ParsePolicy(pol, self.naming, shade_check=False)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertTrue(terms[1] in terms[0], '\n' + str(terms[0]) + '\n' +
                    str(terms[1]))
    self.assertFalse(terms[0] in terms[1], '\n' + str(terms[0]) + '\n' +
                     str(terms[1]))

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWRK'),
        mock.call('PROD_NETWRK'),
        mock.call('PROD_EH')], any_order=True)

  def testIpDualExcludeContains(self):
    # One term has (10.0.0.0/8, except 10.10.0.0/24), it should contain a term
    # that has (10.0.0.0/8 except 10.0.0.0/9.
    pol = HEADER + GOOD_TERM_26 + GOOD_TERM_28
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.10.0.0/24')],
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.0.0.0/9')]]

    ret = policy.ParsePolicy(pol, self.naming, shade_check=False)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertTrue(terms[1] in terms[0], '\n' + str(terms[0]) + '\n' +
                    str(terms[1]))
    self.assertFalse(terms[0] in terms[1], '\n' + str(terms[0]) + '\n' +
                     str(terms[1]))

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWRK'),
        mock.call('PROD_EH'),
        mock.call('PROD_NETWRK'),
        mock.call('BOTTOM_HALF')], any_order=True)

  def testOptionsContains(self):
    # Tests "contains" testing of the options field. A term without set options
    # contains one which has them set.
    pol = HEADER + GOOD_TERM_2 + GOOD_TERM_29
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.0.0.0/8')]]

    ret = policy.ParsePolicy(pol, self.naming, shade_check=False)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertTrue(terms[1] in terms[0], '\n' + str(terms[0]) + '\n' +
                    str(terms[1]))
    self.assertFalse(terms[0] in terms[1], '\n' + str(terms[1]) + '\n' +
                     str(terms[0]))

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWRK'),
        mock.call('PROD_NETWRK')], any_order=True)

  def testPrecedenceContains(self):
    # Tests "contains" testing of the precedence field. A term without set
    # precedence contains one which has them set.
    pol = HEADER + TERM_SUB_2 + GOOD_TERM_22
    ret = policy.ParsePolicy(pol, self.naming, shade_check=False)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertTrue(terms[1] in terms[0], '\n' + str(terms[0]) + '\n' +
                    str(terms[1]))
    self.assertFalse(terms[0] in terms[1], '\n' + str(terms[1]) + '\n' +
                     str(terms[0]))

  def testProtocolExceptContains(self):
    # Test the protocol-except keyword.
    pol = HEADER + TERM_SUPER_3 + TERM_SUB_2
    ret = policy.ParsePolicy(pol, self.naming, shade_check=False)
    _, terms = ret.filters[0]
    self.assertEqual(len(ret.filters), 1)
    self.assertFalse(terms[0] in terms[1], '\n' + str(terms[0]) + '\n' +
                     str(terms[1]))

  def testGoodDestAddrExcludes(self):
    pol = HEADER + GOOD_TERM_7
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.62.0.0/15')]]

    ret = policy.ParsePolicy(pol, self.naming)
    _, terms = ret.filters[0]
    self.assertEquals(terms[0].destination_address_exclude[0],
                      nacaddr.IPv4('10.62.0.0/15'))

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWRK'),
        mock.call('PROD_EH')], any_order=True)

  def testGoodSrcAddrExcludes(self):
    pol = HEADER + GOOD_TERM_26
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.62.0.0/15')]]

    ret = policy.ParsePolicy(pol, self.naming)
    _, terms = ret.filters[0]
    self.assertEquals(terms[0].source_address_exclude[0],
                      nacaddr.IPv4('10.62.0.0/15'))

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWRK'),
        mock.call('PROD_EH')], any_order=True)

  def testGoodAddrExcludes(self):
    pol = HEADER + GOOD_TERM_27
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.62.0.0/15')]]

    ret = policy.ParsePolicy(pol, self.naming)
    _, terms = ret.filters[0]
    self.assertEquals(terms[0].address_exclude[0],
                      nacaddr.IPv4('10.62.0.0/15'))

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWRK'),
        mock.call('PROD_EH')], any_order=True)

  def testGoodAddrExcludesFlatten(self):
    pol = HEADER + GOOD_TERM_27
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.62.0.0/15'), nacaddr.IPv4('10.129.0.0/15')]]

    ret = policy.ParsePolicy(pol, self.naming)
    _, terms = ret.filters[0]
    terms[0].FlattenAll()
    self.assertEquals(terms[0].address,
                      [nacaddr.IPv4('10.0.0.0/11'),
                       nacaddr.IPv4('10.32.0.0/12'),
                       nacaddr.IPv4('10.48.0.0/13'),
                       nacaddr.IPv4('10.56.0.0/14'),
                       nacaddr.IPv4('10.60.0.0/15'),
                       nacaddr.IPv4('10.64.0.0/10'),
                       nacaddr.IPv4('10.130.0.0/15'),
                       nacaddr.IPv4('10.132.0.0/14'),
                       nacaddr.IPv4('10.136.0.0/13'),
                       nacaddr.IPv4('10.144.0.0/12'),
                       nacaddr.IPv4('10.160.0.0/11'),
                       nacaddr.IPv4('10.192.0.0/10')])

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWRK'),
        mock.call('PROD_EH')], any_order=True)

  def testGoodAddrExcludesFlattenMultiple(self):
    pol = HEADER + GOOD_TERM_27
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.1.0.0/16'),
         nacaddr.IPv4('10.2.0.0/16'),
         nacaddr.IPv4('10.3.0.0/16'),
         nacaddr.IPv4('192.168.0.0/16')],
        [nacaddr.IPv4('10.2.0.0/15')]]

    ret = policy.ParsePolicy(pol, self.naming)
    _, terms = ret.filters[0]
    terms[0].FlattenAll()
    self.assertEquals(terms[0].address,
                      [nacaddr.IPv4('10.1.0.0/16'),
                       nacaddr.IPv4('192.168.0.0/16')])

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWRK'),
        mock.call('PROD_EH')], any_order=True)

  def testGoodAddrExcludesFlattenAll(self):
    pol = HEADER + GOOD_TERM_27
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.1.0.0/16'),
         nacaddr.IPv4('10.2.0.0/16'),
         nacaddr.IPv4('10.3.0.0/16')],
        [nacaddr.IPv4('10.0.0.0/8')]]

    ret = policy.ParsePolicy(pol, self.naming)
    _, terms = ret.filters[0]
    terms[0].FlattenAll()
    self.assertEquals(terms[0].address, [])

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWRK'),
        mock.call('PROD_EH')], any_order=True)

  def testLogging(self):
    pol = HEADER + GOOD_TERM_10
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEquals(str(terms[0].logging[0]), 'true')

  def testBadLogging(self):
    pol = HEADER + BAD_TERM_6
    self.assertRaises(policy.InvalidTermLoggingError, policy.ParsePolicy, pol,
                      self.naming)

  def testBadAction(self):
    pol = HEADER + BAD_TERM_7
    self.assertRaises(policy.InvalidTermActionError, policy.ParsePolicy, pol,
                      self.naming)

  def testMultifilter(self):
    pol = HEADER + GOOD_TERM_1 + HEADER_2 + GOOD_TERM_1
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEquals(len(ret.headers), 2)

  def testBadMultifilter(self):
    pol = HEADER + HEADER_2 + GOOD_TERM_1
    self.assertRaises(policy.NoTermsError, policy.ParsePolicy, pol,
                      self.naming)

  def testICMPTypes(self):
    pol = HEADER + GOOD_TERM_11
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(terms[0].icmp_type[0], 'echo-reply')

  def testBadICMPTypes(self):
    pol = HEADER + BAD_TERM_12
    self.assertRaises(policy.TermInvalidIcmpType,
                      policy.ParsePolicy, pol, self.naming)

  def testReservedWordTermName(self):
    pol = HEADER + GOOD_TERM_12
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(terms[0].qos, 'af4')
    self.assertEqual(terms[0].name, 'qos-good-term-12')

  def testMultiPortLines(self):
    pol = HEADER + GOOD_TERM_13
    self.naming.GetServiceByProto.side_effect = [['22', '160-162'], ['161']]

    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertSequenceEqual(terms[0].source_port, [(22, 22), (160, 162)])

    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('GOOGLE_PUBLIC', 'udp'),
        mock.call('SNMP', 'udp')], any_order=True)

  def testErrorLineNumber(self):
    pol = HEADER + GOOD_TERM_13 + BAD_TERM_8
    self.assertRaisesRegexp(policy.ParseError,
                            r'ERROR on "akshun" \(type STRING, line 1',
                            policy.ParsePolicy, pol, self.naming)

  def testPrefixList(self):
    spol = HEADER + GOOD_TERM_14
    dpol = HEADER + GOOD_TERM_15

    # check on the source prefix list
    ret = policy.ParsePolicy(spol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(terms[0].source_prefix, ['foo_prefix_list'])

    # check on the destination prefix list
    ret = policy.ParsePolicy(dpol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(terms[0].destination_prefix,
                     ['bar_prefix_list', 'baz_prefix_list'])

  def testPrefixListExcept(self):
    spol = HEADER + GOOD_TERM_38
    dpol = HEADER + GOOD_TERM_39

    # check on the source prefix except list
    ret = policy.ParsePolicy(spol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(terms[0].source_prefix_except, ['foo_prefix_list'])

    # check on the destination prefix except list
    ret = policy.ParsePolicy(dpol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(terms[0].destination_prefix_except,
                     ['bar_prefix_list', 'baz_prefix_list'])

  def testPrefixListMixed(self):
    spol = HEADER + GOOD_TERM_40
    dpol = HEADER + GOOD_TERM_41

    # check on the source prefix list with mixed values
    ret = policy.ParsePolicy(spol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(terms[0].source_prefix, ['foo_prefix_list'])
    self.assertEqual(terms[0].source_prefix_except,
                     ['foo_prefix_list_except'])

    # check on the destination prefix with mixed values
    ret = policy.ParsePolicy(dpol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(terms[0].destination_prefix, ['bar_prefix_list'])
    self.assertEqual(terms[0].destination_prefix_except,
                     ['bar_prefix_list_except'])

  def testEtherTypes(self):
    pol = HEADER + GOOD_TERM_16
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(terms[0].ether_type[0], 'arp')
    self.assertEqual(terms[0].ether_type[1], 'ipv4')
    self.assertEqual(terms[0].ether_type[2], 'vlan')

  def testTrafficTypes(self):
    pol = HEADER + GOOD_TERM_17
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(terms[0].traffic_type[0], 'broadcast')
    self.assertEqual(terms[0].traffic_type[1], 'unknown-unicast')
    self.assertEqual(terms[0].traffic_type[2], 'multicast')

  def testBadProtocolEtherTypes(self):
    pol = HEADER + BAD_TERM_9
    self.assertRaises(policy.TermProtocolEtherTypeError, policy.ParsePolicy,
                      pol, self.naming)

  def testVerbatimTerm(self):
    pol = policy.ParsePolicy(HEADER + GOOD_TERM_18, self.naming)
    _, terms = pol.filters[0]
    self.assertEqual(terms[0].verbatim[0].value[0], 'iptables')
    self.assertEqual(terms[0].verbatim[0].value[1], 'mary had a little lamb')
    self.assertEqual(terms[0].verbatim[1].value[0], 'juniper')
    self.assertEqual(terms[0].verbatim[1].value[1], 'mary had another lamb')

  def testVerbatimMixed(self):
    pol = HEADER + BAD_TERM_10
    self.assertRaises(policy.ParseError, policy.ParsePolicy, pol, self.naming)

  def testIntegerFilterName(self):
    pol_text = HEADER_3 + GOOD_TERM_0
    pol = policy.ParsePolicy(pol_text, self.naming)
    self.assertEqual(pol.headers[0].target[0].options[0], '50')

  def testPrecedence(self):
    pol_text = HEADER + GOOD_TERM_22
    pol = policy.ParsePolicy(pol_text, self.naming)
    self.assertEquals(len(pol.filters), 1)
    _, terms = pol.filters[0]
    self.assertEquals(terms[0].precedence, [1])

  def testLossPriority(self):
    self.naming.GetServiceByProto.return_value = ['22']

    pol = policy.ParsePolicy(HEADER + GOOD_TERM_23, self.naming)
    self.assertEquals(len(pol.filters), 1)
    _, terms = pol.filters[0]
    self.assertEquals(terms[0].loss_priority, 'low')

    self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

  def testRoutingInstance(self):
    self.naming.GetServiceByProto.return_value = ['22']

    pol = policy.ParsePolicy(HEADER + GOOD_TERM_24, self.naming)
    self.assertEquals(len(pol.filters), 1)
    _, terms = pol.filters[0]
    self.assertEquals(terms[0].routing_instance, 'foobar-router')

    self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

  def testSourceInterface(self):
    self.naming.GetServiceByProto.return_value = ['22']

    pol = policy.ParsePolicy(HEADER_4 + GOOD_TERM_25, self.naming)
    self.assertEquals(len(pol.filters), 1)
    header, terms = pol.filters[0]
    self.assertEqual(str(header.target[0]), 'iptables')
    self.assertEquals(terms[0].source_interface, 'foo0')

    self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

  def testShadingDetection(self):
    pol2 = HEADER + GOOD_TERM_2 + GOOD_TERM_3
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')], [nacaddr.IPv4('10.0.0.0/8')]]
    self.naming.GetServiceByProto.return_value = ['25']

    # same protocol, same saddr, shaded term defines a port.
    self.assertRaises(policy.ShadingError, policy.ParsePolicy, pol2,
                      self.naming, shade_check=True)

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWRK'),
        mock.call('PROD_NETWRK')])
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testVpnConfigWithoutPairPolicy(self):
    pol = policy.ParsePolicy(HEADER_4 + GOOD_TERM_30, self.naming)
    self.assertEquals(len(pol.filters), 1)
    self.assertEquals('special-30', pol.filters[0][1][0].vpn[0])
    self.assertEquals('', pol.filters[0][1][0].vpn[1])

  def testVpnConfigWithPairPolicy(self):
    pol = policy.ParsePolicy(HEADER_4 + GOOD_TERM_31, self.naming)
    self.assertEquals(len(pol.filters), 1)
    self.assertEquals('special-31', pol.filters[0][1][0].vpn[0])
    self.assertEquals('policy-11', pol.filters[0][1][0].vpn[1])

  def testForwardingClassPolicy(self):
    pol = policy.ParsePolicy(HEADER + GOOD_TERM_32, self.naming)
    self.assertEquals(['fritzy'], pol.filters[0][1][0].forwarding_class)

  def testMultipleForwardingClassPolicy(self):
    pol = policy.ParsePolicy(HEADER + GOOD_TERM_36, self.naming)
    self.assertEquals(['flashy', 'fritzy'],
                      pol.filters[0][1][0].forwarding_class)

  def testForwardingClassEqual(self):
    pol_text = HEADER + GOOD_TERM_32 + GOOD_TERM_33
    ret = policy.ParsePolicy(pol_text, self.naming, shade_check=False)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(len(terms), 2)
    self.assertNotEqual(terms[0], terms[1])

  def testTagSupportAndNetworkHeaderParsing(self):
    pol = policy.ParsePolicy(HEADER_5 + GOOD_TERM_34, self.naming)
    self.assertEquals(len(pol.filters), 1)
    header, terms = pol.filters[0]
    self.assertEqual(str(header.target[0]), 'gce')
    self.assertEqual(header.FilterOptions('gce'), ['global/networks/default'])
    self.assertEqual(terms[0].source_tag, ['src-tag'])
    self.assertEqual(terms[0].destination_tag, ['dest-tag'])

  def testEq(self):
    """Sanity test to verify __eq__ works on Policy objects."""
    policy1 = policy.ParsePolicy(HEADER_4 + GOOD_TERM_30, self.naming)
    policy2 = policy.ParsePolicy(HEADER_4 + GOOD_TERM_30, self.naming)
    policy3 = policy.ParsePolicy(HEADER_5 + GOOD_TERM_34, self.naming)
    self.assertEqual(policy1, policy2)
    self.assertNotEqual(policy1, policy3)
    self.assertNotEqual(policy2, policy3)

  def testNextIP(self):
    pol = HEADER_2 + GOOD_TERM_35
    expected = nacaddr.IPv4('10.1.1.1/32')
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')], [nacaddr.IPv4('10.1.1.1/32')]]

    result = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(result.filters[0][1][0].next_ip[0], expected)

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWRK'),
        mock.call('NEXT_IP')])

  def testStr(self):
    """Sanity test to verify __eq__ works on Policy objects."""
    pol = policy.ParsePolicy(HEADER_4 + GOOD_TERM_30, self.naming)
    logging.info('Ensuring string formatting doesn\'t throw errors: %s', pol)

  def testTermAddressByteLength(self):
    """Tests the AddressByteLength function."""
    pol = HEADER + GOOD_TERM_2
    self.naming.GetNetAddr.return_value = [
        nacaddr.IPv4('10.0.0.1/32'), nacaddr.IPv4('10.0.0.2/32'),
        nacaddr.IPv6('2001:4860:4860::8844/128'),
        nacaddr.IPv6('2001:4860:4860::8888/128')]
    ret = policy.ParsePolicy(pol, self.naming)
    term = ret.filters[0][1][0]
    self.assertEqual(2, term.AddressesByteLength([4]))
    self.assertEqual(8, term.AddressesByteLength([6]))
    self.assertEqual(10, term.AddressesByteLength())

# pylint: enable=maybe-no-member

  def testICMPCodes(self):
    pol = HEADER + GOOD_TERM_42

    result = policy.ParsePolicy(pol, self.naming)
    self.assertTrue('icmp_code: [3, 4]' in str(result))

  def testBadICMPCodes(self):
    pol = HEADER + BAD_TERM_13
    pol2 = HEADER + BAD_TERM_14
    self.assertRaises(policy.ICMPCodeError, policy.ParsePolicy, pol,
                      self.naming)
    self.assertRaises(policy.ICMPCodeError, policy.ParsePolicy, pol2,
                      self.naming)

if __name__ == '__main__':
  unittest.main()
