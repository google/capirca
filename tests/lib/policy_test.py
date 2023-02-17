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

from absl.testing import absltest
from unittest import mock

from absl import logging
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy


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
HEADER_SRX = """
header {
  target:: srx from-zone foo to-zone bar
}
"""
HEADER_OBJ_GRP = """
header {
  target:: cisco foo object-group
}
"""
HEADER_ADDRBOOK_MIXED = """
header {
  target:: srx from-zone to-zone bar
  target:: cisco foo
}
"""
HEADER_HF_1 = """
header {
  comment:: "This is a test of HF INGRESS Policy."
  target:: gcp_hf INGRESS
}
"""

INCLUDE_STATEMENT = """
#include "includes/y.inc"
"""
INCLUDED_Y_FILE = """
term included-term-1 {
  protocol:: tcp
  action:: accept
}
#include "includes/z.inc"
"""

BAD_INCLUDED_FILE = """
term included-term-1 {
  protocol:: tcp
  action:: accept
}
#include "/tmp/z.inc"
"""

BAD_INCLUDED_FILE_1 = """
term included-term-1 {
  protocol:: tcp
  action:: accept
}
#include "includes/../../etc/passwd.inc"
"""

GOOD_INCLUDED_FILE_1 = """
term good-included-term-1 {
  protocol:: tcp
  action:: accept
}
#include "includes/../pol/z.inc"
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
GOOD_TERM_43 = """
term good-term-43 {
  ttl:: 10
  action:: accept
}
"""
GOOD_TERM_44 = """
term good-term-44 {
  logging:: syslog
  log-limit:: 999/day
  action:: accept
}
"""
GOOD_TERM_45 = """
term good-term-45 {
  source-address:: ANY
  action:: accept
  target-service-accounts:: acct1@blah.com
}
"""
GOOD_TERM_46 = """
term good-term-46 {
  protocol:: icmp tcp udp gre esp ah sctp
  encapsulate:: stuff_and_things
}
"""
GOOD_TERM_47 = """
term good-term-47 {
  protocol:: icmp tcp udp gre esp ah sctp
  port-mirror:: true
}
"""
GOOD_TERM_48 = """
term good-term-48 {
  protocol:: icmp
  source-zone:: zone1 zone2
  destination-zone:: zone1 zone2
  action:: accept
}
"""
GOOD_TERM_49 = """
term good-term-46 {
  protocol:: udp
  decapsulate:: mpls-in-udp
}
"""
GOOD_TERM_50 = """
term good-term-45 {
  source-address:: ANY
  action:: accept
  source-service-accounts:: acct1@blah.com
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
TERM_SUB_2 = """
term term-sub {
  protocol:: icmp
  action:: accept
}
"""
TERM_UNSORTED_ICMP_TYPE = """
term good-term-11 {
  protocol:: icmp
  icmp-type:: unreachable echo-request echo-reply
  action:: accept
}
"""
TERM_UNSORTED_ICMP_CODE = """
term good-term-11 {
  icmp-type:: unreachable
  icmp-code:: 15 4 9 1
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
BAD_TERM_15 = """
term bad-term-15 {
  ttl:: 300
  action:: accept
}
"""
BAD_TERM_16 = """
term bad-term-16 {
  destination-port:: FOO
  protocol:: tcp udp gre
  action:: accept
}
"""

# pylint: disable=maybe-no-member


class PolicyTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
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
    self.assertEqual(len(terms), 3)
    # ensure included_term_1 is included as first term
    self.assertEqual(terms[0].name, 'included-term-1')
    # ensure good-term-5 is included as second term
    self.assertEqual(terms[1].name, 'good-term-5')
    # ensure good-term-1 shows up as the second term
    self.assertEqual(terms[2].name, 'good-term-1')

    mock_file.assert_has_calls(
        [mock.call('includes/y.inc'), mock.call('includes/z.inc')]
    )

  @mock.patch.object(policy, '_ReadFile')
  def testBadIncludes(self, mock_file):
    """Ensure nested includes error handling works."""
    mock_file.side_effect = [BAD_INCLUDED_FILE, GOOD_TERM_5]

    # contents of our base policy (which has a bad included file)
    pol = HEADER + INCLUDE_STATEMENT + GOOD_TERM_1
    self.assertRaises(
        policy.InvalidIncludeDirectoryError,
        policy.ParsePolicy,
        pol,
        self.naming,
    )
    # Ensuring relative paths don't bypass invalid directory checks
    mock_file.side_effect = [BAD_INCLUDED_FILE_1, GOOD_TERM_5]
    pol = HEADER + BAD_INCLUDED_FILE_1 + GOOD_TERM_1
    self.assertRaises(
        policy.InvalidIncludeDirectoryError,
        policy.ParsePolicy,
        pol,
        self.naming,
    )

  @mock.patch.object(policy, '_ReadFile')
  def testGoodIncludesWithRelativePaths(self, mock_file):
    """Ensure nested includes error handling works for valid files."""
    mock_file.side_effect = [GOOD_TERM_5]
    # base policy has a good included file, with relative paths
    pol = HEADER + GOOD_INCLUDED_FILE_1 + GOOD_TERM_1
    p = policy.ParsePolicy(pol, self.naming)
    _, terms = p.filters[0]
    # ensure include worked and we now have 3 terms in this policy
    self.assertEqual(len(terms), 3)
    self.assertEqual(terms[0].name, 'good-included-term-1')
    self.assertEqual(terms[1].name, 'good-term-5')
    self.assertEqual(terms[2].name, 'good-term-1')

  def testGoodPol(self):
    pol = HEADER + GOOD_TERM_1 + GOOD_TERM_2
    self.naming.GetNetAddr.return_value = [nacaddr.IPv4('10.0.0.0/8')]

    ret = policy.ParsePolicy(pol, self.naming)
    # we should only have one filter from that
    self.assertEqual(len(ret.filters), 1)
    header, terms = ret.filters[0]
    self.assertEqual(type(ret), policy.Policy)
    self.assertEqual(str(terms[0].protocol[0]), 'icmp')
    self.assertEqual(len(terms), 2)
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
    self.assertEqual(str(terms[1].protocol[0]), 'tcp')
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
    self.assertEqual(str(terms[0].protocol[0]), '1')

  def testHopLimitSingle(self):
    pol = HEADER_V6 + GOOD_TERM_V6_1
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(str(terms[0].hop_limit[0]), '5')

  def testHopLimitRange(self):
    pol = HEADER_V6 + GOOD_TERM_V6_2
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(str(terms[0].hop_limit[2]), '7')

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
    self.assertEqual(len(terms), 1)
    self.assertEqual(str(terms[0].action[0]), 'accept')

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

  def testGoodDestAddrExcludes(self):
    pol = HEADER + GOOD_TERM_7
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.62.0.0/15')]]

    ret = policy.ParsePolicy(pol, self.naming)
    _, terms = ret.filters[0]
    self.assertEqual(terms[0].destination_address_exclude[0],
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
    self.assertEqual(terms[0].source_address_exclude[0],
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
    self.assertEqual(terms[0].address_exclude[0],
                     nacaddr.IPv4('10.62.0.0/15'))

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWRK'),
        mock.call('PROD_EH')], any_order=True)

  def testGoodAddrExcludesFlatten(self):
    expected = sorted([nacaddr.IPv4(u'10.0.0.0/11'),
                       nacaddr.IPv4(u'10.32.0.0/12'),
                       nacaddr.IPv4(u'10.48.0.0/13'),
                       nacaddr.IPv4(u'10.56.0.0/14'),
                       nacaddr.IPv4(u'10.60.0.0/15'),
                       nacaddr.IPv4(u'10.64.0.0/10'),
                       nacaddr.IPv4(u'10.130.0.0/15'),
                       nacaddr.IPv4(u'10.132.0.0/14'),
                       nacaddr.IPv4(u'10.136.0.0/13'),
                       nacaddr.IPv4(u'10.144.0.0/12'),
                       nacaddr.IPv4(u'10.160.0.0/11'),
                       nacaddr.IPv4(u'10.192.0.0/10')])
    pol = HEADER + GOOD_TERM_27
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.62.0.0/15'), nacaddr.IPv4('10.129.0.0/15',
                                                    strict=False)]]

    ret = policy.ParsePolicy(pol, self.naming)
    _, terms = ret.filters[0]
    terms[0].FlattenAll()

    self.assertEqual(sorted(terms[0].address), expected)

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
    self.assertEqual(terms[0].address,
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
    self.assertEqual(terms[0].address, [])

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('PROD_NETWRK'),
        mock.call('PROD_EH')], any_order=True)

  def testLogging(self):
    pol = HEADER + GOOD_TERM_10
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertEqual(len(ret.filters), 1)
    _, terms = ret.filters[0]
    self.assertEqual(str(terms[0].logging[0]), 'true')

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
    self.assertEqual(len(ret.headers), 2)

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

  def testICMPTypesSorting(self):
    pol = HEADER + TERM_UNSORTED_ICMP_TYPE
    ret = policy.ParsePolicy(pol, self.naming)
    icmp_types = ['echo-reply', 'echo-request', 'unreachable']
    expected = 'icmp_type: %s' % icmp_types
    self.assertIn(expected, str(ret))

  def testICMPCodesSorting(self):
    pol = HEADER + TERM_UNSORTED_ICMP_CODE
    ret = policy.ParsePolicy(pol, self.naming)
    self.assertIn('icmp_code: [1, 4, 9, 15]', str(ret))

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
    self.assertRaisesRegex(policy.ParseError,
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
    self.assertEqual(terms[0].verbatim[0][0], 'iptables')
    self.assertEqual(terms[0].verbatim[0][1], 'mary had a little lamb')
    self.assertEqual(terms[0].verbatim[1][0], 'juniper')
    self.assertEqual(terms[0].verbatim[1][1], 'mary had another lamb')

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
    self.assertEqual(len(pol.filters), 1)
    _, terms = pol.filters[0]
    self.assertEqual(terms[0].precedence, [1])

  def testLossPriority(self):
    self.naming.GetServiceByProto.return_value = ['22']

    pol = policy.ParsePolicy(HEADER + GOOD_TERM_23, self.naming)
    self.assertEqual(len(pol.filters), 1)
    _, terms = pol.filters[0]
    self.assertEqual(terms[0].loss_priority, 'low')

    self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

  def testRoutingInstance(self):
    self.naming.GetServiceByProto.return_value = ['22']

    pol = policy.ParsePolicy(HEADER + GOOD_TERM_24, self.naming)
    self.assertEqual(len(pol.filters), 1)
    _, terms = pol.filters[0]
    self.assertEqual(terms[0].routing_instance, 'foobar-router')

    self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

  def testSourceInterface(self):
    self.naming.GetServiceByProto.return_value = ['22']

    pol = policy.ParsePolicy(HEADER_4 + GOOD_TERM_25, self.naming)
    self.assertEqual(len(pol.filters), 1)
    header, terms = pol.filters[0]
    self.assertEqual(str(header.target[0]), 'iptables')
    self.assertEqual(terms[0].source_interface, 'foo0')

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
    self.assertEqual(len(pol.filters), 1)
    self.assertEqual('special-30', pol.filters[0][1][0].vpn[0])
    self.assertEqual('', pol.filters[0][1][0].vpn[1])

  def testVpnConfigWithPairPolicy(self):
    pol = policy.ParsePolicy(HEADER_4 + GOOD_TERM_31, self.naming)
    self.assertEqual(len(pol.filters), 1)
    self.assertEqual('special-31', pol.filters[0][1][0].vpn[0])
    self.assertEqual('policy-11', pol.filters[0][1][0].vpn[1])

  def testForwardingClassPolicy(self):
    pol = policy.ParsePolicy(HEADER + GOOD_TERM_32, self.naming)
    self.assertEqual(['fritzy'], pol.filters[0][1][0].forwarding_class)

  def testMultipleForwardingClassPolicy(self):
    pol = policy.ParsePolicy(HEADER + GOOD_TERM_36, self.naming)
    self.assertEqual(['flashy', 'fritzy'],
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
    self.assertEqual(len(pol.filters), 1)
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
    self.assertIn('icmp_code: [3, 4]', str(result))

  def testBadICMPCodes(self):
    pol = HEADER + BAD_TERM_13
    pol2 = HEADER + BAD_TERM_14
    self.assertRaises(policy.ICMPCodeError, policy.ParsePolicy, pol,
                      self.naming)
    self.assertRaises(policy.ICMPCodeError, policy.ParsePolicy, pol2,
                      self.naming)

  def testOptimizedConsistency(self):
    pol = HEADER + GOOD_TERM_2 + GOOD_TERM_3
    unoptimized_addr = [nacaddr.IPv4('10.16.128.6/32'),
                        nacaddr.IPv4('10.16.128.7/32')]
    optimized_addr = nacaddr.CollapseAddrList(unoptimized_addr)
    self.naming.GetNetAddr.return_value = unoptimized_addr
    self.naming.GetServiceByProto.return_value = ['25']
    ret_unoptimized = policy.ParsePolicy(pol, self.naming, optimize=False)
    self.assertFalse(policy._OPTIMIZE)
    ret_optimized = policy.ParsePolicy(pol, self.naming)
    self.assertTrue(policy._OPTIMIZE)
    for _, terms in ret_unoptimized.filters:
      for term in terms:
        self.assertEqual(unoptimized_addr, term.source_address)
    for _, terms in ret_optimized.filters:
      for term in terms:
        self.assertEqual(optimized_addr, term.source_address)

  def testShadeCheckConsistency(self):
    pol = HEADER + TERM_SUPER_3 + TERM_SUB_2
    self.assertRaises(policy.ShadingError, policy.ParsePolicy, pol, self.naming,
                      shade_check=True)
    self.assertTrue(policy._SHADE_CHECK)
    _ = policy.ParsePolicy(pol, self.naming)
    self.assertFalse(policy._SHADE_CHECK)

  def testEncapsulate(self):
    pol = HEADER + GOOD_TERM_46
    result = policy.ParsePolicy(pol, self.naming)
    self.assertIn('encapsulate: stuff_and_things', str(result))

  def testDecapsulate(self):
    pol = HEADER + GOOD_TERM_49
    result = policy.ParsePolicy(pol, self.naming)
    self.assertIn('decapsulate: mpls-in-udp', str(result))

  def testPortMirror(self):
    pol = HEADER + GOOD_TERM_47
    result = policy.ParsePolicy(pol, self.naming)
    self.assertIn('port_mirror: true', str(result))

  def testSrxGLobalZone(self):
    pol = HEADER + GOOD_TERM_48
    result = policy.ParsePolicy(pol, self.naming)
    zones = ['zone1', 'zone2']
    expected_source = 'source_zone: %s' % zones
    expected_destination = 'destination_zone: %s' % zones
    self.assertIn(expected_source, str(result))
    self.assertIn(expected_destination, str(result))

  def testTTL(self):
    pol = HEADER + GOOD_TERM_43
    result = policy.ParsePolicy(pol, self.naming)
    self.assertIn('ttl: 10', str(result))

  def testInvalidTTL(self):
    pol = HEADER + BAD_TERM_15
    self.assertRaises(policy.InvalidTermTTLValue, policy.ParsePolicy,
                      pol, self.naming)

  def testNeedAddressBook(self):
    pol1 = policy.ParsePolicy(HEADER + GOOD_TERM_1, self.naming)
    pol2 = policy.ParsePolicy(HEADER_SRX + GOOD_TERM_1, self.naming)
    pol3 = policy.ParsePolicy(HEADER_OBJ_GRP + GOOD_TERM_1, self.naming)
    pol4 = policy.ParsePolicy(HEADER_ADDRBOOK_MIXED + GOOD_TERM_1, self.naming)
    self.assertFalse(pol1._NeedsAddressBook())
    self.assertTrue(pol2._NeedsAddressBook())
    self.assertTrue(pol3._NeedsAddressBook())
    self.assertTrue(pol4._NeedsAddressBook())

  def testAddressCleanupCorrect(self):
    unoptimized_addr = [nacaddr.IPv4('10.16.128.6/32', token='FOO'),
                        nacaddr.IPv4('10.16.128.7/32', token='BAR')]
    self.naming.GetNetAddr.return_value = unoptimized_addr
    pol = policy.ParsePolicy(HEADER + GOOD_TERM_2, self.naming)
    term = pol.filters[0][1][0]
    self.assertEqual(nacaddr.CollapseAddrList(unoptimized_addr),
                     term.source_address)
    pol = policy.ParsePolicy(HEADER_SRX + GOOD_TERM_2, self.naming)
    term = pol.filters[0][1][0]
    self.assertEqual(nacaddr.CollapseAddrListPreserveTokens(unoptimized_addr),
                     term.source_address)

  def testLogLimit(self):
    pol = policy.ParsePolicy(HEADER_4 + GOOD_TERM_44, self.naming)
    term = pol.filters[0][1][0]
    self.assertEqual((u'999', u'day'), term.log_limit)

  def testGREandTCPUDPError(self):
    pol = HEADER + BAD_TERM_16
    self.naming.GetServiceByProto.return_value = ['25']
    self.assertRaises(policy.MixedPortandNonPortProtos, policy.ParsePolicy,
                      pol, self.naming)

  def testSourceServiceAccount(self):
    pol = HEADER_HF_1 + GOOD_TERM_50

    result = policy.ParsePolicy(pol, self.naming)
    term = result.filters[0][1][0]
    self.assertEqual(
        ['acct1@blah.com'],
        term.source_service_accounts)

  def testTargetServiceAccount(self):
    pol = HEADER_HF_1 + GOOD_TERM_45

    result = policy.ParsePolicy(pol, self.naming)
    term = result.filters[0][1][0]
    self.assertEqual(
        ['acct1@blah.com'],
        term.target_service_accounts)

  # Contains Tests

  def testVerbatimContains(self):
    term_one = policy.Term(policy.VarType(23, ('iptables', 'foo')))
    term_two = policy.Term(policy.VarType(23, ('iptables', 'bar')))
    term_three = policy.Term(policy.VarType(23, ('juniper', 'foo')))
    self.assertIn(term_one, term_one)
    self.assertNotIn(term_two, term_one)
    self.assertNotIn(term_three, term_one)

  @mock.patch.object(policy, 'DEFINITIONS')
  def testIpAndPortContains(self, mock_naming):
    mock_naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.1.1.1/32')]]
    term_one = policy.Term([policy.VarType(3, 'PROD'),
                            policy.VarType(7, (22, 22)),
                            policy.VarType(7, (80, 80)),
                            policy.VarType(10, 'tcp')])
    term_one.AddObject(policy.VarType(2, 'accept'))
    term_two = policy.Term([policy.VarType(3, 'SMALLER_PROD'),
                            policy.VarType(7, (22, 22)),
                            policy.VarType(10, 'tcp')])
    term_two.AddObject(policy.VarType(2, 'accept'))
    self.assertIn(term_two, term_one)
    self.assertNotIn(term_one, term_two)

  @mock.patch.object(policy, 'DEFINITIONS')
  def testEmptyIpContains(self, mock_naming):
    # testTermContains2 differs from testTermContains in that TERM_SUPER_2
    # only defines a source addres. it's meant to catch the case where
    # the containing term has less detail (and is hence, less restrictive)
    # than the contained term
    mock_naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.1.1.1/32')]]
    term_one = policy.Term([policy.VarType(5, 'PROD')])
    term_one.AddObject(policy.VarType(2, 'accept'))
    term_two = policy.Term([policy.VarType(3, 'SMALLER_PROD'),
                            policy.VarType(7, (22, 22))])
    term_two.AddObject(policy.VarType(2, 'accept'))
    self.assertIn(term_two, term_one)
    self.assertNotIn(term_one, term_two)

  @mock.patch.object(policy, 'DEFINITIONS')
  def testIpExcludeContains(self, mock_naming):
    # This 'contains' test kicks the tires on source-address and
    # source-address-exclude.
    mock_naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.62.0.0/15')]]
    term_one = policy.Term([policy.VarType(3, 'FOO')])
    term_two = policy.Term([policy.VarType(3, 'FOO'),
                            policy.VarType(11, 'BAR')])
    self.assertIn(term_two, term_one)
    self.assertNotIn(term_one, term_two)

  @mock.patch.object(policy, 'DEFINITIONS')
  def testIpDualExcludeContains(self, mock_naming):
    # One term has (10.0.0.0/8, except 10.10.0.0/24), it should contain a term
    # that has (10.0.0.0/8 except 10.0.0.0/9.
    mock_naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.10.0.0/24')],
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('10.0.0.0/9')]]
    term_one = policy.Term([policy.VarType(3, 'FOO'),
                            policy.VarType(11, 'BAR')])
    term_two = policy.Term([policy.VarType(3, 'FOO'),
                            policy.VarType(11, 'BAR')])
    self.assertIn(term_two, term_one)
    self.assertNotIn(term_one, term_two)

  def testOptionsContains(self):
    # Tests 'contains' testing of the options field. A term without set options
    # contains one which has them set.
    tcp_est_term = policy.Term([policy.VarType(9, 'tcp-established')])
    term = policy.Term([])
    tcp_udp_est_term = policy.Term([policy.VarType(9, 'tcp-established'),
                                    policy.VarType(9, 'established')])
    self.assertNotIn(term, tcp_est_term)
    self.assertNotIn(tcp_est_term, term)
    self.assertIn(tcp_est_term, tcp_udp_est_term)
    self.assertNotIn(tcp_udp_est_term, tcp_est_term)

  def testPrecedenceContains(self):
    # Tests 'contains' testing of the precedence field. A term without set
    # precedence contains one which has them set.
    p_term = policy.Term([policy.VarType(26, 1)])
    no_p_term = policy.Term([])
    self.assertIn(p_term, p_term)
    self.assertIn(no_p_term, no_p_term)
    self.assertNotIn(no_p_term, p_term)
    self.assertNotIn(p_term, no_p_term)

  def testProtocolExceptContains(self):
    # Test the protocol-except keyword.
    pexcept_term = policy.Term([policy.VarType(8, 'tcp')])
    pexpect_term_udp = policy.Term([policy.VarType(8, 'udp')])
    p_term = policy.Term([policy.VarType(10, 'icmp')])
    p_term_tcp = policy.Term([policy.VarType(10, 'tcp')])
    self.assertIn(p_term, pexcept_term)
    self.assertIn(pexcept_term, pexcept_term)
    self.assertNotIn(p_term_tcp, pexcept_term)
    self.assertNotIn(pexpect_term_udp, pexcept_term)

  def testProtocolTermNotInAnotherTermContains(self):
    term_one = policy.Term([policy.VarType(10, 'tcp')])
    term_two = policy.Term([policy.VarType(10, 'udp')])
    self.assertNotIn(term_one, term_two)

  def testTargetServiceAccountContains(self):
    two_target_sa = ['acct1@blah.com', 'acct2@blah.com']
    one_target_sa = ['acct3@blah.com']

    term = policy.Term([policy.VarType(60, two_target_sa)])
    self.assertIn(two_target_sa, term.target_service_accounts)

    term.AddObject(policy.VarType(60, one_target_sa))
    self.assertIn(one_target_sa, term.target_service_accounts)

  def testProtoExceptNotInEmptyTerm(self):
    term_one = policy.Term([policy.VarType(8, 'tcp')])
    term_two = policy.Term([])
    self.assertNotIn(term_two, term_one)

  def testProtocolNotInProtoExcept(self):
    term_one = policy.Term([policy.VarType(8, 'tcp')])
    term_two = policy.Term([policy.VarType(10, 'udp')])
    self.assertNotIn(term_one, term_two)

  def testProtocolNotInEmptyTerm(self):
    term_one = policy.Term([policy.VarType(10, 'tcp')])
    term_two = policy.Term([])
    self.assertNotIn(term_two, term_one)

  @mock.patch.object(policy, 'DEFINITIONS')
  def testAddrNotInAddr(self, mock_naming):
    mock_naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('192.168.1.1/32')],
        [nacaddr.IPv4('10.1.1.0/24')],
        [nacaddr.IPv4('10.1.1.0/24')],
        [nacaddr.IPv4('10.1.1.0/24')]]
    term = policy.Term([policy.VarType(5, 'FOO')])
    addr_term = policy.Term([policy.VarType(5, 'FOO')])
    saddr_term = policy.Term([policy.VarType(3, 'FOO')])
    daddr_term = policy.Term([policy.VarType(4, 'FOO')])
    self.assertNotIn(addr_term, term)
    self.assertNotIn(saddr_term, term)
    self.assertNotIn(daddr_term, term)

  @mock.patch.object(policy, 'DEFINITIONS')
  def testDestAddrNotInDestAddr(self, mock_naming):
    mock_naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('192.168.1.1/32')],
        [nacaddr.IPv4('10.1.1.0/24')]]
    term_one = policy.Term([policy.VarType(4, 'FOO')])
    term_two = policy.Term([policy.VarType(4, 'FOO')])
    self.assertNotIn(term_one, term_two)

  def testSourcePortNotInSourcePort(self):
    term_one = policy.Term([policy.VarType(6, (22, 22))])
    term_two = policy.Term([policy.VarType(6, (23, 23))])
    self.assertNotIn(term_one, term_two)

  def testDestinationPortNotInDestinationPort(self):
    term_one = policy.Term([policy.VarType(7, (22, 22))])
    term_two = policy.Term([policy.VarType(7, (23, 23))])
    self.assertNotIn(term_one, term_two)

  def testSourcePrefixContains(self):
    term_one = policy.Term([policy.VarType(19, 'foo')])
    self.assertIn(term_one, term_one)

  def testSourcePrefixNotInSourcePrefix(self):
    term_one = policy.Term([policy.VarType(19, 'foo')])
    term_two = policy.Term([policy.VarType(19, 'bar')])
    self.assertNotIn(term_one, term_two)

  def testDestinationPrefixContains(self):
    term_one = policy.Term([policy.VarType(20, 'foo')])
    self.assertIn(term_one, term_one)

  def testDestinationPrefixNotInDestinationPrefix(self):
    term_one = policy.Term([policy.VarType(20, 'foo')])
    term_two = policy.Term([policy.VarType(20, 'bar')])
    self.assertNotIn(term_one, term_two)

  def testSourcePrefixExceptContains(self):
    term_one = policy.Term([policy.VarType(50, 'foo')])
    self.assertIn(term_one, term_one)

  def testSourcePrefixExceptNotInSourcePrefixExcept(self):
    term_one = policy.Term([policy.VarType(50, 'foo')])
    term_two = policy.Term([policy.VarType(50, 'bar')])
    self.assertNotIn(term_one, term_two)

  def testDestinationPrefixExceptContains(self):
    term_one = policy.Term([policy.VarType(51, 'foo')])
    self.assertIn(term_one, term_one)

  def testDestinationPrefixExceptNotInDestinationPrefixExcept(self):
    term_one = policy.Term([policy.VarType(51, 'foo')])
    term_two = policy.Term([policy.VarType(51, 'bar')])
    self.assertNotIn(term_one, term_two)

  def testSourceTagContains(self):
    term_one = policy.Term([policy.VarType(44, 'foo')])
    self.assertIn(term_one, term_one)

  def testSourceTagNotInSourceTag(self):
    term_one = policy.Term([policy.VarType(44, 'foo')])
    term_two = policy.Term([policy.VarType(44, 'bar')])
    self.assertNotIn(term_one, term_two)

  def testForwardingClassContains(self):
    term_one = policy.Term([policy.VarType(43, 'foo')])
    term_two = policy.Term(
        [policy.VarType(43, 'bar'),
         policy.VarType(43, 'foo')])
    self.assertIn(term_one, term_one)
    self.assertIn(term_one, term_two)

  def testForwardingClassNotIn(self):
    term_one = policy.Term([policy.VarType(43, 'foo')])
    term_two = policy.Term([policy.VarType(43, 'bar')])
    term_three = policy.Term([])
    self.assertNotIn(term_one, term_two)
    self.assertNotIn(term_three, term_one)

  def testForwardingClassExceptContains(self):
    term_one = policy.Term([policy.VarType(52, 'foo')])
    self.assertIn(term_one, term_one)

  def testForwardingClassExceptNotIn(self):
    term_one = policy.Term([policy.VarType(52, 'foo')])
    term_two = policy.Term([policy.VarType(52, 'bar')])
    term_three = policy.Term([])
    self.assertNotIn(term_one, term_two)
    self.assertNotIn(term_three, term_one)

  @mock.patch.object(policy, 'DEFINITIONS')
  def testNextIPContained(self, mock_naming):
    mock_naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('192.168.1.1/32')]]
    term_one = policy.Term([policy.VarType(46, 'FOO')])
    self.assertIn(term_one, term_one)

  @mock.patch.object(policy, 'DEFINITIONS')
  def testNextIPNotIn(self, mock_naming):
    mock_naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('192.168.1.1/32')]]
    term_one = policy.Term([policy.VarType(46, 'FOO')])
    term_two = policy.Term([])
    self.assertNotIn(term_two, term_one)

  def testPortContains(self):
    # Test 'contains' against port field and that it matches
    # source/destination/port fields.
    port_term = policy.Term([policy.VarType(32, (25, 25))])
    sport_term = policy.Term([policy.VarType(6, (25, 25))])
    dport_term = policy.Term([policy.VarType(7, (25, 25))])
    self.assertIn(sport_term, port_term)
    self.assertIn(dport_term, port_term)
    self.assertIn(port_term, port_term)
    alt_port_term = policy.Term([policy.VarType(32, (25, 30))])
    sport_term = policy.Term([policy.VarType(6, (25, 30))])
    dport_term = policy.Term([policy.VarType(7, (25, 30))])
    self.assertNotIn(alt_port_term, port_term)
    self.assertNotIn(sport_term, port_term)
    self.assertNotIn(dport_term, port_term)

  def testFragmentOffset(self):
    fo_term = policy.Term([])
    fo_term.AddObject(policy.VarType(17, '80'))
    fo_range_term = policy.Term([])
    fo_range_term.AddObject(policy.VarType(17, '60-90'))
    fo_smaller_range_term = policy.Term([])
    fo_smaller_range_term.AddObject(policy.VarType(17, '65-82'))
    term = policy.Term([])

    self.assertIn(fo_term, fo_term)
    self.assertIn(fo_term, fo_range_term)
    self.assertNotIn(fo_range_term, fo_term)
    self.assertIn(fo_smaller_range_term, fo_range_term)
    self.assertNotIn(fo_range_term, fo_smaller_range_term)
    self.assertNotIn(term, fo_term)

  def testTermTargetResources(self):
    target_resources = [('p1', 'v1'), ('p2', 'v2')]
    target_resource_2 = [('p3', 'v3')]
    term_one = policy.Term(
        [policy.VarType(policy.VarType.TARGET_RESOURCES, target_resources)])
    term_one.AddObject(policy.VarType(59, target_resource_2))

    self.assertIn(target_resources, term_one.target_resources)
    self.assertIn(target_resource_2, term_one.target_resources)

  def testParsePolicySingleTargetResources(self):
    good_term_target_resources = """
    term target-resource-term {
      action:: deny
      target-resources:: (proj1,vpc1)
    }"""
    pol = HEADER_HF_1 + good_term_target_resources
    p = policy.ParsePolicy(pol, self.naming)
    self.assertIsInstance(p, policy.Policy)

    _, terms = p.filters[0]
    self.assertIn('deny', terms[0].action)
    self.assertIn(('proj1', 'vpc1'), terms[0].target_resources)

  def testParsePolicyMultipleTargetResources(self):
    good_term_target_resources = """
    term target-resource-term {
      action:: deny
      target-resources:: (proj1,vpc1)
      target-resources:: (proj2,vpc2)
      target-resources:: (proj3,vpc3)
      target-resources:: (proj4,vpc4)
    }"""
    pol = HEADER_HF_1 + good_term_target_resources
    p = policy.ParsePolicy(pol, self.naming)
    self.assertIsInstance(p, policy.Policy)

    _, terms = p.filters[0]
    self.assertIn('deny', terms[0].action)
    expected_target_resources = [('proj1', 'vpc1'), ('proj2', 'vpc2'),
                                 ('proj3', 'vpc3'), ('proj4', 'vpc4')]
    self.assertListEqual(expected_target_resources, terms[0].target_resources)

  def testParsePolicyMultipleCommaSepTargetResources(self):
    good_term_target_resources = """
    term target-resource-term {
      action:: deny
      target-resources:: (proj1,vpc1),(proj2,vpc2),(proj3,vpc3),(proj4,vpc4)
    }"""
    pol = HEADER_HF_1 + good_term_target_resources
    p = policy.ParsePolicy(pol, self.naming)
    self.assertIsInstance(p, policy.Policy)

    _, terms = p.filters[0]
    self.assertIn('deny', terms[0].action)
    expected_target_resources = [('proj1', 'vpc1'), ('proj2', 'vpc2'),
                                 ('proj3', 'vpc3'), ('proj4', 'vpc4')]
    self.assertListEqual(expected_target_resources, terms[0].target_resources)

  def testParsePolicyMultipleSpaceSepTargetResources(self):
    good_term_target_resources = """
    term target-resource-term {
      action:: deny
      target-resources:: (proj1,vpc1) (proj2,vpc2) (proj3,vpc3) (proj4,vpc4)
    }"""
    pol = HEADER_HF_1 + good_term_target_resources
    p = policy.ParsePolicy(pol, self.naming)
    self.assertIsInstance(p, policy.Policy)

    _, terms = p.filters[0]
    self.assertIn('deny', terms[0].action)
    expected_target_resources = [('proj1', 'vpc1'), ('proj2', 'vpc2'),
                                 ('proj3', 'vpc3'), ('proj4', 'vpc4')]
    self.assertListEqual(expected_target_resources, terms[0].target_resources)

  def testParsePolicyMultipleArrayCommaTargetResources(self):
    good_term_target_resources = """
    term target-resource-term {
      action:: deny
      target-resources:: [(proj1,vpc1),(proj2,vpc2),(proj3,vpc3),(proj4,vpc4)]
    }"""
    pol = HEADER_HF_1 + good_term_target_resources
    p = policy.ParsePolicy(pol, self.naming)
    self.assertIsInstance(p, policy.Policy)

    _, terms = p.filters[0]
    self.assertIn('deny', terms[0].action)
    expected_target_resources = [('proj1', 'vpc1'), ('proj2', 'vpc2'),
                                 ('proj3', 'vpc3'), ('proj4', 'vpc4')]
    self.assertListEqual(expected_target_resources, terms[0].target_resources)

  def testParsePolicyMultipleArraySpaceTargetResources(self):
    good_term_target_resources = """
    term target-resource-term {
      action:: deny
      target-resources:: [(proj1,vpc1) (proj2,vpc2) (proj3,vpc3) (proj4,vpc4)]
    }"""
    pol = HEADER_HF_1 + good_term_target_resources
    p = policy.ParsePolicy(pol, self.naming)
    self.assertIsInstance(p, policy.Policy)

    _, terms = p.filters[0]
    self.assertIn('deny', terms[0].action)
    expected_target_resources = [('proj1', 'vpc1'), ('proj2', 'vpc2'),
                                 ('proj3', 'vpc3'), ('proj4', 'vpc4')]
    self.assertListEqual(expected_target_resources, terms[0].target_resources)


if __name__ == '__main__':
  absltest.main()
