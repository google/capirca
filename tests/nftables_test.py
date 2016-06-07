# Copyright 2014 Google Inc. All Rights Reserved.
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

"""Unittest for Nftables rendering module."""

import datetime
import unittest

from lib import nacaddr
from lib import nftables
from lib import policy
from lib import policyparser
import logging
import mock


BAD_HEADER = """
header {
  target:: nftables %s
}
"""

GOOD_HEADER_1 = """
header {
  target:: nftables chain_name input 0 inet
}
"""

GOOD_HEADER_2 = """
header {
  target:: nftables chain_name
}
"""

GOOD_HEADER_3 = """
header {
  target:: nftables chain_name input 0 inet6
}
"""

GOOD_TERM_1 = """
term good-term-1 {
  action:: accept
}
"""

IPV6_TERM_1 = """
term inet6-icmp {
  protocol:: icmpv6
  icmp-type:: destination-unreachable time-exceeded echo-reply
  action:: deny
}
"""

IPV6_TERM_2 = """
term inet6-icmp {
  action:: deny
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

GOOD_TERM_2 = """
term good-term-2 {
  source-address:: SOURCE_NETWORK
  destination-address:: DESTINATION_NETWORK
  action:: accept
}
"""

GOOD_TERM_3 = """
term good-term-3 {
  source-address:: SOURCE_NETWORK
  destination-address:: DESTINATION_NETWORK
  action:: %s
}
"""

GOOD_TERM_4 = """
term good-term-4 {
  action:: accept
  comment:: "comment first line"
  comment:: "comment second line"
  owner:: owner@enterprise.com
}
"""

GOOD_TERM_5 = """
term good-term-5 {
  protocol:: ah esp
  action:: accept
}
"""

GOOD_TERM_6 = """
term good-term-6 {
  protocol:: ah
  action:: accept
}
"""

GOOD_TERM_7 = """
term good-term-7 {
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_8 = """
term good-term-8 {
  source-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_9 = """
term good-term-9 {
  protocol:: icmp
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

GOOD_TERM_10 = """
term good-term-10 {
  verbatim:: nftables "mary had a little lamb"
  verbatim:: cisco "mary had second lamb"
  verbatim:: juniper "mary had third lamb"
}
"""

GOOD_TERM_11 = """
term good-term-11 {
  source-address:: SOURCE_NETWORK
  source-exclude:: SOURCE_EXCLUDE_NETWORK
  destination-address:: DESTINATION_NETWORK
  destination-exclude:: DESTINATION_EXCLUDE_NETWORK
  action:: accept
}
"""

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class NftablesTest(unittest.TestCase):

  def setUp(self):
    self.mock_naming = mock.MagicMock()

  def testBadHeader(self):
    cases = [
        'chain_name input 0 inet extraneous_target_option',
        'chain_name input 0 unsupported_af',
        'chain_name input not_an_int_priority',
        'chain_name invalid_hook_name 0',
        'chain_name input',
        '',
    ]
    for case in cases:
      logging.info('Testing bad header case %s.', case)
      header = BAD_HEADER % case
      pol = policyparser.ParsePolicy(header + GOOD_TERM_1, self.mock_naming)
      self.assertRaises(nftables.InvalidTargetOption,
                        nftables.Nftables.__init__,
                        nftables.Nftables.__new__(nftables.Nftables),
                        pol, EXP_INFO)

  @mock.patch.object(logging, 'info')
  def testGoodHeader(self, mock_logging_info):
    nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_2 + GOOD_TERM_1,
                                         self.mock_naming), EXP_INFO)
    mock_logging_info.assert_called_once_with('Chain %s is a non-base '
                                              'chain, make sure it is linked.',
                                              'chain_name')
    nft = str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1 +
                                                   GOOD_HEADER_3 + IPV6_TERM_2,
                                                   self.mock_naming),
                                EXP_INFO))
    self.assertIn('flush table ip filter', nft)
    self.assertIn('table ip filter {\n\tchain chain_name {\n\t\ttype filter '
                  'hook input priority 0;\n\t\taccept\n\t}\n}', nft)
    self.assertIn('flush table ip6 filter', nft)
    self.assertIn('table ip6 filter {\n\tchain chain_name {\n\t\ttype filter '
                  'hook input priority 0;\n\t\tdrop\n\t}\n}', nft)

  @mock.patch.object(logging, 'warn')
  def testExpired(self, mock_logging_warn):
    nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + EXPIRED_TERM,
                                         self.mock_naming), EXP_INFO)
    mock_logging_warn.assert_called_once_with('Term %s in policy %s is expired '
                                              'and will not be rendered.',
                                              'is_expired', 'chain_name')

  @mock.patch.object(logging, 'info')
  def testExpiring(self, mock_logging_info):
    exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
    nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + EXPIRING_TERM %
                                         exp_date.strftime('%Y-%m-%d'),
                                         self.mock_naming), EXP_INFO)
    mock_logging_info.assert_called_once_with('Term %s in policy %s '
                                              'expires in less than %d weeks.',
                                              'is_expiring', 'chain_name',
                                              EXP_INFO)

  @mock.patch.object(logging, 'debug')
  def testIcmpv6InetMismatch(self, mock_logging_debug):
    str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + IPV6_TERM_1,
                                             self.mock_naming), EXP_INFO))
    mock_logging_debug.assert_called_once_with('Term inet6-icmp will not be '
                                               'rendered, as it has '
                                               '[\'icmpv6\'] match specified '
                                               'but the ACL is of inet address '
                                               'family.')

  def testSingleSourceDestIp(self):
    source_network = [nacaddr.IPv4('172.16.0.0/24')]
    destination_network = [nacaddr.IPv4('10.0.0.0/24')]
    self.mock_naming.GetNetAddr.side_effect = [source_network,
                                               destination_network]
    nft = str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_2,
                                                   self.mock_naming), EXP_INFO))
    self.assertIn('ip saddr 172.16.0.0/24 ip daddr 10.0.0.0/24', nft)

  def testMultipleSourceDestIp(self):
    source_network = [nacaddr.IPv4('172.16.0.0/24'),
                      nacaddr.IPv4('172.16.2.0/24')]
    destination_network = [nacaddr.IPv4('10.0.0.0/24'),
                           nacaddr.IPv4('10.0.2.0/24')]
    self.mock_naming.GetNetAddr.side_effect = [source_network,
                                               destination_network]
    nft = str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_2,
                                                   self.mock_naming), EXP_INFO))
    self.assertIn('ip saddr { 172.16.0.0/24, 172.16.2.0/24} ip daddr '
                  '{ 10.0.0.0/24, 10.0.2.0/24}', nft)

  def testSingleProtocol(self):
    nft = str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_5,
                                                   self.mock_naming), EXP_INFO))
    self.assertIn('ip protocol { ah, esp}', nft)

  def testMultiProtocol(self):
    nft = str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_6,
                                                   self.mock_naming), EXP_INFO))
    self.assertIn('ip protocol ah', nft)

  def testSingleDport(self):
    destination_ports = ['25']
    self.mock_naming.GetServiceByProto.return_value = destination_ports
    nft = str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_7,
                                                   self.mock_naming), EXP_INFO))
    self.assertIn('dport 25', nft)

  def testMultiDport(self):
    destination_ports = ['25', '80', '6610', '6611', '6612']
    self.mock_naming.GetServiceByProto.return_value = destination_ports
    nft = str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_7,
                                                   self.mock_naming), EXP_INFO))
    self.assertIn('dport { 25, 80, 6610-6612}', nft)

  def testSingleSport(self):
    source_ports = ['25']
    self.mock_naming.GetServiceByProto.return_value = source_ports
    nft = str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_8,
                                                   self.mock_naming), EXP_INFO))
    self.assertIn('sport 25', nft)

  def testMultiSport(self):
    source_ports = ['25', '80', '6610', '6611', '6612']
    self.mock_naming.GetServiceByProto.return_value = source_ports
    nft = str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_8,
                                                   self.mock_naming), EXP_INFO))
    self.assertIn('sport { 25, 80, 6610-6612}', nft)

  def testIcmpType(self):
    nft = str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_9,
                                                   self.mock_naming), EXP_INFO))
    self.assertIn('icmp type { echo-reply, echo-request}', nft)

  def testAction(self):
    cases = {'accept': 'accept',
             'deny': 'drop',
             'reject': 'reject',
             'next': 'continue',
             'reject-with-tcp-rst': 'reject with tcp reset'}
    for case in cases:
      logging.info('Testing action case %s.', case)
      nft = str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 +
                                                     GOOD_TERM_3 % case,
                                                     self.mock_naming),
                                  EXP_INFO))
      self.assertIn(cases[case], nft)

  def testCommentOwner(self):
    nft = str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_4,
                                                   self.mock_naming), EXP_INFO))
    self.assertIn('comment "comment first line comment second line '
                  'Owner: owner@enterprise.com"', nft)

  def testVerbatimTerm(self):
    nft = str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_10,
                                                   self.mock_naming), EXP_INFO))
    self.assertIn('mary had a little lamb', nft)
    # check if another platforms verbatim shows up
    self.assertNotIn('mary had a second lamb', nft)
    self.assertNotIn('mary had a third lamb', nft)

  def testSourceDestExclude(self):
    source_network = [nacaddr.IPv4('192.168.0.0/24')]
    source_exclude_network = [nacaddr.IPv4('192.168.0.0/27')]
    destination_network = [nacaddr.IPv4('10.0.0.0/24')]
    destination_exclude_network = [nacaddr.IPv4('10.0.0.0/27')]
    self.mock_naming.GetNetAddr.side_effect = [source_network,
                                               source_exclude_network,
                                               destination_network,
                                               destination_exclude_network]
    nft = str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_11,
                                                   self.mock_naming), EXP_INFO))
    self.assertIn('ip saddr { 192.168.0.32/27, 192.168.0.64/26, '
                  '192.168.0.128/25}', nft)
    self.assertIn('ip daddr { 10.0.0.32/27, 10.0.0.64/26, '
                  '10.0.0.128/25}', nft)

  def testSourceDestExcludeFromAllIps(self):
    source_network = []
    source_exclude_network = [nacaddr.IPv4('192.168.0.0/27')]
    destination_network = []
    destination_exclude_network = [nacaddr.IPv4('10.0.0.0/27')]
    self.mock_naming.GetNetAddr.side_effect = [source_network,
                                               source_exclude_network,
                                               destination_network,
                                               destination_exclude_network]
    nft = str(nftables.Nftables(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_11,
                                                   self.mock_naming), EXP_INFO))
    self.assertIn('ip saddr { 0.0.0.0/1, 128.0.0.0/2, 192.0.0.0/9, '
                  '192.128.0.0/11, 192.160.0.0/13, 192.168.0.32/27, '
                  '192.168.0.64/26, 192.168.0.128/25, 192.168.1.0/24, '
                  '192.168.2.0/23, 192.168.4.0/22, 192.168.8.0/21, '
                  '192.168.16.0/20, 192.168.32.0/19, 192.168.64.0/18, '
                  '192.168.128.0/17, 192.169.0.0/16, 192.170.0.0/15, '
                  '192.172.0.0/14, 192.176.0.0/12, 192.192.0.0/10, '
                  '193.0.0.0/8, 194.0.0.0/7, 196.0.0.0/6, 200.0.0.0/5, '
                  '208.0.0.0/4, 224.0.0.0/3}', nft)
    self.assertIn('ip daddr { 0.0.0.0/5, 8.0.0.0/7, 10.0.0.32/27, '
                  '10.0.0.64/26, 10.0.0.128/25, 10.0.1.0/24, 10.0.2.0/23, '
                  '10.0.4.0/22, 10.0.8.0/21, 10.0.16.0/20, 10.0.32.0/19, '
                  '10.0.64.0/18, 10.0.128.0/17, 10.1.0.0/16, 10.2.0.0/15, '
                  '10.4.0.0/14, 10.8.0.0/13, 10.16.0.0/12, 10.32.0.0/11, '
                  '10.64.0.0/10, 10.128.0.0/9, 11.0.0.0/8, 12.0.0.0/6, '
                  '16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/1}', nft)


if __name__ == '__main__':
  unittest.main()
