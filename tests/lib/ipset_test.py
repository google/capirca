# Copyright 2013 Google Inc. All Rights Reserved.
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

"""Unittest for Ipset rendering module."""

import unittest

from lib import ipset
from lib import nacaddr
from lib import naming
from lib import policy
from lib import policyparser
import mock


GOOD_HEADER_1 = """
header {
  comment:: "this is a test acl"
  target:: ipset OUTPUT DROP
}
"""

GOOD_TERM_1 = """
term good-term-1 {
  source-address:: INTERNAL
  action:: accept
}
"""

GOOD_TERM_2 = """
term good-term-2 {
  destination-address:: EXTERNAL
  action:: accept
}
"""

GOOD_TERM_3 = """
term good-term-3 {
  source-address:: INTERNAL
  destination-address:: EXTERNAL
  action:: accept
}
"""

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class IpsetTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testMarkers(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IPv4('10.0.0.0/8')]

    acl = ipset.Ipset(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1,
                                         self.naming), EXP_INFO)
    result = str(acl)
    self.assertIn('# begin:ipset-rules', result)
    self.assertIn('# end:ipset-rules', result)

    self.naming.GetNetAddr.assert_called_once_with('INTERNAL')

  def testGenerateSetName(self):
    # iptables superclass currently limits term name length to 26 characters,
    # but that could change
    policy_term = mock.MagicMock()
    policy_term.name = 'filter_name'
    policy_term.protocol = ['tcp']
    term = ipset.Term(policy_term, 'filter_name', False, None)
    self.assertEqual(term._GenerateSetName('good-term-1', 'src'),
                     'good-term-1-src')
    self.assertEqual(term._GenerateSetName('good-but-way-too-long-term-name',
                                           'src'),
                     'good-but-way-too-long-term--src')
    term = ipset.Term(policy_term, 'filter_name', False, None, 'inet6')
    self.assertEqual(term._GenerateSetName('good-term-1', 'src'),
                     'good-term-1-src-v6')
    self.assertEqual(term._GenerateSetName('good-but-way-too-long-term-name',
                                           'src'),
                     'good-but-way-too-long-te-src-v6')

  def testOneSourceAddress(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IPv4('10.0.0.0/8')]

    acl = ipset.Ipset(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1,
                                         self.naming), EXP_INFO)
    result = str(acl)
    self.assertIn('-s 10.0.0.0/8', result)
    self.assertNotIn('-m set --match-set good-term-3-src src', result)

    self.naming.GetNetAddr.assert_called_once_with('INTERNAL')

  def testOneDestinationAddress(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IPv4('172.16.0.0/12')]

    acl = ipset.Ipset(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_2,
                                         self.naming), EXP_INFO)
    result = str(acl)
    self.assertIn('-d 172.16.0.0/12', result)
    self.assertNotIn('-m set --match-set good-term-2-dst dst', result)

    self.naming.GetNetAddr.assert_called_once_with('EXTERNAL')

  def testOneSourceAndDestinationAddress(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/8')],
        [nacaddr.IPv4('172.16.0.0/12')]]

    acl = ipset.Ipset(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_3,
                                         self.naming), EXP_INFO)
    result = str(acl)
    self.assertIn('-s 10.0.0.0/8', result)
    self.assertIn('-d 172.16.0.0/12', result)
    self.assertNotIn('-m set --match-set good-term-3-src src', result)
    self.assertNotIn('-m set --match-set good-term-3-dst dst', result)

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('INTERNAL'),
        mock.call('EXTERNAL')])

  def testManySourceAddresses(self):
    self.naming.GetNetAddr.return_value = [
        nacaddr.IPv4('10.0.0.0/24'), nacaddr.IPv4('10.1.0.0/24')]

    acl = ipset.Ipset(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1,
                                         self.naming), EXP_INFO)
    result = str(acl)
    self.assertIn('create good-term-1-src hash:net family inet hashsize'
                  ' 4 maxelem 4', result)
    self.assertIn('add good-term-1-src 10.0.0.0/24', result)
    self.assertIn('add good-term-1-src 10.1.0.0/24', result)
    self.assertIn('-m set --match-set good-term-1-src src', result)
    self.assertNotIn('-s ', result)

    self.naming.GetNetAddr.assert_called_once_with('INTERNAL')

  def testManyDestinationAddresses(self):
    self.naming.GetNetAddr.return_value = [
        nacaddr.IPv4('172.16.0.0/24'), nacaddr.IPv4('172.17.0.0/24')]

    acl = ipset.Ipset(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_2,
                                         self.naming), EXP_INFO)
    result = str(acl)
    self.assertIn('create good-term-2-dst hash:net family inet hashsize '
                  '4 maxelem 4', result)
    self.assertIn('add good-term-2-dst 172.16.0.0/24', result)
    self.assertIn('add good-term-2-dst 172.17.0.0/24', result)
    self.assertIn('-m set --match-set good-term-2-dst dst', result)
    self.assertNotIn('-s ', result)

    self.naming.GetNetAddr.assert_called_once_with('EXTERNAL')

  def testManySourceAndDestinationAddresses(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IPv4('10.0.0.0/24'), nacaddr.IPv4('10.1.0.0/24')],
        [nacaddr.IPv4('172.16.0.0/24'), nacaddr.IPv4('172.17.0.0/24')]]

    acl = ipset.Ipset(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_3,
                                         self.naming), EXP_INFO)
    result = str(acl)
    self.assertIn('create good-term-3-src hash:net family inet hashsize '
                  '4 maxelem 4', result)
    self.assertIn('create good-term-3-dst hash:net family inet hashsize '
                  '4 maxelem 4', result)
    self.assertIn('add good-term-3-src 10.0.0.0/24', result)
    self.assertIn('add good-term-3-src 10.1.0.0/24', result)
    self.assertIn('add good-term-3-dst 172.16.0.0/24', result)
    self.assertIn('add good-term-3-dst 172.17.0.0/24', result)
    self.assertIn('-m set --match-set good-term-3-src src', result)
    self.assertIn('-m set --match-set good-term-3-dst dst', result)
    self.assertNotIn('-s ', result)
    self.assertNotIn('-d ', result)

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('INTERNAL'),
        mock.call('EXTERNAL')])

if __name__ == '__main__':
  unittest.main()

