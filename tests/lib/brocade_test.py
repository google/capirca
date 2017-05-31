# Copyright 2016 Google Inc. All Rights Reserved.
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
"""Tests for brocade acl rendering module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import re
import unittest

from lib import brocade
from lib import naming
from lib import policy
import mock

GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: brocade test-filter
}
"""
GOOD_TERM = """
term good-term {
  protocol:: tcp
  option:: tcp-established
  action:: accept
}
"""
GOOD_TERM_1 = """
term good-term-1 {
  protocol:: tcp
  policer:: batman
  option:: tcp-established
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
    'icmp_code',
    'icmp_type',
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


class BrocadeTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testTcpEstablished(self):
    acl = brocade.Brocade(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM, self.naming), EXP_INFO)
    self.failUnless(re.search('permit tcp any any established\n',
                              str(acl)), str(acl))

  def testNoTermRemark(self):
    acl = brocade.Brocade(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM, self.naming), EXP_INFO)
    self.failIf('remark good-term-3' in str(acl))

  def testBuildTokens(self):
    pol1 = brocade.Brocade(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM,
                                              self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    pol1 = brocade.Brocade(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1,
                                              self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)


if __name__ == '__main__':
  unittest.main()
