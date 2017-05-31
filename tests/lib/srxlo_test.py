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

"""Unittest for Srxlo rendering module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest


from lib import naming
from lib import policy
from lib import srxlo
import mock


GOOD_HEADER_1 = """
header {
  comment:: "this is a test acl"
  target:: srxlo test-filter inet6
}
"""
GOOD_TERM_1 = """
term good-term-1 {
  protocol:: icmpv6
  action:: accept
}
"""
GOOD_TERM_2 = """
term good-term-2 {
  protocol:: icmpv6
  icmp-type:: destination-unreachable
  action:: accept
}
"""

SUPPORTED_TOKENS = {
    'action',
    'address',
    'comment',
    'counter',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'destination_prefix',
    'destination_prefix_except',
    'dscp_except',
    'dscp_match',
    'dscp_set',
    'ether_type',
    'expiration',
    'forwarding_class',
    'forwarding_class_except',
    'fragment_offset',
    'hop_limit',
    'icmp_code',
    'icmp_type',
    'logging',
    'loss_priority',
    'name',
    'next_ip',
    'option',
    'owner',
    'packet_length',
    'platform',
    'platform_exclude',
    'policer',
    'port',
    'precedence',
    'protocol',
    'protocol_except',
    'qos',
    'routing_instance',
    'source_address',
    'source_address_exclude',
    'source_port',
    'source_prefix',
    'source_prefix_except',
    'traffic_class_count',
    'traffic_type',
    'translated',
    'verbatim',
}

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny', 'reject', 'next', 'reject-with-tcp-rst'},
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
               'first-fragment',
               '.*',  # not actually a lex token!
               'sample',
               'tcp-established',
               'tcp-initial'}
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class SRXloTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testIcmpv6(self):
    output = str(srxlo.SRXlo(policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1,
                                                self.naming), EXP_INFO))
    self.failUnless('next-header icmp6;' in output,
                    'missing or incorrect ICMPv6 specification')

  def testIcmpv6Type(self):
    output = str(srxlo.SRXlo(policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_2,
                                                self.naming), EXP_INFO))
    self.failUnless('next-header icmp6;' in output,
                    'missing or incorrect ICMPv6 specification')
    self.failUnless('icmp-type 1;' in output,
                    'missing or incorrect ICMPv6 type specification')

  def testBuildTokens(self):
    # self.naming.GetServiceByProto.side_effect = [['25'], ['26']]
    pol1 = srxlo.SRXlo(policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1,
                                          self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.maxDiff = None
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    pol1 = srxlo.SRXlo(policy.ParsePolicy(
        GOOD_HEADER_1 + GOOD_TERM_1, self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)


if __name__ == '__main__':
  unittest.main()
