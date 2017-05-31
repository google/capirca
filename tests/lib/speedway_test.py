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

"""Unittest for Speedway rendering module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest


from lib import naming
from lib import policy
from lib import speedway
import mock


GOOD_HEADER_1 = """
header {
  comment:: "this is a test acl"
  target:: speedway INPUT ACCEPT
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
  protocol:: icmp
  policer:: batman
  action:: accept
}
"""

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'counter',
    'destination_address',
    'destination_address_exclude',
    'destination_interface',
    'destination_port',
    'destination_prefix',
    'expiration',
    'fragment_offset',
    'icmp_code',
    'icmp_type',
    'logging',
    'name',
    'option',
    'owner',
    'packet_length',
    'platform',
    'platform_exclude',
    'protocol',
    'routing_instance',
    'source_address',
    'source_address_exclude',
    'source_interface',
    'source_port',
    'source_prefix',
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
               'initial',
               'sample',
               'tcp-established',
               'tcp-initial',
               'syn',
               'ack',
               'fin',
               'rst',
               'urg',
               'psh',
               'all',
               'none'}
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class SpeedwayTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testSpeedwayOutputFormat(self):
    acl = speedway.Speedway(policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1,
                                               self.naming), EXP_INFO)
    result = []
    result.extend(str(acl).split('\n'))
    self.failUnless('*filter' == result[0],
                    '*filter designation does not appear at top of generated '
                    'policy.')
    self.failUnless(':INPUT ACCEPT' in result,
                    'input default policy of accept not set.')
    self.failUnless('-N I_good-term-1' in result,
                    'did not find new chain for good-term-1.')
    self.failUnless(
        '-A I_good-term-1 -p icmp -m state --state NEW,ESTABLISHED,RELATED'
        ' -j ACCEPT' in result, 'did not find append for good-term-1.')
    self.failUnless('COMMIT' == result[len(result)-2],
                    'COMMIT does not appear at end of output policy.')

  def testBuildTokens(self):
    pol1 = speedway.Speedway(policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1,
                                                self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    pol1 = speedway.Speedway(policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_2,
                                                self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)


if __name__ == '__main__':
  unittest.main()
