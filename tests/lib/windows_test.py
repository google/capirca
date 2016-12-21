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

"""Unittest for windows acl rendering module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

from lib import naming
from lib import policy
from lib import windows
import mock


GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: windows test-filter
}
"""

MULTIPLE_PROTOCOLS_TERM = """
term multi-proto {
  protocol:: tcp udp icmp
  action:: accept
}
"""

GOOD_WARNING_TERM = """
term good-warning-term {
  protocol:: tcp udp icmp
  policer:: batman
  action:: accept
}
"""

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'expiration',
    'icmp_type',
    'name',
    'option',
    'platform',
    'platform_exclude',
    'protocol',
    'source_address',
    'source_address_exclude',
    'source_port',
    'translated',
}

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny'},
    'icmp_type': {
        'alternate-address',
        'certification-path-advertisement',
        'certification-path-solicitation',
        'conversion-error',
        'destination-unreachable',
        'echo-reply',
        'echo-request', 'mobile-redirect',
        'home-agent-address-discovery-reply',
        'home-agent-address-discovery-request',
        'icmp-node-information-query',
        'icmp-node-information-response',
        'information-request',
        'inverse-neighbor-discovery-advertisement',
        'inverse-neighbor-discovery-solicitation',
        'mask-reply',
        'mask-request', 'information-reply',
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
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class WindowsGeneratorTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testBuildTokens(self):
    pol1 = windows.WindowsGenerator(
        policy.ParsePolicy(GOOD_HEADER + MULTIPLE_PROTOCOLS_TERM, self.naming),
        EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    pol1 = windows.WindowsGenerator(policy.ParsePolicy(
        GOOD_HEADER + GOOD_WARNING_TERM, self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)


if __name__ == '__main__':
  unittest.main()
