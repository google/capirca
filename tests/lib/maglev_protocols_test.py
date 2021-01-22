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
"""Tests for arista acl rendering module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

from capirca.lib import aclgenerator
from capirca.lib import maglev_protocols
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy
import mock


GOOD_HEADER = """
header {
  comment:: "Test protocol AllowList"
  target:: maglev_protocols test-filter
}
"""

GOOD_TERM = """
term good-term-1 {
  comment:: "Accept esp and tcp."
  protocol:: tcp udp esp
  action:: accept
}
"""

MULTIPLE_TERMS = """
term good-term-1 {
  comment:: "Accept tcp, udp, esp."
  protocol:: tcp udp esp
  action:: accept
}

term good-term-2 {
  comment:: "Accept ah."
  protocol:: ah
  action:: accept
}
"""

UNSUPPORTED_TERM_1 = """
term standard-term-1 {
  protocol:: tcp
  destination-address:: SOME_HOST
  action:: accept
}
"""

UNSUPPORTED_TERM_2 = """
term standard-term-2 {
  protocol:: tcp
  destination-port:: SSH
  action:: accept
}
"""

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class MaglevProtocolsTest(unittest.TestCase):

  def setUp(self):
    super(MaglevProtocolsTest, self).setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def testStandardTerm(self):
    pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM, self.naming)
    acl = maglev_protocols.MaglevProtocols(pol, EXP_INFO)
    expected = 'tcp, udp, esp'
    self.assertIn(expected, str(acl))

  def testTooManyTerms(self):
    self.assertRaises(
        maglev_protocols.ProtocolFilterError,
        maglev_protocols.MaglevProtocols,
        policy.ParsePolicy(
            GOOD_HEADER + MULTIPLE_TERMS, self.naming),
        EXP_INFO)

  def testUnsupportedAddr(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/24')]
    pol = policy.ParsePolicy(GOOD_HEADER + UNSUPPORTED_TERM_1, self.naming)
    self.assertRaises(aclgenerator.UnsupportedFilterError,
                      maglev_protocols.MaglevProtocols, pol, EXP_INFO)

  def testUnsupportedPort(self):
    self.naming.GetServiceByProto.return_value = ['22']
    pol = policy.ParsePolicy(GOOD_HEADER + UNSUPPORTED_TERM_2, self.naming)
    self.assertRaises(aclgenerator.UnsupportedFilterError,
                      maglev_protocols.MaglevProtocols, pol, EXP_INFO)

if __name__ == '__main__':
  unittest.main()
