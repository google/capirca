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

import unittest

from lib import naming
from lib import policy
from lib import policyparser
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

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class SpeedwayTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testSpeedwayOutputFormat(self):
    acl = speedway.Speedway(policyparser.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1,
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


if __name__ == '__main__':
  unittest.main()

