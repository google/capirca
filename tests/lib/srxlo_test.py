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


if __name__ == '__main__':
  unittest.main()
