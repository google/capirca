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
"""Unittest for Cisco XR acl rendering module."""

import unittest

from lib import ciscoxr
from lib import nacaddr
from lib import naming
from lib import policy
import mox

GOOD_HEADER_1 = """
header {
  comment:: "this is a test acl"
  target:: ciscoxr test-filter
}
"""

GOOD_HEADER_2 = """
header {
  comment:: "this is a test ipv6 acl"
  target:: ciscoxr ipv6-test-filter inet6
}
"""

GOOD_TERM_1 = """
term good-term-1 {
  source-address:: SOME_HOST
  protocol:: icmp
  action:: accept
}
"""

GOOD_TERM_2 = """
term good-term-2 {
  protocol:: tcp
  destination-address:: SOME_HOST2
  source-port:: HTTP
  action:: accept
}
"""

EXPIRED_TERM = """
term is_expired {
  expiration:: 2001-01-01
  action:: accept
}
"""

EXP_INFO = 2


class CiscoXRTest(unittest.TestCase):

  def setUp(self):
    self.mox = mox.Mox()
    self.naming = self.mox.CreateMock(naming.Naming)

  def tearDown(self):
    self.mox.VerifyAll()
    self.mox.UnsetStubs()

  def testStandardTermHost(self):
    self.naming.GetNetAddr('SOME_HOST').AndReturn([nacaddr.IP('10.1.1.1/32')])
    self.mox.ReplayAll()
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1,
                             self.naming)
    acl = ciscoxr.CiscoXR(pol, EXP_INFO)
    expected = 'ipv4 access-list test-filter'
    self.failUnless(expected in str(acl), '[%s]' % str(acl))

  def testStandardTermHostIPv6(self):
    self.naming.GetNetAddr('SOME_HOST2').AndReturn([nacaddr.IP('2001::3/128')])
    self.naming.GetServiceByProto('HTTP', 'tcp').AndReturn(['80'])
    self.mox.ReplayAll()
    pol = policy.ParsePolicy(GOOD_HEADER_2 + GOOD_TERM_2,
                             self.naming)
    acl = ciscoxr.CiscoXR(pol, EXP_INFO)
    expected = 'ipv6 access-list ipv6-test-filter'
    self.failUnless(expected in str(acl), '[%s]' % str(acl))

if __name__ == '__main__':
  unittest.main()
