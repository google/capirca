# Copyright 2007 Google Inc. All Rights Reserved.
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

"""Unittest for squid acl rendering module."""

import unittest

from lib import squid
from lib import nacaddr
from lib import naming
from lib import policy
import mock


GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: squid test inet
}
"""
GOOD_HEADER_HASHTERMS = """
header {
  target:: squid test inet hashterms
}
"""
GOOD_TERM_1 = """
term good-term-1 {
  protocol:: tcp
  destination-port:: SMTP
  destination-address:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_2 = """
term good-term-2 {
  protocol:: tcp
  destination-address:: SOME_HOST
  source-port:: HTTP
  option:: established tcp-established
  action:: accept
}
"""
GOOD_TERM_3 = """
term good-term-3 {
  protocol:: icmp
  icmp-type:: echo-reply information-reply information-request
  icmp-type:: router-solicitation timestamp-request
  action:: accept
}
"""
GOOD_TERM_4 = """
term good-term-4 {
  protocol:: icmp
  protocol:: tcp
  action:: accept
}
"""
DEFAULT_TERM_1 = """
term default-term-1 {
  action:: deny
}
"""
LONG_COMMENT_TERM_1 = """
term long-comment-term-1 {
  comment:: "this is very very very very very very very very very very very"
  comment:: "very very very very very very very long."
  action:: deny
}
"""
LONG_TERM_NAME_1 = """
term really-really-really-really-really-really-really-really-long-term-1 {
  protocol:: tcp
  destination-address:: SOME_HOST
  source-port:: HTTP
  action:: deny
}
"""

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class SquidTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testBasic(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    gen = squid.Squid(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1,
                                         self.naming), EXP_INFO)
    output = str(gen)

    self.failUnless('this is a test acl' in output, output)
    self.failUnless('acl good-term-1-dst-port port 25' in output, output)
    self.failUnless('http_access allow good-term-1-dst good-term-1-dst-port'
                    in output, output)

  def testTcpOptionsSrcDstPorts(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    gen = squid.Squid(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_2,
                                         self.naming), EXP_INFO)
    output = str(gen)

    self.failUnless('this is a test acl' in output, output)
    self.failUnless('acl good-term-2-src-port port 25' in output, output)
    self.failUnless('acl good-term-2-dst-port port 1024-65535' in output,
                    output)
    self.failUnless('http_access allow good-term-2-src-port'
                    ' good-term-2-dst-port good-term-2-dst'
                    in output, output)

  def testMixedProtocols(self):
    gen = squid.Squid(
      policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_3 + GOOD_TERM_4 + DEFAULT_TERM_1,
        self.naming),
      EXP_INFO)
    output = str(gen)

    self.failUnless(
      '# skipped good-term-3 due to protocol icmp not being supported'
      in output, output)
    self.failUnless(
      '# skipped good-term-4 due to protocol icmp not being supported'
      in output, output)
    self.failUnless('http_access deny all' in output, output)

  def testLongComment(self):
    gen = squid.Squid(policy.ParsePolicy(GOOD_HEADER + LONG_COMMENT_TERM_1,
                      self.naming), EXP_INFO)
    output = str(gen)

    # we don't support term comments.
    self.failIf('very' in output, output)

  def testHashterms(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['80']

    content = GOOD_HEADER_HASHTERMS + LONG_TERM_NAME_1

    gen = squid.Squid(policy.ParsePolicy(content, self.naming), EXP_INFO)
    output = str(gen)

    self.failUnless('acl 3261695e26debd7dddcf8a-dst dst 10.0.0.0/8' in output,
                    output)
    self.failUnless('acl 3261695e26debd7dddcf8a-src-port port 80' in output,
                    output)
    self.failUnless('http_access deny 3261695e26debd7dddcf8a-dst'
                    ' 3261695e26debd7dddcf8a-src-port' in output, output)


if __name__ == "__main__":
    unittest.main()
