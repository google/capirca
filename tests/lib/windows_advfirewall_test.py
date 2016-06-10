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
"""Unittest for windows_advfirewall rendering module."""

import datetime
import unittest

from lib import aclgenerator
from lib import nacaddr
from lib import naming
from lib import policy
from lib import policyparser
from lib import windows_advfirewall
import mock


GOOD_HEADER_OUT = """
header {
  comment:: "this is an out test acl"
  target:: windows_advfirewall out inet
}
"""

GOOD_HEADER_IN = """
header {
  comment:: "this is an in test acl"
  target:: windows_advfirewall in inet
}
"""

GOOD_TERM_ICMP = """
term good-term-icmp {
  protocol:: icmp
  action:: accept
}
"""

GOOD_TERM_ICMP_TYPES = """
term good-term-icmp-types {
  protocol:: icmp
  icmp-type:: echo-reply unreachable time-exceeded
  action:: deny
}
"""

GOOD_TERM_ICMPV6 = """
term good-term-icmpv6 {
  protocol:: icmpv6
  action:: accept
}
"""

BAD_TERM_ICMP = """
term test-icmp {
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

BAD_TERM_ACTION = """
term bad-term-action {
  protocol:: icmp
  action:: undefined
}
"""

GOOD_TERM_TCP = """
term good-term-tcp {
  comment:: "Test term 1"
  destination-address:: PROD_NETWRK
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_LOG = """
term good-term-log {
  protocol:: tcp
  logging:: true
  action:: accept
}
"""

EXPIRED_TERM = """
term expired_test {
  expiration:: 2000-1-1
  action:: deny
}
"""

EXPIRING_TERM = """
term is_expiring {
  expiration:: %s
  action:: accept
}
"""

MULTIPLE_PROTOCOLS_TERM = """
term multi-proto {
  protocol:: tcp udp icmp
  action:: accept
}
"""

NEXT_TERM = """
term next {
  action:: next
}
"""

NEXT_LOG_TERM = """
term next-log {
  logging:: true
  action:: next
}
"""

EXCEPTION_POLICY = """
header {
  comment:: "Header comment"
  target:: windows_advfirewall out inet
}

term accept-corpdns {
  comment:: "accept-corpdns comment1"
  comment:: "accept-corpdns comment2"
  destination-address:: CORP_ANYCAST_DNS
  destination-port:: DNS
  protocol:: udp
  action:: accept
}

term deny-to-google {
  comment:: "deny-to-google comment"
  destination-address:: INTERNAL
  action:: deny
}
"""

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class WindowsAdvFirewallTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def FailUnless(self, strings, result, term):
    for string in strings:
      fullstring = 'netsh advfirewall firewall add rule %s' % (string)
      super(WindowsAdvFirewallTest, self).failUnless(
          fullstring in result,
          'did not find "%s" for %s' % (fullstring, term))

  def testTcp(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    acl = windows_advfirewall.WindowsAdvFirewall(policyparser.ParsePolicy(
        GOOD_HEADER_OUT + GOOD_TERM_TCP, self.naming), EXP_INFO)
    result = str(acl)
    self.FailUnless(
        ['name=o_good-term-tcp enable=yes interfacetype=any dir=out localip=any'
         ' remoteip=10.0.0.0/8 remoteport=25 protocol=tcp action=allow'],
        result,
        'did not find actual term for good-term-tcp')

    self.naming.GetNetAddr.assert_called_once_with('PROD_NETWRK')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testIcmp(self):
    acl = windows_advfirewall.WindowsAdvFirewall(policyparser.ParsePolicy(
        GOOD_HEADER_OUT + GOOD_TERM_ICMP, self.naming), EXP_INFO)
    result = str(acl)
    self.FailUnless(
        ['name=o_good-term-icmp enable=yes interfacetype=any dir=out'
         ' localip=any remoteip=any protocol=icmpv4 action=allow'],
        result,
        'did not find actual term for good-term-icmp')

  def testIcmpTypes(self):
    acl = windows_advfirewall.WindowsAdvFirewall(policyparser.ParsePolicy(
        GOOD_HEADER_OUT + GOOD_TERM_ICMP_TYPES, self.naming), EXP_INFO)
    result = str(acl)
    self.FailUnless(
        ['name=o_good-term-icmp-types enable=yes interfacetype=any dir=out'
         ' localip=any remoteip=any protocol=icmpv4:0 action=block',
         'name=o_good-term-icmp-types enable=yes interfacetype=any dir=out'
         ' localip=any remoteip=any protocol=icmpv4:3 action=block',
         'name=o_good-term-icmp-types enable=yes interfacetype=any dir=out'
         ' localip=any remoteip=any protocol=icmpv4:11 action=block'],
        result,
        'did not find actual term for good-term-icmp-types')

  def testBadIcmp(self):
    acl = windows_advfirewall.WindowsAdvFirewall(policyparser.ParsePolicy(
        GOOD_HEADER_OUT + BAD_TERM_ICMP, self.naming), EXP_INFO)
    self.assertRaises(aclgenerator.UnsupportedFilterError,
                      str, acl)

  @mock.patch.object(windows_advfirewall.logging, 'warn')
  def testExpiredTerm(self, mock_warn):
    windows_advfirewall.WindowsAdvFirewall(policyparser.ParsePolicy(
        GOOD_HEADER_OUT + EXPIRED_TERM, self.naming), EXP_INFO)

    mock_warn.assert_called_once_with(
        'WARNING: Term %s in policy %s is expired '
        'and will not be rendered.',
        'expired_test', 'out')

  @mock.patch.object(windows_advfirewall.logging, 'info')
  def testExpiringTerm(self, mock_info):
    exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
    windows_advfirewall.WindowsAdvFirewall(policyparser.ParsePolicy(
        GOOD_HEADER_OUT + EXPIRING_TERM % exp_date.strftime('%Y-%m-%d'),
        self.naming), EXP_INFO)

    mock_info.assert_called_once_with(
        'INFO: Term %s in policy %s expires in '
        'less than two weeks.', 'is_expiring',
        'out')

  def testMultiprotocol(self):
    acl = windows_advfirewall.WindowsAdvFirewall(policyparser.ParsePolicy(
        GOOD_HEADER_OUT + MULTIPLE_PROTOCOLS_TERM, self.naming), EXP_INFO)
    result = str(acl)
    self.FailUnless(
        ['name=o_multi-proto enable=yes interfacetype=any dir=out localip=any'
         ' remoteip=any protocol=tcp action=allow',
         'name=o_multi-proto enable=yes interfacetype=any dir=out localip=any'
         ' remoteip=any protocol=udp action=allow',
         'name=o_multi-proto enable=yes interfacetype=any dir=out localip=any'
         ' remoteip=any protocol=icmpv4 action=allow'],
        result,
        'did not find actual term for multi-proto')

  def testDirectionIn(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    acl = windows_advfirewall.WindowsAdvFirewall(policyparser.ParsePolicy(
        GOOD_HEADER_IN + GOOD_TERM_TCP, self.naming), EXP_INFO)
    result = str(acl)
    self.FailUnless(
        ['name=i_good-term-tcp enable=yes interfacetype=any dir=in remoteip=any'
         ' localip=10.0.0.0/8 localport=25 protocol=tcp action=allow'],
        result,
        'did not find actual term for good-term-tcp-direction-in')

    self.naming.GetNetAddr.assert_called_once_with('PROD_NETWRK')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

if __name__ == '__main__':
  unittest.main()
