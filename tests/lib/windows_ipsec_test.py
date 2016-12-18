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
"""Unittest for windows_ipsec rendering module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import datetime
import unittest


from lib import nacaddr
from lib import naming
from lib import policy
from lib import windows_ipsec
import mock


GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: windows_ipsec test-filter
}
"""

GOOD_SIMPLE = """
term good-simple {
  protocol:: tcp
  action:: accept
}
"""

GOOD_SIMPLE_WARNING = """
term good-simple-warning {
  protocol:: tcp
  policer:: batman
  action:: accept
}
"""

GOOD_TERM_ICMP = """
term good-term-icmp {
  protocol:: icmp
  action:: accept
}
"""

BAD_TERM_ICMP = """
term test-icmp {
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

GOOD_TERM_TCP = """
term good-term-tcp {
  comment:: "Test term 1"
  destination-address:: PROD_NET
  destination-port:: SMTP
  protocol:: tcp
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

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'expiration',
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

SUPPORTED_SUB_TOKENS = {'action': {'accept', 'deny'}}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class WindowsIPSecTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  # pylint: disable=invalid-name
  def failUnless(self, strings, result, term):
    for string in strings:
      fullstring = 'netsh ipsec static add %s' % (string)
      super(WindowsIPSecTest, self).failUnless(
          fullstring in result,
          'did not find "%s" for %s' % (fullstring, term))

  def testPolicy(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    acl = windows_ipsec.WindowsIPSec(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_TCP, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        ['policy name=test-filter-policy assign=yes'],
        result,
        'header')

    self.naming.GetNetAddr.assert_called_once_with('PROD_NET')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testTcp(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['25']

    acl = windows_ipsec.WindowsIPSec(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_TCP, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        ['filteraction name=t_good-term-tcp-action action=permit',
         'filter filterlist=t_good-term-tcp-list mirrored=yes srcaddr=any '
         ' dstaddr=10.0.0.0 dstmask=8 dstport=25',
         'rule name=t_good-term-tcp-rule policy=test-filter'
         ' filterlist=t_good-term-tcp-list'
         ' filteraction=t_good-term-tcp-action'],
        result,
        'good-term-tcp')

    self.naming.GetNetAddr.assert_called_once_with('PROD_NET')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testIcmp(self):
    acl = windows_ipsec.WindowsIPSec(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_ICMP, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        ['filterlist name=t_good-term-icmp-list',
         'filteraction name=t_good-term-icmp-action action=permit',
         'filter filterlist=t_good-term-icmp-list mirrored=yes srcaddr=any '
         ' dstaddr=any',
         'rule name=t_good-term-icmp-rule policy=test-filter'
         ' filterlist=t_good-term-icmp-list'
         ' filteraction=t_good-term-icmp-action'],
        result,
        'good-term-icmp')

  @mock.patch.object(windows_ipsec.logging, 'warn')
  def testExpiredTerm(self, mock_warn):
    windows_ipsec.WindowsIPSec(policy.ParsePolicy(
        GOOD_HEADER + EXPIRED_TERM, self.naming), EXP_INFO)

    mock_warn.assert_called_once_with(
        'WARNING: Term %s in policy %s is expired and '
        'will not be rendered.', 'expired_test',
        'test-filter')

  @mock.patch.object(windows_ipsec.logging, 'info')
  def testExpiringTerm(self, mock_info):
    exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
    windows_ipsec.WindowsIPSec(policy.ParsePolicy(
        GOOD_HEADER + EXPIRING_TERM % exp_date.strftime('%Y-%m-%d'),
        self.naming), EXP_INFO)

    mock_info.assert_called_once_with(
        'INFO: Term %s in policy %s expires in '
        'less than two weeks.', 'is_expiring',
        'test-filter')

  def testMultiprotocol(self):
    acl = windows_ipsec.WindowsIPSec(policy.ParsePolicy(
        GOOD_HEADER + MULTIPLE_PROTOCOLS_TERM, self.naming), EXP_INFO)
    result = str(acl)
    self.failUnless(
        ['filterlist name=t_multi-proto-list',
         'filteraction name=t_multi-proto-action action=permit',
         'filter filterlist=t_multi-proto-list mirrored=yes srcaddr=any '
         ' dstaddr=any  protocol=tcp',
         'filter filterlist=t_multi-proto-list mirrored=yes srcaddr=any '
         ' dstaddr=any  protocol=udp',
         'filter filterlist=t_multi-proto-list mirrored=yes srcaddr=any '
         ' dstaddr=any  protocol=icmp',
         'rule name=t_multi-proto-rule policy=test-filter'
         ' filterlist=t_multi-proto-list filteraction=t_multi-proto-action'],
        result,
        'multi-proto')

  def testBuildTokens(self):
    pol1 = windows_ipsec.WindowsIPSec(policy.ParsePolicy(
        GOOD_HEADER + GOOD_SIMPLE, self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    pol1 = windows_ipsec.WindowsIPSec(policy.ParsePolicy(
        GOOD_HEADER + GOOD_SIMPLE_WARNING, self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)


if __name__ == '__main__':
  unittest.main()
