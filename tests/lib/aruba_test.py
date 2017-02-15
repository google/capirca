# Copyright 2017 Google Inc. All Rights Reserved.
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

"""Unittest for Aruba acl rendering module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import datetime
import logging
import textwrap
import unittest


from lib import aruba
from lib import nacaddr
from lib import naming
from lib import policy
import mock

GOOD_HEADER_V4 = """
header {
  target:: aruba test-filter
}
"""

GOOD_HEADER_V6 = """
header {
  target:: aruba test-filter inet6
}
"""

EXPIRED_TERM = """
term is-expired {
  expiration:: 2010-01-01
  action:: accept
}
"""

EXPIRING_TERM = """
term is-expiring {
  expiration:: %s
  action:: accept
}
"""

GOOD_TERM_SIMPLE = """
term good-term-simple {
  action:: accept
}
"""

GOOD_TERM_SHORT_COMMENT = """
term good-term-short-comment {
  comment:: "It will be huge."
  owner:: djtrump
  action:: deny
}
"""

GOOD_TERM_LONG_COMMENT = """
term good-term-long-comment {
  comment:: "Two households, both alike in dignity,"
  comment:: "In fair Verona, where we lay our scene,"
  comment:: "From ancient grudge break to new mutiny, Where civil blood makes civil hands unclean."
  owner:: wshakespeare
  action:: accept
}
"""

GOOD_TERM_VERBATIM = """
term much-verbatim {
  verbatim:: aruba "aruba uses some odd ACL format"
  verbatim:: aruba "which is kinda like, weird"
  verbatim:: aruba ""
  verbatim:: cisco "But Cisco's format is Ok, tho."
  verbatim:: juniper "And Juniper's is the best!"
}
"""

GOOD_TERM_ALLOW_ANY_ANY = """
term good-term-allow-any-any {
  action:: accept
}
"""

GOOD_TERM_DENY_ANY_ANY = """
term good-term-deny-any-any {
  action:: deny
}
"""

GOOD_TERM_SINGLE_NETDESTINATION = """
term gt-one-netd {
  source-address:: SINGLE_HOST
  protocol:: icmp
  action:: accept
}
"""

GOOD_TERM_TWO_NETDESTINATIONS = """
term gt-two-netd {
  source-address:: SINGLE_HOST
  destination-address:: SINGLE_HOST
  protocol:: icmp
  action:: accept
}
"""

GOOD_TERM_TWO_NETWORK_NETDESTINATIONS = """
term gt-mix-netd {
  source-address:: SOME_NETWORK
  destination-address:: SOME_NETWORK
  protocol:: icmp
  action:: accept
}
"""

GOOD_TERM_COMBINED_NETDESTINATIONS = """
term good-term-combined-netdestinations {
  source-address:: MIXED_HOSTS
  protocol:: tcp
  destination-port:: HTTP
  action:: deny
}
"""

GOOD_TERMS_COMBINED_SINGLE_CASE = """
term good-terms-combined-1 {
  source-address:: SOME_HOST
  destination-address:: SOME_HOST
  protocol:: udp
  destination-port:: TFTP
  action:: accept
}

term good-terms-combined-2 {
  action:: deny
}
"""

GOOD_TERM_SOURCE_IS_USER = """
term good-term-source-is-user {
  destination-address:: SOME_NETWORK
  protocol:: tcp
  destination-port:: DNS
  action:: accept
  option:: source-is-user
}
"""

GOOD_TERM_DESTINATION_IS_USER = """
term good-term-destination-is-user {
  source-address:: SOME_NETWORK
  protocol:: tcp
  destination-port:: DNS
  action:: accept
  option:: destination-is-user
}
"""

GOOD_TERM_NEGATE_1 = """
term good-term-negate {
  source-address:: SOME_NETWORK
  action:: deny
  option:: negate
}
"""

GOOD_TERM_NEGATE_2 = """
term good-term-negate {
  action:: accept
  option:: negate
}
"""

GOOD_TERM_PROTOCOL_MAP = """
term allow-icmp {
  protocol:: icmp
  action:: accept
}

term allow-gre {
  protocol:: gre
  action:: accept
}

term allow-esp {
  protocol:: esp
  action:: accept
}
"""

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'destination_address',
    'destination_port',
    'expiration',
    'name',
    'option',
    'protocol',
    'source_address',
    'translated',
    'verbatim',
}

SUPPORTED_SUB_TOKENS = {
    'action': {
        'accept',
        'deny',
    },
    'option': {
        'source-is-user',
        'destination-is-user',
        'negate',
    },
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class ArubaTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testBuildTokens(self):
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_SIMPLE,
                                         self.naming), EXP_INFO)
    st, sst = aru._BuildTokens()
    self.assertEqual(SUPPORTED_TOKENS, st)
    self.assertEqual(SUPPORTED_SUB_TOKENS, sst)

  @mock.patch.object(logging, 'warn')
  def testExpiredTerm(self, mock_warn):
    aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 + EXPIRED_TERM,
                                   self.naming), EXP_INFO)
    mock_warn.assert_called_once_with(
        'WARNING: Term %s in policy %s is expired and will not '
        'be rendered.', 'is-expired', 'test-filter')

  @mock.patch.object(logging, 'info')
  def testExpiringTerm(self, mock_info):
    exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
    aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 + EXPIRING_TERM %
                                   exp_date.strftime('%Y-%m-%d'),
                                   self.naming), EXP_INFO)
    mock_info.assert_called_once_with(
        'INFO: Term %s in policy %s expires in '
        'less than two weeks.', 'is-expiring', 'test-filter')

  def testSimpleTerm(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    ip access-list session test-filter
      any any any permit
    !
    """
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_SIMPLE,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testShortComment(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    ip access-list session test-filter
      # It will be huge.
      # Owner: djtrump
      any any any deny
    !
    """
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_SHORT_COMMENT,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testLongWrappedComment(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    ip access-list session test-filter
      # Two households, both alike in dignity,
      # In fair Verona, where we lay our scene,
      # From ancient grudge break to new mutiny, Where civil blood makes civil
      # hands unclean.
      # Owner: wshakespeare
      any any any permit
    !
    """
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_LONG_COMMENT,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testVerbatim(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    ip access-list session test-filter
      aruba uses some odd ACL format
      which is kinda like, weird
      any any any permit
    !
    """
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_VERBATIM +
                                         GOOD_TERM_ALLOW_ANY_ANY,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testMultipleCallsSingleOwnerLine(self):
    expected_result = textwrap.dedent("""\
        # $Id:$
        # $Date:$
        # $Revision:$
        ip access-list session test-filter
          # Two households, both alike in dignity,
          # In fair Verona, where we lay our scene,
          # From ancient grudge break to new mutiny, Where civil blood makes civil
          # hands unclean.
          # Owner: wshakespeare
          any any any permit
        !
        """)
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_LONG_COMMENT,
                                         self.naming), EXP_INFO)
    self.assertEqual(expected_result, str(aru))
    self.assertEqual(expected_result, str(aru))

  def testTermAllowAnyAnyIPv4(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    ip access-list session test-filter
      any any any permit
    !
    """
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_ALLOW_ANY_ANY,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testTermAllowAnyAnyIPv6(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    ip access-list session test-filter
      ipv6 any any any permit
    !
    """
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V6 +
                                         GOOD_TERM_ALLOW_ANY_ANY,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testTermDenyAnyAnyIPv4(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    ip access-list session test-filter
      any any any deny
    !
    """
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_DENY_ANY_ANY,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testTermDenyAnyAnyIPv6(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    ip access-list session test-filter
      ipv6 any any any deny
    !
    """
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V6 +
                                         GOOD_TERM_DENY_ANY_ANY,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testMultipleCallsSingleNetdestinationsBlock(self):
    expected_result = textwrap.dedent("""\
        # $Id:$
        # $Date:$
        # $Revision:$
        netdestination gt-one-netd_src
          host 10.1.1.1
        !

        ip access-list session test-filter
          alias gt-one-netd_src any 1 permit
        !
        """)
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_SINGLE_NETDESTINATION,
                                         self.naming), EXP_INFO)
    self.assertEqual(expected_result, str(aru))
    self.assertEqual(expected_result, str(aru))

  def testSingleNetdestinationIPv4(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    netdestination gt-one-netd_src
      host 10.1.1.1
    !

    ip access-list session test-filter
      alias gt-one-netd_src any 1 permit
    !
    """
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_SINGLE_NETDESTINATION,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testSingleNetdestinationIPv6(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    netdestination6 gt-one-netd_src
      host 2001::
    !

    ip access-list session test-filter
      ipv6 alias gt-one-netd_src any 1 permit
    !
    """
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2001::/128')]
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V6 +
                                         GOOD_TERM_SINGLE_NETDESTINATION,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testTwoNetdestinationsIPv4(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    netdestination gt-two-netd_src
      host 10.1.1.1
    !

    netdestination gt-two-netd_dst
      host 10.1.1.1
    !

    ip access-list session test-filter
      alias gt-two-netd_src alias gt-two-netd_dst 1 permit
    !
    """
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_TWO_NETDESTINATIONS,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testTwoNetdestinationsIPv6(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    netdestination6 gt-two-netd_src
      host 2001::
    !

    netdestination6 gt-two-netd_dst
      host 2001::
    !

    ip access-list session test-filter
      ipv6 alias gt-two-netd_src alias gt-two-netd_dst 1 permit
    !
    """
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2001::/128')]
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V6 +
                                         GOOD_TERM_TWO_NETDESTINATIONS,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testTwoNetworkNetdestinationsIPv4(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    netdestination gt-mix-netd_src
      network 10.0.0.0 255.0.0.0
    !

    netdestination gt-mix-netd_dst
      network 10.0.0.0 255.0.0.0
    !

    ip access-list session test-filter
      alias gt-mix-netd_src alias gt-mix-netd_dst 1 permit
    !
    """
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_TWO_NETWORK_NETDESTINATIONS,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testTwoNetworkNetdestinationsIPv6(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    netdestination6 gt-mix-netd_src
      network 2001::/64
    !

    netdestination6 gt-mix-netd_dst
      network 2001::/64
    !

    ip access-list session test-filter
      ipv6 alias gt-mix-netd_src alias gt-mix-netd_dst 1 permit
    !
    """
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2001::/64')]
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V6 +
                                         GOOD_TERM_TWO_NETWORK_NETDESTINATIONS,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testCombinedNetdestinationsIPv4(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    netdestination good-term-combined-netdestinations_src
      host 10.0.0.1
      network 100.0.0.0 255.0.0.0
    !

    ip access-list session test-filter
      alias good-term-combined-netdestinations_src any tcp 80 deny
    !
    """
    self.naming.GetNetAddr.return_value = [nacaddr.IP('100.0.0.0/8'),
                                           nacaddr.IP('10.0.0.1/32')]
    self.naming.GetServiceByProto.return_value = ['80']
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_COMBINED_NETDESTINATIONS,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testCombinedNetdestinationsIPv6(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    netdestination6 good-term-combined-netdestinations_src
      host 2001::
      network 2002::/64
    !

    ip access-list session test-filter
      ipv6 alias good-term-combined-netdestinations_src any tcp 80 deny
    !
    """
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2002::/64'),
                                           nacaddr.IP('2001::/128')]
    self.naming.GetServiceByProto.return_value = ['80']
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V6 +
                                         GOOD_TERM_COMBINED_NETDESTINATIONS,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testMultipleTermsIPv4(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    netdestination good-terms-combined-1_src
      host 10.0.0.1
      network 100.0.0.0 255.0.0.0
    !

    netdestination good-terms-combined-1_dst
      host 10.0.0.1
      network 100.0.0.0 255.0.0.0
    !

    ip access-list session test-filter
      alias good-terms-combined-1_src alias good-terms-combined-1_dst udp 69 permit
      any any any deny
    !
    """
    self.naming.GetNetAddr.return_value = [nacaddr.IP('100.0.0.0/8'),
                                           nacaddr.IP('10.0.0.1/32')]
    self.naming.GetServiceByProto.return_value = ['69']
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERMS_COMBINED_SINGLE_CASE,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testMultipleTermsIPv6(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    netdestination6 good-terms-combined-1_src
      host 2001::
      network 2002::/64
    !

    netdestination6 good-terms-combined-1_dst
      host 2001::
      network 2002::/64
    !

    ip access-list session test-filter
      ipv6 alias good-terms-combined-1_src alias good-terms-combined-1_dst udp 69 permit
      ipv6 any any any deny
    !
    """
    self.naming.GetNetAddr.return_value = [nacaddr.IP('2002::/64'),
                                           nacaddr.IP('2001::/128')]
    self.naming.GetServiceByProto.return_value = ['69']
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V6 +
                                         GOOD_TERMS_COMBINED_SINGLE_CASE,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testSourceIsUser(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    netdestination good-term-source-is-user_dst
      network 100.0.0.0 255.0.0.0
    !

    ip access-list session test-filter
      user alias good-term-source-is-user_dst tcp 53 permit
    !
    """
    self.naming.GetNetAddr.return_value = [nacaddr.IP('100.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['53']
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_SOURCE_IS_USER,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testDestinationIsUser(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    netdestination good-term-destination-is-user_src
      network 100.0.0.0 255.0.0.0
    !

    ip access-list session test-filter
      alias good-term-destination-is-user_src user tcp 53 permit
    !
    """
    self.naming.GetNetAddr.return_value = [nacaddr.IP('100.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['53']
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_DESTINATION_IS_USER,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testProtocolIsContiguousRange(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    netdestination good-term-destination-is-user_src
      network 100.0.0.0 255.0.0.0
    !

    ip access-list session test-filter
      alias good-term-destination-is-user_src user tcp 53 55 permit
    !
    """
    self.naming.GetNetAddr.return_value = [nacaddr.IP('100.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['53-55', '54']
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_DESTINATION_IS_USER,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testProtocolIsDiscontiguousRange(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    netdestination good-term-destination-is-user_src
      network 100.0.0.0 255.0.0.0
    !

    ip access-list session test-filter
      alias good-term-destination-is-user_src user tcp 1 permit
      alias good-term-destination-is-user_src user tcp 10 20 permit
      alias good-term-destination-is-user_src user tcp 53 55 permit
    !
    """
    self.naming.GetNetAddr.return_value = [nacaddr.IP('100.0.0.0/8')]
    self.naming.GetServiceByProto.return_value = ['53-55', '54', '10-20', '1']
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_DESTINATION_IS_USER,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testNegateWithNetwork(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    netdestination good-term-negate_src
      network 100.0.0.0 255.0.0.0
    !

    ip access-list session test-filter
      no alias good-term-negate_src any any deny
    !
    """
    self.naming.GetNetAddr.return_value = [nacaddr.IP('100.0.0.0/8')]
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_NEGATE_1,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testNegateAny(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    ip access-list session test-filter
      no any any any permit
    !
    """
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_NEGATE_2,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))

  def testProtocolMap(self):
    expected_result = """\
    # $Id:$
    # $Date:$
    # $Revision:$
    ip access-list session test-filter
      any any 1 permit
      any any 47 permit
      any any 50 permit
    !
    """
    aru = aruba.Aruba(policy.ParsePolicy(GOOD_HEADER_V4 +
                                         GOOD_TERM_PROTOCOL_MAP,
                                         self.naming), EXP_INFO)
    self.assertEqual(textwrap.dedent(expected_result), str(aru))


if __name__ == '__main__':
  unittest.main()
