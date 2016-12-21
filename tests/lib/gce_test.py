# Copyright 2015 Google Inc. All Rights Reserved.
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

"""Unittest for GCE firewall rendering module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import json
import unittest

from lib import aclgenerator
from lib import gce
from lib import nacaddr
from lib import naming
from lib import policy
import mock

GOOD_HEADER = """
header {
  comment:: "The general policy comment."
  target:: gce global/networks/default
}
"""

GOOD_HEADER_NO_NETWORK = """
header {
  comment:: "The general policy comment."
  target:: gce
}
"""

GOOD_TERM = """
term good-term-1 {
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  destination-tag:: dns-servers
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""

GOOD_TERM_2 = """
term good-term-2 {
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  destination-tag:: dns-servers
  destination-port:: DNS
  protocol:: udp tcp
  policer:: batman
  action:: accept
}
"""

GOOD_TERM_EXCLUDE = """
term good-term-1 {
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  source-exclude:: GUEST_WIRELESS_EXTERNAL
  destination-tag:: dns-servers
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""

GOOD_TERM_JSON = """
[
  {
    "name": "default-good-term-1-udp",
    "sourceRanges": [
      "10.2.3.4/32"
    ],
    "allowed": [
      {
        "ports": [
          "53"
        ],
        "IPProtocol": "udp"
      }
    ],
    "description": "DNS access from corp.",
    "targetTags": [
      "dns-servers"
    ],
    "network": "global/networks/default"
  },
  {
    "name": "default-good-term-1-tcp",
    "sourceRanges": [
      "10.2.3.4/32"
    ],
    "allowed": [
      {
        "ports": [
          "53"
        ],
        "IPProtocol": "tcp"
      }
    ],
    "description": "DNS access from corp.",
    "targetTags": [
      "dns-servers"
    ],
    "network": "global/networks/default"
  }
]
"""

GOOD_TERM_NO_NETWORK_JSON = """
[
  {
    "name": "good-term-1-udp",
    "sourceRanges": [
      "10.2.3.4/32"
    ],
    "allowed": [
      {
        "ports": [
          "53"
        ],
        "IPProtocol": "udp"
      }
    ],
    "description": "DNS access from corp.",
    "targetTags": [
      "dns-servers"
    ]
  },
  {
    "name": "good-term-1-tcp",
    "sourceRanges": [
      "10.2.3.4/32"
    ],
    "allowed": [
      {
        "ports": [
          "53"
        ],
        "IPProtocol": "tcp"
      }
    ],
    "description": "DNS access from corp.",
    "targetTags": [
      "dns-servers"
    ]
  }
]
"""


GOOD_TERM_EXPIRED = """
term good-term-expired {
  comment:: "Management access from corp."
  expiration:: 2001-01-01
  source-address:: CORP_EXTERNAL
  destination-tag:: ssh-servers
  destination-port:: SSH
  protocol:: tcp
  action:: accept
}
"""

BAD_TERM_UNSUPPORTED_ACTION = """
term bad-term-unsupported-action {
  comment:: "Management access from corp."
  source-address:: CORP_EXTERNAL
  destination-tag:: ssh-servers
  destination-port:: SSH
  protocol:: tcp
  action:: deny
}
"""

BAD_TERM_NO_SOURCE = """
term bad-term-no-source {
  comment:: "Management access from corp."
  destination-tag:: ssh-servers
  destination-port:: SSH
  protocol:: tcp
  action:: accept
}
"""

BAD_TERM_SOURCE_EXCLUDE_ONLY = """
term bad-term-source-ex-only {
  comment:: "Management access from corp."
  destination-port:: SSH
  source-tag:: ssh-bastion
  source-exclude:: GUEST_WIRELESS_EXTERNAL
  protocol:: tcp
  action:: accept
}
"""

BAD_TERM_SOURCE_PORT = """
term bad-term-source-port {
  comment:: "Management access from corp."
  source-address:: CORP_EXTERNAL
  source-port:: SSH
  destination-tag:: ssh-servers
  protocol:: tcp
  action:: accept
}
"""

BAD_TERM_NAME_TOO_LONG = """
term good-term-whith-a-name-which-is-way-way-too-long-for-gce-to-accept {
  comment:: "Management access from corp."
  source-address:: CORP_EXTERNAL
  destination-port:: SSH
  protocol:: tcp
  action:: accept
}
"""

BAD_TERM_UNSUPPORTED_PORT = """
term good-term-unsupported-port {
  comment:: "Management access from corp."
  source-address:: CORP_EXTERNAL
  destination-port:: SSH
  protocol:: tcp icmp
  action:: accept
}
"""

GOOD_TERM_EXCLUDE_RANGE = """
[
  {
    "name": "default-good-term-1-udp",
    "sourceRanges": [
      "10.128.0.0/10",
      "10.192.0.0/11",
      "10.224.0.0/12",
      "10.241.0.0/16",
      "10.242.0.0/15",
      "10.244.0.0/14",
      "10.248.0.0/13"
    ],
    "allowed": [
      {
        "ports": [
          "53"
        ],
        "IPProtocol": "udp"
      }
    ],
    "description": "DNS access from corp.",
    "targetTags": [
      "dns-servers"
    ],
    "network": "global/networks/default"
  },
  {
    "name": "default-good-term-1-tcp",
    "sourceRanges": [
      "10.128.0.0/10",
      "10.192.0.0/11",
      "10.224.0.0/12",
      "10.241.0.0/16",
      "10.242.0.0/15",
      "10.244.0.0/14",
      "10.248.0.0/13"
    ],
    "allowed": [
      {
        "ports": [
          "53"
        ],
        "IPProtocol": "tcp"
      }
    ],
    "description": "DNS access from corp.",
    "targetTags": [
      "dns-servers"
    ],
    "network": "global/networks/default"
  }
]
"""

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'destination_port',
    'destination_tag',
    'expiration',
    'name',
    'owner',
    'protocol',
    'source_address',
    'source_address_exclude',
    'source_port',
    'source_tag',
    'translated',
}

SUPPORTED_SUB_TOKENS = {'action': {'accept'}}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2

TEST_IPS = [nacaddr.IP('10.2.3.4/32'),
            nacaddr.IP('2001:4860:8000::5/128')]

TEST_INCLUDE_IPS = [nacaddr.IP('10.2.3.4/32'),
                    nacaddr.IP('10.4.3.2/32')]

TEST_EXCLUDE_IPS = [nacaddr.IP('10.4.3.2/32')]

TEST_INCLUDE_RANGE = [nacaddr.IP('10.128.0.0/9')]

TEST_EXCLUDE_RANGE = [nacaddr.IP('10.240.0.0/16')]


class GCETest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def _StripAclHeaders(self, acl):
    return '\n'.join([line for line in str(acl).split('\n')
                      if not line.lstrip().startswith('#')])

  def testGenericTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    acl = gce.GCE(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM, self.naming), EXP_INFO)
    expected = json.loads(GOOD_TERM_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('DNS', 'udp'),
        mock.call('DNS', 'tcp')])

  def testGenericTermWithoutNetwork(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    acl = gce.GCE(policy.ParsePolicy(
        GOOD_HEADER_NO_NETWORK + GOOD_TERM, self.naming), EXP_INFO)
    expected = json.loads(GOOD_TERM_NO_NETWORK_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('DNS', 'udp'),
        mock.call('DNS', 'tcp')])

  def testGenericTermWithExclude(self):
    self.naming.GetNetAddr.side_effect = [TEST_INCLUDE_IPS, TEST_EXCLUDE_IPS]
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    acl = gce.GCE(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_EXCLUDE, self.naming), EXP_INFO)
    expected = json.loads(GOOD_TERM_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('CORP_EXTERNAL'),
        mock.call('GUEST_WIRELESS_EXTERNAL')])
    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('DNS', 'udp'),
        mock.call('DNS', 'tcp')])

  def testGenericTermWithExcludeRange(self):
    self.naming.GetNetAddr.side_effect = [TEST_INCLUDE_RANGE,
                                          TEST_EXCLUDE_RANGE]
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    acl = gce.GCE(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_EXCLUDE, self.naming), EXP_INFO)
    expected = json.loads(GOOD_TERM_EXCLUDE_RANGE)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('CORP_EXTERNAL'),
        mock.call('GUEST_WIRELESS_EXTERNAL')])
    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('DNS', 'udp'),
        mock.call('DNS', 'tcp')])

  def testExpiredTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.return_value = ['22']

    acl = gce.GCE(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM_EXPIRED, self.naming), EXP_INFO)
    self.assertEquals(self._StripAclHeaders(str(acl)), '[]\n\n')

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
    self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

  def testSourceNetworkSplit(self):
    lots_of_ips = []
    for i in range(20):
      for j in range(20):
        lots_of_ips.append(nacaddr.IP('10.%d.%d.1/32' % (i, j)))
    self.naming.GetNetAddr.return_value = lots_of_ips
    self.naming.GetServiceByProto.return_value = ['53']

    acl = gce.GCE(policy.ParsePolicy(
        GOOD_HEADER + GOOD_TERM, self.naming), EXP_INFO)
    self.assertTrue('default-good-term-1-udp-1' in str(acl))
    self.assertTrue('default-good-term-1-udp-2' in str(acl))
    self.assertTrue('default-good-term-1-tcp-1' in str(acl))
    self.assertTrue('default-good-term-1-tcp-2' in str(acl))

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('DNS', 'udp'),
        mock.call('DNS', 'tcp')])

  def testRaisesWithoutSource(self):
    self.naming.GetServiceByProto.return_value = ['22']

    self.assertRaisesRegexp(
        gce.GceFirewallError,
        'GCE firewall needs either to specify source address or source tags.',
        gce.GCE,
        policy.ParsePolicy(
            GOOD_HEADER + BAD_TERM_NO_SOURCE, self.naming),
        EXP_INFO)

    self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

  def testRaisesWithOnlySourceExclusion(self):
    self.naming.GetNetAddr.return_value = TEST_EXCLUDE_IPS
    self.naming.GetServiceByProto.return_value = ['22']

    self.assertRaisesRegexp(
        gce.GceFirewallError,
        ('GCE firewall does not support address exclusions without a source '
         'address list.'),
        gce.GCE,
        policy.ParsePolicy(
            GOOD_HEADER + BAD_TERM_SOURCE_EXCLUDE_ONLY, self.naming),
        EXP_INFO)

    self.naming.GetNetAddr.assert_called_once_with('GUEST_WIRELESS_EXTERNAL')
    self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

  def testRaisesNoSourceAfterExclude(self):
    self.naming.GetNetAddr.side_effect = [TEST_INCLUDE_IPS, TEST_INCLUDE_IPS]
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    self.assertRaisesRegexp(
        gce.GceFirewallError,
        ('GCE firewall rule no longer contains any source addresses after '
         'the prefixes in source_address_exclude were removed.'),
        gce.GCE,
        policy.ParsePolicy(
            GOOD_HEADER + GOOD_TERM_EXCLUDE, self.naming),
        EXP_INFO)

    self.naming.GetNetAddr.assert_has_calls([
        mock.call('CORP_EXTERNAL'),
        mock.call('GUEST_WIRELESS_EXTERNAL')])
    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('DNS', 'udp'),
        mock.call('DNS', 'tcp')])

  def testRaisesWithSourcePort(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.return_value = ['22']

    self.assertRaisesRegexp(
        gce.GceFirewallError,
        'GCE firewall does not support source port restrictions.',
        gce.GCE,
        policy.ParsePolicy(
            GOOD_HEADER + BAD_TERM_SOURCE_PORT, self.naming),
        EXP_INFO)

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
    self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

  def testRaisesWithLongTermName(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.return_value = ['22']

    self.assertRaises(
        aclgenerator.TermNameTooLongError,
        gce.GCE,
        policy.ParsePolicy(
            GOOD_HEADER + BAD_TERM_NAME_TOO_LONG, self.naming),
        EXP_INFO)

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
    self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

  def testRaisesWithIcmpAndDestinationPort(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.side_effect = [['22'], ['22']]

    self.assertRaisesRegexp(
        gce.GceFirewallError,
        'Only TCP and UDP protocols support destination ports.',
        gce.GCE,
        policy.ParsePolicy(
            GOOD_HEADER + BAD_TERM_UNSUPPORTED_PORT, self.naming),
        EXP_INFO)

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('SSH', 'tcp'),
        mock.call('SSH', 'icmp')])

  def testBuildTokens(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
    pol1 = gce.GCE(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM,
                                      self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    pol1 = gce.GCE(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_2,
                                      self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEquals(st, SUPPORTED_TOKENS)
    self.assertEquals(sst, SUPPORTED_SUB_TOKENS)


if __name__ == '__main__':
  unittest.main()
