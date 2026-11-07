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

"""Unittest for ciscoasa acl rendering module."""

from absl.testing import absltest
from unittest import mock

from capirca.lib import ciscoasa
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy


GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: ciscoasa test-filter
}
"""

GOOD_TERM_1 = """
term good-term-1 {
  verbatim:: ciscoasa "mary had a little lamb"
  verbatim:: iptables "mary had second lamb"
  verbatim:: juniper "mary had third lamb"
}
"""

GOOD_TERM_2 = """
term good-term-2 {
  verbatim:: ciscoasa "mary had a little lamb"
  policer:: batman
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
    'stateless_reply',
    'logging',
    'name',
    'option',
    'owner',
    'platform',
    'platform_exclude',
    'protocol',
    'source_address',
    'source_address_exclude',
    'source_port',
    'translated',
    'verbatim',
}

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny', 'reject', 'next',
               'reject-with-tcp-rst'},
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
        'traceroute',
        'unreachable',
        'version-2-multicast-listener-report',
    },
    'option': {'established', 'tcp-established'}}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class CiscoASATest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def testBuildTokens(self):
    pol1 = ciscoasa.CiscoASA(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1,
                                                self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    pol1 = ciscoasa.CiscoASA(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_2,
                                                self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

  def test_ipv6_addresses(self):
    """Render only IPv6 members of dual-stack address definitions."""
    self.naming.GetNetAddr.side_effect = lambda name: {
        'SOURCE': [nacaddr.IP('2001:db8::/64'), nacaddr.IP('192.0.2.0/24')],
        'DESTINATION': [nacaddr.IP('2001:db8:1::1/128'),
                        nacaddr.IP('198.51.100.1/32')],
    }[name]
    text = GOOD_HEADER.replace('test-filter', 'test-filter inet6') + """
term ipv6 {
  action:: accept
  protocol:: tcp
  source-address:: SOURCE
  destination-address:: DESTINATION
}
"""
    rendered = str(ciscoasa.CiscoASA(
        policy.ParsePolicy(text, self.naming), EXP_INFO))
    self.assertIn('permit tcp 2001:db8::/64 host 2001:db8:1::1', rendered)
    self.assertNotIn('192.0.2.', rendered)
    self.assertNotIn('198.51.100.', rendered)

  def test_ipv6_unspecified_addresses(self):
    """Keep IPv6 wildcards from also matching IPv4 traffic."""
    text = GOOD_HEADER.replace('test-filter', 'test-filter inet6') + """
term ipv6 {
  action:: accept
  protocol:: tcp
}
"""
    rendered = str(ciscoasa.CiscoASA(
        policy.ParsePolicy(text, self.naming), EXP_INFO))
    self.assertIn('permit tcp any6 any6', rendered)

  def test_ipv6_icmp(self):
    """Use the ASA protocol name and IPv6 ICMP type numbers."""
    text = GOOD_HEADER.replace('test-filter', 'test-filter inet6') + """
term ping {
  action:: accept
  protocol:: icmpv6
  icmp-type:: echo-request
}
"""
    rendered = str(ciscoasa.CiscoASA(
        policy.ParsePolicy(text, self.naming), EXP_INFO))
    self.assertIn('permit icmp6 any6 any6 128', rendered)
    rendered = str(ciscoasa.CiscoASA(policy.ParsePolicy(
        text.replace('echo-request', 'time-exceeded'), self.naming), EXP_INFO))
    self.assertIn('permit icmp6 any6 any6 3', rendered)

  def test_address_family_is_per_filter(self):
    """Do not carry the family over to the next filter."""
    term = """
term allow-tcp {
  action:: accept
  protocol:: tcp
}
"""
    text = (GOOD_HEADER.replace('test-filter', 'v6 inet6') + term +
            GOOD_HEADER.replace('test-filter', 'v4') + term)
    rendered = str(ciscoasa.CiscoASA(
        policy.ParsePolicy(text, self.naming), EXP_INFO))
    self.assertIn('access-list v6 extended permit tcp any6 any6', rendered)
    self.assertIn('access-list v4 extended permit tcp any any', rendered)

  def test_default_address_family_unchanged(self):
    """Preserve the default IPv4 output with or without inet."""
    self.naming.GetNetAddr.return_value = [nacaddr.IP('192.0.2.0/24'),
                                            nacaddr.IP('2001:db8::/64')]
    text = GOOD_HEADER + """
term ipv4 {
  action:: accept
  protocol:: tcp
  source-address:: SOURCE
}
"""
    rendered = str(ciscoasa.CiscoASA(
        policy.ParsePolicy(text, self.naming), EXP_INFO))
    explicit = str(ciscoasa.CiscoASA(policy.ParsePolicy(
        text.replace('test-filter', 'test-filter inet'), self.naming),
        EXP_INFO))
    self.assertEqual(rendered, explicit)
    self.assertIn('permit tcp 192.0.2.0 255.255.255.0 any', rendered)
    self.assertNotIn('2001:db8', rendered)

  def test_invalid_address_family(self):
    """Reject unsupported or conflicting header options."""
    for option in ('inet7', 'inet inet6'):
      with self.subTest(option=option):
        text = GOOD_HEADER.replace('test-filter', 'test-filter ' + option)
        with self.assertRaises(ciscoasa.UnsupportedCiscoAccessListError):
          ciscoasa.CiscoASA(policy.ParsePolicy(text + GOOD_TERM_1,
                                              self.naming), EXP_INFO)


if __name__ == '__main__':
  absltest.main()
