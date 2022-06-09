# Copyright 2022 Google Inc. All Rights Reserved.
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

"""Unittest for juniper evo acl rendering module."""

from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
from capirca.lib import juniperevo
from capirca.lib import naming
from capirca.lib import policy


GOOD_HEADER_1 = """
header {
  comment:: "this is a test acl"
  target:: juniperevo test-filter inet6 ingress
}
"""
GOOD_HEADER_2 = """
header {
  comment:: "this is a test acl"
  target:: juniperevo test-filter inet6 ingress loopback
}
"""
GOOD_HEADER_3 = """
header {
  comment:: "this is a test acl"
  target:: juniperevo test-filter inet6 egress physical
}
"""
GOOD_HEADER_4 = """
header {
  comment:: "this is a test acl"
  target:: juniperevo test-filter inet6 egress loopback
}
"""
BAD_HEADER_1 = """
header {
  comment:: "this is a test acl"
  target:: juniperevo test-filter inet6
}
"""
GOOD_TERM_1 = """
term good-term-1 {
  protocol:: hopopt
  action:: deny
}
"""
GOOD_TERM_2 = """
term good-term-2 {
  protocol-except:: hopopt
  action:: accept
}
"""
GOOD_TERM_3 = """
term good-term-3 {
  protocol:: fragment
  action:: accept
}
"""
GOOD_TERM_4 = """
term good-term-4 {
  protocol-except:: fragment
  action:: accept
}
"""
GOOD_TERM_5 = """
term good-term-5 {
  protocol:: tcp
  action:: accept
}
"""
GOOD_TERM_6 = """
term good-term-6 {
  protocol-except:: tcp
  action:: accept
}
"""

SUPPORTED_TOKENS = frozenset([
    'action',
    'address',
    'comment',
    'counter',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'destination_prefix',
    'destination_prefix_except',
    'dscp_except',
    'dscp_match',
    'dscp_set',
    'encapsulate',
    'ether_type',
    'expiration',
    'filter_term',
    'flexible_match_range',
    'forwarding_class',
    'forwarding_class_except',
    'fragment_offset',
    'hop_limit',
    'icmp_code',
    'icmp_type',
    'stateless_reply',
    'logging',
    'loss_priority',
    'name',
    'next_ip',
    'option',
    'owner',
    'packet_length',
    'platform',
    'platform_exclude',
    'policer',
    'port',
    'port_mirror',
    'precedence',
    'protocol',
    'protocol_except',
    'qos',
    'restrict_address_family',
    'routing_instance',
    'source_address',
    'source_address_exclude',
    'source_port',
    'source_prefix',
    'source_prefix_except',
    'traffic_class_count',
    'traffic_type',
    'translated',
    'ttl',
    'verbatim'])

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny', 'reject', 'next', 'reject-with-tcp-rst'},
    'icmp_type': {
        'alternate-address',
        'certification-path-advertisement',
        'certification-path-solicitation',
        'conversion-error',
        'destination-unreachable',
        'echo-reply',
        'echo-request',
        'mobile-redirect',
        'home-agent-address-discovery-reply',
        'home-agent-address-discovery-request',
        'icmp-node-information-query',
        'icmp-node-information-response',
        'information-request',
        'inverse-neighbor-discovery-advertisement',
        'inverse-neighbor-discovery-solicitation',
        'mask-reply',
        'mask-request',
        'information-reply',
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
        'unreachable',
        'version-2-multicast-listener-report',
    },
    'option': {'established',
               'first-fragment',
               'inactive',
               'is-fragment',
               '.*',   # not actually a lex token!
               'sample',
               'tcp-established',
               'tcp-initial'}
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class JuniperEvoTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def testIPv6HopOptProtocolIngressPhysical(self):
    output = str(
        juniperevo.JuniperEvo(
            policy.ParsePolicy(
                GOOD_HEADER_1 + GOOD_TERM_1, self.naming),
            EXP_INFO))
    self.assertIn('next-header hop-by-hop;', output,
                  'missing or incorrect HOPOPT specification')
    self.assertNotIn('payload-protocol hop-by-hop;', output,
                     'missing or incorrect HOPOPT specification')
    self.assertNotIn('next-header 0;', output,
                     'missing or incorrect HOPOPT specification')
    self.assertNotIn('payload-protocol 0;', output,
                     'missing or incorrect HOPOPT specification')

  def testIPv6HopOptProtocolExceptIngressPhysical(self):
    output = str(
        juniperevo.JuniperEvo(
            policy.ParsePolicy(
                GOOD_HEADER_1 + GOOD_TERM_2, self.naming),
            EXP_INFO))
    self.assertIn('next-header-except hop-by-hop;', output,
                  'missing or incorrect HOPOPT specification')
    self.assertNotIn('payload-protocol-except hop-by-hop;', output,
                     'missing or incorrect HOPOPT specification')
    self.assertNotIn('next-header-except 0;', output,
                     'missing or incorrect HOPOPT specification')
    self.assertNotIn('payload-protocol-except 0;', output,
                     'missing or incorrect HOPOPT specification')

  def testIPv6FragmentProtocolIngressPhysical(self):
    output = str(
        juniperevo.JuniperEvo(
            policy.ParsePolicy(
                GOOD_HEADER_1 + GOOD_TERM_3, self.naming),
            EXP_INFO))
    self.assertIn('next-header fragment;', output,
                  'missing or incorrect IPv6-Frag specification')
    self.assertNotIn('payload-protocol fragment;', output,
                     'missing or incorrect IPv6-Frag specification')
    self.assertNotIn('next-header 44;', output,
                     'missing or incorrect IPv6-Frag specification')
    self.assertNotIn('payload-protocol 44;', output,
                     'missing or incorrect IPv6-Frag specification')

  def testIPv6FragmentProtocolExceptIngressPhysical(self):
    output = str(
        juniperevo.JuniperEvo(
            policy.ParsePolicy(
                GOOD_HEADER_1 + GOOD_TERM_4, self.naming),
            EXP_INFO))
    self.assertIn('next-header-except fragment;', output,
                  'missing or incorrect IPv6-Frag specification')
    self.assertNotIn('payload-protocol-except fragment;', output,
                     'missing or incorrect IPv6-Frag specification')
    self.assertNotIn('next-header-except 44;', output,
                     'missing or incorrect IPv6-Frag specification')
    self.assertNotIn('payload-protocol-except 44;', output,
                     'missing or incorrect IPv6-Frag specification')

  def testIPv6TcpProtocolIngressPhysical(self):
    output = str(
        juniperevo.JuniperEvo(
            policy.ParsePolicy(
                GOOD_HEADER_1 + GOOD_TERM_5, self.naming),
            EXP_INFO))
    self.assertIn('payload-protocol tcp;', output,
                  'missing or incorrect TCP specification')
    self.assertNotIn('next-header tcp;', output,
                     'missing or incorrect TCP specification')
    self.assertNotIn('payload-protocol 6;', output,
                     'missing or incorrect TCP specification')
    self.assertNotIn('next-header 6;', output,
                     'missing or incorrect TCP specification')

  def testIPv6TcpProtocolExceptIngressPhysical(self):
    output = str(
        juniperevo.JuniperEvo(
            policy.ParsePolicy(
                GOOD_HEADER_1 + GOOD_TERM_6, self.naming),
            EXP_INFO))
    self.assertIn('payload-protocol-except tcp;', output,
                  'missing or incorrect TCP specification')
    self.assertNotIn('next-header-except tcp;', output,
                     'missing or incorrect TCP specification')
    self.assertNotIn('payload-protocol-except 6;', output,
                     'missing or incorrect TCP specification')
    self.assertNotIn('next-header-except 6;', output,
                     'missing or incorrect TCP specification')

  @parameterized.named_parameters(
      ('IngressLoopback', GOOD_HEADER_2),
      ('EgressPhysical', GOOD_HEADER_3),
      ('EgressLoopback', GOOD_HEADER_4),
  )
  def testIPv6HopOptProtocol(self, header):
    output = str(
        juniperevo.JuniperEvo(
            policy.ParsePolicy(
                header + GOOD_TERM_1, self.naming),
            EXP_INFO))
    self.assertIn('payload-protocol 0;', output,
                  'missing or incorrect HOPOPT specification')
    self.assertNotIn('next-header 0;', output,
                     'missing or incorrect HOPOPT specification')
    self.assertNotIn('payload-protocol hop-by-hop;', output,
                     'missing or incorrect HOPOPT specification')
    self.assertNotIn('next-header hop-by-hop;', output,
                     'missing or incorrect HOPOPT specification')

  @parameterized.named_parameters(
      ('IngressLoopback', GOOD_HEADER_2),
      ('EgressPhysical', GOOD_HEADER_3),
      ('EgressLoopback', GOOD_HEADER_4),
  )
  def testIPv6HopOptProtocolExcept(self, header):
    output = str(
        juniperevo.JuniperEvo(
            policy.ParsePolicy(
                header + GOOD_TERM_2, self.naming),
            EXP_INFO))
    self.assertIn('payload-protocol-except 0;', output,
                  'missing or incorrect HOPOPT specifications')
    self.assertNotIn('next-header-except 0;', output,
                     'missing or incorrect HOPOPT specifications')
    self.assertNotIn('payload-protocol-except hop-by-hop;', output,
                     'missing or incorrect HOPOPT specifications')
    self.assertNotIn('next-header-except hop-by-hop;', output,
                     'missing or incorrect HOPOPT specifications')

  @parameterized.named_parameters(
      ('IngressLoopback', GOOD_HEADER_2),
      ('EgressPhysical', GOOD_HEADER_3),
      ('EgressLoopback', GOOD_HEADER_4),
  )
  def testIPv6FragmentProtocol(self, header):
    output = str(
        juniperevo.JuniperEvo(
            policy.ParsePolicy(
                header + GOOD_TERM_3, self.naming),
            EXP_INFO))
    self.assertIn('payload-protocol 44;', output,
                  'missing or incorrect IPv6-Frag specification')
    self.assertNotIn('next-header 44;', output,
                     'missing or incorrect IPv6-Frag specification')
    self.assertNotIn('payload-protocol fragment;', output,
                     'missing or incorrect IPv6-Frag specification')
    self.assertNotIn('next-header fragment;', output,
                     'missing or incorrect IPv6-Frag specification')

  @parameterized.named_parameters(
      ('IngressLoopback', GOOD_HEADER_2),
      ('EgressPhysical', GOOD_HEADER_3),
      ('EgressLoopback', GOOD_HEADER_4),
  )
  def testIPv6FragmentProtocolExcept(self, header):
    output = str(
        juniperevo.JuniperEvo(
            policy.ParsePolicy(
                header + GOOD_TERM_4, self.naming),
            EXP_INFO))
    self.assertIn('payload-protocol-except 44;', output,
                  'missing or incorrect IPv6-Frag specification')
    self.assertNotIn('next-header-except 44;', output,
                     'missing or incorrect IPv6-Frag specification')
    self.assertNotIn('payload-protocol-except fragment;', output,
                     'missing or incorrect IPv6-Frag specification')
    self.assertNotIn('next-header-except fragment;', output,
                     'missing or incorrect IPv6-Frag specification')

  @parameterized.named_parameters(
      ('IngressLoopback', GOOD_HEADER_2),
      ('EgressPhysical', GOOD_HEADER_3),
      ('EgressLoopback', GOOD_HEADER_4),
  )
  def testIPv6TcpProtocol(self, header):
    output = str(
        juniperevo.JuniperEvo(
            policy.ParsePolicy(
                header + GOOD_TERM_5, self.naming),
            EXP_INFO))
    self.assertIn('payload-protocol tcp;', output,
                  'missing or incorrect TCP specification')
    self.assertNotIn('next-header tcp;', output,
                     'missing or incorrect TCP specification')
    self.assertNotIn('payload-protocol 6;', output,
                     'missing or incorrect TCP specification')
    self.assertNotIn('next-header 6;', output,
                     'missing or incorrect TCP specification')

  @parameterized.named_parameters(
      ('IngressLoopback', GOOD_HEADER_2),
      ('EgressPhysical', GOOD_HEADER_3),
      ('EgressLoopback', GOOD_HEADER_4),
  )
  def testIPv6TcpProtocolExcept(self, header):
    output = str(
        juniperevo.JuniperEvo(
            policy.ParsePolicy(
                header + GOOD_TERM_6, self.naming),
            EXP_INFO))
    self.assertIn('payload-protocol-except tcp;', output,
                  'missing or incorrect TCP specification')
    self.assertNotIn('next-header-except tcp;', output,
                     'missing or incorrect TCP specification')
    self.assertNotIn('payload-protocol-except 6;', output,
                     'missing or incorrect TCP specification')
    self.assertNotIn('next-header-except 6;', output,
                     'missing or incorrect TCP specification')

  def testIPv6FilterWithNoDirection(self):
    evojcl = juniperevo.JuniperEvo(
        policy.ParsePolicy(BAD_HEADER_1 + GOOD_TERM_1, self.naming), EXP_INFO)
    self.assertRaises(juniperevo.FilterDirectionError, str, evojcl)

if __name__ == '__main__':
  absltest.main()
