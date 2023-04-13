# Copyright 2023 The Capirca Project Authors All Rights Reserved.
# Copyright 2023 VMware, Inc. SPDX-License-Identifier: Apache-2.0
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
"""UnitTest class for nsxt.py."""

import json
from absl.testing import absltest
from unittest import mock

from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import nsxt
from capirca.lib import policy

ICMPV6_TERM = """\
  term test-icmpv6 {
    protocol:: icmpv6
    icmp-type:: echo-request echo-reply
    action:: accept
  }
  """

UDP_POLICY = """\
  header {
    comment:: "Sample inet NSXT filter"
    target:: nsxt INET_FILTER_NAME inet
  }

  term allow-ntp-request {
    comment::"Allow ntp request"
    source-address:: NTP_SERVERS
    source-port:: NTP
    destination-address:: INTERNAL
    destination-port:: NTP
    protocol:: udp
    action:: accept
  }
  """

UDP_NSXT_POLICY = {
  'rules': [{
    'action': 'ALLOW',
    'resource_type': 'Rule',
    'display_name': 'allow-ntp-request',
    'source_groups': ['10.0.0.1/32', '10.0.0.2/32'],
    'destination_groups': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
    'services': ['ANY'],
    'profiles': ['ANY'],
    'scope': ['ANY'],
    'logged': False,
    'notes': 'Allow ntp request',
    'direction': 'IN_OUT',
    'ip_protocol': 'IPV4_IPV6',
    'service_entries': [{
      'l4_protocol': 'UDP',
      'resource_type': 'L4PortSetServiceEntry',
      'source_ports': ['123-123'],
      'destination_ports': ['123-123']
    }]
  }],
  'resource_type': 'SecurityPolicy',
  'display_name': 'INET_FILTER_NAME',
  'category': 'Application',
  'is_default': 'false',
  'id': 'INET_FILTER_NAME',
  'scope': ['ANY']
}

UDP_RULE = {
  "action": "ALLOW",
  "resource_type": "Rule",
  "display_name": "allow-ntp-request",
  "source_groups": ["10.0.0.1/32", "10.0.0.2/32"],
  "destination_groups": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "services": ["ANY"],
  "profiles": ["ANY"],
  "scope": ["ANY"],
  "logged": False,
  "notes": "Allow ntp request",
  "direction": "IN_OUT",
  "ip_protocol": "IPV4_IPV6",
  "service_entries": [{
    "l4_protocol": "UDP",
    "resource_type": "L4PortSetServiceEntry",
    "source_ports": ["123-123"],
    "destination_ports": ["123-123"]
  }]
}

ICMPV6_POLICY = """\
  header {
    comment:: "Sample ICMPv6 NSXT filter"
    target:: nsxt INET6_FILTER_NAME inet6
  }

  term test-icmpv6 {
    #destination-address:: WEB_SERVERS
    protocol:: icmpv6
    icmp-type:: echo-request echo-reply
    action:: accept
  }
  """

ICMPV6_RULE = {
  'action': 'ALLOW',
  'resource_type': 'Rule',
  'display_name': 'test-icmpv6',
  'source_groups': ['ANY'],
  'destination_groups': ['ANY'],
  'services': ['ANY'],
  'profiles': ['ANY'],
  'scope': ['ANY'],
  'logged': False,
  'notes': '',
  'direction': 'IN_OUT',
  'ip_protocol': 'IPV4_IPV6',
  'service_entries': [{
    'protocol': 'ICMPv6',
    'resource_type': 'ICMPTypeServiceEntry',
    'icmp_type': 128
  }]
}

UDP_AND_TCP_POLICY = """\
  header {
    comment:: "Sample mixed NSXT filter"
    target:: nsxt MIXED_FILTER_NAME mixed
  }

  term accept-to-honestdns {
    comment:: "Allow name resolution using honestdns."
    destination-address:: GOOGLE_DNS
    destination-port:: DNS
    protocol:: udp
    action:: accept
  }

  term permit-mail-services {
    destination-address:: MAIL_SERVERS
    protocol:: tcp
    destination-port:: MAIL_SERVICES
    action:: accept
  }
  """

UDP_AND_TCP_NSXT_POLICY = {
  'rules': [{
    'action': 'ALLOW',
    'resource_type': 'Rule',
    'display_name': 'accept-to-honestdns',
    'source_groups': ['ANY'],
    'destination_groups': [
      '8.8.4.4/32',
      '8.8.8.8/32',
      '2001:4860:4860::8844/128',
      '2001:4860:4860::8888/128'
    ],
    'services': ['ANY'],
    'profiles': ['ANY'],
    'scope': ['ANY'],
    'logged': False,
    'notes': 'Allow name resolution using honestdns.',
    'direction': 'IN_OUT',
    'ip_protocol': 'IPV4_IPV6',
    'service_entries': [{
      'l4_protocol': 'UDP',
      'resource_type': 'L4PortSetServiceEntry',
      'destination_ports': ['53-53']
    }]
  },
    {
      'action': 'ALLOW',
      'resource_type': 'Rule',
      'display_name': 'permit-mail-services',
      'source_groups': ['ANY'],
      'destination_groups': ['2001:4860:4860::8845'],
      'services': ['ANY'],
      'profiles': ['ANY'],
      'scope': ['ANY'],
      'logged': False,
      'notes': '',
      'direction': 'IN_OUT',
      'ip_protocol': 'IPV4_IPV6',
      'service_entries': [{
        'l4_protocol': 'TCP',
        'resource_type': 'L4PortSetServiceEntry',
        'destination_ports': ['53-53']
      }]
    }],
  'resource_type': 'SecurityPolicy',
  'display_name': 'MIXED_FILTER_NAME',
  'category': 'Application',
  'is_default': 'false',
  'id': 'MIXED_FILTER_NAME',
  'scope': ['ANY']
}

ICMP_POLICY_WITH_SECURITY_GROUP = """\
  header {
    comment:: "Sample filter with Security Group"
    target:: nsxt POLICY_WITH_SECURITY_GROUP_NAME inet 1010 securitygroup \
    securitygroup-Id
  }

  term accept-icmp {
    protocol:: icmp
    action:: accept
  }
  """

ICMP_NSXT_POLICY_WITH_SECURITY_GROUP = {
  'rules': [{
    'action': 'ALLOW',
    'resource_type': 'Rule',
    'display_name': 'accept-icmp',
    'source_groups': ['ANY'],
    'destination_groups': ['ANY'],
    'services': ['ANY'],
    'profiles': ['ANY'],
    'scope': ['ANY'],
    'logged': False,
    'notes': '',
    'direction': 'IN_OUT',
    'ip_protocol': 'IPV4_IPV6',
    'service_entries': [{
      'protocol': 'ICMPv4',
      'resource_type': 'ICMPTypeServiceEntry'
    }]
  }],
  'resource_type': 'SecurityPolicy',
  'display_name': 'POLICY_WITH_SECURITY_GROUP_NAME',
  'category': 'Application',
  'is_default': 'false',
  'id': '1010',
  'scope': ['/infra/domains/default/groups/securitygroup-Id']
}

BAD_HEADER = """\
  header {
    comment:: "Sample NSXT filter3"
    target:: nsxt BAD_HEADER_NAME inet 1011 securitygroup
  }
  """

BAD_HEADER_1 = """\
  header {
    comment:: "Sample NSXT filter4"
    target:: nsxt BAD_HEADER_1_NAME 1012
  }
  """

BAD_HEADER_2 = """\
  header {
    comment:: "Sample NSXT filter5"
    target:: nsxt BAD_HEADER_2_NAME inet securitygroup
  }
  """

BAD_HEADER_3 = """\
  header {
    comment:: "Sample NSXT filter6"
    target:: nsxt BAD_HEADER_3_NAME
  }
  """

BAD_HEADER_4 = """\
  header {
    comment:: "Sample NSXT filter7"
    target:: nsxt BAD_HEADER_3_NAME inet 1234 securitygroup securitygroup \
    securitygroupId1
  }
  """

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class TermTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def test_udp_term(self):
    """Test __init__ and __str__ for udp term defining destination and source addresses and ports"""
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('10.0.0.1'), nacaddr.IP('10.0.0.2')],
        [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('172.16.0.0/12'),
         nacaddr.IP('192.168.0.0/16')]]
    self.naming.GetServiceByProto.return_value = ['123']

    policies = policy.ParsePolicy(UDP_POLICY, self.naming, False)
    af = 4
    pol = policies.filters[0]
    terms = pol[1]
    term = terms[0]

    nsxt_term = nsxt.Term(term, af)
    rule_str = str(nsxt_term)
    rule = json.loads(rule_str)

    self.assertEqual(nsxt_term.af, af)
    self.assertEqual(rule, UDP_RULE)

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('NTP_SERVERS'), mock.call('INTERNAL')])
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('NTP', 'udp')] * 2)

  def test_icmpv6_term(self):
    """Test __init__ and __str__ for term inet6"""
    policies = policy.ParsePolicy(ICMPV6_POLICY, self.naming, False)
    af = 6
    filter_type = 'inet6'
    pol = policies.filters[0]
    terms = pol[1]
    term = terms[0]

    nsxt_term = nsxt.Term(term, filter_type, None, af)
    rule_str = str(nsxt_term)
    rule = json.loads(rule_str)

    self.assertEqual(rule, ICMPV6_RULE)

  def test_udp_policy(self):
    """Test for Nsxt.test_TranslatePolicy."""
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP('10.0.0.1'), nacaddr.IP('10.0.0.2')],
        [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('172.16.0.0/12'),
         nacaddr.IP('192.168.0.0/16')]]
    self.naming.GetServiceByProto.return_value = ['123']

    pol = policy.ParsePolicy(UDP_POLICY, self.naming, False)
    nsxt_policy = nsxt.Nsxt(pol, EXP_INFO)
    api_policy = json.loads(str(nsxt_policy))

    self.assertEqual(api_policy, UDP_NSXT_POLICY)
    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('NTP_SERVERS'), mock.call('INTERNAL')])
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('NTP', 'udp')] * 2)

  def test_udp_and_tcp_policy(self):
    """Test for Nsxt._str_."""
    self.naming.GetNetAddr.side_effect = [
      [
        nacaddr.IP('8.8.4.4'),
        nacaddr.IP('8.8.8.8'),
        nacaddr.IP('2001:4860:4860::8844'),
        nacaddr.IP('2001:4860:4860::8888')
      ],
      nacaddr.IP('2001:4860:4860::8845')]
    self.naming.GetServiceByProto.return_value = ['53']

    pol = policy.ParsePolicy(UDP_AND_TCP_POLICY, self.naming, False)
    nsxt_policy = nsxt.Nsxt(pol, EXP_INFO)
    api_policy = json.loads(str(nsxt_policy))

    self.assertEqual(api_policy, UDP_AND_TCP_NSXT_POLICY)

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('GOOGLE_DNS'), mock.call('MAIL_SERVERS')])
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('DNS', 'udp'), mock.call('MAIL_SERVICES', 'tcp')])

  def test_icmp_policy_with_security_group(self):
    """Test for Nsxt._str_ with security group in scope"""
    pol = policy.ParsePolicy(ICMP_POLICY_WITH_SECURITY_GROUP, self.naming, False)
    nsxt_policy = nsxt.Nsxt(pol, EXP_INFO)
    api_policy = json.loads(str(nsxt_policy))

    self.assertEqual(api_policy, ICMP_NSXT_POLICY_WITH_SECURITY_GROUP)

  def test_bad_header_case_0(self):
    pol = policy.ParsePolicy(BAD_HEADER + ICMPV6_TERM, self.naming, False)
    self.assertRaises(nsxt.UnsupportedNsxtAccessListError,
                      nsxt.Nsxt, pol, EXP_INFO)

  def test_bad_header_case_1(self):
    pol = policy.ParsePolicy(BAD_HEADER_1 + ICMPV6_TERM, self.naming, False)
    self.assertRaises(nsxt.UnsupportedNsxtAccessListError,
                      nsxt.Nsxt, pol, EXP_INFO)

  def test_bad_header_case_2(self):
    pol = policy.ParsePolicy(BAD_HEADER_2 + ICMPV6_TERM, self.naming, False)
    self.assertRaises(nsxt.UnsupportedNsxtAccessListError,
                      nsxt.Nsxt, pol, EXP_INFO)

  def test_bad_header_case_3(self):
    pol = policy.ParsePolicy(BAD_HEADER_3 + ICMPV6_TERM, self.naming, False)
    self.assertRaises(nsxt.UnsupportedNsxtAccessListError,
                      nsxt.Nsxt, pol, EXP_INFO)

  def test_bad_header_case_4(self):
    pol = policy.ParsePolicy(BAD_HEADER_4 + ICMPV6_TERM, self.naming, False)
    self.assertRaises(nsxt.UnsupportedNsxtAccessListError,
                      nsxt.Nsxt, pol, EXP_INFO)


if __name__ == '__main__':
  absltest.main()
