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

import copy
import json
from typing import Any, Literal, Tuple, Union
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import nsxt
from capirca.lib import policy


ICMPV6_TERM = """\
  term test-icmpv6 {
    protocol:: icmpv6
    icmp-type:: echo-request echo-reply router-solicit
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
        'ip_protocol': 'IPV4',  # inet, not inet6 or mixed
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
    'scope': ['ANY'],
    'description': '$Id:$ $Date:$ $Revision:$ :: Sample inet NSXT filter',
}

UDP_RULE = {
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
    'ip_protocol': 'IPV4',
    'service_entries': [{
        'l4_protocol': 'UDP',
        'resource_type': 'L4PortSetServiceEntry',
        'source_ports': ['123-123'],
        'destination_ports': ['123-123']
    }]
}

ICMPV6_POLICY = """\
  header {
    comment:: "Sample ICMPv6 NSXT filter"
    target:: nsxt INET6_FILTER_NAME mixed
  }

  term test-icmpv6 {
    protocol:: icmpv6
    icmp-type:: echo-request echo-reply router-solicit
    action:: accept
  }
  """


ICMPV6_INET6_POLICY = """\
  header {
    comment:: "Sample ICMPv6 NSXT filter"
    target:: nsxt INET6_FILTER_NAME inet6
  }

  term test-icmpv6 {
    protocol:: icmpv6
    icmp-type:: echo-request echo-reply router-solicit
    action:: accept
  }
  """


# Rule used in the ICMPV6_NSXT_POLICY.
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
    'service_entries': [
        {
            'protocol': 'ICMPv6',
            'resource_type': 'ICMPTypeServiceEntry',
            'icmp_type': 128,
        },
        {
            'protocol': 'ICMPv6',
            'resource_type': 'ICMPTypeServiceEntry',
            'icmp_type': 129,
        },
        {
            'protocol': 'ICMPv6',
            'resource_type': 'ICMPTypeServiceEntry',
            'icmp_type': 133,
        }],
}


# Rule used in the ICMPV6_NSXT_POLICY.
ICMPV6_INET6_RULE = {
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
    'ip_protocol': 'IPV6',
    'service_entries': [
        {
            'protocol': 'ICMPv6',
            'resource_type': 'ICMPTypeServiceEntry',
            'icmp_type': 128,
        },
        {
            'protocol': 'ICMPv6',
            'resource_type': 'ICMPTypeServiceEntry',
            'icmp_type': 129,
        },
        {
            'protocol': 'ICMPv6',
            'resource_type': 'ICMPTypeServiceEntry',
            'icmp_type': 133,
        }],
}

ICMPV6_NSXT_POLICY = {
    'rules': [
        ICMPV6_RULE,
    ],
    'resource_type': 'SecurityPolicy',
    'display_name': 'INET6_FILTER_NAME',
    'category': 'Application',
    'is_default': 'false',
    'id': 'INET6_FILTER_NAME',
    'scope': ['ANY'],
    'description': '$Id:$ $Date:$ $Revision:$ :: Sample ICMPv6 NSXT filter',
}

# Objects in the output JSON generated from ICMPV6_NSXT_POLICY.
ICMPV6_INET6_NSXT_POLICY = {
    'rules': [
        ICMPV6_INET6_RULE,
    ],
    'resource_type': 'SecurityPolicy',
    'display_name': 'INET6_FILTER_NAME',
    'category': 'Application',
    'is_default': 'false',
    'id': 'INET6_FILTER_NAME',
    'scope': ['ANY'],
    'description': '$Id:$ $Date:$ $Revision:$ :: Sample ICMPv6 NSXT filter',
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

# Objects in the output JSON generated from UDP_AND_TCP_POLICY.
UDP_AND_TCP_NSXT_POLICY = {
    'rules': [
        {
            'action': 'ALLOW',
            'resource_type': 'Rule',
            'display_name': 'accept-to-honestdns',
            'source_groups': ['ANY'],
            'destination_groups': [
                '8.8.4.4/32',
                '8.8.8.8/32',
                '2001:4860:4860::8844/128',
                '2001:4860:4860::8888/128',
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
                'destination_ports': ['53-53'],
            }],
        },
        {
            'action': 'ALLOW',
            'resource_type': 'Rule',
            'display_name': 'permit-mail-services',
            'source_groups': ['ANY'],
            'destination_groups': ['2001:4860:4860::8845/128'],
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
                'destination_ports': ['53-53'],
            }],
        },
    ],
    'resource_type': 'SecurityPolicy',
    'display_name': 'MIXED_FILTER_NAME',
    'category': 'Application',
    'is_default': 'false',
    'id': 'MIXED_FILTER_NAME',
    'scope': ['ANY'],
    'description': '$Id:$ $Date:$ $Revision:$ :: Sample mixed NSXT filter',
}

ICMP_POLICY_WITH_SECURITY_GROUP = """\
  header {
    comment:: "Sample filter with Security Group"
    target:: nsxt POLICY_WITH_SECURITY_GROUP_NAME mixed 1010 securitygroup \
    securitygroup-Id
  }

  term accept-icmp {
    protocol:: icmp
    action:: accept
  }

  term accept-icmpv6 {
    protocol:: icmpv6
    action:: accept
  }
  """

# Objects appearing in the JSON generated from ICMP_POLICY_WITH_SECURITY_GROUP.
ICMP_NSXT_POLICY_WITH_SECURITY_GROUP = {
    'rules': [
        {
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
                'resource_type': 'ICMPTypeServiceEntry',
            }],
        },
        {
            'action': 'ALLOW',
            'resource_type': 'Rule',
            'display_name': 'accept-icmpv6',
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
            }],
        },
    ],
    'resource_type': 'SecurityPolicy',
    'display_name': 'POLICY_WITH_SECURITY_GROUP_NAME',
    'category': 'Application',
    'is_default': 'false',
    'id': '1010',
    'scope': ['/infra/domains/default/groups/securitygroup-Id'],
    'description': ('$Id:$ $Date:$ $Revision:$'
                    ' :: Sample filter with Security Group'),
}


ICMP_POLICY_WITH_EXPIRY = """\
  header {
    comment:: "Sample filter with expiration"
    target:: nsxt POLICY_WITH_EXPIRY mixed 1010 securitygroup \
    securitygroup-Id
  }

  term accept-icmp {
    protocol:: icmp
    source-address:: MAIL_SERVERS
    action:: accept
  }

  term accept-icmpv6 {
    protocol:: icmpv6
    source-address:: MAIL_SERVERS
    action:: accept
  }

  term accept-icmp-expired {
    protocol:: icmp
    source-address:: NTP_SERVERS
    action:: accept
    expiration:: 2001-01-01
  }

  term accept-icmpv6-expired {
    protocol:: icmpv6
    source-address:: NTP_SERVERS
    action:: accept
    expiration:: 2001-01-01
  }
  """


# Objects appearing in the JSON generated from ICMP_POLICY_WITH_EXPIRY.
ICMP_NSXT_POLICY_WITH_EXPIRY = {
    'rules': [
        {
            'action': 'ALLOW',
            'resource_type': 'Rule',
            'display_name': 'accept-icmp',
            'source_groups': [
                '200.1.1.4/32',
                '200.1.1.5/32',
                '2001:4860:4860::8845/128'
            ],
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
                'resource_type': 'ICMPTypeServiceEntry',
            }],
        },
        {
            'action': 'ALLOW',
            'resource_type': 'Rule',
            'display_name': 'accept-icmpv6',
            'source_groups': [
                '200.1.1.4/32',
                '200.1.1.5/32',
                '2001:4860:4860::8845/128'
            ],
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
            }],
        },
        # Note how 'accept-icmp-expired' and 'accept-icmpv6-expired' do not
        # appear in the output.
    ],
    'resource_type': 'SecurityPolicy',
    'display_name': 'POLICY_WITH_EXPIRY',
    'category': 'Application',
    'is_default': 'false',
    'id': '1010',
    'scope': ['/infra/domains/default/groups/securitygroup-Id'],
    'description': '$Id:$ $Date:$ $Revision:$ :: Sample filter with expiration',
}


ICMP_POLICY_WITH_EXCLUSION = """\
  header {
    comment:: "Sample filter with exclusion"
    target:: nsxt POLICY_WITH_EXCLUSION mixed 1010 securitygroup \
    securitygroup-Id
  }

  term src-exclude-from-any {
    protocol:: icmp
    source-exclude:: PUBLIC_NAT
    action:: accept
  }

  term src-exclude-from-corporate {
    protocol:: icmp
    source-address:: CORPORATE
    source-exclude:: PUBLIC_NAT
    action:: accept
  }

  term dst-exclude-from-any {
    protocol:: icmp
    destination-exclude:: PUBLIC_NAT
    action:: accept
  }

  term dst-exclude-from-corporate {
    protocol:: icmp
    destination-address:: CORPORATE
    destination-exclude:: PUBLIC_NAT
    action:: accept
  }
  """


ICMP_NSXT_POLICY_WITH_EXCLUSION = {
    'rules': [
        {
            # This test covers the (potentially surprising) behavior that was
            # present in NSX-V plugin as well: if source-address is not
            # specified, then source-exclude will be ignored as well.
            'action': 'ALLOW',
            'resource_type': 'Rule',
            'display_name': 'src-exclude-from-any',
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
                'resource_type': 'ICMPTypeServiceEntry',
            }],
        },
        {
            'action': 'ALLOW',
            'resource_type': 'Rule',
            'display_name': 'src-exclude-from-corporate',
            'source_groups': [
                '200.1.1.0/31',
                '200.1.1.2/32',
                '200.1.1.4/30',
                '200.1.1.8/29',
                '200.1.1.16/28',
                '200.1.1.32/27',
                '200.1.1.64/26',
                '200.1.1.128/25',
            ],
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
                'resource_type': 'ICMPTypeServiceEntry',
            }],
        },
        {
            # This test covers the (potentially surprising) behavior that was
            # present in NSX-V plugin as well: if destination-address is not
            # specified, then destination-exclude will be ignored as well.
            'action': 'ALLOW',
            'resource_type': 'Rule',
            'display_name': 'dst-exclude-from-any',
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
                'resource_type': 'ICMPTypeServiceEntry',
            }],
        },
        {
            'action': 'ALLOW',
            'resource_type': 'Rule',
            'display_name': 'dst-exclude-from-corporate',
            'source_groups': ['ANY'],
            'destination_groups': [
                '200.1.1.0/31',
                '200.1.1.2/32',
                '200.1.1.4/30',
                '200.1.1.8/29',
                '200.1.1.16/28',
                '200.1.1.32/27',
                '200.1.1.64/26',
                '200.1.1.128/25',
            ],
            'services': ['ANY'],
            'profiles': ['ANY'],
            'scope': ['ANY'],
            'logged': False,
            'notes': '',
            'direction': 'IN_OUT',
            'ip_protocol': 'IPV4_IPV6',
            'service_entries': [{
                'protocol': 'ICMPv4',
                'resource_type': 'ICMPTypeServiceEntry',
            }],
        },
    ],
    'resource_type': 'SecurityPolicy',
    'display_name': 'POLICY_WITH_EXCLUSION',
    'category': 'Application',
    'is_default': 'false',
    'id': '1010',
    'scope': ['/infra/domains/default/groups/securitygroup-Id'],
    'description': '$Id:$ $Date:$ $Revision:$ :: Sample filter with exclusion',
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


class TestTrafficKindGrid(parameterized.TestCase):
  """Verify whether all expected policy types get generated.

  `mixed` policies are meant to correctly generate rules for both v4 and v6
  addresses, if provided.
  """
  _TRAFFIC_KIND = Union['mixed', 'v4', 'v6', 'any']
  _ADDRESSES = Union['GOOGLE_DNS', 'INTERNAL_V4', 'INTERNAL_V6']

  # Which address set should be put into the policy, based on the type of policy
  # we're testing?
  KIND_TO_ADDRESS: dict[_TRAFFIC_KIND, _ADDRESSES] = {
      'mixed': 'GOOGLE_DNS',
      'v4': 'INTERNAL_V4',
      'v6': 'INTERNAL_V6'}

  # Which expanded address group (e.g. netblocks) is expected, based on the type
  # of policy we're testing?
  KIND_TO_ADDRESS_GROUPS: dict[
      _TRAFFIC_KIND, Union[nacaddr.IPv4, nacaddr.IPv6, Literal['ANY']]] = {
          # 'GOOGLE_DNS'
          'mixed': [nacaddr.IP('8.8.4.4/32'), nacaddr.IP('8.8.8.8/32'),
                    nacaddr.IP('2001:4860:4860::8844/128'),
                    nacaddr.IP('2001:4860:4860::8888/128')],
          # 'INTERNAL_V4'
          'v4': [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('172.16.0.0/12'),
                 nacaddr.IP('192.168.0.0/16')],
          # 'INTERNAL_V6'
          'v6': [nacaddr.IP('2001:4860:8000::/33')],
          'any': ['ANY']}

  class InvalidTestError(Exception):
    pass

  def setUp(self):
    super().setUp()

    defs = naming.Naming(None)
    servicedata = copy.deepcopy(SERVICES_SVC)
    networkdata = copy.deepcopy(NETWORK_NET)

    defs.ParseServiceList(servicedata)
    defs.ParseNetworkList(networkdata)

    self._defs = defs

  def make_policy(self,
                  frm: _TRAFFIC_KIND,
                  to: _TRAFFIC_KIND) -> str:
    """Generate a Capirca header+term based on srcand dst traffic kind.

    Args:
      frm: which address family is meant to be the source of the traffic.
      to: which address family is meant to be the recipient of the traffic.

    Returns:
      a Capirca policy including a header and a term.

    Raises:
      InvalidTestError: if one of the tests is actually bad.
    """
    kind_to_address = TestTrafficKindGrid.KIND_TO_ADDRESS

    pol = [
        'header {',
        f'  comment:: "Sample policy, testing from {frm} to {to}"',
        f'  target:: nsxt POLICY_{frm.upper()}_TO_{to.upper()} mixed',
        '}',
    ]

    pol.append(f'term {frm}_to_{to} ' + '{')
    pol.append('  action:: accept')
    if frm in kind_to_address:
      pol.append(f'  source-address:: {kind_to_address[frm]}')
    elif frm == 'any':
      pass
    else:
      raise TestTrafficKindGrid.InvalidTestError('invalid test')

    if to in kind_to_address:
      pol.append(f'  destination-address:: {kind_to_address[to]}')
    elif to == 'any':
      pass
    else:
      raise TestTrafficKindGrid.InvalidTestError('invalid test')

    pol.append('}')

    return '\n'.join(pol)

  def test_generator_works(self):
    """Validate that our test's policy generator works correctly.

    Minimal check just to see that the policies fed into Capirca are sane.
    Useful because this is implemented as a parameterized test, and even if not
    all combinations are covered, this is still nice.
    """
    self.assertEqual(self.make_policy('mixed', 'v6'), '\n'.join([
        'header {',
        '  comment:: "Sample policy, testing from mixed to v6"',
        '  target:: nsxt POLICY_MIXED_TO_V6 mixed',
        '}',
        'term mixed_to_v6 {',
        '  action:: accept',
        '  source-address:: GOOGLE_DNS',
        '  destination-address:: INTERNAL_V6',
        '}']))

  def get_source_dest_addresses(self, nsxt_json: dict[str, Any]) -> (
      Tuple[list[str], list[str]]):
    rules: list[dict[str, Any]] = nsxt_json['rules']
    src: list[str] = []
    dst: list[str] = []

    for rule in rules:
      src.extend(i for i in rule['source_groups'])
      dst.extend(i for i in rule['destination_groups'])

    return [str(s) for s in src], [str(d) for d in dst]

  def testV4OnlyAppears(self):
    """Spot-check a variation without depending on the complex grid code."""
    policy_text = self.make_policy('v4', 'mixed')

    pol = (
        policy.ParsePolicy(policy_text, self._defs, False))
    nsxt_policy = nsxt.Nsxt(pol, EXP_INFO)
    api_policy = json.loads(str(nsxt_policy))

    rules = api_policy['rules']

    self.assertLen(rules, 1)
    self.assertEqual(rules[0]['source_groups'],
                     ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])
    self.assertEqual(rules[0]['destination_groups'],
                     ['8.8.4.4/32', '8.8.8.8/32'])

  def testV4OnlyAppearsWithAny(self):
    """Spot-check a variation without depending on the complex grid code."""
    policy_text = self.make_policy('v4', 'any')

    pol = (
        policy.ParsePolicy(policy_text, self._defs, False))
    nsxt_policy = nsxt.Nsxt(pol, EXP_INFO)
    api_policy = json.loads(str(nsxt_policy))

    rules = api_policy['rules']

    self.assertLen(rules, 1)
    self.assertEqual(rules[0]['source_groups'],
                     ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])
    self.assertEqual(rules[0]['destination_groups'],
                     ['ANY'])

  @parameterized.product(
      frm=['v4', 'v6', 'mixed', 'any'],
      to=['v4', 'v6', 'mixed', 'any'],
  )
  def testCase(self, frm, to):
    policy_text = self.make_policy(frm, to)

    pol = (
        policy.ParsePolicy(policy_text, self._defs, False))
    nsxt_policy = nsxt.Nsxt(pol, EXP_INFO)
    api_policy = json.loads(str(nsxt_policy))

    got_src, got_dst = self.get_source_dest_addresses(api_policy)

    kind_to_group = TestTrafficKindGrid.KIND_TO_ADDRESS_GROUPS
    want_src, want_dst = kind_to_group[frm], kind_to_group[to]

    def is_wanted_type(a: TestTrafficKindGrid._TRAFFIC_KIND,
                       b: TestTrafficKindGrid._TRAFFIC_KIND,
                       grp: Any) -> bool:
      if a == 'v4' and b == 'v6' or a == 'v6' and b == 'v4':
        return False

      if a == 'mixed':
        if b == 'v4' and (not isinstance(grp, nacaddr.IPv4) or grp == 'ANY'):
          return False
        if b == 'v6' and (not isinstance(grp, nacaddr.IPv6) or grp == 'ANY'):
          return False

      if b == 'mixed':
        if a == 'v4' and (not isinstance(grp, nacaddr.IPv4) or grp == 'ANY'):
          return False
        if a == 'v6' and (not isinstance(grp, nacaddr.IPv6) or grp == 'ANY'):
          return False

      return True

    want_src = [str(i) for i in want_src if is_wanted_type(frm, to, i)]
    want_dst = [str(i) for i in want_dst if is_wanted_type(frm, to, i)]

    self.assertSetEqual(set(want_src), set(got_src),
                        f'Source addresses differ: got {str(got_src)},'
                        f' want {str(want_src)}.')
    self.assertSetEqual(set(want_dst), set(got_dst),
                        f'Destination addresses differ: got {str(got_dst)},'
                        f' want {str(want_dst)}.')


# Some tests may use non-mocked naming.Naming definitions. These define the
# constants for use in this. Taken from def/NETWORK.net and def/SERVICES.svc.
#
# One entry per line, as this is what the parsing code expects.
NETWORK_NET = (
    'GOOGLE_PUBLIC_DNS_ANYCAST = 8.8.4.4/32               # IPv4 Anycast',
    '                            8.8.8.8/32               # IPv4 Anycast',
    '                            2001:4860:4860::8844/128 # IPv6 Anycast',
    '                            2001:4860:4860::8888/128 # IPv6 Anycast',
    'GOOGLE_DNS = GOOGLE_PUBLIC_DNS_ANYCAST',

    'MAIL_SERVERS = 200.1.1.4/32             # Example mail server 1',
    '               200.1.1.5/32             # Example mail server 2',
    '               2001:4860:4860::8845/128 # Example mail server 3',

    'NTP_SERVERS = 10.0.0.1/32   # Example NTP server',
    '              10.0.0.2/32   # Example NTP server',

    'CORPORATE = 200.1.1.0/24    # Example company netblock',
    'PUBLIC_NAT = 200.1.1.3/32   # Example company NAT address',

    # In NSX-V tests, "INTERNAL".
    'INTERNAL_V4 = 10.0.0.0/8    # Used in tests for',
    '              172.16.0.0/12 # {v4,v6,mixed,any}_to_{v4,v6,mixed,any}.',
    '              192.168.0.0/16',

    # In NSX-V tests, "SOME_HOST".
    'INTERNAL_V6 = 2001:4860:8000::/33  # Also used in same tests',
)

SERVICES_SVC = (
    'SMTP = 25/tcp',
    'ESMTP = 587/tcp',
    'SMTP_SSL = 465/tcp',
    'POP_SSL = 995/tcp',
    'MAIL_SERVICES = SMTP',
    '                ESMTP',
    '                SMTP_SSL',
    '                POP_SSL',
)


# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class TermTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def test_udp_term(self):
    """Test __init__ and __str__.

    test for udp term defining dst and src addrs and ports.
    """

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

    nsxt_term = nsxt.Term(term, 'inet', af)
    rule_str = str(nsxt_term)
    rule = json.loads(rule_str)

    self.assertEqual(nsxt_term.af, af)
    self.assertEqual(rule, UDP_RULE)

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('NTP_SERVERS'), mock.call('INTERNAL')])
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('NTP', 'udp')] * 2)

  def test_icmpv6_term(self):
    """Test rendering of an icmpv6 term used in a mixed IPv4+6 policy.

    This test parses a policy with a header and a term. The header and a list
    of terms are found in policies.filters[0]. Header is ignored and has no
    bearing on the outcome of the test; only the terms are extracted.
    """
    policies = policy.ParsePolicy(ICMPV6_POLICY, self.naming, False)
    af = 6
    pol = policies.filters[0]
    _, terms = pol
    term = terms[0]

    nsxt_term = nsxt.Term(term, 'mixed', af)
    rule_str = str(nsxt_term)
    rule = json.loads(rule_str)

    self.assertEqual(rule, ICMPV6_RULE)

  def test_icmpv6_policy(self):
    """Test rendering of an icmpv6 term used in a mixed IPv4+6 policy.

    This test parses a policy with a header and a term. The header and a list
    of terms are found in policies.filters[0]. Since the entire policy is
    rendered, there might be an expectation that both terms are rendered --
    except we are asking for icmpv6 specifically, hence we expect only one
    term to be created and thus rendered.
    """
    policies = policy.ParsePolicy(ICMPV6_POLICY, self.naming, False)

    nsxt_policy = nsxt.Nsxt(policies, EXP_INFO)
    got_str = str(nsxt_policy)
    got = json.loads(got_str)
    want = ICMPV6_NSXT_POLICY

    self.assertEqual(got, want)

  def test_icmpv6_policy_inet6(self):
    """Test rendering of an icmpv6 term used in an inet6 policy.

    This test parses a policy with a header and a term. The header and a list
    of terms are found in policies.filters[0]. Since the entire policy is
    rendered, there might be an expectation that both terms are rendered --
    except we are asking for icmpv6 specifically, hence we expect only one
    term to be created and thus rendered.
    """
    policies = policy.ParsePolicy(ICMPV6_INET6_POLICY, self.naming, False)

    nsxt_policy = nsxt.Nsxt(policies, EXP_INFO)
    got_str = str(nsxt_policy)
    got = json.loads(got_str)
    want = ICMPV6_INET6_NSXT_POLICY

    self.assertEqual(got, want)

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

    self.assertEqual(json.dumps(api_policy, sort_keys=True, indent=2),
                     json.dumps(UDP_NSXT_POLICY,
                                sort_keys=True,
                                indent=2))
    self.assertEqual(api_policy, UDP_NSXT_POLICY)

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('NTP_SERVERS'), mock.call('INTERNAL')]
    )
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('NTP', 'udp')] * 2
    )

  def test_udp_and_tcp_policy(self):
    """Test for Nsxt._str_."""
    self.naming.GetNetAddr.side_effect = [
        [
            nacaddr.IP('8.8.4.4'),
            nacaddr.IP('8.8.8.8'),
            nacaddr.IP('2001:4860:4860::8844'),
            nacaddr.IP('2001:4860:4860::8888'),
        ],
        [
            nacaddr.IP('2001:4860:4860::8845'),
        ],
    ]
    self.naming.GetServiceByProto.return_value = ['53']

    pol = policy.ParsePolicy(UDP_AND_TCP_POLICY, self.naming, False)
    nsxt_policy = nsxt.Nsxt(pol, EXP_INFO)
    api_policy = json.loads(str(nsxt_policy))

    self.assertEqual(json.dumps(api_policy, sort_keys=True, indent=2),
                     json.dumps(UDP_AND_TCP_NSXT_POLICY,
                                sort_keys=True,
                                indent=2))
    self.assertEqual(api_policy, UDP_AND_TCP_NSXT_POLICY)

    self.naming.GetNetAddr.assert_has_calls(
        [mock.call('GOOGLE_DNS'), mock.call('MAIL_SERVERS')])
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('DNS', 'udp'), mock.call('MAIL_SERVICES', 'tcp')])

  def test_icmp_policy_with_security_group(self):
    """Test for Nsxt._str_ with security group in scope."""
    pol = (
        policy.ParsePolicy(ICMP_POLICY_WITH_SECURITY_GROUP, self.naming, False))
    nsxt_policy = nsxt.Nsxt(pol, EXP_INFO)
    api_policy = json.loads(str(nsxt_policy))

    # Comparing prettified JSON strings because the output is easier to
    # understand.
    self.assertEqual(json.dumps(api_policy, sort_keys=True, indent=2),
                     json.dumps(ICMP_NSXT_POLICY_WITH_SECURITY_GROUP,
                                sort_keys=True,
                                indent=2))

  def test_icmp_policy_with_expiry(self):
    """Test for Nsxt._str_ with an expiration specified."""
    defs = naming.Naming(None)
    servicedata = copy.deepcopy(SERVICES_SVC)
    networkdata = copy.deepcopy(NETWORK_NET)

    defs.ParseServiceList(servicedata)
    defs.ParseNetworkList(networkdata)

    pol = (
        policy.ParsePolicy(ICMP_POLICY_WITH_EXPIRY, defs, False))
    nsxt_policy = nsxt.Nsxt(pol, EXP_INFO)
    api_policy = json.loads(str(nsxt_policy))

    # Comparing prettified JSON strings because the output is easier to
    # understand.
    self.assertEqual(json.dumps(api_policy, sort_keys=True, indent=2),
                     json.dumps(ICMP_NSXT_POLICY_WITH_EXPIRY,
                                sort_keys=True,
                                indent=2))

  def test_icmp_policy_with_exclusion(self):
    """Test for Nsxt._str_ with exclusions specified."""
    defs = naming.Naming(None)
    servicedata = copy.deepcopy(SERVICES_SVC)
    networkdata = copy.deepcopy(NETWORK_NET)

    defs.ParseServiceList(servicedata)
    defs.ParseNetworkList(networkdata)

    pol = policy.ParsePolicy(ICMP_POLICY_WITH_EXCLUSION, defs, False)
    nsxt_policy = nsxt.Nsxt(pol, EXP_INFO)
    api_policy = json.loads(str(nsxt_policy))

    # Comparing prettified JSON strings because the output is easier to
    # understand.
    self.assertEqual(json.dumps(api_policy, sort_keys=True, indent=2),
                     json.dumps(ICMP_NSXT_POLICY_WITH_EXCLUSION,
                                sort_keys=True,
                                indent=2))

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
