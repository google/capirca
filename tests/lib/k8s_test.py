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
"""Unittest for K8s NetworkPolicy rendering module."""

from unittest import mock
from absl.testing import absltest
from absl.testing import parameterized

from capirca.lib import aclgenerator
from capirca.lib import k8s
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy
import yaml

GOOD_HEADER = """
header {
  comment:: "The general policy comment."
  target:: k8s
}
"""

GOOD_HEADER_INGRESS = """
header {
  comment:: "The general policy comment."
  target:: k8s INGRESS
}
"""

GOOD_HEADER_EGRESS = """
header {
  comment:: "The general policy comment."
  target:: k8s EGRESS
}
"""

GOOD_TERM = """
term good-term-1 {
  owner:: myself
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""

GOOD_TERM_CUSTOM_NAME = """
term %s {
  owner:: myself
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""

GOOD_TERM_CUSTOM_PROTO = """
term custom-proto-term {
  owner:: myself
  comment:: "custom proto term"
  source-address:: CORP_EXTERNAL
  protocol:: %s
  action:: accept
}
"""

GOOD_TERM_PROTO_ALL = """
term good-term-2 {
  owner:: myself
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  destination-port:: DNS
  protocol:: udp tcp sctp
  action:: accept
}
"""

GOOD_TERM_ALLOW_ALL_TCP = """
term good-term-3 {
  owner:: myself
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_EGRESS = """
term good-term-4 {
  comment:: "DNS access from corp."
  destination-address:: CORP_EXTERNAL
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
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

GOOD_TERM_EXCLUDE_SOURCE = """
term good-term-exclude-source {
  comment:: "term with source exclusions"
  source-address:: ANY_IPS
  source-exclude:: TEST_IPS
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_EXCLUDE_DEST = """
term good-term-exclude-destination {
  comment:: "term with destination exclusions"
  destination-address:: ANY_IPS
  destination-exclude:: TEST_IPS
  protocol:: tcp
  action:: accept
}
"""

DEFAULT_DENY = """
term default-deny {
  comment:: "default_deny."
  action:: deny
}
"""

BAD_TERM_DENY = """
term bad-term-1 {
  comment:: "explicit deny"
  source-address:: CORP_EXTERNAL
  protocol:: tcp
  action:: deny
}
"""

BAD_TERM_INVALID_SOURCE_EXCLUDE = """
term bad-term-2 {
  comment:: "source exclude without source address"
  source-exclude:: CORP_EXTERNAL
  protocol:: tcp
  action:: accept
}
"""

BAD_TERM_NO_ADDR = """
term bad-term-3 {
  comment:: "ingress no source"
  protocol:: tcp
  action:: accept
}
"""

BAD_TERM_INGRESS_DESTINATION = """
term bad-term-4 {
  comment:: "source exclude without source address"
  source-address:: CORP_EXTERNAL
  destination-address:: CORP_EXTERNAL
  protocol:: tcp
  action:: accept
}
"""

BAD_TERM_SOURCE_PORT = """
term bad-term-5 {
  comment:: "source port restriction"
  source-address:: CORP_EXTERNAL
  source-port:: DNS
  protocol:: udp
  action:: accept
}
"""

BAD_TERM_EMPTY_SOURCE = """
term bad-term-6 {
  comment:: "empty source address after flattening"
  source-address:: CORP_EXTERNAL
  source-exclude:: CORP_EXTERNAL
  protocol:: tcp
  action:: accept
}
"""

BAD_TERM_EMPTY_DEST = """
term bad-term-7 {
  comment:: "empty destination address after flattening"
  destination-address:: CORP_EXTERNAL
  destination-exclude:: CORP_EXTERNAL
  protocol:: tcp
  action:: accept
}
"""

VALID_TERM_NAMES = [
    'gcp-to-gcp',
    'default-deny',
    'google-web',
    'zo6hmxkfibardh6tgbiy7ua6',
    'http.frontend.web.com',
]

INVALID_TERM_NAMES = [
    'CAPS-ARE-NOT-VALID',
    '_underscores_',
    'mIxEdCaSe',
    'an-otherwise-valid-term-ending-in-a-dash-',
]

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'destination_tag',
    'expiration',
    'stateless_reply',
    'name',
    'owner',
    'protocol',
    'source_address',
    'source_address_exclude',
    'translated',
    'platform',
    'platform_exclude',
}

SUPPORTED_SUB_TOKENS = {'action': {'accept', 'deny'}}

SUPPORTED_PROTOS = ['tcp', 'udp', 'sctp']

UNSUPPORTED_PROTOS = ['igmp', 'pim', 'ah']

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2

TEST_IPS = [nacaddr.IP('10.2.3.4/32'), nacaddr.IP('2001:4860:8000::5/128')]

TEST_INCLUDE_IPS = [nacaddr.IP('10.2.3.4/32'), nacaddr.IP('10.4.3.2/32')]

TEST_EXCLUDE_IPS = [nacaddr.IP('10.4.3.2/32')]

TEST_INCLUDE_RANGE = [nacaddr.IP('10.128.0.0/9')]

TEST_EXCLUDE_RANGE = [nacaddr.IP('10.240.0.0/16')]

ANY_IPS = [nacaddr.IP('0.0.0.0/0'), nacaddr.IP('::/0')]

ANY_IPV4 = [nacaddr.IP('0.0.0.0/0')]

ANY_IPV6 = [nacaddr.IP('::/0')]

TEST_IPV4_ONLY = [nacaddr.IP('10.2.3.4/32')]

TEST_IPV6_ONLY = [nacaddr.IP('2001:4860:8000::5/128')]


class K8sTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def testGenericTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    expected = {
        'apiVersion':
            k8s.K8s._API_VERSION,
        'kind':
            k8s.K8s._RESOURCE_KIND,
        'items': [{
            'apiVersion': k8s.Term._API_VERSION,
            'kind': k8s.Term._RESOURCE_KIND,
            'metadata': {
                'name': 'good-term-1',
                'annotations': {
                    'owner': 'myself',
                    'comment': 'DNS access from corp.'
                },
            },
            'spec': {
                'podSelector': {},
                'policyTypes': ['Ingress'],
                'ingress': [{
                    'from': [{
                        'ipBlock': {
                            'cidr': '10.2.3.4/32'
                        }
                    }, {
                        'ipBlock': {
                            'cidr': '2001:4860:8000::5/128'
                        }
                    }],
                    'ports': [{
                        'port': 53,
                        'protocol': 'UDP'
                    }, {
                        'port': 53,
                        'protocol': 'TCP'
                    }],
                }]
            },
        }]
    }

    acl = k8s.K8s(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM, self.naming), EXP_INFO)

    policy_list = yaml.safe_load(str(acl))
    self.assertDictEqual(expected, policy_list)

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('DNS', 'udp'),
         mock.call('DNS', 'tcp')])

  def testGenericEgressTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    expected = {
        'apiVersion':
            k8s.K8s._API_VERSION,
        'kind':
            k8s.K8s._RESOURCE_KIND,
        'items': [{
            'apiVersion': k8s.Term._API_VERSION,
            'kind': k8s.Term._RESOURCE_KIND,
            'metadata': {
                'name': 'good-term-4-e',
                'annotations': {
                    'comment': 'DNS access from corp.'
                },
            },
            'spec': {
                'podSelector': {},
                'policyTypes': ['Egress'],
                'egress': [{
                    'to': [{
                        'ipBlock': {
                            'cidr': '10.2.3.4/32'
                        }
                    }, {
                        'ipBlock': {
                            'cidr': '2001:4860:8000::5/128'
                        }
                    }],
                    'ports': [{
                        'port': 53,
                        'protocol': 'UDP'
                    }, {
                        'port': 53,
                        'protocol': 'TCP'
                    }],
                }]
            },
        }]
    }

    acl = k8s.K8s(
        policy.ParsePolicy(GOOD_HEADER_EGRESS + GOOD_TERM_EGRESS, self.naming),
        EXP_INFO)

    policy_list = yaml.safe_load(str(acl))
    self.assertDictEqual(expected, policy_list)

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('DNS', 'udp'),
         mock.call('DNS', 'tcp')])

  def testAllProtosTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.side_effect = [['53'], ['53'], ['53']]

    acl = k8s.K8s(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_PROTO_ALL, self.naming),
        EXP_INFO)

    policy_list = yaml.safe_load(str(acl))
    policies = policy_list['items']
    self.assertLen(policies, 1)
    net_policy = policies[0]
    self.assertLen(net_policy['spec']['ingress'], 1)
    ingress_rule = net_policy['spec']['ingress'][0]
    self.assertLen(ingress_rule['ports'], 3)
    unique_protos = {
        port_selector['protocol'] for port_selector in ingress_rule['ports']
    }
    self.assertSetEqual({'UDP', 'TCP', 'SCTP'}, unique_protos)

  def testPortRangeTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.return_value = ['0-1024']

    acl = k8s.K8s(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM, self.naming), EXP_INFO)
    policy_list = yaml.safe_load(str(acl))
    policies = policy_list['items']

    self.assertLen(policies, 1)
    net_policy = policies[0]
    self.assertLen(net_policy['spec']['ingress'], 1)
    ingress_rule = net_policy['spec']['ingress'][0]
    self.assertLen(ingress_rule['ports'], 2)
    expected = {'endPort': 1024, 'port': 0}
    for port_selector in ingress_rule['ports']:
      self.assertEqual(port_selector, {**port_selector, **expected})

  def testAllowAllTcpTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.return_value = ['53']
    expected_ingress_ports = [{'protocol': 'TCP'}]

    acl = k8s.K8s(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_ALLOW_ALL_TCP, self.naming),
        EXP_INFO)

    policy_list = yaml.safe_load(str(acl))
    policies = policy_list['items']
    self.assertLen(policies, 1)
    net_policy = policies[0]
    self.assertLen(net_policy['spec']['ingress'], 1)
    ingress_rule = net_policy['spec']['ingress'][0]
    self.assertLen(ingress_rule['ports'], 1)
    self.assertSequenceEqual(ingress_rule['ports'], expected_ingress_ports)

  def testDefaultDenyTerm(self):
    expected = {
        'apiVersion': k8s.Term._API_VERSION,
        'kind': k8s.Term._RESOURCE_KIND,
        'metadata': {
            'name': 'default-deny',
            'annotations': {
                'comment': 'default_deny.'
            },
        },
        'spec': {
            'podSelector': {},
            'policyTypes': ['Ingress']
        },
    }

    acl = k8s.K8s(
        policy.ParsePolicy(GOOD_HEADER + DEFAULT_DENY, self.naming), EXP_INFO)

    policy_list = yaml.safe_load(str(acl))
    policies = policy_list['items']
    self.assertDictEqual(expected, policies[0])

  def testDefaultDenyEgressTerm(self):
    expected = {
        'apiVersion': k8s.Term._API_VERSION,
        'kind': k8s.Term._RESOURCE_KIND,
        'metadata': {
            'name': 'default-deny-e',
            'annotations': {
                'comment': 'default_deny.'
            },
        },
        'spec': {
            'podSelector': {},
            'policyTypes': ['Egress']
        },
    }

    acl = k8s.K8s(
        policy.ParsePolicy(GOOD_HEADER_EGRESS + DEFAULT_DENY, self.naming),
        EXP_INFO)

    policy_list = yaml.safe_load(str(acl))
    policies = policy_list['items']
    self.assertLen(policies, 1)
    self.assertDictEqual(expected, policies[0])

  def testBadDenyTerm(self):
    self.assertRaisesRegex(
        k8s.K8sNetworkPolicyError, 'not support explicit deny', k8s.K8s,
        policy.ParsePolicy(GOOD_HEADER + BAD_TERM_DENY, self.naming), EXP_INFO)

  def testBadSourceExclusionTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.assertRaisesRegex(
        k8s.K8sNetworkPolicyError, 'missing required field', k8s.K8s,
        policy.ParsePolicy(GOOD_HEADER + BAD_TERM_INVALID_SOURCE_EXCLUDE,
                           self.naming), EXP_INFO)

  def testBadIngressNoAddressTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.assertRaisesRegex(
        k8s.K8sNetworkPolicyError, 'missing required field.+source', k8s.K8s,
        policy.ParsePolicy(GOOD_HEADER + BAD_TERM_NO_ADDR, self.naming),
        EXP_INFO)

  def testBadEgressNoAddressTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.assertRaisesRegex(
        k8s.K8sNetworkPolicyError, 'missing required field.+destination',
        k8s.K8s,
        policy.ParsePolicy(GOOD_HEADER_EGRESS + BAD_TERM_NO_ADDR,
                           self.naming), EXP_INFO)

  @parameterized.named_parameters(
      {
          'testcase_name': 'IPv4',
          'ip_block_cidr': TEST_INCLUDE_RANGE,
          'ip_block_exclude': TEST_EXCLUDE_RANGE,
      }, {
          'testcase_name': 'IPv6',
          'ip_block_cidr': ANY_IPV6,
          'ip_block_exclude': TEST_IPV6_ONLY,
      }, {
          'testcase_name': 'MultiExclude',
          'ip_block_cidr': TEST_INCLUDE_IPS,
          'ip_block_exclude': TEST_EXCLUDE_RANGE + TEST_EXCLUDE_IPS,
      })
  def testGoodSourceAddressExcludeTerm(self, ip_block_cidr, ip_block_exclude):
    expected_peer_specs = []
    expected_peer_spec_except = [str(ex) for ex in ip_block_exclude[::-1]]
    for ip in ip_block_cidr:
      expected_peer_specs.append(
          {'ipBlock': {
              'cidr': str(ip),
              'except': expected_peer_spec_except
          }})

    expected = {
        'apiVersion': k8s.Term._API_VERSION,
        'kind': k8s.Term._RESOURCE_KIND,
        'metadata': {
            'name': 'good-term-exclude-source',
            'annotations': {
                'comment': 'term with source exclusions'
            },
        },
        'spec': {
            'ingress': [{
                'from': expected_peer_specs,
                'ports': [{
                    'protocol': 'TCP'
                }],
            }],
            'podSelector': {},
            'policyTypes': ['Ingress'],
        },
    }
    self.naming.GetNetAddr.side_effect = [ip_block_cidr, ip_block_exclude]
    acl = k8s.K8s(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_EXCLUDE_SOURCE, self.naming),
        EXP_INFO)

    policy_list = yaml.safe_load(str(acl))
    policies = policy_list['items']
    self.assertDictEqual(expected, policies[0])

  @parameterized.named_parameters(
      {
          'testcase_name': 'IPv4',
          'ip_block_cidr': TEST_INCLUDE_RANGE,
          'ip_block_exclude': TEST_EXCLUDE_RANGE,
      }, {
          'testcase_name': 'IPv6',
          'ip_block_cidr': ANY_IPV6,
          'ip_block_exclude': TEST_IPV6_ONLY,
      }, {
          'testcase_name': 'MultiExclude',
          'ip_block_cidr': TEST_INCLUDE_IPS,
          'ip_block_exclude': TEST_EXCLUDE_RANGE + TEST_EXCLUDE_IPS,
      })
  def testGoodDestAddressExcludeTerm(self, ip_block_cidr, ip_block_exclude):
    expected_peer_specs = []
    expected_peer_spec_except = [str(ex) for ex in ip_block_exclude[::-1]]
    for ip in ip_block_cidr:
      expected_peer_specs.append(
          {'ipBlock': {
              'cidr': str(ip),
              'except': expected_peer_spec_except
          }})

    expected = {
        'apiVersion': k8s.Term._API_VERSION,
        'kind': k8s.Term._RESOURCE_KIND,
        'metadata': {
            'name': 'good-term-exclude-destination-e',
            'annotations': {
                'comment': 'term with destination exclusions'
            },
        },
        'spec': {
            'egress': [{
                'to': expected_peer_specs,
                'ports': [{
                    'protocol': 'TCP'
                }],
            }],
            'podSelector': {},
            'policyTypes': ['Egress'],
        },
    }
    self.naming.GetNetAddr.side_effect = [ip_block_cidr, ip_block_exclude]
    acl = k8s.K8s(
        policy.ParsePolicy(GOOD_HEADER_EGRESS + GOOD_TERM_EXCLUDE_DEST,
                           self.naming), EXP_INFO)

    policy_list = yaml.safe_load(str(acl))
    policies = policy_list['items']
    self.assertDictEqual(expected, policies[0])

  def testBadSourceAddressExcludeTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPV4_ONLY
    acl = k8s.K8s(
        policy.ParsePolicy(GOOD_HEADER + BAD_TERM_EMPTY_SOURCE, self.naming),
        EXP_INFO)

    self.assertEqual(str(acl), '')

  def testBadDestinationAddressExcludeTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPV4_ONLY

    acl = k8s.K8s(
        policy.ParsePolicy(GOOD_HEADER_EGRESS + BAD_TERM_EMPTY_DEST,
                           self.naming), EXP_INFO)

    self.assertEqual(str(acl), '')

  def testBadSourcePortTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.side_effect = [['53']]

    self.assertRaisesRegex(
        k8s.K8sNetworkPolicyError, 'not support source port', k8s.K8s,
        policy.ParsePolicy(GOOD_HEADER + BAD_TERM_SOURCE_PORT, self.naming),
        EXP_INFO)

  def testBadIngressDestinationTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.side_effect = [['53']]

    self.assertRaisesRegex(
        k8s.K8sNetworkPolicyError,
        '[Ii]ngress rules cannot include.+destination', k8s.K8s,
        policy.ParsePolicy(GOOD_HEADER + BAD_TERM_INGRESS_DESTINATION,
                           self.naming), EXP_INFO)

  def testBadEgressSourceTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    self.assertRaisesRegex(
        k8s.K8sNetworkPolicyError, '[Ee]gress rules cannot include.+source',
        k8s.K8s, policy.ParsePolicy(GOOD_HEADER_EGRESS + GOOD_TERM,
                                    self.naming), EXP_INFO)

  def testValidTermNames(self):
    for name in VALID_TERM_NAMES:
      self.naming.GetNetAddr.return_value = TEST_IPS
      self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
      pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_CUSTOM_NAME % name,
                               self.naming)
      acl = k8s.K8s(pol, EXP_INFO)
      self.assertIsNotNone(str(acl))

  def testInvalidTermNames(self):
    for name in INVALID_TERM_NAMES:
      self.naming.GetNetAddr.return_value = TEST_IPS
      self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
      pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_CUSTOM_NAME % name,
                               self.naming)
      self.assertRaisesRegex(k8s.K8sNetworkPolicyError,
                             'name %s is not valid' % name, k8s.K8s, pol,
                             EXP_INFO)

  def testSkipExpiredTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.return_value = ['22']

    acl = k8s.K8s(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_EXPIRED, self.naming),
        EXP_INFO)
    self.assertEqual(str(acl), '')

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
    self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

  def testSkipStatelessReply(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.return_value = ['22']

    # Add stateless_reply to terms, there is no current way to include it in the
    # term definition.
    ret = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM, self.naming)
    _, terms = ret.filters[0]
    for term in terms:
      term.stateless_reply = True

    acl = k8s.K8s(ret, EXP_INFO)
    self.assertEqual(str(acl), '')

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call('DNS', 'udp'),
         mock.call('DNS', 'tcp')])

  def testValidTermProtos(self):
    for proto in SUPPORTED_PROTOS:
      self.naming.GetNetAddr.return_value = TEST_IPS
      self.naming.GetServiceByProto.return_value = ['53']
      pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_CUSTOM_PROTO % proto,
                               self.naming)
      acl = k8s.K8s(pol, EXP_INFO)
      self.assertIsNotNone(str(acl))

  def testInvalidTermProtos(self):
    for proto in UNSUPPORTED_PROTOS:
      self.naming.GetNetAddr.return_value = TEST_IPS
      self.naming.GetServiceByProto.return_value = ['53']
      pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_CUSTOM_PROTO % proto,
                               self.naming)
      self.assertRaises(aclgenerator.UnsupportedFilterError, k8s.K8s, pol,
                        EXP_INFO)

  def testMultipleTerms(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.return_value = ['53']

    acl = k8s.K8s(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM + GOOD_TERM_ALLOW_ALL_TCP,
                           self.naming), EXP_INFO)

    policy_list = yaml.safe_load(str(acl))
    self.assertLen(policy_list['items'], 2)


if __name__ == '__main__':
  absltest.main()
