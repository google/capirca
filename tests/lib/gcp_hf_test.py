"""Tests for google3.third_party.py.capirca.lib.gcp_hf.py."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import json
import unittest

from absl.testing import parameterized

from capirca.lib import gcp
from capirca.lib import gcp_hf
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy
import mock


HEADER_NO_OPTIONS = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname
}
"""

HEADER_OPTION_MAX = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname 20
}
"""

HEADER_OPTION_EGRESS = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname EGRESS
}
"""

HEADER_OPTION_AF = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname inet
}
"""

HEADER_OPTION_EGRESS_AND_MAX = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname EGRESS 20
}
"""

HEADER_OPTION_EGRESS_AND_AF = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname EGRESS inet
}
"""

HEADER_OPTION_MAX_AND_AF = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname 20 inet
}
"""

HEADER_VERY_LOW_DEFAULT_MAX = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname 1
}
"""

BAD_HEADER_UNKNOWN_OPTION = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname INGRESS randomOption
}
"""

BAD_HEADER_UNKNOWN_DIRECTION = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname BIGRESS
}
"""

BAD_HEADER_INVALID_MAX_COST = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname INGRESS 888888888
}
"""

BAD_HEADER_WRONG_PLATFORM = """
header {
  comment:: "The general policy comment."
  target:: wrong_platform
}
"""


TERM_ALLOW_ALL_INTERNAL = """
term allow-internal-traffic {
  comment:: "Generic description"
  source-address:: INTERNAL
  protocol:: tcp icmp udp
  action:: next
}
"""

TERM_ALLOW_DNS = """
term allow-dns-traffic {
  comment:: "Generic description"
  source-address:: PUBLIC_NAT
  protocol:: tcp udp
  destination-port:: DNS
  action:: next
}
"""

TERM_ALLOW_PORT = """
term allow-traffic-to-port {
  comment:: "Generic description"
  source-address:: PUBLIC_NAT
  protocol:: tcp
  destination-port:: PORT
  action:: next
}
"""

TERM_ALLOW_PORT_RANGE = """
term allow-port-range {
  comment:: "Generic description"
  source-address:: PUBLIC_NAT
  protocol:: tcp
  destination-port:: RANGE
  action:: next
}
"""

TERM_RESTRICT_EGRESS = """
term restrict_egress {
  comment:: "Generic description"
  destination-address:: PUBLIC_NAT
  protocol:: tcp icmp udp
  action:: next
}
"""

TERM_DENY_INGRESS = """
term default-deny-ingress {
  comment:: "Generic description"
  source-address:: ANY
  action:: deny
}
"""

TERM_DENY_EGRESS = """
term default-deny-egress {
  comment:: "Generic description"
  destination-address:: ANY
  action:: deny
}
"""

TERM_WITH_TARGET_RESOURCES = """
term default-deny-ingress-on-target {
  comment:: "Generic description"
  source-address:: ANY
  action:: deny
  target-resources:: (project1, vpc1)
  target-resources:: (project2, vpc2)
}
"""

TERM_WITH_TARGET_RESOURCES_2 = """
term default-deny-ingress-on-target {
  comment:: "Generic description"
  source-address:: ANY
  action:: deny
  target-resources:: [(project1, vpc1),(project2,vpc2)]
}
"""

TERM_WITH_LOGGING = """
term term-with-logging {
  comment:: "Generic description"
  source-address:: ANY
  protocol:: tcp
  action:: accept
  logging:: true
}
"""

TERM_NO_COMMENT = """
term allow-internal-traffic {
  source-address:: INTERNAL
  protocol:: tcp icmp udp
  action:: next
}
"""

TERM_LONG_COMMENT = """
term allow-internal-traffic {
  comment:: "This is a very long description, it is longer than sixty-four chars"
  source-address:: INTERNAL
  protocol:: tcp icmp udp
  action:: next
}
"""

BAD_TERM_NO_SOURCE_IP = """
  term bad-term-missing-source-ip {
  comment:: "Generic description"
  protocol:: udp
  destination-port:: DNS
  action:: accept
}
"""

BAD_TERM_PROTO = """
  term bad-term-unsupp-proto {
  comment:: "Generic description"
  source-address:: PUBLIC_NAT
  protocol:: ggp
  action:: next
}
"""

BAD_TERM_USING_SOURCE_TAG = """
  term bad-term-with-tag {
  comment:: "Generic description"
  source-address:: PUBLIC_NAT
  source-tag:: a-tag
  protocol:: tcp icmp udp
  action:: next
}
"""

BAD_TERM_USING_DEST_TAG = """
  term bad-term-with-tag {
  comment:: "Generic description"
  source-address:: PUBLIC_NAT
  destination-tag:: a-tag
  protocol:: tcp icmp udp
  action:: next
}
"""

BAD_TERM_NO_SOURCE_IP = """
  term bad-term-missing-source-ip {
  comment:: "Generic description"
  protocol:: udp
  destination-port:: DNS
  action:: accept
}
"""

BAD_TERM_NO_DEST_IP = """
  term bad-term-missing-dest-ip {
  comment:: "Generic description"
  protocol:: udp
  destination-address:: PUBLIC_NAT
  action:: accept
}
"""

BAD_TERM_NON_VALID_PROJECT_ID = """
term default-deny-ingress-on-target {
  comment:: "Generic description"
  protocol:: tcp
  source-address:: ANY
  action:: deny
  target-resources:: (proj, vpc1)
}
"""

BAD_TERM_NON_VALID_VPC_NAME = """
term default-deny-ingress-on-target {
  comment:: "Generic description"
  protocol:: tcp
  source-address:: ANY
  action:: deny
  target-resources:: (project, Vpc)
}
"""

EXPECTED_ONE_RULE_INGRESS = """
[
  {
    "display_name": "displayname",
    "rules": [
      {
        "action": "goto_next",
        "description": "Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Config": [
              {
                "ipProtocol": "tcp"
              },
              {
                "ipProtocol": "icmp"
              },
              {
                "ipProtocol": "udp"
              }
            ],
            "srcIpRange": ["10.0.0.0/8"]
          }
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_ONE_RULE_INGRESS_W_LOGGING = """
[
  {
    "display_name": "displayname",
    "rules": [
      {
        "action": "allow",
        "description": "Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Config": [
              {
                "ipProtocol": "tcp"
              }
            ],
            "srcIpRange": ["10.0.0.0/8"]
          }
        },
        "priority": 1,
        "enableLogging": true
      }
    ]
  }
]
"""

EXPECTED_ONE_RULE_EGRESS = """
[
  {
    "display_name": "displayname",
    "rules": [
      {
        "action": "goto_next",
        "description": "Generic description",
        "direction": "EGRESS",
        "match": {
          "config": {
            "layer4Config": [
              {
                "ipProtocol": "tcp"
              },
              {
                "ipProtocol": "icmp"
              },
              {
                "ipProtocol": "udp"
              }
            ],
            "destIpRange": ["10.0.0.0/8"]
          }
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_MULTIPLE_RULE_INGRESS = """
[
  {
    "display_name": "displayname",
    "rules": [
      {
        "action": "goto_next",
        "description": "Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "config": {
            "layer4Config": [
              {
                "ipProtocol": "tcp"
              },
              {
                "ipProtocol": "icmp"
              },
              {
                "ipProtocol": "udp"
              }
            ],
            "srcIpRange": ["10.0.0.0/8"]
          }
        },
        "priority": 1
      },
      {
        "action": "goto_next",
        "description": "Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "config": {
            "layer4Config": [
              {
                "ipProtocol": "tcp",
                "ports": ["53"]
              },
              {
                "ipProtocol": "udp",
                "ports": ["53"]
              }
            ],
            "srcIpRange": ["10.0.0.0/8"]
          }
        },
        "priority": 2
      }
    ]
  }
]
"""

EXPECTED_MULTIPLE_RULE_INGRESS_W_DENY = """
[
  {
    "display_name": "displayname",
    "rules": [
      {
        "action": "goto_next",
        "description": "Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Config": [
              {
                "ipProtocol": "tcp"
              },
              {
                "ipProtocol": "icmp"
              },
              {
                "ipProtocol": "udp"
              }
            ],
            "srcIpRange": ["10.0.0.0/8"]
          }
        },
        "priority": 1,
        "enableLogging": false
      },
      {
        "action": "deny",
        "description": "Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "srcIpRange": ["0.0.0.0/0"]
          }
        },
        "priority": 2,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_PORT_RANGE_INGRESS = """
[
  {
    "display_name": "displayname",
    "rules": [
      {
        "action": "goto_next",
        "description": "Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Config": [
              {
                "ipProtocol": "tcp",
                "ports": ["8000-9000"]
              }
            ],
            "srcIpRange": ["10.0.0.0/8"]
          }
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_DENY_INGRESS = """
[
  {
    "display_name": "displayname",
    "rules": [
      {
        "action": "deny",
        "description": "Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "srcIpRange": ["0.0.0.0/0"]
          }
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_DENY_INGRESS_ON_TARGET = """
[
  {
    "display_name": "displayname",
    "rules": [
      {
        "action": "deny",
        "description": "Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "srcIpRange": ["0.0.0.0/0"]
          }
        },
        "priority": 1,
        "enableLogging": false,
        "targetResources": ["projects/project1/networks/vpc1",
                            "projects/project2/networks/vpc2"]
      }
    ]
  }
]
"""

EXPECTED_DENY_EGRESS = """
[
  {
    "display_name": "displayname",
    "rules": [
      {
        "action": "deny",
        "description": "Generic description",
        "direction": "EGRESS",
        "match": {
          "config": {
            "destIpRange": ["0.0.0.0/0"]
          }
        },
        "priority": 1,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_COST_OF_ONE = """
[
  {
    "display_name": "displayname",
    "rules": [
      {
        "action": "goto_next",
        "description": "Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "config": {
            "layer4Config": [
              {
                "ipProtocol": "tcp",
                "ports": ["80"]
              }
            ],
            "srcIpRange": ["10.1.1.0/24"]
          }
        },
        "priority": 1
      }
    ]
  }
]
"""

SUPPORTED_TOKENS = frozenset({
    'action',
    'comment',
    'destination_address',
    'destination_port',
    'destination_tag',
    'logging',
    'name',
    'protocol',
    'source_address',
    'source_tag',
    'target_resources',
    'translated',
})

SUPPORTED_SUB_TOKENS = {
    'action': {
        'accept', 'deny', 'next'
    }
}

EXP_INFO = 2

TEST_IP = [nacaddr.IP('10.0.0.0/8')]


class GcpHfTest(parameterized.TestCase):

  def setUp(self):
    super(GcpHfTest, self).setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def _StripAclHeaders(self, acl):
    return '\n'.join([line for line in str(acl).split('\n')
                      if not line.lstrip().startswith('#')])

  def testDefaultHeader(self):
    """Test that a header without options is accepted."""
    self.naming.GetNetAddr.return_value = TEST_IP

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_ALLOW_ALL_INTERNAL,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_INGRESS)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testOptionMaxHeader(self):
    """Test that a header with a default maximum cost is accepted."""
    self.naming.GetNetAddr.return_value = TEST_IP

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_MAX + TERM_ALLOW_ALL_INTERNAL,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_INGRESS)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testOptionEgressHeader(self):
    """Test that a header with direction is accepted."""
    self.naming.GetNetAddr.return_value = TEST_IP

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_EGRESS + TERM_RESTRICT_EGRESS,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_EGRESS)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testOptionAFHeader(self):
    """Test that a header with address family is accepted."""
    self.naming.GetNetAddr.return_value = TEST_IP

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_AF + TERM_ALLOW_ALL_INTERNAL,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_INGRESS)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testOptionEgressAndMaxHeader(self):
    """Test a header with direction and default maximum cost is accepted."""
    self.naming.GetNetAddr.return_value = TEST_IP

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_EGRESS_AND_MAX + TERM_RESTRICT_EGRESS,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_EGRESS)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testOptionEgressAndAF(self):
    """Test a header with a direction and address family is accepted."""
    self.naming.GetNetAddr.return_value = TEST_IP

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_EGRESS_AND_AF + TERM_RESTRICT_EGRESS,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_EGRESS)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testOptionMaxAndAF(self):
    """Test a header with default maximum cost & address family is accepted."""
    self.naming.GetNetAddr.return_value = TEST_IP

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_MAX_AND_AF + TERM_ALLOW_ALL_INTERNAL,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_INGRESS)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testRaisesHeaderErrorOnUnknownOption(self):
    """Test that an unknown header option raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(BAD_HEADER_UNKNOWN_OPTION
                             + TERM_ALLOW_ALL_INTERNAL,
                             self.naming),
          EXP_INFO)

  def testRaisesHeaderErrorOnUnknownDirection(self):
    """Test that an unknown direction option raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(BAD_HEADER_UNKNOWN_DIRECTION
                             + TERM_ALLOW_ALL_INTERNAL,
                             self.naming),
          EXP_INFO)

  def testRaisesHeaderErrorOnInvalidMaxCost(self):
    """Test that a maximum default cost over 2^16 raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(BAD_HEADER_INVALID_MAX_COST
                             + TERM_ALLOW_ALL_INTERNAL,
                             self.naming),
          EXP_INFO)

  def testRaisesTermErrorOnTermWithDestinationTag(self):
    """Test that a term with a destination tag raises an error.

    Tags are not supported in HF.
    """
    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_USING_DEST_TAG,
                             self.naming),
          EXP_INFO)

  def testRaisesTermErrorOnTermWithSourceTag(self):
    """Test that a term with a source tag raises an error.

    Tags are not supported in HF.
    """
    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_USING_SOURCE_TAG,
                             self.naming),
          EXP_INFO)

  def testRaisesTermErrorOnTermWithUnsupportedProtocol(self):
    """Test that a term with an unsupported protocol raises an error."""
    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_PROTO, self.naming),
          EXP_INFO)

  def testRaisesTermErrorOnIngressTermMissingSourceIP(self):
    """Test that an ingress term without a source IP raises an error."""
    self.naming.GetServiceByProto.side_effect = [['53']]
    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_NO_SOURCE_IP,
                             self.naming),
          EXP_INFO)

  def testRaisesTermErrorOnEgressTermMissingDestIP(self):
    """Test that an egress term without a destination IP raises an error."""
    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_OPTION_EGRESS + BAD_TERM_NO_DEST_IP,
                             self.naming),
          EXP_INFO)

  def testRaisesTermErrorOnInvalidProjectID(self):
    """Test that an invalid project ID on target resources raises Term error."""
    self.naming.GetNetAddr.return_value = TEST_IP

    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_NON_VALID_PROJECT_ID,
                             self.naming),
          EXP_INFO)

  def testRaisesTermErrorOnInvalidVPCName(self):
    """Test that an invalid VPC name on target resources raises Term error."""
    self.naming.GetNetAddr.return_value = TEST_IP

    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_NON_VALID_VPC_NAME,
                             self.naming),
          EXP_INFO)

  def testIgnorePolicyFromADifferentPlatform(self):
    """Test that a policy with a header from a different platform is ignored."""
    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(BAD_HEADER_WRONG_PLATFORM
                           + TERM_ALLOW_ALL_INTERNAL,
                           self.naming),
        EXP_INFO)
    self.assertEqual([], json.loads(self._StripAclHeaders(str(acl))))

  def testPriority(self):
    """Test that priority is set based on terms' ordering."""
    self.naming.GetNetAddr.return_value = TEST_IP
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_ALLOW_ALL_INTERNAL
                           + TERM_ALLOW_DNS, self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_MULTIPLE_RULE_INGRESS)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testLogging(self):
    """Test that logging is used when it is set on a term."""
    self.naming.GetNetAddr.return_value = TEST_IP
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_WITH_LOGGING, self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_INGRESS_W_LOGGING)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testTargetResources(self):
    """Test that the target resources is used correctly."""
    self.naming.GetNetAddr.return_value = [nacaddr.IP('0.0.0.0/0')]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_WITH_TARGET_RESOURCES,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_DENY_INGRESS_ON_TARGET)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testSecondWayOfPassingTargetResources(self):
    """Test that the target resources is used correctly."""
    self.naming.GetNetAddr.return_value = [nacaddr.IP('0.0.0.0/0')]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_WITH_TARGET_RESOURCES_2,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_DENY_INGRESS_ON_TARGET)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testPortRange(self):
    """Test that a port range is accepted and used correctly."""
    self.naming.GetNetAddr.return_value = TEST_IP
    self.naming.GetServiceByProto.side_effect = [['8000-9000']]

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_ALLOW_PORT_RANGE,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_PORT_RANGE_INGRESS)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testTermLongComment(self):
    """Test that a term's long comment gets truncated."""
    self.naming.GetNetAddr.return_value = TEST_IP

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_LONG_COMMENT,
                           self.naming),
        EXP_INFO)
    comment_truncated = EXPECTED_ONE_RULE_INGRESS.replace(
        'Generic description',
        'This is a very long description, it is longer than sixty-four ch')
    expected = json.loads(comment_truncated)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testDefaultDenyIngressCreation(self):
    """Test that the correct IP is correctly set on a deny all ingress term."""
    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_DENY_INGRESS, self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_DENY_INGRESS)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testDefaultDenyEgressCreation(self):
    """Test that the correct IP is correctly set on a deny all egress term."""
    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_EGRESS + TERM_DENY_EGRESS,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_DENY_EGRESS)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testBuildTokens(self):
    """Test that _BuildTokens generates the expected list of tokens."""
    self.naming.GetNetAddr.side_effect = [TEST_IP]

    pol1 = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_ALLOW_ALL_INTERNAL,
                           self.naming),
        EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

  def testRaisesExceededCostError(self):
    """Test that ExceededCostError is raised when policy exceeds max cost."""
    self.naming.GetNetAddr.side_effect = [TEST_IP]
    with self.assertRaises(gcp_hf.ExceededCostError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_VERY_LOW_DEFAULT_MAX
                             + TERM_ALLOW_ALL_INTERNAL, self.naming),
          EXP_INFO)

  def testCostIsCorrectlyCalculatedWhenPassingACollapsableIPRange(self):
    """Test GetCost works as-expected with a term using collapsable IP range."""
    self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.0/25'),
                                           nacaddr.IP('10.1.1.128/25')]
    self.naming.GetServiceByProto.side_effect = [['80']]
    # Notice that:
    # - EXPECTED_COST_OF_ONE has 10.1.1.0/24 as source IP instead of
    # 10.1.1.0/25 and 10.1.1.128/25.
    # - HEADER_VERY_LOW_DEFAULT_MAX allows a maximum cost of 1, and that if the
    # IP ranges were not compressed, the total cost of the term TERM_ALLOW_PORT
    # would be 2 and this test would raise ExceededCostError.
    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_VERY_LOW_DEFAULT_MAX + TERM_ALLOW_PORT,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_COST_OF_ONE)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  @parameterized.named_parameters(
      ('all fields unset', [], [], [], 1),
      ('all fields set once', [nacaddr.IP('1.2.3.4/32')], ['TCP'], [80], 1),
      ('0 IPs set', [], ['TCP'], [80], 1),
      ('2 IPs set', [nacaddr.IP('1.2.3.4/32'),
                     nacaddr.IP('1.2.3.5/32')], ['TCP'], [80], 2),
      ('0 protocols set', [nacaddr.IP('1.2.3.4/32')], [], [80], 1),
      ('2 protocols set', [nacaddr.IP('1.2.3.4/32')], ['TCP', 'UDP'], [80], 2),
      ('0 ports set', [nacaddr.IP('1.2.3.4/32')], ['TCP'], [], 1),
      ('2 ports set', [nacaddr.IP('1.2.3.4/32')], ['TCP'], [80, 443], 2)
  )
  @mock.patch.object(policy, 'DEFINITIONS')
  def testGetCost(self, ips, protocols, ports, expected, mock_naming):
    mock_naming.GetNetAddr.side_effect = ips
    t = []
    for i in ips:
      t.append(policy.VarType(3, i))
    for p in protocols:
      t.append(policy.VarType(10, p))
    for p in ports:
      t.append(policy.VarType(7, p))
    term = policy.Term(t)

    self.assertEqual(gcp_hf.GetCost(term), expected)


if __name__ == '__main__':
  unittest.main()
