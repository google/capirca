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

HEADER_OPTION_EGRESS_2 = """
header {
  comment:: "The general policy comment."
  target:: gcp_hf displayname2 EGRESS
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

BAD_HEADER_NO_DISPLAYNAME = """
header {
  comment:: "Header without a policy name."
  target:: gcp_hf
}
"""

BAD_HEADER_LONG_DISPLAYNAME = """
header {
  comment:: "Using a display name with 64 characters."
  target:: gcp_hf this-is-a-very-very-long-policy-name-which-is-over-63-characters
}
"""

BAD_HEADER_INVALID_DISPLAYNAME_1 = """
header {
  comment:: "Using a display name with an upper case letter."
  target:: gcp_hf Displayname
}
"""

BAD_HEADER_INVALID_DISPLAYNAME_2 = """
header {
  comment:: "Using a display name with an underscore character."
  target:: gcp_hf display_name
}
"""

BAD_HEADER_INVALID_DISPLAYNAME_3 = """
header {
  comment:: "Using a display name that ends in a dash."
  target:: gcp_hf displayname-
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
  action:: deny
}
"""

TERM_DENY_EGRESS = """
term default-deny-egress {
  comment:: "Generic description"
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

BAD_TERM_SOURCE_PORT = """
term allow-traffic-from-port {
  comment:: "Generic description"
  destination-address:: INTERNAL
  protocol:: tcp
  source-port:: PORT
  action:: next
}
"""

BAD_TERM_IP_VERSION_MISMATCH = """
term icmpv6-in-inet-term {
  comment:: "Generic description"
  source-address:: INTERNAL
  protocol:: icmpv6
  action:: next
}
"""

BAD_TERM_OPTIONS = """
term term-with-options {
  comment:: "Generic description"
  destination-address:: INTERNAL
  option:: TCP_ESTABLISHED
  action:: next
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
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-internal-traffic: Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
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
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
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
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "allow",
        "description": "term-with-logging: Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp"
              }
            ],
            "srcIpRanges": ["10.0.0.0/8"]
          },
          "versionedExpr": "FIREWALL"
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
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "restrict_egress: Generic description",
        "direction": "EGRESS",
        "match": {
          "config": {
            "layer4Configs": [
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
            "destIpRanges": ["10.0.0.0/8"]
          },
          "versionedExpr": "FIREWALL"
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
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-internal-traffic: Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "config": {
            "layer4Configs": [
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
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1
      },
      {
        "action": "goto_next",
        "description": "allow-dns-traffic: Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp",
                "ports": ["53"]
              },
              {
                "ipProtocol": "udp",
                "ports": ["53"]
              }
            ],
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
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
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
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
            "srcIpRanges": ["10.0.0.0/8"]
          },
          "versionedExpr": "FIREWALL"
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
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
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
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-port-range: Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp",
                "ports": ["8000-9000"]
              }
            ],
            "srcIpRanges": ["10.0.0.0/8"]
          },
          "versionedExpr": "FIREWALL"
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
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "deny",
        "description": "default-deny-ingress: Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "all"
              }
            ],
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
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
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "deny",
        "description": "default-deny-ingress-on-target: Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "all"
              }
            ],
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false,
        "targetResources": ["https://www.googleapis.com/compute/v1/projects/project1/global/networks/vpc1",
                            "https://www.googleapis.com/compute/v1/projects/project2/global/networks/vpc2"]
      }
    ]
  }
]
"""

EXPECTED_INGRESS_AND_EGRESS_W_DENY = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-internal-traffic: Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
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
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1,
        "enableLogging": false
      },
      {
        "action": "deny",
        "description": "default-deny-ingress: Generic description",
        "direction": "INGRESS",
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "all"
              }
            ],
            "srcIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 2,
        "enableLogging": false
      },
      {
        "action": "goto_next",
        "description": "restrict_egress: Generic description",
        "direction": "EGRESS",
        "match": {
          "config": {
            "layer4Configs": [
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
            "destIpRanges": ["0.0.0.0/0"]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 3,
        "enableLogging": false
      },
      {
        "action": "deny",
        "description": "default-deny-egress: Generic description",
        "direction": "EGRESS",
        "match": {
          "config": {
            "destIpRanges": ["0.0.0.0/0"],
            "layer4Configs": [
              {
                "ipProtocol": "all"
              }
            ]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 4,
        "enableLogging": false
      }
    ]
  }
]
"""

EXPECTED_DENY_EGRESS = """
[
  {
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "deny",
        "description": "default-deny-egress: Generic description",
        "direction": "EGRESS",
        "match": {
          "config": {
            "destIpRanges": ["0.0.0.0/0"],
            "layer4Configs": [
              {
                "ipProtocol": "all"
              }
            ]
          },
          "versionedExpr": "FIREWALL"
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
    "displayName": "displayname",
    "type": "FIREWALL",
    "rules": [
      {
        "action": "goto_next",
        "description": "allow-traffic-to-port: Generic description",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp",
                "ports": ["80"]
              }
            ],
            "srcIpRanges": ["10.1.1.0/24"]
          },
          "versionedExpr": "FIREWALL"
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
    'option',
    'protocol',
    'source_address',
    'source_port',
    'source_tag',
    'stateless_reply',
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
ALL_IPS = [nacaddr.IP('0.0.0.0/0')]


class GcpHfTest(parameterized.TestCase):

  def setUp(self):
    super(GcpHfTest, self).setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def _StripAclHeaders(self, acl):
    return '\n'.join([line for line in str(acl).split('\n')
                      if not line.lstrip().startswith('#')])

  def testDefaultHeader(self):
    """Test that a header without options is accepted."""
    self.naming.GetNetAddr.return_value = ALL_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_ALLOW_ALL_INTERNAL,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_ONE_RULE_INGRESS)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testOptionMaxHeader(self):
    """Test that a header with a default maximum cost is accepted."""
    self.naming.GetNetAddr.return_value = ALL_IPS

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
    self.naming.GetNetAddr.return_value = ALL_IPS

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
    self.naming.GetNetAddr.return_value = ALL_IPS

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

  def testRaisesHeaderErrorOnLongDisplayName(self):
    """Test that a long displayName raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(BAD_HEADER_LONG_DISPLAYNAME
                             + TERM_ALLOW_ALL_INTERNAL,
                             self.naming),
          EXP_INFO)

  def testRaisesHeaderErrorOnHeaderWithoutDisplayName(self):
    """Test that a header without a policy name raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(BAD_HEADER_NO_DISPLAYNAME
                             + TERM_ALLOW_ALL_INTERNAL, self.naming),
          EXP_INFO)

  def testRaisesHeaderErrorOnIncorrectDisplayName1(self):
    """Test that an invalid displayName raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(BAD_HEADER_INVALID_DISPLAYNAME_1
                             + TERM_ALLOW_ALL_INTERNAL,
                             self.naming),
          EXP_INFO)

  def testRaisesHeaderErrorOnIncorrectDisplayName2(self):
    """Test that an invalid displayName raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(BAD_HEADER_INVALID_DISPLAYNAME_2
                             + TERM_ALLOW_ALL_INTERNAL,
                             self.naming),
          EXP_INFO)

  def testRaisesHeaderErrorOnIncorrectDisplayName3(self):
    """Test that an invalid displayName raises a HeaderError."""
    with self.assertRaises(gcp.HeaderError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(BAD_HEADER_INVALID_DISPLAYNAME_3
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

  def testRaisesTermErrorOnTermWithSourcePort(self):
    """Test that a term with a source port raises Term error."""
    self.naming.GetNetAddr.return_value = TEST_IP
    self.naming.GetServiceByProto.side_effect = [['53']]

    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_SOURCE_PORT,
                             self.naming),
          EXP_INFO)

  def testRaisesTermErrorOnTermWithOptions(self):
    """Test that a term with a source port raises Term error."""
    self.naming.GetNetAddr.return_value = TEST_IP

    with self.assertRaises(gcp.TermError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + BAD_TERM_OPTIONS,
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

  def testRaisesDifferentPolicyNameErrorWhenDifferentPolicyNames(self):
    """Test that different policy names raises DifferentPolicyNameError."""
    with self.assertRaises(gcp_hf.DifferentPolicyNameError):
      gcp_hf.HierarchicalFirewall(
          policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_DENY_INGRESS
                             + HEADER_OPTION_EGRESS_2 + TERM_DENY_EGRESS,
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

  def testIgnoreTermWithICMPv6(self):
    """Test that a term with only an icmpv6 protocol is not rendered."""
    self.naming.GetNetAddr.return_value = TEST_IP

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_OPTION_AF
                           + BAD_TERM_IP_VERSION_MISMATCH,
                           self.naming),
        EXP_INFO)
    exp = [{'displayName': 'displayname', 'rules': [{}], 'type': 'FIREWALL'}]
    self.assertEqual(exp, json.loads(self._StripAclHeaders(str(acl))))

  def testPriority(self):
    """Test that priority is set based on terms' ordering."""
    self.naming.GetNetAddr.return_value = ALL_IPS
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

  def testMultiplePolicies(self):
    """Tests that both ingress and egress rules are included in one policy."""
    self.maxDiff = None
    self.naming.GetNetAddr.return_value = ALL_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_ALLOW_ALL_INTERNAL +
                           TERM_DENY_INGRESS + HEADER_OPTION_EGRESS +
                           TERM_RESTRICT_EGRESS + TERM_DENY_EGRESS,
                           self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_INGRESS_AND_EGRESS_W_DENY)
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
    """Test that a term's long comment gets truncated and prefixed with term name."""
    self.naming.GetNetAddr.return_value = ALL_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_LONG_COMMENT,
                           self.naming),
        EXP_INFO)
    comment_truncated = EXPECTED_ONE_RULE_INGRESS.replace(
        'Generic description',
        'This is a very long description, it is l')
    expected = json.loads(comment_truncated)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testDefaultDenyIngressCreation(self):
    """Test that the correct IP is correctly set on a deny all ingress term."""
    self.naming.GetNetAddr.return_value = ALL_IPS

    acl = gcp_hf.HierarchicalFirewall(
        policy.ParsePolicy(HEADER_NO_OPTIONS + TERM_DENY_INGRESS, self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_DENY_INGRESS)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testDefaultDenyEgressCreation(self):
    """Test that the correct IP is correctly set on a deny all egress term."""
    self.naming.GetNetAddr.return_value = ALL_IPS

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

  @parameterized.named_parameters(
      ('1 ip, 2 protocols',
       {'match': {
           'config': {
               'destIpRanges': ['0.0.0.0/0'],
               'layer4Configs': [
                   {'ipProtocol': 'tcp'},
                   {'ipProtocol': 'icmp'}
               ]
           }
       }}, 2),
      ('1 ip, 3 protocols, ',
       {'match': {
           'config': {
               'srcIpRanges': ['0.0.0.0/0'],
               'layer4Configs': [
                   {'ipProtocol': 'tcp'},
                   {'ipProtocol': 'icmp'},
                   {'ipProtocol': 'udp'}
               ]
           }
       }}, 3),
      ('1 ip, 1 protocol with 1 port',
       {'match': {
           'config': {
               'srcIpRanges': ['0.0.0.0/0'],
               'layer4Configs': [
                   {'ipProtocol': 'tcp', 'ports': ['22']}
               ]
           }
       }}, 1),
      ('1 ip, 2 protocols with 2 ports each',
       {'match': {
           'config': {
               'srcIpRanges': ['0.0.0.0/0'],
               'layer4Configs': [
                   {'ipProtocol': 'tcp', 'ports': ['22']},
                   {'ipProtocol': 'udp', 'ports': ['22']}
               ]
           }
       }}, 2),
      ('1 ip, 1 protocol with 2 ports',
       {'match': {
           'config': {
               'srcIpRanges': ['0.0.0.0/0'],
               'layer4Configs': [
                   {'ipProtocol': 'tcp', 'ports': ['22', '23']}
               ]
           }
       }}, 2),
      ('2 ips, 1 protocol with 2 ports',
       {'match': {
           'config': {
               'srcIpRanges': ['1.4.6.8/10', '1.2.3.4/5'],
               'layer4Configs': [
                   {'ipProtocol': 'tcp', 'ports': ['22', '23']}
               ]
           }
       }}, 4),
      ('2 ips, 2 protocols with 2 ports each',
       {'match': {
           'config': {
               'srcIpRanges': ['1.4.6.8/10', '1.2.3.4/5'],
               'layer4Configs': [
                   {'ipProtocol': 'tcp', 'ports': ['22', '23']},
                   {'ipProtocol': 'udp', 'ports': ['22', '23']}
               ]
           }
       }}, 8)
  )
  def testGetCost(self, dict_term, expected):
    self.assertEqual(gcp_hf.GetCost(dict_term), expected)


if __name__ == '__main__':
  unittest.main()
