"""Tests for google3.third_party.py.capirca.lib.cloudarmor."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import json
import random
import unittest

from capirca.lib import cloudarmor
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy
import mock

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'priority',
    'source_address'
}

EXP_INFO = 2

GOOD_HEADER = """
header {
  comment:: "Test ACL for CloudArmor (IPv4)"
  target:: cloudarmor inet
}
"""

GOOD_HEADER_IPV6_ONLY = """
header {
  comment:: "Test ACL for CloudArmor (IPv6 only)"
  target:: cloudarmor inet6
}
"""

GOOD_HEADER_NOVERBOSE = """
header {
  comment:: "Test ACL for CloudArmor (IPv4)"
  target:: cloudarmor inet noverbose
}
"""

GOOD_HEADER_MIXED = """
header {
  comment:: "Test ACL for CloudArmor (IPv4 + IPv6)"
  target:: cloudarmor mixed
}
"""

GOOD_HEADER_NO_AF = """
header {
  comment:: "Test ACL for CloudArmor (Default AF = IPv4)"
  target:: cloudarmor
}
"""

BAD_HEADER_INVALID_AF = """
header {
  comment:: "Test ACL for CloudArmor (IPv4 + IPv6)"
  target:: cloudarmor inet8
}
"""

GOOD_TERM_ALLOW = """
term good-term-allow {
  comment:: "Sample CloudArmor Allow Rule"
  source-address:: GOOGLE_PUBLIC_DNS_ANYCAST
  action:: accept
}
"""
GOOD_TERM_DENY = """
term good-term-deny {
  comment:: "Sample Deny Rule"
  source-address:: INTERNAL
  action:: deny
}
"""

GOOD_TERM_NO_COMMENT = """
term good-term-nocomment {
  source-address:: GOOGLE_PUBLIC_DNS_ANYCAST
  action:: accept
}
"""

GOOD_TERM_LARGE_COMMENT = """
term good-term-allow {
  comment:: "This is an unnecessarily long term comment that's going to be truncated"
  source-address:: GOOGLE_PUBLIC_DNS_ANYCAST
  action:: accept
}
"""

BAD_TERM_NO_ACTION = """
term bad-term-no-action {
  comment:: "Sample rule with missing 'action' attribute"
  source-address:: GOOGLE_PUBLIC_DNS_ANYCAST
}
"""


EXPECTED_IPV4_NOSPLIT_JSON = """
[
  {
    "action": "allow",
    "description": "Sample CloudArmor Allow Rule",
    "match": {
      "config": {
        "srcIpRanges": [
          "10.2.3.4/32"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 1
  },
  {
    "action": "deny(404)",
    "description": "Sample Deny Rule",
    "match": {
      "config": {
        "srcIpRanges": [
          "10.2.3.4/32"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 2
  }
]
"""

EXPECTED_IPV6_NOSPLIT_JSON = """
[
  {
    "action": "allow",
    "description": "Sample CloudArmor Allow Rule",
    "match": {
      "config": {
        "srcIpRanges": [
          "2001:4860:8000::5/128"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 1
  },
  {
    "action": "deny(404)",
    "description": "Sample Deny Rule",
    "match": {
      "config": {
        "srcIpRanges": [
          "2001:4860:8000::5/128"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 2
  }
]

"""

EXPECTED_MIXED_NOSPLIT_JSON = """
[
  {
    "action": "allow",
    "description": "Sample CloudArmor Allow Rule",
    "match": {
      "config": {
        "srcIpRanges": [
          "10.2.3.4/32",
          "2001:4860:8000::5/128"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 1
  },
  {
    "action": "deny(404)",
    "description": "Sample Deny Rule",
    "match": {
      "config": {
        "srcIpRanges": [
          "10.2.3.4/32",
          "2001:4860:8000::5/128"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 2
  }
]

"""

EXPECTED_IPV4_SPLIT_JSON = """
[
  {
    "action": "allow",
    "description": "Sample CloudArmor Allow Rule [1/2]",
    "match": {
      "config": {
        "srcIpRanges": [
          "5.2.3.2/32",
          "10.2.3.4/32",
          "23.2.3.3/32",
          "54.2.3.4/32",
          "76.2.3.5/32"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 1
  },
  {
    "action": "allow",
    "description": "Sample CloudArmor Allow Rule [2/2]",
    "match": {
      "config": {
        "srcIpRanges": [
          "132.2.3.6/32",
          "197.2.3.7/32"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 2
  },
  {
    "action": "deny(404)",
    "description": "Sample Deny Rule [1/2]",
    "match": {
      "config": {
        "srcIpRanges": [
          "5.2.3.2/32",
          "10.2.3.4/32",
          "23.2.3.3/32",
          "54.2.3.4/32",
          "76.2.3.5/32"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 3
  },
  {
    "action": "deny(404)",
    "description": "Sample Deny Rule [2/2]",
    "match": {
      "config": {
        "srcIpRanges": [
          "132.2.3.6/32",
          "197.2.3.7/32"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 4
  }
]

"""

EXPECTED_IPV6_SPLIT_JSON = """
[
  {
    "action": "allow",
    "description": "Sample CloudArmor Allow Rule [1/2]",
    "match": {
      "config": {
        "srcIpRanges": [
          "2001:4860:8000::5/128",
          "24da:3ed8:32a0::7/128",
          "3051:abd2:5400::9/128",
          "577e:5400:3051::6/128",
          "6f5d:abd2:1403::1/128"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 1
  },
  {
    "action": "allow",
    "description": "Sample CloudArmor Allow Rule [2/2]",
    "match": {
      "config": {
        "srcIpRanges": [
          "aee2:37ba:3cc0::3/128",
          "af22:32d2:3f00::2/128"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 2
  },
  {
    "action": "deny(404)",
    "description": "Sample Deny Rule [1/2]",
    "match": {
      "config": {
        "srcIpRanges": [
          "2001:4860:8000::5/128",
          "24da:3ed8:32a0::7/128",
          "3051:abd2:5400::9/128",
          "577e:5400:3051::6/128",
          "6f5d:abd2:1403::1/128"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 3
  },
  {
    "action": "deny(404)",
    "description": "Sample Deny Rule [2/2]",
    "match": {
      "config": {
        "srcIpRanges": [
          "aee2:37ba:3cc0::3/128",
          "af22:32d2:3f00::2/128"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 4
  }
]

"""

EXPECTED_MIXED_SPLIT_JSON = """
[
  {
    "action": "allow",
    "description": "Sample CloudArmor Allow Rule [1/3]",
    "match": {
      "config": {
        "srcIpRanges": [
          "5.2.3.2/32",
          "10.2.3.4/32",
          "23.2.3.3/32",
          "54.2.3.4/32",
          "76.2.3.5/32"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 1
  },
  {
    "action": "allow",
    "description": "Sample CloudArmor Allow Rule [2/3]",
    "match": {
      "config": {
        "srcIpRanges": [
          "132.2.3.6/32",
          "197.2.3.7/32",
          "2001:4860:8000::5/128",
          "24da:3ed8:32a0::7/128",
          "3051:abd2:5400::9/128"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 2
  },
  {
    "action": "allow",
    "description": "Sample CloudArmor Allow Rule [3/3]",
    "match": {
      "config": {
        "srcIpRanges": [
          "577e:5400:3051::6/128",
          "6f5d:abd2:1403::1/128",
          "aee2:37ba:3cc0::3/128",
          "af22:32d2:3f00::2/128"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 3
  },
  {
    "action": "deny(404)",
    "description": "Sample Deny Rule [1/3]",
    "match": {
      "config": {
        "srcIpRanges": [
          "5.2.3.2/32",
          "10.2.3.4/32",
          "23.2.3.3/32",
          "54.2.3.4/32",
          "76.2.3.5/32"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 4
  },
  {
    "action": "deny(404)",
    "description": "Sample Deny Rule [2/3]",
    "match": {
      "config": {
        "srcIpRanges": [
          "132.2.3.6/32",
          "197.2.3.7/32",
          "2001:4860:8000::5/128",
          "24da:3ed8:32a0::7/128",
          "3051:abd2:5400::9/128"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 5
  },
  {
    "action": "deny(404)",
    "description": "Sample Deny Rule [3/3]",
    "match": {
      "config": {
        "srcIpRanges": [
          "577e:5400:3051::6/128",
          "6f5d:abd2:1403::1/128",
          "aee2:37ba:3cc0::3/128",
          "af22:32d2:3f00::2/128"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 6
  }
]

"""

EXPECTED_NOCOMMENT_SPLIT_JSON = """
[
  {
    "action": "allow",
    "description": " [1/2]",
    "match": {
      "config": {
        "srcIpRanges": [
          "5.2.3.2/32",
          "10.2.3.4/32",
          "23.2.3.3/32",
          "54.2.3.4/32",
          "76.2.3.5/32"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 1
  },
  {
    "action": "allow",
    "description": " [2/2]",
    "match": {
      "config": {
        "srcIpRanges": [
          "132.2.3.6/32",
          "197.2.3.7/32"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 2
  }
]

"""

EXPECTED_NOCOMMENT_NOSPLIT_JSON = """
[
  {
    "action": "allow",
    "match": {
      "config": {
        "srcIpRanges": [
          "10.2.3.4/32"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 1
  }
]
"""

EXPECTED_LARGECOMMENT_NOSPLIT_JSON = """
[
  {
    "action": "allow",
    "description": "This is an unnecessarily long term comment that's going to be tr",
    "match": {
      "config": {
        "srcIpRanges": [
          "10.2.3.4/32"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 1
  }
]
"""

EXPECTED_LARGECOMMENT_SPLIT_JSON = """
[
  {
    "action": "allow",
    "description": "This is an unnecessarily long term comment that's going to [1/2]",
    "match": {
      "config": {
        "srcIpRanges": [
          "5.2.3.2/32",
          "10.2.3.4/32",
          "23.2.3.3/32",
          "54.2.3.4/32",
          "76.2.3.5/32"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 1
  },
  {
    "action": "allow",
    "description": "This is an unnecessarily long term comment that's going to [2/2]",
    "match": {
      "config": {
        "srcIpRanges": [
          "132.2.3.6/32",
          "197.2.3.7/32"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 2
  }
]
"""

TEST_IPS_NOSPLIT = [nacaddr.IP('10.2.3.4/32'),
                    nacaddr.IP('2001:4860:8000::5/128')]

TEST_IPS_SPLIT = [nacaddr.IP('10.2.3.4/32'),
                  nacaddr.IP('5.2.3.2/32'),
                  nacaddr.IP('23.2.3.3/32'),
                  nacaddr.IP('54.2.3.4/32'),
                  nacaddr.IP('76.2.3.5/32'),
                  nacaddr.IP('132.2.3.6/32'),
                  nacaddr.IP('197.2.3.7/32'),
                  nacaddr.IP('2001:4860:8000::5/128'),
                  nacaddr.IP('3051:abd2:5400::9/128'),
                  nacaddr.IP('aee2:37ba:3cc0::3/128'),
                  nacaddr.IP('6f5d:abd2:1403::1/128'),
                  nacaddr.IP('577e:5400:3051::6/128'),
                  nacaddr.IP('af22:32d2:3f00::2/128'),
                  nacaddr.IP('24da:3ed8:32a0::7/128')]


class CloudArmorTest(unittest.TestCase):

  def setUp(self):
    super(CloudArmorTest, self).setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def _StripAclHeaders(self, acl):
    return '\n'.join([line for line in str(acl).split('\n')
                      if not line.lstrip().startswith('#')])

  def testGenericIPv4Term(self):
    self.naming.GetNetAddr.return_value = TEST_IPS_NOSPLIT

    acl = cloudarmor.CloudArmor(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_ALLOW + GOOD_TERM_DENY,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_IPV4_NOSPLIT_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testGenericIPv6Term(self):
    self.naming.GetNetAddr.return_value = TEST_IPS_NOSPLIT

    acl = cloudarmor.CloudArmor(
        policy.ParsePolicy(
            GOOD_HEADER_IPV6_ONLY + GOOD_TERM_ALLOW + GOOD_TERM_DENY,
            self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_IPV6_NOSPLIT_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testGenericMixedTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS_NOSPLIT

    acl = cloudarmor.CloudArmor(
        policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM_ALLOW + GOOD_TERM_DENY,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_MIXED_NOSPLIT_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testDefaultAddressFamily(self):
    self.naming.GetNetAddr.return_value = TEST_IPS_NOSPLIT

    acl = cloudarmor.CloudArmor(
        policy.ParsePolicy(GOOD_HEADER_NO_AF + GOOD_TERM_ALLOW + GOOD_TERM_DENY,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_IPV4_NOSPLIT_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testIPv4TermSplitting(self):
    self.naming.GetNetAddr.return_value = TEST_IPS_SPLIT

    acl = cloudarmor.CloudArmor(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_ALLOW + GOOD_TERM_DENY,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_IPV4_SPLIT_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testIPv6TermSplitting(self):
    self.naming.GetNetAddr.return_value = TEST_IPS_SPLIT

    acl = cloudarmor.CloudArmor(
        policy.ParsePolicy(
            GOOD_HEADER_IPV6_ONLY + GOOD_TERM_ALLOW + GOOD_TERM_DENY,
            self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_IPV6_SPLIT_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testMixedTermSplitting(self):
    self.naming.GetNetAddr.return_value = TEST_IPS_SPLIT

    acl = cloudarmor.CloudArmor(
        policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM_ALLOW + GOOD_TERM_DENY,
                           self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_MIXED_SPLIT_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testInvalidAddressFamilyCheck(self):

    self.naming.GetNetAddr.return_value = TEST_IPS_NOSPLIT

    self.assertRaisesRegex(
        cloudarmor.UnsupportedFilterTypeError,
        "'inet8' is not a valid filter type",
        cloudarmor.CloudArmor,
        policy.ParsePolicy(
            BAD_HEADER_INVALID_AF + GOOD_TERM_ALLOW, self.naming),
        EXP_INFO)

  def testMaxRuleLimitEnforcement(self):
    test_1001_ips_list = []

    for _ in range(1001):
      random_ip_octets = []
      for _ in range(4):
        random_ip_octets.append(str(int(random.randint(1, 255))))
      rand_ip = '.'.join(random_ip_octets)
      test_1001_ips_list.append(nacaddr.IP(rand_ip + '/32'))

    self.naming.GetNetAddr.return_value = test_1001_ips_list

    self.assertRaisesRegex(
        cloudarmor.ExceededMaxTermsError,
        'Exceeded maximum number of rules in a single policy | MAX = 200',
        cloudarmor.CloudArmor,
        policy.ParsePolicy(
            GOOD_HEADER + GOOD_TERM_ALLOW, self.naming),
        EXP_INFO)

  def testNoCommentWithSplit(self):
    self.naming.GetNetAddr.return_value = TEST_IPS_SPLIT

    acl = cloudarmor.CloudArmor(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_NO_COMMENT, self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_NOCOMMENT_SPLIT_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testNoCommentWithoutSplit(self):
    self.naming.GetNetAddr.return_value = TEST_IPS_NOSPLIT

    acl = cloudarmor.CloudArmor(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_NO_COMMENT, self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_NOCOMMENT_NOSPLIT_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testLargeCommentWithSplit(self):
    self.naming.GetNetAddr.return_value = TEST_IPS_SPLIT

    acl = cloudarmor.CloudArmor(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_LARGE_COMMENT, self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_LARGECOMMENT_SPLIT_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testLargeCommentWithoutSplit(self):
    self.naming.GetNetAddr.return_value = TEST_IPS_NOSPLIT

    acl = cloudarmor.CloudArmor(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_LARGE_COMMENT, self.naming),
        EXP_INFO)
    expected = json.loads(EXPECTED_LARGECOMMENT_NOSPLIT_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

  def testNoVerbose(self):
    self.naming.GetNetAddr.return_value = TEST_IPS_NOSPLIT

    acl = cloudarmor.CloudArmor(
        policy.ParsePolicy(GOOD_HEADER_NOVERBOSE + GOOD_TERM_LARGE_COMMENT,
                           self.naming), EXP_INFO)
    self.assertNotIn('description', str(acl))


if __name__ == '__main__':
  unittest.main()
