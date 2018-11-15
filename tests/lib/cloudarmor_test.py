

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import json
import unittest
import random


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
  comment:: "Test ACL for CloudArmor"
  target:: cloudarmor ca-test-filter inet
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

EXPECTED_NOSPLIT_JSON = """
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

EXPECTED_SPLIT_JSON = """
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

TEST_IPS_NOSPLIT = [nacaddr.IP('10.2.3.4/32'),
                    nacaddr.IP('2001:4860:8000::5/128')]

TEST_IPS_SPLIT = [nacaddr.IP('10.2.3.4/32'),
                  nacaddr.IP('5.2.3.2/32'),
                  nacaddr.IP('23.2.3.3/32'),
                  nacaddr.IP('54.2.3.4/32'),
                  nacaddr.IP('76.2.3.5/32'),
                  nacaddr.IP('132.2.3.6/32'),
                  nacaddr.IP('197.2.3.7/32'),
                  nacaddr.IP('2001:4860:8000::5/128')]


class CloudArmorTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def _StripAclHeaders(self, acl):
    return '\n'.join([line for line in str(acl).split('\n')
                      if not line.lstrip().startswith('#')])

  def testGenericTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS_NOSPLIT

    acl = cloudarmor.CloudArmor(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_ALLOW + GOOD_TERM_DENY, self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_NOSPLIT_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))
    print(acl)

  def testTermSplitting(self):
    self.naming.GetNetAddr.return_value = TEST_IPS_SPLIT

    acl = cloudarmor.CloudArmor(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_ALLOW + GOOD_TERM_DENY, self.naming), EXP_INFO)
    expected = json.loads(EXPECTED_SPLIT_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))
    print(acl)

  def testMaxRuleLimitEnforcement(self):
    TEST_1001_IPs_LIST = []

    for i in range(1001):
      random_ip_octets = []
      for j in range(4):
        random_ip_octets.append(str(int(random.randint(1, 255))))
      rand_ip = '.'.join(random_ip_octets)
      TEST_1001_IPs_LIST.append(nacaddr.IP(rand_ip + '/32'))

    self.naming.GetNetAddr.return_value = TEST_1001_IPs_LIST

    self.assertRaisesRegexp(
        cloudarmor.ExceededMaxTermsError,
        'Exceeded maximum number of rules in a single policy | MAX = 200',
        cloudarmor.CloudArmor,
        policy.ParsePolicy(
            GOOD_HEADER + GOOD_TERM_ALLOW, self.naming),
        EXP_INFO)

if __name__ == '__main__':
  unittest.main()

