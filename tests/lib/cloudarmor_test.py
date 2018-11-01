

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import re
import unittest
import json

from capirca.lib import cloudarmor
from capirca.lib import naming
from capirca.lib import nacaddr
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

GOOD_TERM_JSON = """
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

TEST_IPS = [nacaddr.IP('10.2.3.4/32'),
            nacaddr.IP('2001:4860:8000::5/128')]

class CloudArmorTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def _StripAclHeaders(self, acl):
    return '\n'.join([line for line in str(acl).split('\n')
                      if not line.lstrip().startswith('#')])

  def testGenericTerm(self):
    self.naming.GetNetAddr.return_value = TEST_IPS

    acl = cloudarmor.CloudArmor(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_ALLOW + GOOD_TERM_DENY, self.naming), EXP_INFO)
    expected = json.loads(GOOD_TERM_JSON)
    self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))
    #print(acl)


if __name__ == '__main__':
  unittest.main()

