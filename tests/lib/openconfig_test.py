# Copyright 2021 Google Inc. All Rights Reserved.
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

"""Unittest for OpenConfig rendering module."""

import json
from absl.testing import absltest
from unittest import mock

from absl.testing import parameterized
from capirca.lib import aclgenerator
from capirca.lib import openconfig
from capirca.lib import gcp
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy

GOOD_HEADER = """
header {
  comment:: "The general policy comment."
  target:: openconfig test-filter inet
}
"""

GOOD_SADDR = """
term good-term-1 {
  comment:: "Allow source address."
  source-address:: CORP_EXTERNAL
  action:: accept
}
"""

GOOD_DADDR = """
term good-term-1 {
  comment:: "Allow destination address."
  destination-address:: CORP_EXTERNAL
  action:: accept
}
"""

GOOD_SPORT = """
term good-term-1 {
  comment:: "Allow TCP 53 source."
  source-port:: DNS
  protocol:: tcp
  action:: accept
}
"""

GOOD_DPORT = """
term good-term-1 {
  comment:: "Allow TCP 53 dest."
  destination-port:: DNS
  protocol:: tcp
  action:: accept
}
"""

GOOD_MULTI_PROTO_DPORT = """
term good-term-1 {
  comment:: "Allow TCP & UDP 53."
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""

GOOD_EVERYTHING = """
term good-term-1 {
  comment:: "Allow TCP & UDP 53 with saddr/daddr."
  destination-address:: CORP_EXTERNAL
  source-address:: CORP_EXTERNAL
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""

PLATFORM_EXCLUDE = """
term excluded-term-2 {
  comment:: "Allow TCP & UDP 53 with saddr/daddr."
  source-address:: CORP_INTERNAL
  action:: accept
  platform-exclude:: openconfig
}
"""

PLATFORM_EXCLUDE_NOTOC = """
term not-excluded-term-1 {
  comment:: "Allow TCP & UDP 53 with saddr/daddr."
  source-address:: CORP_EXTERNAL
  action:: accept
  platform-exclude:: juniper
}
"""

PLATFORM_OC = """
term platform-term-1 {
  comment:: "Allow TCP & UDP 53 with saddr/daddr."
  source-address:: CORP_EXTERNAL
  action:: accept
  platform:: openconfig
}
"""

PLATFORM_NOTOC = """
term not-excluded-term-1 {
  comment:: "Allow TCP & UDP 53 with saddr/daddr."
  source-address:: CORP_EXTERNAL
  action:: accept
  platform:: juniper
}
"""

GOOD_JSON_SADDR = """
{
  "acl-sets": {
    "acl-set": [
      {
        "acl-entries": {
          "acl-entry": [
            {
              "actions": {
                "config": {
                  "forwarding-action": "ACCEPT"
                }
              },
              "config": {
                "description": "[good-term-1]: Allow source address.",
                "sequence-id": 1
              },
              "ipv4": {
                "config": {
                  "source-address": "10.2.3.4/32"
                }
              },
              "sequence-id": 1
            }
          ]
        },
        "config": {
          "name": "test-filter",
          "type": "ACL_IPV4"
        },
        "name": "test-filter",
        "type": "ACL_IPV4"
      }
    ]
  }
}
"""

GOOD_JSON_SADDR_NOTOC = """
{
  "acl-sets": {
    "acl-set": [
      {
        "acl-entries": {
          "acl-entry": [
            {
              "actions": {
                "config": {
                  "forwarding-action": "ACCEPT"
                }
              },
              "config": {
                "description": "[not-excluded-term-1]: Allow TCP & UDP 53 with saddr/daddr.",
                "sequence-id": 1
              },
              "ipv4": {
                "config": {
                  "source-address": "10.2.3.4/32"
                }
              },
              "sequence-id": 1
            }
          ]
        },
        "config": {
          "name": "test-filter",
          "type": "ACL_IPV4"
        },
        "name": "test-filter",
        "type": "ACL_IPV4"
      }
    ]
  }
}
"""

GOOD_JSON_SADDR_PLATFORM_OC = """
{
  "acl-sets": {
    "acl-set": [
      {
        "acl-entries": {
          "acl-entry": [
            {
              "actions": {
                "config": {
                  "forwarding-action": "ACCEPT"
                }
              },
              "config": {
                "description": "[platform-term-1]: Allow TCP & UDP 53 with saddr/daddr.",
                "sequence-id": 1
              },
              "ipv4": {
                "config": {
                  "source-address": "10.2.3.4/32"
                }
              },
              "sequence-id": 1
            }
          ]
        },
        "config": {
          "name": "test-filter",
          "type": "ACL_IPV4"
        },
        "name": "test-filter",
        "type": "ACL_IPV4"
      }
    ]
  }
}
"""

GOOD_JSON_V6_SADDR = """
{
  "acl-sets": {
    "acl-set": [
      {
        "acl-entries": {
          "acl-entry": [
            {
              "actions": {
                "config": {
                  "forwarding-action": "ACCEPT"
                }
              },
              "config": {
                "description": "[good-term-1]: Allow source address.",
                "sequence-id": 1
              },
              "ipv6": {
                "config": {
                  "source-address": "2001:4860:8000::5/128"
                }
              },
              "sequence-id": 1
            }
          ]
        },
        "config": {
          "name": "test-v6-filter",
          "type": "ACL_IPV6"
        },
        "name": "test-v6-filter",
        "type": "ACL_IPV6"
      }
    ]
  }
}
"""

GOOD_JSON_DADDR = """
{
  "acl-sets": {
    "acl-set": [
      {
        "acl-entries": {
          "acl-entry": [
            {
              "actions": {
                "config": {
                  "forwarding-action": "ACCEPT"
                }
              },
              "config": {
                "description": "[good-term-1]: Allow destination address.",
                "sequence-id": 1
              },
              "ipv4": {
                "config": {
                  "destination-address": "10.2.3.4/32"
                }
              },
              "sequence-id": 1
            }
          ]
        },
        "config": {
          "name": "test-filter",
          "type": "ACL_IPV4"
        },
        "name": "test-filter",
        "type": "ACL_IPV4"
      }
    ]
  }
}
"""

GOOD_JSON_V6_DADDR = """
{
  "acl-sets": {
    "acl-set": [
      {
        "acl-entries": {
          "acl-entry": [
            {
              "actions": {
                "config": {
                  "forwarding-action": "ACCEPT"
                }
              },
              "config": {
                "description": "[good-term-1]: Allow destination address.",
                "sequence-id": 1
              },
              "ipv6": {
                "config": {
                  "destination-address": "2001:4860:8000::5/128"
                }
              },
              "sequence-id": 1
            }
          ]
        },
        "config": {
          "name": "test-v6-filter",
          "type": "ACL_IPV6"
        },
        "name": "test-v6-filter",
        "type": "ACL_IPV6"
      }
    ]
  }
}
"""

GOOD_JSON_MIXED_DADDR = """
{
  "acl-sets": {
    "acl-set": [
      {
        "acl-entries": {
          "acl-entry": [
            {
              "actions": {
                "config": {
                  "forwarding-action": "ACCEPT"
                }
              },
              "config": {
                "description": "[good-term-1]: Allow destination address.",
                "sequence-id": 1
              },
              "ipv4": {
                "config": {
                  "destination-address": "10.2.3.4/32"
                }
              },
              "sequence-id": 1
            }
          ]
        },
        "config": {
          "name": "test-mixed-filter4",
          "type": "ACL_IPV4"
        },
        "name": "test-mixed-filter4",
        "type": "ACL_IPV4"
      },
      {
        "acl-entries": {
          "acl-entry": [
            {
              "actions": {
                "config": {
                  "forwarding-action": "ACCEPT"
                }
              },
              "config": {
                "description": "[good-term-1]: Allow destination address.",
                "sequence-id": 2
              },
              "ipv6": {
                "config": {
                  "destination-address": "2001:4860:8000::5/128"
                }
              },
              "sequence-id": 2
            }
          ]
        },
        "config": {
          "name": "test-mixed-filter6",
          "type": "ACL_IPV6"
        },
        "name": "test-mixed-filter6",
        "type": "ACL_IPV6"
      }
    ]
  }
}
"""

GOOD_JSON_SPORT = """
{
  "acl-sets": {
    "acl-set": [
      {
        "acl-entries": {
          "acl-entry": [
            {
              "actions": {
                "config": {
                  "forwarding-action": "ACCEPT"
                }
              },
              "config": {
                "description": "[good-term-1]: Allow TCP 53 source.",
                "sequence-id": 1
              },
              "ipv4": {
                "config": {
                  "protocol": 6
                }
              },
              "sequence-id": 1,
              "transport": {
                "config": {
                  "source-port": 53
                }
              }
            }
          ]
        },
        "config": {
          "name": "test-filter",
          "type": "ACL_IPV4"
        },
        "name": "test-filter",
        "type": "ACL_IPV4"
      }
    ]
  }
}
"""

GOOD_JSON_DPORT = """
{
  "acl-sets": {
    "acl-set": [
      {
        "acl-entries": {
          "acl-entry": [
            {
              "actions": {
                "config": {
                  "forwarding-action": "ACCEPT"
                }
              },
              "config": {
                "description": "[good-term-1]: Allow TCP 53 dest.",
                "sequence-id": 1
              },
              "ipv4": {
                "config": {
                  "protocol": 6
                }
              },
              "sequence-id": 1,
              "transport": {
                "config": {
                  "destination-port": 53
                }
              }
            }
          ]
        },
        "config": {
          "name": "test-filter",
          "type": "ACL_IPV4"
        },
        "name": "test-filter",
        "type": "ACL_IPV4"
      }
    ]
  }
}
"""

GOOD_JSON_EVERYTHING = """
{
  "acl-sets": {
    "acl-set": [
      {
        "acl-entries": {
          "acl-entry": [
            {
              "actions": {
                "config": {
                  "forwarding-action": "ACCEPT"
                }
              },
              "config": {
                "description": "[good-term-1]: Allow TCP & UDP 53 with saddr/daddr.",
                "sequence-id": 1
              },
              "ipv4": {
                "config": {
                  "destination-address": "10.2.3.4/32",
                  "protocol": 17,
                  "source-address": "10.2.3.4/32"
                }
              },
              "sequence-id": 1,
              "transport": {
                "config": {
                  "destination-port": 53
                }
              }
            },
            {
              "actions": {
                "config": {
                  "forwarding-action": "ACCEPT"
                }
              },
              "config": {
                "description": "[good-term-1]: Allow TCP & UDP 53 with saddr/daddr.",
                "sequence-id": 2
              },
              "ipv4": {
                "config": {
                  "destination-address": "10.2.3.4/32",
                  "protocol": 6,
                  "source-address": "10.2.3.4/32"
                }
              },
              "sequence-id": 2,
              "transport": {
                "config": {
                  "destination-port": 53
                }
              }
            }
          ]
        },
        "config": {
          "name": "test-filter",
          "type": "ACL_IPV4"
        },
        "name": "test-filter",
        "type": "ACL_IPV4"
      }
    ]
  }
}
"""

GOOD_HEADER_INET6 = """
header {
  comment:: "The general policy comment."
  target:: openconfig test-v6-filter inet6
}
"""

GOOD_HEADER_MIXED = """
header {
  comment:: "The general policy comment."
  target:: openconfig test-mixed-filter mixed
}
"""

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2

TEST_IPS = [nacaddr.IP('10.2.3.4/32'),
            nacaddr.IP('2001:4860:8000::5/128')]


_TERM_SOURCE_TAGS_LIMIT = 30
_TERM_TARGET_TAGS_LIMIT = 70
_TERM_PORTS_LIMIT = 256


class OpenConfigTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def testSaddr(self):
    self.naming.GetNetAddr.return_value = TEST_IPS

    acl = openconfig.OpenConfig(policy.ParsePolicy(
        GOOD_HEADER + GOOD_SADDR, self.naming), EXP_INFO)
    expected = json.loads(GOOD_JSON_SADDR)
    self.assertEqual(expected, json.loads(str(acl)))

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')

  def testPlatformExclude(self):
    self.naming.GetNetAddr.return_value = TEST_IPS

    acl = openconfig.OpenConfig(
        policy.ParsePolicy(GOOD_HEADER + GOOD_SADDR + PLATFORM_EXCLUDE,
                           self.naming), EXP_INFO)
    expected = json.loads(GOOD_JSON_SADDR)
    self.assertEqual(expected, json.loads(str(acl)))

  def testPlatformExcludeNoTOC(self):
    self.naming.GetNetAddr.return_value = TEST_IPS

    acl = openconfig.OpenConfig(policy.ParsePolicy(
        GOOD_HEADER + PLATFORM_EXCLUDE_NOTOC, self.naming), EXP_INFO)
    expected = json.loads(GOOD_JSON_SADDR_NOTOC)
    self.assertEqual(expected, json.loads(str(acl)))

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')

  def testPlatformOC(self):
    self.naming.GetNetAddr.return_value = TEST_IPS

    acl = openconfig.OpenConfig(policy.ParsePolicy(
        GOOD_HEADER + PLATFORM_OC, self.naming), EXP_INFO)
    expected = json.loads(GOOD_JSON_SADDR_PLATFORM_OC)
    self.assertEqual(expected, json.loads(str(acl)))

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')

  def testPlatformJNPR(self):
    self.naming.GetNetAddr.return_value = TEST_IPS

    acl = openconfig.OpenConfig(policy.ParsePolicy(
        GOOD_HEADER + GOOD_SADDR + PLATFORM_NOTOC, self.naming), EXP_INFO)
    expected = json.loads(GOOD_JSON_SADDR)
    self.assertEqual(expected, json.loads(str(acl)))

  def testDaddr(self):
    self.naming.GetNetAddr.return_value = TEST_IPS

    acl = openconfig.OpenConfig(policy.ParsePolicy(
        GOOD_HEADER + GOOD_DADDR, self.naming), EXP_INFO)
    expected = json.loads(GOOD_JSON_DADDR)
    self.assertEqual(expected, json.loads(str(acl)))

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')

  def testSport(self):
    self.naming.GetNetAddr.return_value = TEST_IPS
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    acl = openconfig.OpenConfig(policy.ParsePolicy(
        GOOD_HEADER + GOOD_SPORT, self.naming), EXP_INFO)
    expected = json.loads(GOOD_JSON_SPORT)
    self.assertEqual(expected, json.loads(str(acl)))

    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('DNS', 'tcp')])

  def testDport(self):
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

    acl = openconfig.OpenConfig(policy.ParsePolicy(
        GOOD_HEADER + GOOD_DPORT, self.naming), EXP_INFO)
    expected = json.loads(GOOD_JSON_DPORT)
    self.assertEqual(expected, json.loads(str(acl)))

    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('DNS', 'tcp')])

  def testEverything(self):
    self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
    self.naming.GetNetAddr.return_value = TEST_IPS

    acl = openconfig.OpenConfig(policy.ParsePolicy(
        GOOD_HEADER + GOOD_EVERYTHING, self.naming), EXP_INFO)
    expected = json.loads(GOOD_JSON_EVERYTHING)
    self.assertEqual(expected, json.loads(str(acl)))

    self.naming.GetServiceByProto.assert_has_calls([
        mock.call('DNS', 'udp'),
        mock.call('DNS', 'tcp')])

  def testV6Saddr(self):
    self.naming.GetNetAddr.return_value = TEST_IPS

    acl = openconfig.OpenConfig(policy.ParsePolicy(
        GOOD_HEADER_INET6 + GOOD_SADDR, self.naming), EXP_INFO)
    expected = json.loads(GOOD_JSON_V6_SADDR)
    self.assertEqual(expected, json.loads(str(acl)))

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')

  def testV6Daddr(self):
    self.naming.GetNetAddr.return_value = TEST_IPS

    acl = openconfig.OpenConfig(policy.ParsePolicy(
        GOOD_HEADER_INET6 + GOOD_DADDR, self.naming), EXP_INFO)
    expected = json.loads(GOOD_JSON_V6_DADDR)
    self.assertEqual(expected, json.loads(str(acl)))

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')

  def testMixedDaddr(self):
    self.naming.GetNetAddr.return_value = TEST_IPS

    acl = openconfig.OpenConfig(policy.ParsePolicy(
        GOOD_HEADER_MIXED + GOOD_DADDR, self.naming), EXP_INFO)
    expected = json.loads(GOOD_JSON_MIXED_DADDR)
    self.assertEqual(expected, json.loads(str(acl)))

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')



if __name__ == '__main__':
  absltest.main()
