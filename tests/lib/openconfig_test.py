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
  target:: openconfig inet
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

GOOD_JSON_SADDR = """
[
  {
    "actions": {
      "forwarding-action": "ACCEPT"
    },
    "ipv4": {
      "config": {
        "source-address": "10.2.3.4/32"
      }
    }
  }
]
"""

GOOD_JSON_V6_SADDR = """
 [
  {
    "actions": {
      "forwarding-action": "ACCEPT"
    },
    "ipv6": {
      "config": {
        "source-address": "2001:4860:8000::5/128"
      }
    }
  }
]
"""

GOOD_JSON_DADDR = """
[
  {
    "actions": {
      "forwarding-action": "ACCEPT"
    },
    "ipv4": {
      "config": {
        "destination-address": "10.2.3.4/32"
      }
    }
  }
]
"""

GOOD_JSON_V6_DADDR = """
 [
  {
    "actions": {
      "forwarding-action": "ACCEPT"
    },
    "ipv6": {
      "config": {
        "destination-address": "2001:4860:8000::5/128"
      }
    }
  }
]
"""

GOOD_JSON_MIXED_DADDR = """
[
  {
    "actions": {
      "forwarding-action": "ACCEPT"
    },
    "ipv4": {
      "config": {
        "destination-address": "10.2.3.4/32"
      }
    }
  },
  {
    "actions": {
      "forwarding-action": "ACCEPT"
    },
    "ipv6": {
      "config": {
        "destination-address": "2001:4860:8000::5/128"
      }
    }
  }
]
"""

GOOD_JSON_SPORT = """
[
  {
    "actions": {
      "forwarding-action": "ACCEPT"
    },
    "ipv4": {
      "config": {
        "protocol": 6
    },
    "transport": {
      "config": {
        "source-port": 53}
      }
    }
  }
]
"""

GOOD_JSON_DPORT = """
[
  {
    "actions": {
      "forwarding-action": "ACCEPT"
    },
    "ipv4": {
      "config": {
        "protocol": 6
    },
    "transport": {
      "config": {
        "destination-port": 53}
      }
    }
  }
]
"""

GOOD_JSON_MULTI_PROTO_DPORT = """
[
  {
    "actions": {
      "forwarding-action": "ACCEPT"
    },
    "ipv4": {
      "config": {
        "protocol": 17
    },
    "transport": {
      "config": {
        "destination-port": 53}
      }
    }
  },
  {
    "actions": {
      "forwarding-action": "ACCEPT"
    },
    "ipv4": {
      "config": {
        "protocol": 6
      },
      "transport": {
        "config": {
          "destination-port": 53}
        }
      }
  }
]
"""

GOOD_JSON_EVERYTHING = """
 [
  {
    "actions": {
      "forwarding-action": "ACCEPT"
    },
    "ipv4": {
      "config": {
        "destination-address": "10.2.3.4/32",
        "protocol": 17,
        "source-address": "10.2.3.4/32"
      },
      "transport": {
        "config": {
          "destination-port": 53
        }
      }
    }
  },
  {
    "actions": {
      "forwarding-action": "ACCEPT"
    },
    "ipv4": {
      "config": {
        "destination-address": "10.2.3.4/32",
        "protocol": 6,
        "source-address": "10.2.3.4/32"
      },
      "transport": {
        "config": {
          "destination-port": 53
        }
      }
    }
  }
]
"""
GOOD_HEADER_INET6 = """
header {
  comment:: "The general policy comment."
  target:: openconfig inet6
}
"""

GOOD_HEADER_MIXED = """
header {
  comment:: "The general policy comment."
  target:: openconfig mixed
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

  def _StripAclHeaders(self, acl):
    return '\n'.join([line for line in str(acl).split('\n')
                      if not line.lstrip().startswith('#')])

  def testSaddr(self):
    self.naming.GetNetAddr.return_value = TEST_IPS

    acl = openconfig.OpenConfig(policy.ParsePolicy(
        GOOD_HEADER + GOOD_SADDR, self.naming), EXP_INFO)
    expected = json.loads(GOOD_JSON_SADDR)
    self.assertEqual(expected, json.loads(str(acl)))

    self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')

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
