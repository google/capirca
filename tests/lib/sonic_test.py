# Copyright 2022 Google Inc. All Rights Reserved.
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
"""Unittest for Sonic rendering module."""

import json
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy
from capirca.lib import sonic

GOOD_HEADER = """
header {
  comment:: "The general policy comment."
  target:: sonic MyPolicyName inet
}
"""


class SonicTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.addCleanup(mock.patch.stopall)

    self.naming = naming.Naming("./def")
    self.mock_naming_get_net_addr = mock.patch.object(
        self.naming, "GetNetAddr", autospec=True).start()
    self.mock_naming_get_net_addr.return_value = [
        nacaddr.IP("10.2.3.4/32"),
        nacaddr.IP("2001:4860:8000::5/128"),
    ]
    # Print a info message when a term is set to expire in that many weeks.
    # This is normally passed from command line.
    self.exp_info = 2

  def testSingleSrcIPv4(self):
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      action:: accept
    }
    """
    expected = json.loads("""
    {
      "ACL_RULE": {
        "MyPolicyName|RULE_10": {
          "PRIORITY": "65526",
          "PACKET_ACTION": "FORWARD",
          "SRC_IP": "10.2.3.4/32"
        }
      }
    }
    """)

    acl = sonic.Sonic(
        policy.ParsePolicy(GOOD_HEADER + pol, self.naming), self.exp_info)

    self.assertEqual(expected, json.loads(str(acl)))
    self.mock_naming_get_net_addr.assert_called_once_with("CORP_EXTERNAL")

  def testSingleSrcSingleDstIPv4(self):
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      destination-address:: CORP_EXTERNAL
      action:: accept
    }
    """
    expected = json.loads("""{
    "ACL_RULE": {
      "MyPolicyName|RULE_10": {
        "PRIORITY": "65526",
        "PACKET_ACTION": "FORWARD",
        "SRC_IP": "10.2.3.4/32",
        "DST_IP": "10.2.3.4/32"
      }
    }
    }""")

    acl = sonic.Sonic(
        policy.ParsePolicy(GOOD_HEADER + pol, self.naming), self.exp_info)

    self.assertEqual(expected, json.loads(str(acl)))

  def testSingleSrcSingleDstIPv6(self):
    header = """
    header {
      comment:: "The general policy comment."
      target:: sonic MyPolicyName inet6
    }
    """
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      destination-address:: CORP_EXTERNAL
      action:: accept
    }
    """
    expected = json.loads("""{
    "ACL_RULE": {
      "MyPolicyName|RULE_10": {
        "PRIORITY": "65526",
        "PACKET_ACTION": "FORWARD",
        "SRC_IPV6": "2001:4860:8000::5/128",
        "DST_IPV6": "2001:4860:8000::5/128"
      }
    }
    }""")

    acl = sonic.Sonic(
        policy.ParsePolicy(header + pol, self.naming), self.exp_info)

    self.assertEqual(expected, json.loads(str(acl)))

  def testMultiSrcIPv4(self):
    self.mock_naming_get_net_addr.return_value = [
        nacaddr.IP("10.2.3.4/32"),
        nacaddr.IP("4.4.4.4/32"),
    ]
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      action:: accept
    }
    """
    expected = json.loads("""
    {
      "ACL_RULE": {
        "MyPolicyName|RULE_10": {
          "PRIORITY": "65526",
          "PACKET_ACTION": "FORWARD",
          "SRC_IP": "4.4.4.4/32"
        },
        "MyPolicyName|RULE_20": {
          "PRIORITY": "65516",
          "PACKET_ACTION": "FORWARD",
          "SRC_IP": "10.2.3.4/32"
        }
      }
    }
    """)

    acl = sonic.Sonic(
        policy.ParsePolicy(GOOD_HEADER + pol, self.naming), self.exp_info)

    self.assertEqual(expected, json.loads(str(acl)))

  def testMultiSrcMultiDstIPv4(self):
    self.mock_naming_get_net_addr.return_value = [
        nacaddr.IP("10.2.3.4/32"),
        nacaddr.IP("4.4.4.4/32"),
    ]
    expected = json.loads("""
    {
      "ACL_RULE": {
        "MyPolicyName|RULE_10": {
          "DST_IP": "4.4.4.4/32",
          "PACKET_ACTION": "FORWARD",
          "PRIORITY": "65526",
          "SRC_IP": "4.4.4.4/32"
        },
        "MyPolicyName|RULE_20": {
          "DST_IP": "10.2.3.4/32",
          "PACKET_ACTION": "FORWARD",
          "PRIORITY": "65516",
          "SRC_IP": "4.4.4.4/32"
        },
        "MyPolicyName|RULE_30": {
          "DST_IP": "4.4.4.4/32",
          "PACKET_ACTION": "FORWARD",
          "PRIORITY": "65506",
          "SRC_IP": "10.2.3.4/32"
        },
        "MyPolicyName|RULE_40": {
          "DST_IP": "10.2.3.4/32",
          "PACKET_ACTION": "FORWARD",
          "PRIORITY": "65496",
          "SRC_IP": "10.2.3.4/32"
        }
      }
    }
    """)
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      destination-address:: CORP_EXTERNAL
      action:: accept
    }
    """
    acl = sonic.Sonic(
        policy.ParsePolicy(GOOD_HEADER + pol, self.naming), self.exp_info)

    self.assertEqual(expected, json.loads(str(acl)))

  def testDrop(self):
    pol = """
    term good-term-1 {
      action:: deny
    }
    """

    expected = json.loads("""
    {
      "ACL_RULE": {
        "MyPolicyName|RULE_10": {
          "PRIORITY": "65526",
          "PACKET_ACTION": "DROP"
        }
      }
    }
    """)

    acl = sonic.Sonic(
        policy.ParsePolicy(GOOD_HEADER + pol, self.naming), self.exp_info)

    self.assertEqual(expected, json.loads(str(acl)))

  def testMultiTerm(self):
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      action:: accept
    }
    term good-term-2 {
      destination-address:: CORP_EXTERNAL
      action:: accept
    }
    """

    expected = json.loads("""
    {
      "ACL_RULE": {
        "MyPolicyName|RULE_10": {
          "PRIORITY": "65526",
          "PACKET_ACTION": "FORWARD",
          "SRC_IP": "10.2.3.4/32"
        },
        "MyPolicyName|RULE_20": {
          "PRIORITY": "65516",
          "PACKET_ACTION": "FORWARD",
          "DST_IP": "10.2.3.4/32"
        }
      }
    }
    """)

    acl = sonic.Sonic(
        policy.ParsePolicy(GOOD_HEADER + pol, self.naming), self.exp_info)

    self.assertEqual(expected, json.loads(str(acl)))

  def testProtocols(self):
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      protocol:: tcp udp
      action:: accept
    }
    """
    expected = json.loads("""
    {
      "ACL_RULE": {
        "MyPolicyName|RULE_10": {
          "IP_PROTOCOL": "6",
          "PRIORITY": "65526",
          "PACKET_ACTION": "FORWARD",
          "SRC_IP": "10.2.3.4/32"
        },
        "MyPolicyName|RULE_20": {
          "IP_PROTOCOL": "17",
          "PRIORITY": "65516",
          "PACKET_ACTION": "FORWARD",
          "SRC_IP": "10.2.3.4/32"
        }
      }
    }
    """)

    acl = sonic.Sonic(
        policy.ParsePolicy(GOOD_HEADER + pol, self.naming), self.exp_info)

    self.assertEqual(expected, json.loads(str(acl)))

  def testICMPv4(self):
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      protocol:: icmp
      icmp-type:: echo-request echo-reply
      action:: accept
    }
    """
    expected = json.loads("""
    {
      "ACL_RULE": {
        "MyPolicyName|RULE_10": {
          "ICMP_TYPE": "0",
          "IP_PROTOCOL": "1",
          "PRIORITY": "65526",
          "PACKET_ACTION": "FORWARD",
          "SRC_IP": "10.2.3.4/32"
        },
        "MyPolicyName|RULE_20": {
          "ICMP_TYPE": "8",
          "IP_PROTOCOL": "1",
          "PRIORITY": "65516",
          "PACKET_ACTION": "FORWARD",
          "SRC_IP": "10.2.3.4/32"
        }
      }
    }
    """)

    acl = sonic.Sonic(
        policy.ParsePolicy(GOOD_HEADER + pol, self.naming), self.exp_info)

    self.assertEqual(expected, json.loads(str(acl)))

  def testICMPv6(self):
    header = """
    header {
      comment:: "The general policy comment."
      target:: sonic MyPolicyName inet6
    }
    """
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      protocol:: icmpv6
      icmp-type:: echo-request echo-reply
      action:: accept
    }
    """
    expected = json.loads("""
    {
      "ACL_RULE": {
        "MyPolicyName|RULE_10": {
          "ICMPV6_TYPE": "128",
          "IP_PROTOCOL": "58",
          "PACKET_ACTION": "FORWARD",
          "PRIORITY": "65526",
          "SRC_IPV6": "2001:4860:8000::5/128"
        },
        "MyPolicyName|RULE_20": {
          "ICMPV6_TYPE": "129",
          "IP_PROTOCOL": "58",
          "PACKET_ACTION": "FORWARD",
          "PRIORITY": "65516",
          "SRC_IPV6": "2001:4860:8000::5/128"
        }
      }
    }""")

    acl = sonic.Sonic(
        policy.ParsePolicy(header + pol, self.naming), self.exp_info)

    self.assertEqual(expected, json.loads(str(acl)))

  def testICMPv4DoesNotRenderIPv6(self):
    mixed_af_header = """
    header {
      comment:: "The general policy comment."
      target:: sonic MyPolicyName inet inet6
    }
    """
    self.mock_naming_get_net_addr.return_value = [
        nacaddr.IP("2001:a:b:c::/128"),
    ]
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      protocol:: icmp
      icmp-type:: echo-request
      action:: accept
    }
    """

    acl = sonic.Sonic(
        policy.ParsePolicy(mixed_af_header + pol, self.naming), self.exp_info)

    self.assertEqual({"ACL_RULE": {}}, json.loads(str(acl)))

  def testICMPv6DoesNotRenderIPv4(self):
    mixed_af_header = """
    header {
      comment:: "The general policy comment."
      target:: sonic MyPolicyName inet inet6
    }
    """
    self.mock_naming_get_net_addr.return_value = [
        nacaddr.IP("1.2.3.4/32"),
    ]
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      protocol:: icmpv6
      icmp-type:: echo-request
      action:: accept
    }
    """

    acl = sonic.Sonic(
        policy.ParsePolicy(mixed_af_header + pol, self.naming), self.exp_info)

    self.assertEqual({"ACL_RULE": {}}, json.loads(str(acl)))

  def testSrcPortSingle(self):
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      protocol:: tcp
      source-port:: SSH HTTPS
      action:: accept
    }
    """
    expected = json.loads("""
    {
      "ACL_RULE": {
        "MyPolicyName|RULE_10": {
          "IP_PROTOCOL": "6",
          "PACKET_ACTION": "FORWARD",
          "PRIORITY": "65526",
          "SRC_IP": "10.2.3.4/32",
          "L4_SRC_PORT": "22"
        },
        "MyPolicyName|RULE_20": {
          "IP_PROTOCOL": "6",
          "PACKET_ACTION": "FORWARD",
          "PRIORITY": "65516",
          "SRC_IP": "10.2.3.4/32",
          "L4_SRC_PORT": "443"
        }
      }
    }
    """)

    acl = sonic.Sonic(
        policy.ParsePolicy(GOOD_HEADER + pol, self.naming), self.exp_info)

    self.assertEqual(expected, json.loads(str(acl)))

  def testSrcPortRange(self):
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      protocol:: udp
      source-port:: TRACEROUTE
      action:: accept
    }
    """
    expected = json.loads("""
    {
      "ACL_RULE": {
        "MyPolicyName|RULE_10": {
          "IP_PROTOCOL": "17",
          "PACKET_ACTION": "FORWARD",
          "PRIORITY": "65526",
          "SRC_IP": "10.2.3.4/32",
          "L4_SRC_PORT_RANGE": "33434-33534"
        }
      }
    }
    """)

    acl = sonic.Sonic(
        policy.ParsePolicy(GOOD_HEADER + pol, self.naming), self.exp_info)

    self.assertEqual(expected, json.loads(str(acl)))

  def testDstPortSingle(self):
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      protocol:: tcp
      destination-port:: SSH HTTPS
      action:: accept
    }
    """
    expected = json.loads("""
    {
      "ACL_RULE": {
        "MyPolicyName|RULE_10": {
          "IP_PROTOCOL": "6",
          "PACKET_ACTION": "FORWARD",
          "PRIORITY": "65526",
          "SRC_IP": "10.2.3.4/32",
          "L4_DST_PORT": "22"
        },
        "MyPolicyName|RULE_20": {
          "IP_PROTOCOL": "6",
          "PACKET_ACTION": "FORWARD",
          "PRIORITY": "65516",
          "SRC_IP": "10.2.3.4/32",
          "L4_DST_PORT": "443"
        }
      }
    }
    """)

    acl = sonic.Sonic(
        policy.ParsePolicy(GOOD_HEADER + pol, self.naming), self.exp_info)

    self.assertEqual(expected, json.loads(str(acl)))

  def testDstPortRange(self):
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      protocol:: udp
      destination-port:: TRACEROUTE
      action:: accept
    }
    """
    expected = json.loads("""
    {
      "ACL_RULE": {
        "MyPolicyName|RULE_10": {
          "IP_PROTOCOL": "17",
          "PACKET_ACTION": "FORWARD",
          "PRIORITY": "65526",
          "SRC_IP": "10.2.3.4/32",
          "L4_DST_PORT_RANGE": "33434-33534"
        }
      }
    }
    """)

    acl = sonic.Sonic(
        policy.ParsePolicy(GOOD_HEADER + pol, self.naming), self.exp_info)

    self.assertEqual(expected, json.loads(str(acl)))

  def testTCPEstablished(self):
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      protocol:: tcp
      option:: tcp-established
      action:: accept
    }
    """
    expected = json.loads("""
    {
      "ACL_RULE": {
        "MyPolicyName|RULE_10": {
          "IP_PROTOCOL": "6",
          "PACKET_ACTION": "FORWARD",
          "PRIORITY": "65526",
          "SRC_IP": "10.2.3.4/32",
          "TCP_FLAGS": [
            "0x10/0x10",
            "0x4/0x4"
          ]
        }
      }
    }
    """)

    acl = sonic.Sonic(
        policy.ParsePolicy(GOOD_HEADER + pol, self.naming), self.exp_info)

    self.assertEqual(expected, json.loads(str(acl)))

  def testTermWithWrongPlatform(self):
    pol = """
    term good-term-1 {
      source-address:: CORP_EXTERNAL
      protocol:: tcp
      source-port:: SSH
      action:: accept
      platform:: FAKEPLATFORM
    }
    """

    acl = sonic.Sonic(
        policy.ParsePolicy(GOOD_HEADER + pol, self.naming), self.exp_info)

    self.assertEqual({"ACL_RULE": {}}, json.loads(str(acl)))


if __name__ == "__main__":
  absltest.main()
