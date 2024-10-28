# Copyright 2021 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""unittest for arista traffic-policy rendering module."""

import datetime
import re
from absl.testing import absltest
from unittest import mock

from capirca.lib import aclgenerator
from capirca.lib import arista_tp
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy

GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: arista_tp test-filter
}
"""
# XXX check
GOOD_HEADER_INET = """
header {
  comment:: "test inet acl"
  target:: arista_tp test-filter inet
}
"""
GOOD_HEADER_INET6 = """
header {
  comment:: "this is a test acl"
  target:: arista_tp test-filter inet6
}
"""
GOOD_NOVERBOSE_MIXED_HEADER = """
header {
  target:: arista_tp test-filter mixed noverbose
}
"""
GOOD_NOVERBOSE_V4_HEADER = """
header {
  target:: arista_tp test-filter inet noverbose
}
"""
GOOD_NOVERBOSE_V6_HEADER = """
header {
  target:: arista_tp test-filter inet6 noverbose
}
"""

BAD_HEADER = """
header {
  target:: arista_tp test-filter bridged
}
"""
EXPIRED_TERM = """
term is_expired {
  expiration:: 2001-01-01
  action:: accept
}
"""
EXPIRING_TERM = """
term is_expiring {
  expiration:: %s
  action:: accept
}
"""
DUPLICATE_TERMS = """
term good-term-1 {
  protocol:: icmp
  action:: accept
}

term good-term-1 {
  protocol:: tcp
  destination-port:: SMTP
  destination-address:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_1 = """
term good-term-1 {
  protocol:: icmp
  action:: accept
}
term good-term-2 {
  protocol:: tcp
  destination-port:: SMTP
  destination-address:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_1_V6 = """
term good-term-1 {
  protocol:: icmpv6
  action:: accept
}
term good-term-2 {
  protocol:: tcp
  destination-port:: SMTP
  destination-address:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_2 = """
term good-term-3 {
  protocol:: tcp
  destination-address:: SOME_HOST
  source-port:: HTTP
  option:: established tcp-established
  action:: accept
}
"""
GOOD_TERM_3 = """
term good-term-3 {
  protocol:: icmp
  icmp-type:: echo-reply information-reply information-request
  icmp-type:: router-solicitation timestamp-request
  action:: accept
}
"""
GOOD_TERM_5 = """
term good-term-5 {
  protocol:: icmp
  protocol:: tcp
  action:: accept
}
"""

PROTO_EXC_TCP = """
term good-term-7 {
  protocol-except:: tcp
  action:: accept
}
"""
PROTO_EXC_LIST = """
term good-term-7 {
  protocol-except:: igmp egp rdp hopopt
  action:: accept
}
"""

GOOD_TERM_8 = """
term good-term-8 {
  source-prefix:: foo_prefix_list
  destination-prefix:: bar_prefix_list baz_prefix_list
  action:: accept
}
"""
GOOD_TERM_11 = """
term good-term-11 {
  verbatim:: arista_tp "mary had a little lamb"
  verbatim:: iptables "mary had a second lamb"
  verbatim:: cisco "mary had a third lamb"
}
"""
GOOD_TERM_OWNER = """
term owner-term {
  protocol:: tcp
  owner:: foo@gmail.com
  action:: accept
}
"""
GOOD_TERM_18_SRC = """
term address-exclusions {
  source-address:: INTERNAL
  source-exclude:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_18_DST = """
term address-exclusions {
  destination-address:: INTERNAL
  destination-exclude:: SOME_HOST
  action:: accept
}
"""
# write a test for this term.
GOOD_TERM_19 = """
term minimize-prefix-list {
  source-address:: INCLUDES
  source-exclude:: EXCLUDES
  action:: accept
}
"""
GOOD_TERM_V6_HOP_LIMIT = """
term good-term-v6-hl {
  hop-limit:: 25
  action:: accept
}
"""
GOOD_TERM_20_V6 = """
term good-term-20-v6 {
  protocol-except:: icmpv6
  action:: accept
}
"""
GOOD_TERM_21 = """
term good_term_21 {
  ttl:: 10
  action:: accept
}
"""
GOOD_TERM_28 = """
term good_term_28 {
  action:: accept
}
"""
GOOD_TERM_35 = """
term good_term_35 {
  protocol:: icmp
  icmp-type:: unreachable
  icmp-code:: 3 4
  action:: accept
}
"""
GOOD_TERM_36 = """
term good_term_36 {
  protocol:: tcp
  source-port:: SSH DNS HTTP
  action:: accept
}
"""
GOOD_TERM_37 = """
term good_term_37 {
  protocol:: tcp
  destination-port:: SSH DNS HTTP
  action:: accept
}
"""
GOOD_TERM_COMMENT = """
term good-term-comment {
  protocol:: udp
  comment:: "This is a COMMENT"
  action:: accept
}
"""
BAD_TERM_1 = """
term bad-term-1 {
  protocol:: tcp udp
  source-port:: DNS
  option:: tcp-established
  action:: accept
}
"""
ESTABLISHED_TERM_1 = """
term established-term-1 {
  protocol:: tcp
  source-port:: DNS
  option:: established
  action:: accept
}
"""
MISSING_MATCH = """
term missing-match {
  action:: accept
}
"""
OPTION_TERM_1 = """
term option-term {
  protocol:: tcp
  option:: is-fragment
  action:: accept
}
"""
BAD_ICMPTYPE_TERM_1 = """
term icmptype-mismatch {
  comment:: "error when icmpv6 paired with inet filter"
  protocol:: icmpv6
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""
BAD_ICMPTYPE_TERM_2 = """
term icmptype-mismatch {
  comment:: "error when icmp paired with inet6 filter"
  protocol:: icmp
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""
DEFAULT_TERM_1 = """
term default-term-1 {
  action:: deny
}
"""
LONG_COMMENT_TERM_1 = """
term long-comment-term-1 {
  comment:: "this is very very very very very very very very very very very
  comment:: "very very very very very very very long."
  action:: deny
}
"""

LONG_COMMENT_TERM_ANET = """
term long-comment-term-1 {
  comment:: "0 this is very very very very very very very very very very very"
  comment:: "1 very very very very very very very very very very very"
  comment:: "2 very very very very very very very very very very very"
  comment:: "3 very very very very very very very very very very very"
  comment:: "4 very very very very very very very long comment. "
  protocol:: icmpv6
  action:: deny
}
"""
HOPOPT_TERM = """
term good-term-1 {
  protocol:: hopopt
  action:: accept
}
"""
FRAGOFFSET_TERM = """
term good-term-1 {
  fragment-offset:: 1-7
  action:: accept
}
"""
COUNTER_CLEANUP_TERM = """
term good-term-1 {
  protocol:: tcp
  counter:: test.cleanup.check
  action:: accept
}
"""
# test the various mixed filter_type permutations
MIXED_INET = """
term MIXED_INET {
  source-address:: GOOGLE_DNS
  destination-address:: INTERNAL
  protocol:: tcp udp
  action:: accept
}
"""
INET_MIXED = """
term INET_MIXED {
  source-address:: INTERNAL
  destination-address:: GOOGLE_DNS
  protocol:: tcp udp
  action:: accept
}
"""
MIXED_INET6 = """
term MIXED_INET6 {
  source-address:: GOOGLE_DNS
  destination-address:: SOME_HOST
  action:: accept
}
"""

INET6_MIXED = """
term INET6_MIXED {
  source-address:: SOME_HOST
  destination-address:: GOOGLE_DNS
  action:: accept
}
"""

MIXED_MIXED = """
term MIXED_MIXED {
  source-address:: GOOGLE_DNS
  destination-address:: GOOGLE_DNS
  action:: accept
}
"""

MIXED_ANY = """
term MIXED_ANY {
  source-address:: GOOGLE_DNS
  action:: accept
}
"""

ANY_MIXED = """
term ANY_MIXED {
  destination-address:: GOOGLE_DNS
  action:: accept
}
"""

INET_INET = """
term INET_INET {
  source-address:: NTP_SERVERS
  destination-address:: INTERNAL
  action:: accept
}
"""

INET6_INET6 = """
term INET6_INET6 {
  source-address:: SOME_HOST
  destination-address:: SOME_HOST
  action:: accept
}
"""

INET_INET6 = """
term INET_INET6 {
  source-address:: INTERNAL
  destination-address:: SOME_HOST
  action:: accept
}
"""

INET6_INET = """
term INET6_INET {
  source-address:: SOME_HOST
  destination-address:: INTERNAL
  action:: accept
}
"""

SRC_FIELD_SET_INET = """
term FS_INET {
  source-address:: INTERNAL
  source-exclude:: SOME_HOST
  action:: accept
}
"""
SRC_FIELD_SET_INET6 = """
term FS_INET6 {
  source-address:: INTERNAL
  source-exclude:: SOME_HOST
  action:: accept
}
"""
SRC_FIELD_SET_MIXED = """
term FS_MIXED {
  source-address:: INTERNAL
  source-exclude:: SOME_HOST
  action:: accept
}
"""

DST_FIELD_SET_INET = """
term FS_INET {
  destination-address:: INTERNAL
  destination-exclude:: SOME_HOST
  action:: accept
}
"""
DST_FIELD_SET_INET6 = """
term FS_INET6 {
  destination-address:: INTERNAL
  destination-exclude:: SOME_HOST
  action:: accept
}
"""
DST_FIELD_SET_MIXED = """
term FS_MIXED {
  destination-address:: INTERNAL
  destination-exclude:: SOME_HOST
  action:: accept
}
"""

# this term should not have the logging element rendered
LOGGING_ACCEPT = """
term logging-term-1 {
  protocol:: icmp
  action:: accept
  logging:: true
}
"""
# this term _should_ have the logging element rendered
LOGGING_DENY = """
term logging-term-1 {
  protocol:: icmp
  action:: deny
  logging:: true
}
"""

SUPPORTED_TOKENS = frozenset([
    "action",
    "comment",
    "counter",
    "destination_address",
    "destination_address_exclude",
    "destination_port",
    "destination_prefix",
    "dscp_set",
    "expiration",
    "fragment_offset",
    "hop_limit",
    "icmp_code",
    "icmp_type",
    "logging",
    "name",
    "option",
    "owner",
    "packet_length",
    "platform",
    "platform_exclude",
    "port",
    "protocol",
    "protocol_except",
    "source_address",
    "source_address_exclude",
    "source_port",
    "source_prefix",
    "stateless_reply",
    "translated",
    "ttl",
    "verbatim",
])

SUPPORTED_SUB_TOKENS = {
    "action": {"accept", "deny", "reject", "next", "reject-with-tcp-rst"},
    "icmp_type": {
        "alternate-address",
        "certification-path-advertisement",
        "certification-path-solicitation",
        "conversion-error",
        "destination-unreachable",
        "echo-reply",
        "echo-request",
        "mobile-redirect",
        "home-agent-address-discovery-reply",
        "home-agent-address-discovery-request",
        "icmp-node-information-query",
        "icmp-node-information-response",
        "information-request",
        "inverse-neighbor-discovery-advertisement",
        "inverse-neighbor-discovery-solicitation",
        "mask-reply",
        "mask-request",
        "information-reply",
        "mobile-prefix-advertisement",
        "mobile-prefix-solicitation",
        "multicast-listener-done",
        "multicast-listener-query",
        "multicast-listener-report",
        "multicast-router-advertisement",
        "multicast-router-solicitation",
        "multicast-router-termination",
        "neighbor-advertisement",
        "neighbor-solicit",
        "packet-too-big",
        "parameter-problem",
        "redirect",
        "redirect-message",
        "router-advertisement",
        "router-renumbering",
        "router-solicit",
        "router-solicitation",
        "source-quench",
        "time-exceeded",
        "timestamp-reply",
        "timestamp-request",
        "unreachable",
        "version-2-multicast-listener-report",
    },
    "option": {
        "established",
        "is-fragment",
        ".*",  # not actually a lex token!
        "tcp-established",
        "tcp-initial",
    },
}

# print an info message when a term is set to expire in that many weeks.
# normally passed from command line.
EXP_INFO = 2


class AristaTpTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def testOptions(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP("10.0.0.0/8")]
    self.naming.GetServiceByProto.return_value = ["80"]

    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_2, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("destination port 1024-65535", output, output)
    # verify that tcp-established; doesn't get duplicated if both
    # 'established' and 'tcp-established' options are included in term
    self.assertEqual(output.count("established"), 1)

    self.naming.GetNetAddr.assert_called_once_with("SOME_HOST")
    self.naming.GetServiceByProto.assert_called_once_with("HTTP", "tcp")

  def testTermAndFilterName(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP("10.0.0.0/8")]
    self.naming.GetServiceByProto.return_value = ["25"]

    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("match good-term-1", output, output)
    self.assertIn("traffic-policy test-filter", output, output)

    self.naming.GetNetAddr.assert_called_once_with("SOME_HOST")
    self.naming.GetServiceByProto.assert_called_once_with("SMTP", "tcp")

  def testBadFilterType(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP("10.0.0.0/8")]
    self.naming.GetServiceByProto.return_value = ["25"]

    pol = policy.ParsePolicy(BAD_HEADER + GOOD_TERM_1, self.naming)
    self.assertRaises(
        aclgenerator.UnsupportedAFError,
        arista_tp.AristaTrafficPolicy,
        pol,
        EXP_INFO,
    )
    self.naming.GetNetAddr.assert_called_once_with("SOME_HOST")
    self.naming.GetServiceByProto.assert_called_once_with("SMTP", "tcp")

  def testDuplicateTermName(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP("10.0.0.0/8")]
    self.naming.GetServiceByProto.return_value = ["25"]

    pol = policy.ParsePolicy(GOOD_HEADER + DUPLICATE_TERMS, self.naming)
    self.assertRaises(
        aclgenerator.DuplicateTermError,
        arista_tp.AristaTrafficPolicy,
        pol,
        EXP_INFO,
    )
    self.naming.GetNetAddr.assert_called_once_with("SOME_HOST")
    self.naming.GetServiceByProto.assert_called_once_with("SMTP", "tcp")

  def testCounterCleanup(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + COUNTER_CLEANUP_TERM, self.naming),
        EXP_INFO)
    output = str(atp)
    self.assertIn("      counter test-cleanup-check", output, output)
    self.assertIn("count test-cleanup-check", output, output)

  def testDefaultDeny(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + DEFAULT_TERM_1, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("match ipv4-default-all ipv4", output, output)
    self.assertIn("match ipv6-default-all ipv6", output, output)

  def testIcmpType(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_3, self.naming), EXP_INFO)
    output = str(atp)
    # verify proper translation from policy icmp-type text to
    # traffic-policy
    self.assertIn("icmp type ", output, output)
    self.assertIn("0,", output, output)
    self.assertIn("10,", output, output)
    self.assertIn("13,", output, output)
    self.assertIn("15,", output, output)
    self.assertIn("16", output, output)

  def testIcmpCode(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_35, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("code 3,4", output, output)

  def testInet6(self):
    self.naming.GetNetAddr.return_value = [nacaddr.IP("2001::/33")]
    self.naming.GetServiceByProto.return_value = ["25"]

    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_TERM_1_V6, self.naming),
        EXP_INFO)
    output = str(atp)
    self.assertTrue("protocol icmpv6" in output and "protocol tcp" in output,
                    output)

    self.naming.GetNetAddr.assert_called_once_with("SOME_HOST")
    self.naming.GetServiceByProto.assert_called_once_with("SMTP", "tcp")

  def testHopLimit(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_TERM_V6_HOP_LIMIT,
                           self.naming),
        EXP_INFO,
    )
    output = str(atp)
    self.assertIn("ttl 25", output, output)

  def testPortsSrc(self):
    self.naming.GetServiceByProto.return_value = ['22', '53', '80']
    ports = arista_tp.AristaTrafficPolicy(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_36, self.naming), EXP_INFO)
    output = str(ports)
    self.assertIn("source port 22, 53, 80", output, output)

  def testPortsDst(self):
    self.naming.GetServiceByProto.return_value = ['22', '53', '80']
    ports = arista_tp.AristaTrafficPolicy(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_37, self.naming), EXP_INFO)
    output = str(ports)
    self.assertIn("destination port 22, 53, 80", output, output)

  def testProtocol(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_5, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("protocol icmp tcp", output, output)

  def testProtocolExceptTcp(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + PROTO_EXC_TCP, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("protocol 1-5,7-255", output, output)
    self.assertIn("protocol 0-5,7-255", output, output)

  def testProtocolExceptList(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + PROTO_EXC_LIST, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("protocol 1,3-7,9-26,28-255", output, output)

  def testPrefixList(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_8, self.naming), EXP_INFO)
    spfx_re = re.compile(r"source prefix field-set\W+foo_prefix_list\W+")
    dpfx_re = re.compile(
        r"destination prefix field-set\W+bar_prefix_list\W+baz_prefix_list\W+")
    output = str(atp)
    self.assertTrue(spfx_re.search(output), output)
    self.assertTrue(dpfx_re.search(output), output)

  def testVerbatimTerm(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_11, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("mary had a little lamb", output, output)
    # check if other platforms verbatim shows up in output
    self.assertNotIn("mary had a second lamb", output, output)
    self.assertNotIn("mary had a third lamb", output, output)

  def testTcpEstablished(self):
    self.naming.GetServiceByProto.return_value = ["53"]

    policy_text = GOOD_HEADER + ESTABLISHED_TERM_1
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("established", output, output)

    self.naming.GetServiceByProto.assert_called_once_with("DNS", "tcp")

  def testNonTcpWithTcpEstablished(self):
    self.naming.GetServiceByProto.return_value = ["53"]

    policy_text = GOOD_HEADER + BAD_TERM_1
    pol_obj = policy.ParsePolicy(policy_text, self.naming)
    atp = arista_tp.AristaTrafficPolicy(pol_obj, EXP_INFO)
    self.assertRaises(arista_tp.TcpEstablishedWithNonTcpError, str, atp)

    self.naming.GetServiceByProto.assert_has_calls(
        [mock.call("DNS", "tcp"),
         mock.call("DNS", "udp")])

  def testNoVerboseMixed(self):
    addr_list = list()
    for octet in range(0, 256):
      net = nacaddr.IP("192.168." + str(octet) + ".64/27")
      addr_list.append(net)
    self.naming.GetNetAddr.return_value = addr_list
    self.naming.GetServiceByProto.return_value = ["25"]

    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(
            GOOD_NOVERBOSE_MIXED_HEADER + GOOD_TERM_1 + GOOD_TERM_COMMENT,
            self.naming), EXP_INFO)
    self.assertIn("192.168.0.64/27", str(atp))
    self.assertNotIn("COMMENT", str(atp))
    self.naming.GetNetAddr.assert_called_once_with("SOME_HOST")
    self.naming.GetServiceByProto.assert_called_once_with("SMTP", "tcp")

  def testNoVerboseV4(self):
    addr_list = list()
    for octet in range(0, 256):
      net = nacaddr.IP("192.168." + str(octet) + ".64/27")
      addr_list.append(net)
    self.naming.GetNetAddr.return_value = addr_list
    self.naming.GetServiceByProto.return_value = ["25"]

    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(
            GOOD_NOVERBOSE_V4_HEADER + GOOD_TERM_1 + GOOD_TERM_COMMENT,
            self.naming), EXP_INFO)
    self.assertIn("192.168.0.64/27", str(atp))
    self.assertNotIn("COMMENT", str(atp))
    self.naming.GetNetAddr.assert_called_once_with("SOME_HOST")
    self.naming.GetServiceByProto.assert_called_once_with("SMTP", "tcp")

  def testNoVerboseV6(self):
    addr_list = list()
    for octet in range(0, 256):
      net = nacaddr.IPv6(
          "2001:db8:1010:" + str(octet) + "::64/64", strict=False)
      addr_list.append(net)
    self.naming.GetNetAddr.return_value = addr_list
    self.naming.GetServiceByProto.return_value = ["25"]

    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(
            GOOD_NOVERBOSE_V6_HEADER + GOOD_TERM_1 + GOOD_TERM_COMMENT,
            self.naming), EXP_INFO)
    self.assertIn("2001:db8:1010:90::/61", str(atp))
    self.assertNotIn("COMMENT", str(atp))
    self.naming.GetNetAddr.assert_called_once_with("SOME_HOST")
    self.naming.GetServiceByProto.assert_called_once_with("SMTP", "tcp")

  def testTermTypeIndexKeys(self):
    # ensure an _INET entry for each _TERM_TYPE entry
    self.assertCountEqual(
        arista_tp.Term._TERM_TYPE.keys(),
        arista_tp.Term.AF_MAP.keys())

  def testCommentReflow(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + LONG_COMMENT_TERM_ANET, self.naming),
        EXP_INFO)
    output = str(atp)
    self.assertIn("!! 0 this is v", output, output)
    self.assertIn("!! very", output, output)
    self.assertIn("!! 1 very very", output, output)
    self.assertIn("!! 2 very very", output, output)
    self.assertIn("!! 3 very very", output, output)
    self.assertIn("!! 4 very very", output, output)

  @mock.patch.object(arista_tp.logging, "warning")
  def testArbitraryOptions(self, mock_warn):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + OPTION_TERM_1, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("fragment", output, output)
    # since this is a mixed term, check to make sure that the fragment term
    # isn't rendered for inet6
    mock_warn.assert_any_call(
        "WARNING: term %s in mixed policy %s uses fragment "
        "the ipv6 version of the term will not be rendered.",
        "ipv6-option-term", "test-filter")

  @mock.patch.object(arista_tp.logging, "warning")
  def testLoggingOptionFail(self, mock_warn):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + LOGGING_ACCEPT, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("match logging-term-1", output)
    self.assertNotIn(" log\n", output)  # check for bare 'log' word
    mock_warn.assert_any_call(
        "WARNING: term %s uses logging option but is not a deny "
        "action. logging will not be added.",
        "logging-term-1",
    )

  def testLoggingOption(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + LOGGING_DENY, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn(" log\n", output)

  @mock.patch.object(arista_tp.logging, "debug")
  def testIcmpv6InetMismatch(self, mock_debug):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + BAD_ICMPTYPE_TERM_1, self.naming),
        EXP_INFO)
    str(atp)

    mock_debug.assert_called_once_with(
        "Term icmptype-mismatch will not be rendered, "
        "as it has icmpv6 match specified but "
        "the ACL is of inet address family.")

  @mock.patch.object(arista_tp.logging, "debug")
  def testIcmpInet6Mismatch(self, mock_debug):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER_INET6 + BAD_ICMPTYPE_TERM_2,
                           self.naming),
        EXP_INFO,
    )
    str(atp)

    mock_debug.assert_called_once_with(
        "Term icmptype-mismatch will not be rendered, "
        "as it has icmp match specified but "
        "the ACL is of inet6 address family.")

  # icmptype-mismatch test for mixed filter type
  @mock.patch.object(arista_tp.logging, "debug")
  def testIcmpMismatchMixedInet(self, mock_debug):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + BAD_ICMPTYPE_TERM_1, self.naming),
        EXP_INFO,
    )
    str(atp)

    mock_debug.assert_called_once_with(
        "Term icmptype-mismatch will not be rendered, "
        "as it has icmpv6 match specified but "
        "the ACL is of inet address family.")

  @mock.patch.object(arista_tp.logging, "debug")
  def testIcmpMismatchMixedInet6(self, mock_debug):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + BAD_ICMPTYPE_TERM_2, self.naming),
        EXP_INFO,
    )
    str(atp)

    mock_debug.assert_called_once_with(
        "Term ipv6-icmptype-mismatch will not be rendered, "
        "as it has icmp match specified but "
        "the ACL is of inet6 address family.")

  @mock.patch.object(arista_tp.logging, "warning")
  def testExpiredTerm(self, mock_warn):
    _ = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + EXPIRED_TERM, self.naming), EXP_INFO)

    mock_warn.assert_any_call(
        "WARNING: term %s in policy %s is expired and will "
        "not be rendered.",
        "is_expired",
        "test-filter",
    )
    mock_warn.assert_any_call(
        "WARNING: term %s in policy %s is expired and will "
        "not be rendered.",
        "ipv6-is_expired",
        "test-filter",
    )

  @mock.patch.object(arista_tp.logging, "info")
  def testExpiringTerm(self, mock_info):
    exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
    _ = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(
            GOOD_HEADER + EXPIRING_TERM % exp_date.strftime("%Y-%m-%d"),
            self.naming),
        EXP_INFO,
    )
    mock_info.assert_any_call(
        "INFO: term %s in policy %s expires in "
        "less than two weeks.", "is_expiring", "test-filter")

  def testOwnerTerm(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_OWNER, self.naming),
        EXP_INFO)
    output = str(atp)
    self.assertIn("!! owner: foo@gmail.com", output, output)

  # confirm that we don't generate a term for non-default
  @mock.patch.object(arista_tp.logging, "warning")
  def testMissingMatchCriteria(self, mock_warn):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + MISSING_MATCH, self.naming), EXP_INFO)
    output = str(atp)
    self.assertNotIn("match", output, output)
    mock_warn.has_calls(
        "WARNING: term %s has no valid match criteria and "
        "will not be rendered.",
        "missing-match",
    )

  def testAddressExclude(self):
    big = nacaddr.IPv4("0.0.0.0/1")
    ip1 = nacaddr.IPv4("10.0.0.0/8")
    ip2 = nacaddr.IPv4("172.16.0.0/12")
    terms = (GOOD_TERM_18_SRC, GOOD_TERM_18_DST)
    self.naming.GetNetAddr.side_effect = [[big, ip1, ip2], [ip1]] * len(terms)

    mock_calls = []
    for term in terms:
      atp = arista_tp.AristaTrafficPolicy(
          policy.ParsePolicy(GOOD_HEADER + term, self.naming), EXP_INFO)
      output = str(atp)
      self.assertIn("except 10.0.0.0/8", output, output)
      # note that the additional spaces are in the following assert to insure
      # that it's not being rendered w/o the "except"
      self.assertNotIn("  10.0.0.0/8", output, output)
      self.assertIn("172.16.0.0/12", output, output)
      self.assertNotIn("except 172.16.0.0/12", output, output)
      mock_calls.append(mock.call("INTERNAL"))
      mock_calls.append(mock.call("SOME_HOST"))

    self.naming.GetNetAddr.assert_has_calls(mock_calls)

  def testMixedInet(self):
    self.naming.GetNetAddr.side_effect = [[
        nacaddr.IP("8.8.4.4"),
        nacaddr.IP("8.8.8.8"),
        nacaddr.IP("2001:4860:4860::8844"),
        nacaddr.IP("2001:4860:4860::8888")
    ],
                                          [
                                              nacaddr.IP("10.0.0.0/8"),
                                              nacaddr.IP("172.16.0.0/12"),
                                              nacaddr.IP("192.168.0.0/16")
                                          ]]

    pol = policy.ParsePolicy(GOOD_HEADER + MIXED_INET, self.naming)
    atp = arista_tp.AristaTrafficPolicy(pol, EXP_INFO)
    output = str(atp)
    self.assertIn("match MIXED_INET ipv4", output, output)
    self.assertIn("source prefix 8.8.4.4/32", output, output)
    self.assertIn("destination prefix 10.0.0.0/8", output, output)
    self.assertNotIn("match ipv6-MIXED_INET ipv6", output, output)
    self.assertNotIn("source prefix 2001:4860:4860::8844/128", output, output)

  def testInetMixed(self):
    self.naming.GetNetAddr.side_effect = [
        [
            nacaddr.IP("10.0.0.0/8"),
            nacaddr.IP("172.16.0.0/12"),
            nacaddr.IP("192.168.0.0/16")
        ],
        [
            nacaddr.IP("8.8.4.4"),
            nacaddr.IP("8.8.8.8"),
            nacaddr.IP("2001:4860:4860::8844"),
            nacaddr.IP("2001:4860:4860::8888")
        ],
    ]

    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + INET_MIXED, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("match INET_MIXED ipv4", output, output)
    self.assertIn("source prefix 10.0.0.0/8", output, output)
    self.assertIn("destination prefix 8.8.4.4/32", output, output)
    self.assertNotIn("match ipv6-INET_MIXED ipv6", output, output)
    self.assertNotIn("destination prefix 2001:4860:4860::8844/128", output,
                     output)

  def testMixedInet6(self):
    self.naming.GetNetAddr.side_effect = [[
        nacaddr.IP("8.8.4.4"),
        nacaddr.IP("8.8.8.8"),
        nacaddr.IP("2001:4860:4860::8844"),
        nacaddr.IP("2001:4860:4860::8888")
    ], [nacaddr.IP("2001:4860:4860::8844")]]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + MIXED_INET6, self.naming), EXP_INFO)
    output = str(atp)
    # note that the term name will contain the 'ipv6-' prefix
    self.assertIn("match ipv6-MIXED_INET6 ipv6", output, output)
    self.assertIn("source prefix 2001:4860:4860::8844/128", output, output)
    self.assertIn("destination prefix 2001:4860:4860::8844/128", output, output)
    # check to make sure that the IPv4 elements are not rendered
    self.assertNotIn("match MIXED_INET6 ipv4", output, output)
    self.assertNotIn("source prefix 8.8.8.8", output, output)

  def testInet6Mixed(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP("2001:4860:4860::8844")],
        [
            nacaddr.IP("8.8.4.4"),
            nacaddr.IP("8.8.8.8"),
            nacaddr.IP("2001:4860:4860::8844"),
            nacaddr.IP("2001:4860:4860::8888")
        ]
    ]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + INET6_MIXED, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("match ipv6-INET6_MIXED ipv6", output, output)
    self.assertIn("source prefix 2001:4860:4860::8844/128", output, output)
    self.assertIn("destination prefix 2001:4860:4860::8844/128", output, output)
    self.assertNotIn("match INET6_MIXED ipv4", output, output)
    self.assertNotIn("destination prefix 8.8.8.8", output, output)

  def testMixedMixed(self):
    self.naming.GetNetAddr.side_effect = [
        [
            nacaddr.IP("8.8.4.4"),
            nacaddr.IP("8.8.8.8"),
            nacaddr.IP("2001:4860:4860::8844"),
            nacaddr.IP("2001:4860:4860::8888")
        ],
        [
            nacaddr.IP("4.4.2.2"),
            nacaddr.IP("4.4.4.4"),
            nacaddr.IP("2001:4860:1337::8844"),
            nacaddr.IP("2001:4860:1337::8888")
        ]
    ]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + MIXED_MIXED, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("match MIXED_MIXED ipv4", output, output)
    self.assertIn("source prefix 8.8.4.4/32", output, output)
    self.assertIn("destination prefix 4.4.2.2", output, output)

    self.assertIn("match ipv6-MIXED_MIXED ipv6", output, output)
    self.assertIn("source prefix 2001:4860:4860::8844/128", output, output)
    self.assertIn("destination prefix 2001:4860:1337::8844/128", output, output)

  def testMixedAny(self):
    self.naming.GetNetAddr.side_effect = [[
        nacaddr.IP("8.8.4.4"),
        nacaddr.IP("8.8.8.8"),
        nacaddr.IP("2001:4860:4860::8844"),
        nacaddr.IP("2001:4860:4860::8888")
    ]]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + MIXED_ANY, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("match MIXED_ANY ipv4", output, output)
    self.assertIn("source prefix 8.8.4.4/32", output, output)

    self.assertIn("match ipv6-MIXED_ANY ipv6", output, output)
    self.assertIn("source prefix 2001:4860:4860::8844/128", output, output)

  def testAnyMixed(self):
    self.naming.GetNetAddr.side_effect = [[
        nacaddr.IP("8.8.4.4"),
        nacaddr.IP("8.8.8.8"),
        nacaddr.IP("2001:4860:4860::8844"),
        nacaddr.IP("2001:4860:4860::8888")
    ]]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + ANY_MIXED, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("match ANY_MIXED ipv4", output, output)
    self.assertIn("destination prefix 8.8.4.4/32", output, output)

    self.assertIn("match ipv6-ANY_MIXED ipv6", output, output)
    self.assertIn("destination prefix 2001:4860:4860::8844/128", output, output)

  def testInetInet(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP("8.8.4.4"), nacaddr.IP("8.8.8.8")],
        [nacaddr.IP("4.4.2.2"), nacaddr.IP("4.4.4.4")],
    ]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + INET_INET, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("match INET_INET ipv4", output, output)
    self.assertIn("source prefix 8.8.4.4/32", output, output)
    self.assertIn("destination prefix 4.4.2.2/32", output, output)

  def testInet6Inet6(self):
    self.naming.GetNetAddr.side_effect = [[
        nacaddr.IP("2001:4860:4860::8844"),
        nacaddr.IP("2001:4860:4860::8888")
    ], [nacaddr.IP("2001:4860:1337::8844"),
        nacaddr.IP("2001:4860:1337::8888")]]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + INET6_INET6, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("match ipv6-INET6_INET6 ipv6", output, output)
    self.assertIn("source prefix 2001:4860:4860::8844/128", output, output)
    self.assertIn("destination prefix 2001:4860:1337::8844/128", output, output)

  def testInetInet6(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP("8.8.4.4"), nacaddr.IP("8.8.8.8")],
        [
            nacaddr.IP("2001:4860:4860::8844"),
            nacaddr.IP("2001:4860:4860::8888")
        ],
    ]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + INET_INET6, self.naming), EXP_INFO)
    output = str(atp)
    # we should not generate this term we should, however, throw a warning.
    self.assertNotIn("match INET_INET6 ipv4", output, output)
    self.assertNotIn("match ipv6-INET_INET6 ipv6", output, output)

  def testInet6Inet(self):
    self.naming.GetNetAddr.side_effect = [
        [
            nacaddr.IP("2001:4860:4860::8844"),
            nacaddr.IP("2001:4860:4860::8888")
        ],
        [nacaddr.IP("8.8.4.4"), nacaddr.IP("8.8.8.8")],
    ]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + INET6_INET, self.naming), EXP_INFO)
    output = str(atp)
    self.assertNotIn("match INET6_INET ipv4", output, output)
    self.assertNotIn("match ipv6-INET6_INET ipv6", output, output)

  def testSrcFsInet(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP("8.8.4.0/24"),
         nacaddr.IP("8.8.8.0/24")],
        [nacaddr.IP("8.8.4.4"), nacaddr.IP("8.8.8.8")],
    ]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + SRC_FIELD_SET_INET, self.naming),
        EXP_INFO)
    output = str(atp)
    self.assertIn("field-set ipv4 prefix src-FS_INET", output, output)
    self.assertIn("source prefix field-set src-FS_INET", output, output)

  def testSrcFsInet6(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP("2001:4860:4860::/64"),
         nacaddr.IP("2001:4860:4861::/64")],
        [
            nacaddr.IP("2001:4860:4860::8844"),
            nacaddr.IP("2001:4860:4861::8888")
        ],
    ]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + SRC_FIELD_SET_INET6, self.naming),
        EXP_INFO)
    output = str(atp)
    self.assertIn("field-set ipv6 prefix src-ipv6-FS_INET6", output, output)
    self.assertIn("source prefix field-set src-ipv6-FS_INET6", output, output)

  def testSrcFsMixed(self):
    self.naming.GetNetAddr.side_effect = [
        [
            nacaddr.IP("8.8.4.0/24"),
            nacaddr.IP("8.8.8.0/24"),
            nacaddr.IP("2001:4860:4860::/64"),
            nacaddr.IP("2001:4860:4860::/64"),
            nacaddr.IP("2001:4860:4861::/64")
        ],
        [
            nacaddr.IP("2001:4860:4860::8844"),
            nacaddr.IP("2001:4860:4861::8888"),
            nacaddr.IP("8.8.4.4"),
            nacaddr.IP("8.8.8.8"),
        ],
    ]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + SRC_FIELD_SET_MIXED, self.naming),
        EXP_INFO)
    output = str(atp)
    self.assertIn("field-set ipv4 prefix src-FS_MIXED", output, output)
    self.assertIn("field-set ipv6 prefix src-ipv6-FS_MIXED", output, output)
    self.assertIn("source prefix field-set src-FS_MIXED", output, output)
    self.assertIn("source prefix field-set src-ipv6-FS_MIXED", output, output)

  def testDstFsInet(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP("8.8.4.0/24"),
         nacaddr.IP("8.8.8.0/24")],
        [nacaddr.IP("8.8.4.4"), nacaddr.IP("8.8.8.8")],
    ]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + DST_FIELD_SET_INET, self.naming),
        EXP_INFO)
    output = str(atp)
    self.assertIn("field-set ipv4 prefix dst-FS_INET", output, output)
    self.assertIn("destination prefix field-set dst-FS_INET", output, output)

  def testDstFsInet6(self):
    self.naming.GetNetAddr.side_effect = [
        [nacaddr.IP("2001:4860:4860::/64"),
         nacaddr.IP("2001:4860:4861::/64")],
        [
            nacaddr.IP("2001:4860:4860::8844"),
            nacaddr.IP("2001:4860:4861::8888")
        ],
    ]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + DST_FIELD_SET_INET6, self.naming),
        EXP_INFO)
    output = str(atp)
    self.assertIn("field-set ipv6 prefix dst-ipv6-FS_INET6", output, output)
    self.assertIn("destination prefix field-set dst-ipv6-FS_INET6", output,
                  output)

  def testDstFsMixed(self):
    self.naming.GetNetAddr.side_effect = [
        [
            nacaddr.IP("8.8.4.0/24"),
            nacaddr.IP("8.8.8.0/24"),
            nacaddr.IP("2001:4860:4860::/64"),
            nacaddr.IP("2001:4860:4860::/64"),
            nacaddr.IP("2001:4860:4861::/64")
        ],
        [
            nacaddr.IP("2001:4860:4860::8844"),
            nacaddr.IP("2001:4860:4861::8888"),
            nacaddr.IP("8.8.4.4"),
            nacaddr.IP("8.8.8.8"),
        ],
    ]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + DST_FIELD_SET_MIXED, self.naming),
        EXP_INFO)
    output = str(atp)
    self.assertIn("field-set ipv4 prefix dst-FS_MIXED", output, output)
    self.assertIn("field-set ipv6 prefix dst-ipv6-FS_MIXED", output, output)
    self.assertIn("destination prefix field-set dst-FS_MIXED", output, output)
    self.assertIn("destination prefix field-set dst-ipv6-FS_MIXED", output,
                  output)

  def testConfigHelper(self):
    match_indent = " " * 6
    config = arista_tp.Config()
    config.Append(match_indent, "test")
    config.Append(match_indent, "blah")
    config.Append(match_indent, "foo")
    config.Append(match_indent, "bar")
    config.Append(match_indent, "Mr. T Pities the fool!", verbatim=True)
    self.assertMultiLineEqual(
        str(config), "      test\n"
        "      blah\n"
        "      foo\n"
        "      bar\n"
        "Mr. T Pities the fool!")

  def testFragmentOffset(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + FRAGOFFSET_TERM, self.naming),
        EXP_INFO)
    output = str(atp)
    self.assertIn("fragment offset 1-7", output, output)

  def testTTL(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_21, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("ttl 10", output)

  def testBuildTokens(self):
    self.naming.GetNetAddr.return_value = [
        nacaddr.IP("10.1.1.1/26", strict=False)
    ]

    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28, self.naming), EXP_INFO)
    st, sst = atp._BuildTokens()
    # print(ppr.pprint(st))
    # print(ppr.pprint(SUPPORTED_TOKENS))
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

  def testBuildWarningTokens(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28, self.naming), EXP_INFO)
    st, sst = atp._BuildTokens()
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

  def testHopOptProtocol(self):
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + HOPOPT_TERM, self.naming), EXP_INFO)
    output = str(atp)
    self.assertIn("protocol 0", output, output)

  def testFailIsFragmentInV6(self):
    self.naming.GetServiceByProto.return_value = ["22"]
    pol = policy.ParsePolicy(GOOD_HEADER_INET6 + OPTION_TERM_1, self.naming)

    self.assertRaises(
        arista_tp.AristaTpFragmentInV6Error,
        arista_tp.AristaTrafficPolicy,
        pol,
        EXP_INFO,
    )

  @mock.patch.object(arista_tp.logging, "warning")
  def testFailIsFragmentInMixed(self, mock_warn):
    self.naming.GetServiceByProto.return_value = ["22"]
    atp = arista_tp.AristaTrafficPolicy(
        policy.ParsePolicy(GOOD_HEADER + OPTION_TERM_1, self.naming), EXP_INFO)
    output = str(atp)
    self.assertNotIn("match ipv6-option-term ipv6", output, output)
    mock_warn.assert_any_call(
        "WARNING: term %s in mixed policy %s uses fragment "
        "the ipv6 version of the term will not be rendered.",
        "ipv6-option-term", "test-filter")


if __name__ == "__main__":
  absltest.main()
