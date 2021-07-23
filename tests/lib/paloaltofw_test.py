# Copyright 2012 Google Inc. All Rights Reserved.
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
"""Unit test for Palo Alto Firewalls acl rendering module."""

from absl.testing import absltest
from unittest import mock

from capirca.lib import aclgenerator
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import paloaltofw
from capirca.lib import policy

GOOD_HEADER_1 = """
header {
  comment:: "This is a test acl with a comment"
  target:: paloalto from-zone trust to-zone untrust
}
"""

GOOD_HEADER_2 = """
header {
  comment:: "This is a test acl with a comment"
  target:: paloalto from-zone all to-zone all
}
"""

GOOD_HEADER_INET6 = """
header {
  comment:: "This is a test acl with a comment"
  target:: paloalto from-zone trust to-zone untrust inet6
}
"""

GOOD_HEADER_MIXED = """
header {
  comment:: "This is a test acl with a comment"
  target:: paloalto from-zone trust to-zone untrust mixed
}
"""

BAD_HEADER_1 = """
header {
  comment:: "This header has two address families"
  target:: paloalto from-zone trust to-zone untrust inet6 mixed
}
"""

GRE_PROTO_TERM = """
term test-gre-protocol {
  comment:: "allow GRE protocol to FOOBAR"
  destination-address:: FOOBAR
  protocol:: gre
  action:: accept
}
"""

GOOD_TERM_1 = """
term good-term-1 {
  comment:: "This header is very very very very very very very very very very very very very very very very very very very very large"
  destination-address:: FOOBAR
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}

"""

GOOD_TERM_2 = """
term good-term-4 {
  destination-address:: SOME_HOST
  protocol:: tcp
  pan-application:: ssl http
  action:: accept
}
"""

GOOD_TERM_3 = """
term only-pan-app {
  pan-application:: ssl
  action:: accept
}
"""

GOOD_TERM_4_STATELESS_REPLY = """
term good-term-stateless-reply {
  comment:: "ThisIsAStatelessReply"
  destination-address:: SOME_HOST
  protocol:: tcp
  pan-application:: ssl http
  action:: accept
}
"""

SVC_TERM_1 = """
term ssh-term-1 {
  comment:: "Allow SSH"
  destination-address:: FOOBAR
  destination-port:: SSH
  protocol:: tcp
  action:: accept
}

term smtp-term-1 {
  comment:: "Allow SMTP"
  destination-address:: FOOBAR
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

SVC_TERM_2 = """
term smtp-term-1 {
  comment:: "Allow SMTP"
  destination-address:: FOOBAR
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

TCP_ESTABLISHED_TERM = """
term tcp-established {
  destination-address:: SOME_HOST
  protocol:: tcp
  option:: tcp-established
  action:: accept
}
"""

UDP_ESTABLISHED_TERM = """
term udp-established-term {
  destination-address:: SOME_HOST
  protocol:: udp
  option:: established
  action:: accept
}
"""

UNSUPPORTED_OPTION_TERM = """
term unsupported-option-term {
  destination-address:: SOME_HOST
  protocol:: udp
  option:: inactive
  action:: accept
}
"""

EXPIRED_TERM_1 = """
term expired_test {
  expiration:: 2000-1-1
  action:: deny
}
"""

EXPIRING_TERM = """
term is_expiring {
  expiration:: %s
  action:: accept
}
"""

ICMP_TYPE_TERM_1 = """
term test-icmp {
  protocol:: icmp
  icmp-type:: echo-request echo-reply unreachable
  action:: accept
}
"""

ICMPV6_ONLY_TERM = """
term test-icmpv6-only {
  protocol:: icmpv6
  action:: accept
}
"""

ICMPV6_TYPE_TERM = """
term test-icmpv6-types {
  protocol:: icmpv6
  icmp-type:: echo-request echo-reply destination-unreachable
  action:: accept
}
"""

BAD_ICMPV6_TYPE_TERM = """
term test-icmp {
  protocol:: icmpv6
  icmp-type:: echo-request echo-reply unreachable
  action:: accept
  comment:: "This is incorrect because unreachable is not an icmpv6-type."
}
"""

BAD_ICMP_TERM_1 = """
term test-icmp-type {
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

ICMP_ONLY_TERM_1 = """
term test-icmp-only {
  protocol:: icmp
  action:: accept
}
"""

MULTIPLE_PROTOCOLS_TERM = """
term multi-proto {
  protocol:: tcp udp icmp
  action:: accept
}
"""

DEFAULT_TERM_1 = """
term default-term-1 {
  action:: deny
}
"""

TIMEOUT_TERM = """
term timeout-term {
  protocol:: icmp
  icmp-type:: echo-request
  timeout:: 77
  action:: accept
}
"""

LOGGING_DISABLED = """
term test-disabled-log {
  comment:: "Testing disabling logging for tcp."
  protocol:: tcp
  logging:: disable
  action:: accept
}
"""

LOGGING_BOTH_TERM = """
term test-log-both {
  comment:: "Testing enabling log-both for tcp."
  protocol:: tcp
  logging:: log-both
  action:: accept
}
"""

LOGGING_TRUE_KEYWORD = """
term test-true-log {
  comment:: "Testing enabling logging for udp with true keyword."
  protocol:: udp
  logging:: true
  action:: accept
}
"""

LOGGING_PYTRUE_KEYWORD = """
term test-pytrue-log {
  comment:: "Testing enabling logging for udp with True keyword."
  protocol:: udp
  logging:: True
  action:: accept
}
"""

LOGGING_SYSLOG_KEYWORD = """
term test-syslog-log {
  comment:: "Testing enabling logging for udp with syslog keyword."
  protocol:: udp
  logging:: syslog
  action:: accept
}
"""

LOGGING_LOCAL_KEYWORD = """
term test-local-log {
  comment:: "Testing enabling logging for udp with local keyword."
  protocol:: udp
  logging:: local
  action:: accept
}
"""

ACTION_ACCEPT_TERM = """
term test-accept-action {
  comment:: "Testing accept action for tcp."
  protocol:: tcp
  action:: accept
}
"""

ACTION_COUNT_TERM = """
term test-count-action {
  comment:: "Testing unsupported count action for tcp."
  protocol:: tcp
  action:: count
}
"""

ACTION_NEXT_TERM = """
term test-next-action {
  comment:: "Testing unsupported next action for tcp."
  protocol:: tcp
  action:: next
}
"""

ACTION_DENY_TERM = """
term test-deny-action {
  comment:: "Testing deny action for tcp."
  protocol:: tcp
  action:: deny
}
"""

ACTION_REJECT_TERM = """
term test-reject-action {
  comment:: "Testing reject action for tcp."
  protocol:: tcp
  action:: reject
}
"""

ACTION_RESET_TERM = """
term test-reset-action {
  comment:: "Testing reset action for tcp."
  protocol:: tcp
  action:: reject-with-tcp-rst
}
"""

PLATFORM_TERM = """
term test-accept-action {
  comment:: "Testing accept action for tcp."
  protocol:: tcp
  action:: accept
  platform:: paloalto
}
"""

OTHER_PLATFORM_TERM = """
term test-accept-action {
  comment:: "Testing accept action for tcp."
  protocol:: tcp
  action:: accept
  platform:: juniper
}
"""

PLATFORM_EXCLUDE_TERM = """
term test-accept-action {
  comment:: "Testing accept action for tcp."
  protocol:: tcp
  action:: accept
  platform-exclude:: paloalto
}
"""

OTHER_PLATFORM_EXCLUDE_TERM = """
term test-accept-action {
  comment:: "Testing accept action for tcp."
  protocol:: tcp
  action:: accept
  platform-exclude:: junipersrx
}
"""

HEADER_COMMENTS = """
header {
  comment:: "comment 1"
  comment:: "comment 2"
  target:: paloalto from-zone trust to-zone untrust
}
term policy-1 {
  pan-application:: ssh
  action:: accept
}
term policy-2 {
  pan-application:: web-browsing
  action:: accept
}
header {
  comment:: "comment 3"
  target:: paloalto from-zone trust to-zone dmz
}
term policy-3 {
  pan-application:: web-browsing
  action:: accept
}
header {
  # no comment
  target:: paloalto from-zone trust to-zone dmz-2
}
term policy-4 {
  pan-application:: web-browsing
  action:: accept
}
"""

ZONE_LEN_ERROR = """
header {
  target:: paloalto from-zone %s to-zone %s
}
term policy {
  pan-application:: web-browsing
  action:: accept
}
"""

SUPPORTED_TOKENS = frozenset({
    'action',
    'comment',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'expiration',
    'icmp_type',
    'logging',
    'name',
    'option',
    'owner',
    'platform',
    'platform_exclude',
    'protocol',
    'source_address',
    'source_address_exclude',
    'source_port',
    'stateless_reply',
    'timeout',
    'pan_application',
    'translated',
})

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny', 'reject', 'reject-with-tcp-rst'},
    'option': {'established', 'tcp-established'},
    'icmp_type': {
        'alternate-address',
        'certification-path-advertisement',
        'certification-path-solicitation',
        'conversion-error',
        'destination-unreachable',
        'echo-reply',
        'echo-request',
        'mobile-redirect',
        'home-agent-address-discovery-reply',
        'home-agent-address-discovery-request',
        'icmp-node-information-query',
        'icmp-node-information-response',
        'information-request',
        'inverse-neighbor-discovery-advertisement',
        'inverse-neighbor-discovery-solicitation',
        'mask-reply',
        'mask-request',
        'information-reply',
        'mobile-prefix-advertisement',
        'mobile-prefix-solicitation',
        'multicast-listener-done',
        'multicast-listener-query',
        'multicast-listener-report',
        'multicast-router-advertisement',
        'multicast-router-solicitation',
        'multicast-router-termination',
        'neighbor-advertisement',
        'neighbor-solicit',
        'packet-too-big',
        'parameter-problem',
        'redirect',
        'redirect-message',
        'router-advertisement',
        'router-renumbering',
        'router-solicit',
        'router-solicitation',
        'source-quench',
        'time-exceeded',
        'timestamp-reply',
        'timestamp-request',
        'unreachable',
        'version-2-multicast-listener-report',
    },
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2

_IPSET = [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('2001:4860:8000::/33')]
_IPSET2 = [nacaddr.IP('10.23.0.0/22'), nacaddr.IP('10.23.0.6/23', strict=False)]
_IPSET3 = [nacaddr.IP('10.23.0.0/23')]

PATH_VSYS = "./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
PATH_RULES = PATH_VSYS + '/rulebase/security/rules'
PATH_TAG = PATH_VSYS + '/tag'
PATH_SERVICE = PATH_VSYS + '/service'


class PaloAltoFWTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def testTermAndFilterName(self):
    self.naming.GetNetAddr.return_value = _IPSET
    self.naming.GetServiceByProto.return_value = ['25']

    paloalto = paloaltofw.PaloAltoFW(
        policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1, self.naming), EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.find(PATH_RULES + "/entry[@name='good-term-1']")
    self.assertIsNotNone(x, output)

    self.naming.GetNetAddr.assert_called_once_with('FOOBAR')
    self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

  def testServiceMap(self):
    definitions = naming.Naming()
    definitions._ParseLine('SSH = 22/tcp', 'services')
    definitions._ParseLine('SMTP = 25/tcp', 'services')
    definitions._ParseLine('FOOBAR = 10.0.0.0/8', 'networks')
    definitions._ParseLine('         2001:4860:8000::/33', 'networks')

    pol1 = paloaltofw.PaloAltoFW(
        policy.ParsePolicy(GOOD_HEADER_1 + SVC_TERM_1, definitions), EXP_INFO)
    self.assertEqual(
        pol1.service_map.entries, {
            ((), ('22',), 'tcp'): {
                'name': 'service-ssh-term-1-tcp'
            },
            ((), ('25',), 'tcp'): {
                'name': 'service-smtp-term-1-tcp'
            }
        }, pol1.service_map.entries)

    pol2 = paloaltofw.PaloAltoFW(
        policy.ParsePolicy(GOOD_HEADER_1 + SVC_TERM_2, definitions), EXP_INFO)
    # The expectation is that there will be a single port mapped.
    self.assertEqual(
        pol2.service_map.entries, {
            ((), ('25',), 'tcp'): {
                'name': 'service-smtp-term-1-tcp'
            }
        }, pol2.service_map.entries)

  def testDefaultDeny(self):
    paloalto = paloaltofw.PaloAltoFW(
        policy.ParsePolicy(GOOD_HEADER_1 + DEFAULT_TERM_1, self.naming),
        EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.find(PATH_RULES +
                             "/entry[@name='default-term-1']/action")
    self.assertIsNotNone(x, output)
    self.assertEqual(x.text, 'deny', output)

  def testIcmpTypes(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + ICMP_TYPE_TERM_1, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.find(PATH_RULES +
                             "/entry[@name='test-icmp']/application")
    self.assertIsNotNone(x, output)
    members = []
    for node in x:
      self.assertEqual(node.tag, 'member', output)
      members.append(node.text)

    self.assertCountEqual(
        ['icmp-echo-reply', 'icmp-echo-request', 'icmp-unreachable'], members,
        output)

  def testIcmpV6Types(self):
    pol = policy.ParsePolicy(GOOD_HEADER_MIXED + ICMPV6_TYPE_TERM, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.find(PATH_RULES +
                             "/entry[@name='test-icmpv6-types']/application")
    self.assertIsNotNone(x, output)
    members = []
    for node in x:
      self.assertEqual(node.tag, 'member', output)
      members.append(node.text)

    self.assertCountEqual([
        'icmp6-echo-reply', 'icmp6-echo-request',
        'icmp6-destination-unreachable'
    ], members, output)

  def testBadICMP(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + BAD_ICMP_TERM_1, self.naming)
    self.assertRaises(paloaltofw.UnsupportedFilterError, paloaltofw.PaloAltoFW,
                      pol, EXP_INFO)

  def testBadICMPv6Type(self):
    pol = policy.ParsePolicy(GOOD_HEADER_MIXED + BAD_ICMPV6_TYPE_TERM,
                             self.naming)
    self.assertRaises(paloaltofw.PaloAltoFWBadIcmpTypeError,
                      paloaltofw.PaloAltoFW, pol, EXP_INFO)

  def testICMPProtocolOnly(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + ICMP_ONLY_TERM_1, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.find(PATH_RULES +
                             "/entry[@name='test-icmp-only']/application")
    self.assertIsNotNone(x, output)
    members = []
    for node in x:
      self.assertEqual(node.tag, 'member', output)
      members.append(node.text)

    self.assertEqual(['icmp'], members, output)

  def testICMPv6ProtocolOnly(self):
    pol = policy.ParsePolicy(GOOD_HEADER_INET6 + ICMPV6_ONLY_TERM, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.find(PATH_RULES +
                             "/entry[@name='test-icmpv6-only']/application")
    self.assertIsNotNone(x, output)
    members = []
    for node in x:
      self.assertEqual(node.tag, 'member', output)
      members.append(node.text)

    self.assertEqual(['ipv6-icmp'], members, output)

  def testSkipStatelessReply(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_4_STATELESS_REPLY,
                             self.naming)

    # Add stateless_reply to terms, there is no current way to include it in the
    # term definition.
    _, terms = pol.filters[0]
    for term in terms:
      term.stateless_reply = True

    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.find(PATH_RULES +
                             "/entry[@name='good-term-stateless-reply']")
    self.assertIsNone(x, output)

  def testSkipEstablished(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + TCP_ESTABLISHED_TERM, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.find(PATH_RULES + "/entry[@name='tcp-established']")
    self.assertIsNone(x, output)

    pol = policy.ParsePolicy(GOOD_HEADER_1 + UDP_ESTABLISHED_TERM, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.find(PATH_RULES +
                             "/entry[@name='udp-established-term']")
    self.assertIsNone(x, output)

  def testUnsupportedOptions(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + UNSUPPORTED_OPTION_TERM,
                             self.naming)
    self.assertRaises(aclgenerator.UnsupportedFilterError,
                      paloaltofw.PaloAltoFW, pol, EXP_INFO)

  def testBuildTokens(self):
    self.naming.GetServiceByProto.side_effect = [['25'], ['26']]
    pol1 = paloaltofw.PaloAltoFW(
        policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_2, self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

  def testLoggingBoth(self):
    paloalto = paloaltofw.PaloAltoFW(
        policy.ParsePolicy(GOOD_HEADER_1 + LOGGING_BOTH_TERM, self.naming),
        EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='test-log-both']/log-start")
    self.assertEqual(x, 'yes', output)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='test-log-both']/log-end")
    self.assertEqual(x, 'yes', output)

  def testDisableLogging(self):
    paloalto = paloaltofw.PaloAltoFW(
        policy.ParsePolicy(GOOD_HEADER_1 + LOGGING_DISABLED, self.naming),
        EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='test-disabled-log']/log-start")
    self.assertEqual(x, 'no', output)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='test-disabled-log']/log-end")
    self.assertEqual(x, 'no', output)

  def testLogging(self):
    for term in [
        LOGGING_SYSLOG_KEYWORD, LOGGING_LOCAL_KEYWORD, LOGGING_PYTRUE_KEYWORD,
        LOGGING_TRUE_KEYWORD
    ]:
      paloalto = paloaltofw.PaloAltoFW(
          policy.ParsePolicy(GOOD_HEADER_1 + term, self.naming), EXP_INFO)
      output = str(paloalto)

      # we don't have term name so match all elements with attribute
      # name at the entry level
      x = paloalto.config.findall(PATH_RULES + '/entry[@name]/log-start')
      self.assertEqual(len(x), 0, output)
      x = paloalto.config.findall(PATH_RULES + '/entry[@name]/log-end')
      self.assertEqual(len(x), 1, output)
      self.assertEqual(x[0].text, 'yes', output)

  def testAcceptAction(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + ACTION_ACCEPT_TERM, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='test-accept-action']/action")
    self.assertEqual(x, 'allow', output)

  def testDenyAction(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + ACTION_DENY_TERM, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='test-deny-action']/action")
    self.assertEqual(x, 'deny', output)

  def testRejectAction(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + ACTION_REJECT_TERM, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='test-reject-action']/action")
    self.assertEqual(x, 'reset-client', output)

  def testResetAction(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + ACTION_RESET_TERM, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='test-reset-action']/action")
    self.assertEqual(x, 'reset-client', output)

  def testCountAction(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + ACTION_COUNT_TERM, self.naming)
    self.assertRaises(aclgenerator.UnsupportedFilterError,
                      paloaltofw.PaloAltoFW, pol, EXP_INFO)

  def testNextAction(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + ACTION_NEXT_TERM, self.naming)
    self.assertRaises(aclgenerator.UnsupportedFilterError,
                      paloaltofw.PaloAltoFW, pol, EXP_INFO)

  def testPlatformTerm(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + PLATFORM_TERM, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='test-accept-action']/action")
    self.assertEqual(x, 'allow', output)

  def testOtherPlatformTerm(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + OTHER_PLATFORM_TERM, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='test-accept-action']/action")
    self.assertIsNone(x, output)

  def testPlatformExcludeTerm(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + PLATFORM_EXCLUDE_TERM, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='test-accept-action']/action")
    self.assertIsNone(x, output)

  def testOtherPlatformExcludeTerm(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + OTHER_PLATFORM_EXCLUDE_TERM,
                             self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='test-accept-action']/action")
    self.assertEqual(x, 'allow', output)

  def testGreProtoTerm(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GRE_PROTO_TERM, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.find(PATH_RULES +
                             "/entry[@name='test-gre-protocol']/application")
    self.assertIsNotNone(x, output)
    self.assertEqual(len(x), 1, output)
    self.assertEqual(x[0].tag, 'member', output)
    self.assertEqual(x[0].text, 'gre', output)

  def testHeaderComments(self):
    pol = policy.ParsePolicy(HEADER_COMMENTS, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)

    tag = 'trust_untrust_policy-comment-1'
    x = paloalto.config.find(PATH_TAG + "/entry[@name='%s']/comments" % tag)
    self.assertIsNotNone(x, output)
    self.assertEqual(x.text, 'comment 1 comment 2', output)
    x = paloalto.config.find(PATH_RULES + "/entry[@name='policy-2']/tag")
    self.assertIsNotNone(x, output)
    self.assertEqual(len(x), 1, output)
    self.assertEqual(x[0].tag, 'member', output)
    self.assertEqual(x[0].text, tag, output)

    tag = 'trust_dmz_policy-comment-2'
    x = paloalto.config.find(PATH_TAG + "/entry[@name='%s']/comments" % tag)
    self.assertIsNotNone(x, output)
    self.assertEqual(x.text, 'comment 3', output)
    x = paloalto.config.find(PATH_RULES + "/entry[@name='policy-3']/tag")
    self.assertIsNotNone(x, output)
    self.assertEqual(len(x), 1, output)
    self.assertEqual(x[0].tag, 'member', output)
    self.assertEqual(x[0].text, tag, output)

    x = paloalto.config.find(PATH_RULES + "/entry[@name='policy-4']/tag")
    self.assertIsNone(x, output)

  def testZoneLen(self):
    ZONE_MAX_LEN = 'Z' * 31
    ZONE_TOO_LONG = 'Z' * 32

    # from
    pol = policy.ParsePolicy(ZONE_LEN_ERROR % (ZONE_MAX_LEN, 'dmz'),
                             self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='policy']/from/member")
    self.assertEqual(x, ZONE_MAX_LEN, output)

    pol = policy.ParsePolicy(ZONE_LEN_ERROR % (ZONE_TOO_LONG, 'dmz'),
                             self.naming)
    self.assertRaisesRegex(paloaltofw.PaloAltoFWNameTooLongError,
                           '^Source zone must be 31 characters max',
                           paloaltofw.PaloAltoFW, pol, EXP_INFO)

    # to
    pol = policy.ParsePolicy(ZONE_LEN_ERROR % ('dmz', ZONE_MAX_LEN),
                             self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='policy']/to/member")
    self.assertEqual(x, ZONE_MAX_LEN, output)

    pol = policy.ParsePolicy(ZONE_LEN_ERROR % ('dmz', ZONE_TOO_LONG),
                             self.naming)
    self.assertRaisesRegex(paloaltofw.PaloAltoFWNameTooLongError,
                           '^Destination zone must be 31 characters max',
                           paloaltofw.PaloAltoFW, pol, EXP_INFO)

  def test_ZonesRequired(self):
    BAD_HEADERS = [
        'header{target::paloalto}',
        'header{target::paloalto from-zone x}',
        'header{target::paloalto x x to-zone x}',
    ]

    msg = ('^Palo Alto Firewall filter arguments '
           'must specify from-zone and to-zone[.]$')
    for header in BAD_HEADERS:
      pol = policy.ParsePolicy(header + GOOD_TERM_3, self.naming)
      self.assertRaisesRegex(paloaltofw.UnsupportedFilterError, msg,
                             paloaltofw.PaloAltoFW, pol, EXP_INFO)

  def test_LongComments(self):
    POL = """
header {
  comment:: "%s"
  target:: paloalto from-zone trust to-zone untrust
}
term rule-1 {
  comment:: "%s"
  pan-application:: ssl
  action:: accept
}"""

    # get maximum lengths
    pol = policy.ParsePolicy(POL % ('C', 'C'), self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    MAX_TAG_COMMENTS_LENGTH = paloalto._MAX_TAG_COMMENTS_LENGTH
    MAX_RULE_DESCRIPTION_LENGTH = paloalto._MAX_RULE_DESCRIPTION_LENGTH

    tag = 'trust_untrust_policy-comment-1'

    # maximum length
    pol = policy.ParsePolicy(
        POL %
        ('C' * MAX_TAG_COMMENTS_LENGTH, 'C' * MAX_RULE_DESCRIPTION_LENGTH),
        self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)

    x = paloalto.config.findtext(PATH_TAG + "/entry[@name='%s']/comments" % tag)
    self.assertEqual(x, 'C' * MAX_TAG_COMMENTS_LENGTH, output)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='rule-1']/description")
    self.assertEqual(x, 'C' * MAX_RULE_DESCRIPTION_LENGTH, output)

    # maximum length + 1
    pol = policy.ParsePolicy(
        POL % ('C' * (MAX_TAG_COMMENTS_LENGTH + 1), 'C' *
               (MAX_RULE_DESCRIPTION_LENGTH + 1)), self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)

    # verify warning
    with self.assertLogs(level='WARN') as log:
      output = str(paloalto)
      self.assertEqual(len(log.output), 2, log.output)
      self.assertIn('comments exceeds maximum length', log.output[0])
      self.assertIn('description exceeds maximum length', log.output[1])

    x = paloalto.config.findtext(PATH_TAG + "/entry[@name='%s']/comments" % tag)
    self.assertEqual(x, 'C' * MAX_TAG_COMMENTS_LENGTH, output)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='rule-1']/description")
    self.assertEqual(x, 'C' * MAX_RULE_DESCRIPTION_LENGTH, output)

  def testTermLen(self):
    TERM = """
term %s {
  pan-application:: ssl
  action:: accept
}
"""

    # get maximum length
    pol = policy.ParsePolicy(GOOD_HEADER_1 + TERM % 'T', self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    TERM_MAX_LENGTH = paloalto._TERM_MAX_LENGTH

    # maximum length
    term = 'T' * TERM_MAX_LENGTH
    pol = policy.ParsePolicy(GOOD_HEADER_1 + TERM % term, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.find(PATH_RULES + "/entry[@name='%s']" % term)
    self.assertIsNotNone(x, output)

    # maximum length + 1
    term = 'T' * (TERM_MAX_LENGTH + 1)
    pol = policy.ParsePolicy(GOOD_HEADER_1 + TERM % term, self.naming)
    regex = '^Term .+ is too long[.] Limit is %d characters' % TERM_MAX_LENGTH
    self.assertRaisesRegex(aclgenerator.TermNameTooLongError, regex,
                           paloaltofw.PaloAltoFW, pol, EXP_INFO)

  def testPanApplication(self):
    POL1 = """
header {
  target:: paloalto from-zone trust to-zone untrust
}
term rule-1 {
  action:: accept
}"""

    POL2 = """
header {
  target:: paloalto from-zone trust to-zone untrust
}
term rule-1 {
  pan-application:: %s
  action:: accept
}"""

    APPS = [
        {'app1'},
        {'app1', 'app2'},
        {'app1', 'app2', 'app3'},
    ]

    pol = policy.ParsePolicy(POL1, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.findtext(PATH_RULES +
                                 "/entry[@name='rule-1']/application/member")
    self.assertEqual(x, 'any', output)

    for i, app in enumerate(APPS):
      pol = policy.ParsePolicy(POL2 % ' '.join(app), self.naming)
      paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
      output = str(paloalto)
      x = paloalto.config.findall(PATH_RULES +
                                  "/entry[@name='rule-1']/application/member")
      apps = {elem.text for elem in x}
      self.assertEqual(APPS[i], apps, output)

  def testPanPorts(self):
    POL = """
header {
  target:: paloalto from-zone trust to-zone untrust
}
term rule-1 {
%s
  action:: accept
}"""

    T = """
  protocol:: udp
  destination-port:: NTP
"""

    definitions = naming.Naming()
    definitions._ParseLine('NTP = 123/tcp 123/udp', 'services')
    definitions._ParseLine('DNS = 53/tcp 53/udp', 'services')

    pol = policy.ParsePolicy(POL % T, definitions)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    name = "service-rule-1-udp"
    path = "/entry[@name='%s']/protocol/udp/port" % name
    x = paloalto.config.findtext(PATH_SERVICE + path)
    self.assertEqual(x, "123", output)
    path = "/entry[@name='%s']/protocol/udp/source-port" % name
    x = paloalto.config.findtext(PATH_SERVICE + path)
    self.assertIsNone(x, output)

    T = """
  protocol:: udp
  source-port:: NTP
"""

    pol = policy.ParsePolicy(POL % T, definitions)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    name = "service-rule-1-udp"
    path = "/entry[@name='%s']/protocol/udp/port" % name
    x = paloalto.config.findtext(PATH_SERVICE + path)
    self.assertEqual(x, "0-65535", output)
    path = "/entry[@name='%s']/protocol/udp/source-port" % name
    x = paloalto.config.findtext(PATH_SERVICE + path)
    self.assertEqual(x, "123", output)

    T = """
  protocol:: tcp
  source-port:: NTP
  destination-port:: NTP DNS
"""

    pol = policy.ParsePolicy(POL % T, definitions)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    name = "service-rule-1-tcp"
    path = "/entry[@name='%s']/protocol/tcp/port" % name
    x = paloalto.config.findtext(PATH_SERVICE + path)
    self.assertEqual(x, "53,123", output)
    path = "/entry[@name='%s']/protocol/tcp/source-port" % name
    x = paloalto.config.findtext(PATH_SERVICE + path)
    self.assertEqual(x, "123", output)

    T = """
  protocol:: tcp
"""

    pol = policy.ParsePolicy(POL % T, definitions)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    name = "any-tcp"
    path = "/entry[@name='%s']/protocol/tcp/port" % name
    x = paloalto.config.findtext(PATH_SERVICE + path)
    self.assertEqual(x, "0-65535", output)
    path = "/entry[@name='%s']/protocol/tcp/source-port" % name
    x = paloalto.config.find(PATH_SERVICE + path)
    self.assertIsNone(x, output)

    T = """
  protocol:: tcp udp
"""

    pol = policy.ParsePolicy(POL % T, definitions)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    name = "any-tcp"
    path = "/entry[@name='%s']/protocol/tcp/port" % name
    x = paloalto.config.findtext(PATH_SERVICE + path)
    self.assertEqual(x, "0-65535", output)
    name = "any-udp"
    path = "/entry[@name='%s']/protocol/udp/port" % name
    x = paloalto.config.findtext(PATH_SERVICE + path)
    self.assertEqual(x, "0-65535", output)
    x = paloalto.config.findall(PATH_RULES +
                                "/entry[@name='rule-1']/service/member")
    services = {elem.text for elem in x}
    self.assertEqual({"any-tcp", "any-udp"}, services, output)

  def testPortLessNonPort(self):
    POL = """
header {
  target:: paloalto from-zone trust to-zone untrust
}
term rule-1 {
%s
  action:: accept
}"""

    T = """
  protocol:: udp icmp
"""

    pol = policy.ParsePolicy(POL % T, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.findall(PATH_RULES +
                                "/entry[@name='rule-1-1']/service/member")
    self.assertTrue(len(x) > 0, output)
    services = {elem.text for elem in x}
    self.assertEqual({"any-udp"}, services, output)
    x = paloalto.config.findall(PATH_RULES +
                                "/entry[@name='rule-1-2']/application/member")
    self.assertTrue(len(x) > 0, output)
    applications = {elem.text for elem in x}
    self.assertEqual({"icmp"}, applications, output)

    T = """
  protocol:: udp tcp icmp gre
"""

    pol = policy.ParsePolicy(POL % T, self.naming)
    paloalto = paloaltofw.PaloAltoFW(pol, EXP_INFO)
    output = str(paloalto)
    x = paloalto.config.findall(PATH_RULES +
                                "/entry[@name='rule-1-1']/service/member")
    self.assertTrue(len(x) > 0, output)
    services = {elem.text for elem in x}
    self.assertEqual({"any-udp", "any-tcp"}, services, output)
    x = paloalto.config.findall(PATH_RULES +
                                "/entry[@name='rule-1-2']/application/member")
    self.assertTrue(len(x) > 0, output)
    applications = {elem.text for elem in x}
    self.assertEqual({"icmp", "gre"}, applications, output)


if __name__ == '__main__':
  absltest.main()
