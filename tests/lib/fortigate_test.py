# Copyright 2019 Google Inc. All Rights Reserved.
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

"""Unittest for fortigate policy rendering module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import re
import string
import unittest

from capirca.lib import fortigate
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy
import mock


GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: fortigate from-id 2
}
"""

BAD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: fortigate edge-filter
}
"""

TERM_TEMPLATE = """
term good-term-2 {{
  source-interface:: {src_interface}
  destination-interface:: {dest_interface}
  protocol:: {protocol}
  destination-address:: {dest_addr}
  destination-port:: {dest_port}
  source-address:: {src_addr}
  source-port:: {src_port}
  action:: {action}
  logging:: {logging}
}}
"""

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'expiration',
    'icmp_type',
    'stateless_reply',
    'logging',
    'name',
    'option',
    'platform',
    'platform_exclude',
    'protocol',
    'source_interface',
    'destination_interface',
    'source_address',
    'source_address_exclude',
    'source_port',
    'translated',
    'verbatim',
}

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny', 'reject',
               'reject-with-tcp-rst'},
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
    'option': {'from_id'}
}

EXP_INFO = 2


class CustomFormatter(string.Formatter):
  DEFAULT_VALUES = {
      'src_interface': 'wan1',
      'dest_interface': 'wan2',
      'protocol': 'tcp',
      'src_addr': 'SOME_HOST',
      'dest_addr': 'SOME_HOST',
      'src_port': 'HTTP',
      'dest_port': 'HTTP',
      'action': 'accept',
      'logging': 'true'
  }

  def format(*args, **kwargs):
    if 'remove_fields' in kwargs:
      args = list(args)
      for field in kwargs['remove_fields']:
        remove_regex = '.*' + field + '.*'
        args[1] = re.sub(remove_regex, '', args[1])

      return string.Formatter.format(*args, **kwargs)
    return string.Formatter.format(*args, **kwargs)

  def get_value(self, key, args, kwds):
    try:
      return kwds[key]
    except KeyError:
      return self.DEFAULT_VALUES[key]


class FortigateTest(unittest.TestCase):
  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

    def get_addr_side_eff(host):
      hosts = {
          'SOME_HOST': [nacaddr.IP('10.0.0.0/8')],
          'SOME_HOST2': [nacaddr.IP('20.0.0.0/8')]
      }
      return hosts[host]

    def get_port_side_eff(*args):
      hosts = {
          'HTTP': ['80'],
          'HTTPS': ['443'],
          'SSH': ['22'],
          'WHOIS': ['43']
      }
      return hosts[args[0]]

    self.naming.GetNetAddr.side_effect = get_addr_side_eff
    self.naming.GetServiceByProto.side_effect = get_port_side_eff
    self.fmt = CustomFormatter()

  def testGoodHeader(self):
    term = self.fmt.format(TERM_TEMPLATE)
    acl = fortigate.Fortigate(policy.ParsePolicy(GOOD_HEADER + term,
                                                 self.naming), EXP_INFO)

    expected_sig = 'edit 2'

    get_net_calls = [mock.call('SOME_HOST')] * 2
    get_server_by_proto_calls = [mock.call('HTTP', 'tcp')] * 2

    self.assertIn(expected_sig, str(acl), '[%s]' % str(acl))
    self.naming.GetNetAddr.assert_has_calls(get_net_calls)
    self.naming.GetServiceByProto.assert_has_calls(get_server_by_proto_calls)

  def testBadHeader(self):
    term = self.fmt.format(TERM_TEMPLATE)
    parsed_p = policy.ParsePolicy(BAD_HEADER + term,
                                  self.naming)

    self.assertRaises(fortigate.FilterError,
                      fortigate.Fortigate,
                      parsed_p,
                      EXP_INFO)

  def testBuildTokens(self):
    term = self.fmt.format(TERM_TEMPLATE)
    pol1 = fortigate.Fortigate(policy.ParsePolicy(GOOD_HEADER + term,
                                            self.naming), EXP_INFO)
    st, sst = pol1._BuildTokens()
    self.assertEqual(st, SUPPORTED_TOKENS)
    self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

  def testActionAccept(self):
    accept_term = self.fmt.format(TERM_TEMPLATE, action='accept')

    accept_acl = fortigate.Fortigate(
      policy.ParsePolicy(GOOD_HEADER + accept_term,
                         self.naming), EXP_INFO)

    accept_sig = 'set action accept'
    self.assertIn(
      accept_sig, str(accept_acl), '[%s]' % str(accept_acl))

  def testActionDeny(self):
    deny_term = self.fmt.format(TERM_TEMPLATE, action='deny')
    reject_term = self.fmt.format(TERM_TEMPLATE, action='reject')

    deny_acl = fortigate.Fortigate(
      policy.ParsePolicy(GOOD_HEADER + deny_term,
                         self.naming), EXP_INFO)
    reject_acl = fortigate.Fortigate(
      policy.ParsePolicy(GOOD_HEADER + reject_term,
                         self.naming), EXP_INFO)

    deny_sig = 'set action deny'
    self.assertIn(
      deny_sig, str(deny_sig), '[%s]' % str(deny_acl))
    self.assertIn(
      deny_sig, str(reject_acl), '[%s]' % str(reject_acl))

  def testAddressDiff(self):
    diff_addr_term = self.fmt.format(TERM_TEMPLATE,
                                     src_addr='SOME_HOST',
                                     dest_addr='SOME_HOST2')

    diff_addr_acl = fortigate.Fortigate(
      policy.ParsePolicy(GOOD_HEADER + diff_addr_term,
                         self.naming), EXP_INFO)

    src_sig = 'set srcaddr 10.0.0.0/8'
    dest_sig = 'set dstaddr 20.0.0.0/8'

    self.assertTrue(
      src_sig in str(diff_addr_acl) and dest_sig in str(diff_addr_acl),
      '[%s]' % str(diff_addr_acl))

  def testAddressSame(self):
    same_addr_term = self.fmt.format(TERM_TEMPLATE,
                                     src_addr='SOME_HOST2',
                                     dest_addr='SOME_HOST2')

    same_addr_acl = fortigate.Fortigate(
      policy.ParsePolicy(GOOD_HEADER + same_addr_term,
                         self.naming), EXP_INFO)

    self.assertEqual(
      str(same_addr_acl).count('set subnet'), 1)

  def testAddressAny(self):
    any_src_term = self.fmt.format(TERM_TEMPLATE,
                                   remove_fields=('src_addr',))
    any_dest_term = self.fmt.format(TERM_TEMPLATE,
                                    remove_fields=('dest_addr',))

    any_src_acl = fortigate.Fortigate(
      policy.ParsePolicy(GOOD_HEADER + any_src_term,
                         self.naming), EXP_INFO)

    any_dest_acl = fortigate.Fortigate(
      policy.ParsePolicy(GOOD_HEADER + any_dest_term,
                         self.naming), EXP_INFO)

    any_dest_sig = 'set dstaddr all'
    any_src_sig = 'set srcaddr all'

    self.assertIn(
      any_src_sig, str(any_src_acl), '[%s]' % str(any_src_acl))
    self.assertIn(
      any_dest_sig, str(any_dest_acl), '[%s]' % str(any_dest_acl))

  def testServiceDupPort(self):
    dup_port_term = self.fmt.format(TERM_TEMPLATE,
                                    src_port='HTTP',
                                    dest_port='HTTP')

    dup_acl = fortigate.Fortigate(policy.ParsePolicy(
      GOOD_HEADER + dup_port_term,
      self.naming), EXP_INFO)

    dup_sig = 'set service HTTP\n'

    self.assertIn(
      dup_sig, str(dup_acl), '[%s]' % str(dup_acl))

  def testServiceDiffPort(self):
    diff_port_term = self.fmt.format(TERM_TEMPLATE,
                                     src_port='HTTP',
                                     dest_port='HTTPS')

    diff_acl = fortigate.Fortigate(policy.ParsePolicy(
      GOOD_HEADER + diff_port_term,
      self.naming), EXP_INFO)

    diff_sig = 'set service HTTP HTTPS\n'

    self.assertIn(
      diff_sig, str(diff_acl), '[%s]' % str(diff_acl))

  def testServiceSrcOnly(self):
    src_only_term = self.fmt.format(TERM_TEMPLATE,
                                    src_port='HTTP',
                                    remove_fields=('dest_port',))

    src_only_acl = fortigate.Fortigate(policy.ParsePolicy(
      GOOD_HEADER + src_only_term,
      self.naming), EXP_INFO)

    src_only_sig = 'set service HTTP\n'

    self.assertIn(
      src_only_sig, str(src_only_acl), '[%s]' % str(src_only_acl))

  def testServiceIp(self):
    icmp_term = self.fmt.format(TERM_TEMPLATE,
                                protocol='icmp',
                                remove_fields=('dest_port', 'src_port'))
    ip_term = self.fmt.format(TERM_TEMPLATE,
                              remove_fields=('dest_port',
                                             'src_port', 'protocol'))

    icmp_acl = fortigate.Fortigate(policy.ParsePolicy(
      GOOD_HEADER + icmp_term,
      self.naming), EXP_INFO)
    ip_acl = fortigate.Fortigate(policy.ParsePolicy(
      GOOD_HEADER + ip_term,
      self.naming), EXP_INFO)

    icmp_sig = 'set service ALL_ICMP\n'
    ip_sig = 'set service ALL\n'

    self.assertIn(
      icmp_sig, str(icmp_acl), '[%s]' % str(icmp_acl))
    self.assertIn(
      ip_sig, str(ip_acl), '[%s]' % str(ip_acl))

  def testServiceCustomPort(self):
    custom_port_term = self.fmt.format(TERM_TEMPLATE, src_port='WHOIS')

    custom_port_acl = fortigate.Fortigate(
      policy.ParsePolicy(GOOD_HEADER + custom_port_term,
                         self.naming), EXP_INFO)

    custom_port_sig = ('config firewall service custom\n\tedit 43\n\t\t'
                       'set protocol TCP/UDP\n\t\tset tcp-portrange 43\n\tnext')

    self.assertIn(
      custom_port_sig, str(custom_port_acl), '[%s]' % str(custom_port_acl))

  def testInterfaceNone(self):
    no_interfaces_term = self.fmt.format(TERM_TEMPLATE,
                                         remove_fields=('src_interface',
                                                        'dest_interface'))

    no_interfaces_acl = fortigate.Fortigate(
      policy.ParsePolicy(GOOD_HEADER + no_interfaces_term,
                         self.naming), EXP_INFO)

    no_interfaces_sig = 'set srcintf any\n\t\tset dstintf any'

    self.assertIn(
      no_interfaces_sig, str(no_interfaces_acl),
      '[%s]' % str(no_interfaces_acl))

  def testInterfaceSrcOnly(self):
    src_only_int_term = self.fmt.format(TERM_TEMPLATE,
                                        src_interface='wan1',
                                        remove_fields=('dest_interface',))

    src_only_int_acl = fortigate.Fortigate(
      policy.ParsePolicy(GOOD_HEADER + src_only_int_term,
                         self.naming), EXP_INFO)

    src_int_only_sig = 'set srcintf wan1\n\t\tset dstintf any'

    self.assertIn(
      src_int_only_sig, str(src_only_int_acl),
      '[%s]' % str(src_only_int_acl))

  def testInterfaceDestOnly(self):
    dest_only_int_term = self.fmt.format(TERM_TEMPLATE,
                                         dest_interface='wan2',
                                         remove_fields=('src_interface',))

    dest_only_int_acl = fortigate.Fortigate(
      policy.ParsePolicy(GOOD_HEADER + dest_only_int_term,
                         self.naming), EXP_INFO)

    dest_int_only_sig = 'set srcintf any\n\t\tset dstintf wan2'

    self.assertIn(
      dest_int_only_sig, str(dest_only_int_acl),
      '[%s]' % str(dest_only_int_acl))

  def testInterfaceBoth(self):
    both_interfaces_term = self.fmt.format(TERM_TEMPLATE,
                                           src_interface='wan1',
                                           dest_interface='wan2')

    both_interfaces_acl = fortigate.Fortigate(
      policy.ParsePolicy(GOOD_HEADER + both_interfaces_term,
                         self.naming), EXP_INFO)

    both_interfaces_sig = 'set srcintf wan1\n\t\tset dstintf wan2'

    self.assertIn(
      both_interfaces_sig, str(both_interfaces_acl),
      '[%s]' % str(both_interfaces_acl))

  def testLogging(self):
    log_term = self.fmt.format(TERM_TEMPLATE,
                               logging='true')
    no_log_term = self.fmt.format(TERM_TEMPLATE,
                                  remove_fields=('logging',))

    log_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + log_term,
                           self.naming), EXP_INFO)
    no_log_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + no_log_term,
                           self.naming), EXP_INFO)

    log_sig = 'set logtraffic all'

    self.assertIn(
        log_sig, str(log_acl), '[%s]' % str(log_acl))
    self.assertNotIn(
        log_sig, str(no_log_term), '[%s]' % str(no_log_acl))

  def testDuplicateTermError(self):
    term = self.fmt.format(TERM_TEMPLATE, logging='true')
    duplicate_terms = term + term
    parsed_p = policy.ParsePolicy(GOOD_HEADER + duplicate_terms,
                                  self.naming)

    self.assertRaises(fortigate.FortiGateDuplicateTermError,
                      fortigate.Fortigate,
                      parsed_p,
                      EXP_INFO)

  def testPortMap(self):
    port_map = fortigate.FortigatePortMap()
    self.assertEqual('SSH', port_map.get_protocol('tcp', 22))
    self.assertRaises(fortigate.FortiGatePortDoesNotExistError,
                      port_map.get_protocol,
                      'tcp', 5000)
    self.assertRaises(fortigate.FortiGateValueError,
                      port_map.get_protocol,
                      'bad_proto', 22)


if __name__ == '__main__':
  unittest.main()