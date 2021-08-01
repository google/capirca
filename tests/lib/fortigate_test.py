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
import mock

from capirca.lib import fortigate
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy


GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: fortigate from-id 2
}
"""

GOOD_HEADER_1 = """
header {
  comment:: "this is a test acl"
  target:: fortigate ngfw-mode policy-based
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

_SP = '    '

EXP_INFO = 2


class CustomFormatter(string.Formatter):
  """
  Checks the custom formatter for fortigate output.

  """
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
    if 'remove_fields' in kwargs or 'add_fields' in kwargs:
      args = list(args)

    if 'remove_fields' in kwargs:
      for field in kwargs['remove_fields']:
        remove_regex = '.*' + field + '.*'
        args[1] = re.sub(remove_regex, '', args[1])

    if 'add_fields' in kwargs:
      add_fields_string = ""
      for field, value in kwargs['add_fields'].items():
        add_fields_string += "  " + field + ":: " + value + "\n"
      args[1] = args[1][:-3] + add_fields_string + args[1][-3:]

    return string.Formatter.format(*args, **kwargs)

  def get_value(self, key, args, kwds):
    try:
      return kwds[key]
    except KeyError:
      return self.DEFAULT_VALUES[key]


class FortigateTest(unittest.TestCase):
  """
  Fortigate test class.

  """
  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

    def get_addr_side_eff(host):
      hosts = {
          'SOME_HOST': [nacaddr.IP('10.0.0.0/8')],
          'SOME_HOST2': [nacaddr.IP('20.0.0.0/8')],
          'SOME_HOST6': [nacaddr.IP('fec0::/10')]
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
    """
    Tests a good header value.

    """
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
    """
    Tests a bad header value.

    """
    term = self.fmt.format(TERM_TEMPLATE)
    parsed_p = policy.ParsePolicy(BAD_HEADER + term,
                                  self.naming)

    self.assertRaises(fortigate.FilterError,
                      fortigate.Fortigate,
                      parsed_p,
                      EXP_INFO)

  def testAction(self):
    """
    Tests the action detection.

    """
    accept_term = self.fmt.format(TERM_TEMPLATE, action='accept')
    deny_term = self.fmt.format(TERM_TEMPLATE, action='deny')
    reject_term = self.fmt.format(TERM_TEMPLATE, action='reject')

    accept_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + accept_term,
                           self.naming), EXP_INFO)
    deny_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + deny_term,
                           self.naming), EXP_INFO)
    reject_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + reject_term,
                           self.naming), EXP_INFO)

    accept_sig = 'set action accept'
    deny_sig = 'set action deny'
    reject_sig = 'set send-deny-packet enable'
    reject_sys_sig = ('config sys setting\n' +
                      _SP + 'set deny-tcp-with-icmp enable\n' +
                      'end\n')

    self.assertIn(
        accept_sig, str(accept_acl), '[%s]' % str(accept_acl))
    self.assertIn(
        deny_sig, str(deny_sig), '[%s]' % str(deny_acl))
    self.assertIn(
        reject_sys_sig, str(reject_acl), '[%s]' % str(reject_acl))
    self.assertTrue(
        deny_sig in str(reject_acl) and reject_sig in str(reject_acl),
        '[%s]' % str(reject_acl))

  def testAddresses(self):
    """
    Tests an address object.

    """
    diff_addr_term = self.fmt.format(TERM_TEMPLATE,
                                     src_addr='SOME_HOST',
                                     dest_addr='SOME_HOST2')
    same_addr_term = self.fmt.format(TERM_TEMPLATE,
                                     src_addr='SOME_HOST2',
                                     dest_addr='SOME_HOST2')
    any_src_term = self.fmt.format(TERM_TEMPLATE,
                                   remove_fields=('src_addr',))
    any_dest_term = self.fmt.format(TERM_TEMPLATE,
                                    remove_fields=('dest_addr',))
    # testing for IPv6
    same_addr6_term = self.fmt.format(TERM_TEMPLATE,
                                      src_addr='SOME_HOST6',
                                      dest_addr='SOME_HOST6')

    diff_addr_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + diff_addr_term,
                           self.naming), EXP_INFO)

    same_addr_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + same_addr_term,
                           self.naming), EXP_INFO)

    any_src_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + any_src_term,
                           self.naming), EXP_INFO)

    any_dest_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + any_dest_term,
                           self.naming), EXP_INFO)

    same_addr6_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + same_addr6_term,
                           self.naming), EXP_INFO)

    src_sig = 'set srcaddr "10.0.0.0/8"'
    dest_sig = 'set dstaddr "20.0.0.0/8"'
    any_dest_sig = 'set dstaddr "all"'
    any_src_sig = 'set srcaddr "all"'
    src_sig_v6 = 'set srcaddr6 "fec0::/10"'
    dest_sig_v6 = 'set dstaddr6 "fec0::/10"'

    self.assertTrue(
        src_sig in str(diff_addr_acl) and dest_sig in str(diff_addr_acl),
        '[%s]' % str(diff_addr_acl))
    # [] check acl generate one 'set subnet' for dup addresses
    self.assertEqual(
        str(same_addr_acl).count('set subnet'), 1)
    self.assertIn(
        any_src_sig, str(any_src_acl), '[%s]' % str(any_src_acl))
    self.assertIn(
        any_dest_sig, str(any_dest_acl), '[%s]' % str(any_dest_acl))
    self.assertTrue(
        src_sig_v6 in str(same_addr6_acl)
        and dest_sig_v6 in str(same_addr6_acl),
        '[%s]' % str(same_addr6_acl))

  def testServices(self):
    """
    Tests services objects.

    """
    dest_only_term = self.fmt.format(TERM_TEMPLATE,
                                     dest_port='HTTP',
                                     remove_fields=('src_port',))
    diff_port_term = self.fmt.format(TERM_TEMPLATE,
                                     dest_port='HTTP HTTPS',
                                     remove_fields=('src_port',))
    dup_port_term = self.fmt.format(TERM_TEMPLATE,
                                    src_port='HTTP',
                                    dest_port='HTTP')
    icmp_term = self.fmt.format(TERM_TEMPLATE,
                                protocol='icmp',
                                add_fields={'icmp-type': 'echo-request'},
                                remove_fields=('src_addr', 'dest_addr',
                                               'dest_port', 'src_port'))
    ip_term = self.fmt.format(TERM_TEMPLATE,
                              remove_fields=('dest_port', 'src_port'))
    custom_port_term = self.fmt.format(TERM_TEMPLATE, src_port='WHOIS')
    #print("\icmp_term=========\n", icmp_term)

    dest_only_acl = fortigate.Fortigate(policy.ParsePolicy(
        GOOD_HEADER + dest_only_term,
        self.naming), EXP_INFO)
    diff_acl = fortigate.Fortigate(policy.ParsePolicy(
        GOOD_HEADER + diff_port_term,
        self.naming), EXP_INFO)
    dup_acl = fortigate.Fortigate(policy.ParsePolicy(
        GOOD_HEADER + dup_port_term,
        self.naming), EXP_INFO)
    icmp_acl = fortigate.Fortigate(policy.ParsePolicy(
        GOOD_HEADER + icmp_term,
        self.naming), EXP_INFO)
    ip_acl = fortigate.Fortigate(policy.ParsePolicy(
        GOOD_HEADER + ip_term,
        self.naming), EXP_INFO)
    custom_port_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + custom_port_term,
                           self.naming), EXP_INFO)
    #print("\ncustom_port_acl=========\n", custom_port_acl)

    dest_only_sig = 'set service HTTP\n'
    diff_sig = 'set service HTTP HTTPS\n'
    dup_sig = 'set service good-term-2-svc\n'
    icmp_sig = 'set service icmp-type-echo-request\n'
    ip_sig = 'set service ALL_TCP\n'
    custom_port_sig = ('config firewall service custom\n' +
                       _SP + 'edit good-term-2-svc\n' +
                       _SP*2 + 'set comment "Generated by Capirca"\n' +
                       _SP*2 + 'set tcp-portrange 80:43\n' +
                       _SP + 'next\n')

    self.assertIn(
        dest_only_sig, str(dest_only_acl), '[%s]' % str(dest_only_acl))
    self.assertIn(
        diff_sig, str(diff_acl), '[%s]' % str(diff_acl))
    self.assertIn(
        dup_sig, str(dup_acl), '[%s]' % str(dup_acl))
    self.assertIn(
        icmp_sig, str(icmp_acl), '[%s]' % str(icmp_acl))
    self.assertIn(
        ip_sig, str(ip_acl), '[%s]' % str(ip_acl))
    self.assertIn(
        custom_port_sig, str(custom_port_acl), '[%s]' % str(custom_port_acl))

  def testInterfaces(self):
    """
    Tests interfaces.

    """
    no_interfaces_term = self.fmt.format(TERM_TEMPLATE,
                                         remove_fields=('src_interface',
                                                        'dest_interface'))
    #print("no_interfaces_term=", no_interfaces_term)
    src_only_int_term = self.fmt.format(TERM_TEMPLATE,
                                        src_interface='wan1',
                                        remove_fields=('dest_interface',))
    dest_only_int_term = self.fmt.format(TERM_TEMPLATE,
                                         dest_interface='wan2',
                                         remove_fields=('src_interface',))
    both_interfaces_term = self.fmt.format(TERM_TEMPLATE,
                                           src_interface='wan1',
                                           dest_interface='wan2',)

    no_interfaces_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + no_interfaces_term,
                           self.naming), EXP_INFO)
    src_only_int_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + src_only_int_term,
                           self.naming), EXP_INFO)
    dest_only_int_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + dest_only_int_term,
                           self.naming), EXP_INFO)
    both_interfaces_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + both_interfaces_term,
                           self.naming), EXP_INFO)

    no_interfaces_sig = 'set srcintf any\n' + _SP*2 + 'set dstintf any'
    src_int_only_sig = 'set srcintf wan1\n' + _SP*2 + 'set dstintf any'
    dest_int_only_sig = 'set srcintf any\n' + _SP*2 + 'set dstintf wan2'
    both_interfaces_sig = 'set srcintf wan1\n' + _SP*2 + 'set dstintf wan2'

    self.assertIn(
        no_interfaces_sig, str(no_interfaces_acl),
        '[%s]' % str(no_interfaces_acl))
    self.assertIn(
        src_int_only_sig, str(src_only_int_acl),
        '[%s]' % str(src_only_int_acl))
    self.assertIn(
        dest_int_only_sig, str(dest_only_int_acl),
        '[%s]' % str(dest_only_int_acl))
    self.assertIn(
        both_interfaces_sig, str(both_interfaces_acl),
        '[%s]' % str(both_interfaces_acl))

  def testExpiration(self):
    """
    Tests expiration / schedule object.

    """
    no_expiration_term = self.fmt.format(TERM_TEMPLATE)
    expiration_term = self.fmt.format(TERM_TEMPLATE,
                                      add_fields={'expiration':
                                                  '2022-12-31',
                                                  'comment':
                                                  '"test expiration"'})

    no_expiration_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + no_expiration_term,
                           self.naming), EXP_INFO)
    expiration_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER + expiration_term,
                           self.naming), EXP_INFO)

    no_expiration_sig = 'set schedule always'
    expiration_sig = 'set schedule 2022/12/31_00:00'
    expiration_config_sig = ('config firewall schedule onetime\n' +
                             _SP + 'edit 2022/12/31_00:00\n' +
                             _SP*2 + 'set end 00:00 2022/12/31\n' +
                             _SP + 'next\n' +
                             'end\n')

    self.assertIn(
        no_expiration_sig, str(no_expiration_acl),
        '[%s]' % str(no_expiration_acl))
    self.assertTrue(
        expiration_config_sig in str(expiration_acl)
        and expiration_sig in str(expiration_acl),
        '[%s]' % str(expiration_acl))

  def testApplication_ID(self):
    """
    Tests an application ID being used.

    """
    application_term = self.fmt.format(TERM_TEMPLATE,
                                       add_fields={'application-id': '15816'},
                                       remove_fields=('src_addr', 'src_port'))

    application_acl = fortigate.Fortigate(
        policy.ParsePolicy(GOOD_HEADER_1 + application_term,
                           self.naming), EXP_INFO)

    application_sig = 'set application 15816'

    self.assertIn(
        application_sig, str(application_acl),
        '[%s]' % str(application_acl))

  def testLogging(self):
    """
    Tests logger input.

    """
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
    """
    Tests for duplicate term detection.

    """
    term = self.fmt.format(TERM_TEMPLATE, logging='true')
    duplicate_terms = term + term
    parsed_p = policy.ParsePolicy(GOOD_HEADER + duplicate_terms,
                                  self.naming)

    self.assertRaises(fortigate.FortiGateDuplicateTermError,
                      fortigate.Fortigate,
                      parsed_p,
                      EXP_INFO)

  def testPortMap(self):
    """
    Tests port map object.

    """
    port_map = fortigate.FortigatePortMap()
    self.assertEqual('SSH', port_map.get_protocol('tcp', '22'))
    self.assertRaises(fortigate.FortiGatePortDoesNotExistError,
                      port_map.get_protocol,
                      'tcp', 5000)
    self.assertRaises(fortigate.FortiGateValueError,
                      port_map.get_protocol,
                      'bad_proto', 22)
