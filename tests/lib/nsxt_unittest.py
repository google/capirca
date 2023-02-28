# Copyright 2023 The Capirca Project Authors All Rights Reserved.
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
#
"""UnitTest class for nsxt.py."""

import json
import optparse
from absl.testing import absltest

from capirca.lib import naming
from capirca.lib import nsxt
from capirca.lib import policy
from tests.lib import nsxt_mocktest


class TermTest(absltest.TestCase):

  def setUp(self):
    """Call before every test case."""
    super().setUp()
    parser = optparse.OptionParser()
    parser.add_option(
        '-d',
        '--def',
        dest='definitions',
        help='definitions directory',
        default='../def')
    (FLAGS, args) = parser.parse_args([])
    self.defs = naming.Naming(FLAGS.definitions)

  def tearDown(self):
    super().setUp()
    pass

  def runTest(self):
    pass

  def test_init_forinet(self):
    """Test for Term._init_."""
    inet_term = nsxt.Term(nsxt_mocktest.INET_TERM, 'inet')
    self.assertEqual(inet_term.af, 4)
    self.assertEqual(inet_term.filter_type, 'inet')

  def test_init_forinet6(self):
    """Test for Term._init_."""
    inet6_term = nsxt.Term(nsxt_mocktest.INET6_TERM, 'inet6', 6)
    self.assertEqual(inet6_term.af, 4)
    self.assertEqual(inet6_term.filter_type, 'inet6')

  def test_str_forinet(self):
    """Test for Term._str_."""
    pol = policy.ParsePolicy(nsxt_mocktest.INET_FILTER, self.defs, False)
    af = 4
    for _, terms in pol.filters:
      nsxt_term = nsxt.Term(terms[0], af)
      rule_str = nsxt.Term.__str__(nsxt_term)
    # parse xml rule and check if the values are correct
    rule_json = json.loads(rule_str)
    # check name and action
    self.assertEqual(rule_json["display_name"], 'allow-ntp-request')
    self.assertEqual(rule_json["action"][0], 'accept')

    # check source address
    exp_sourceaddr = ['10.0.0.1/32', '10.0.0.2/32']
    for destination in rule_json["source_groups"]:
      if destination not in exp_sourceaddr:
        self.fail('IPv4Address source address not found in test_str_forinet()')

    # check destination address
    exp_destaddr = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
    for destination in rule_json["destination_groups"]:
      if destination not in exp_destaddr:
        self.fail('IPv4Address destination not found in test_str_forinet()')

    # check protocol
    protocol = rule_json["ip_protocol"]
    self.assertEqual(protocol, "")

    # check notes
    notes = rule_json["notes"]
    self.assertEqual(notes[0], 'Allow ntp request')

  def test_TranslatePolicy(self):
    """Test for Nsxt.test_TranslatePolicy."""
    # exp_info default is 2
    exp_info = 2
    pol = policy.ParsePolicy(nsxt_mocktest.INET_FILTER, self.defs, False)
    translate_pol = nsxt.Nsxt(pol, exp_info)
    nsxt_policies = translate_pol.nsxt_policies
    for (_, filter_name, filter_list, terms) in nsxt_policies:
      self.assertEqual(filter_name, 'inet')
      self.assertEqual(filter_list, [''])
      self.assertEqual(len(terms), 1)

  def test_nsxt_str(self):
    """Test for Nsxt._str_."""
    # exp_info default is 2
    exp_info = 2
    pol = policy.ParsePolicy(nsxt_mocktest.MIXED_FILTER, self.defs, False)
    target = nsxt.Nsxt(pol, exp_info)

    # parse the xml and check the values
    nsxt_json = json.loads(str(target))
    rule = nsxt_json["rules"][0]
    # check name and action
    self.assertEqual(rule["display_name"], 'accept-to-honestdns')
    self.assertEqual(rule["action"][0], 'accept')

    # check IPV4 and IPV6 destinations
    exp_dest = ['8.8.4.4/32', '8.8.8.8/32', '2001:4860:4860::8844/128', '2001:4860:4860::8888/128']

    for destination in rule["destination_groups"]:
      if destination not in exp_dest:
        self.fail('IPv4Address not found in test_nsxt_str()')

    # check protocol
    protocol = rule["ip_protocol"]
    self.assertEqual(protocol, "")

    # check notes
    notes = rule["notes"]
    self.assertEqual(notes[0], 'Allow name resolution using honestdns.')

  if __name__ == '__main__':
    absltest.main()
