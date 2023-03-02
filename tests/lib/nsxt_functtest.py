# Copyright 2023 The Capirca Project Authors All Rights Reserved.
# Copyright 2023 VMware, Inc. SPDX-License-Identifier: Apache-2.0
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
"""Functional test class for nsxt.py."""

import copy
import json
import optparse
from absl.testing import absltest

from capirca.lib import naming
from capirca.lib import nsxt
from capirca.lib import policy
from tests.lib import nsxt_mocktest


class NsxtFunctionalTest(absltest.TestCase):
  """Functional testing for NSX-T."""

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
    super().tearDown()
    pass

  def runTest(self):
    pass

  def test_nsxt_policy(self):
    pol = policy.ParsePolicy(nsxt_mocktest.POLICY, self.defs)
    exp_info = 2
    nsx = copy.deepcopy(pol)
    fw = nsxt.Nsxt(nsx, exp_info)
    nsxt_json = json.loads(str(fw))
    rule = nsxt_json["rules"][0]
    # check name and action
    self.assertEqual(rule["display_name"], 'reject-imap-requests')
    self.assertEqual(rule["action"][0], 'reject-with-tcp-rst')

    # check IPV4 destination
    exp_destaddr = ['200.1.1.4/31']

    for destination in rule["destination_groups"]:
      if destination not in exp_destaddr:
        self.fail('IPv4Address destination not found in test_nsxt_str()')

    # check protocol
    protocol = rule["ip_protocol"]
    self.assertEqual(protocol, '')

  def test_nsxt_nosectiondid(self):
    pol = policy.ParsePolicy(nsxt_mocktest.POLICY_NO_SECTION_ID, self.defs)
    exp_info = 2
    nsx = copy.deepcopy(pol)
    fw = nsxt.Nsxt(nsx, exp_info)
    nsxt_json = json.loads(str(fw))
    rule = nsxt_json["rules"][0]
    # check name and action
    self.assertEqual(rule["display_name"], 'accept-icmp')
    self.assertEqual(rule["action"][0], 'accept')

    # check protocol
    protocol = rule["ip_protocol"]
    self.assertEqual(protocol, '')

  def test_nsxt_nofiltertype(self):
    pol = policy.ParsePolicy(nsxt_mocktest.POLICY_NO_FILTERTYPE, self.defs)
    self.assertRaises(nsxt.UnsupportedNsxtAccessListError, nsxt.Nsxt, pol, 2)

  def test_nsxt_incorrectfiltertype(self):
    pol = policy.ParsePolicy(nsxt_mocktest.POLICY_INCORRECT_FILTERTYPE,
                             self.defs)
    self.assertRaises(nsxt.UnsupportedNsxtAccessListError, nsxt.Nsxt, pol, 2)

  if __name__ == '__main__':
    absltest.main()
