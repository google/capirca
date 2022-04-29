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
"""Unittest for Nftables rendering module."""

import datetime
from unittest import mock

from absl import logging
from absl.testing import absltest
from absl.testing import parameterized
from capirca.lib import aclgenerator
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import newnftables
from capirca.lib import policy

HEADER_TEMPLATE = """
header {
  target:: newnftables %s
}
"""

HEAD_OVERRIDE_DEFAULT_ACTION = """
header {
  target:: newnftables inet output ACCEPT
}
"""

HEADER_COMMENT = """
header {
  comment:: "Noverbose + custom priority policy example"
  target:: newnftables inet output ACCEPT
}
"""

# TODO(gfm): Noverbose testing once Term handling is added.
HEADER_NOVERBOSE = """
header {
  target:: newnftables mixed output noverbose
}
"""

GOOD_HEADER_1 = """
header {
  target:: newnftables inet6 INPUT
}
"""

GOOD_HEADER_2 = """
header {
  target:: newnftables mixed output accept
}
"""

ICMP_TERM = """
term good-icmp {
  protocol:: icmp
  action:: accept
}
"""

GOOD_TERM_1 = """
term good-term-1 {
  action:: accept
}
"""

IPV6_TERM_2 = """
term inet6-icmp {
  action:: deny
}
"""

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class NftablesTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.naming = mock.create_autospec(naming.Naming)

  def testDuplicateTerm(self):
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1 + GOOD_TERM_1,
                             self.naming)
    with self.assertRaises(newnftables.TermError):
      newnftables.NewNftables.__init__(
          newnftables.NewNftables.__new__(newnftables.NewNftables), pol,
          EXP_INFO)

  @parameterized.parameters(
      'chain_name input 0 inet extraneous_target_option',
      'ip6 OUTPUT 300 400'  # pylint: disable=implicit-str-concat
      'mixed input',
      'ip forwarding',
      'ip7 0 spaghetti',
      'ip6 prerouting',
      'chain_name',
      '',
  )
  def testBadHeader(self, case):
    logging.info('Testing bad header case %s.', case)
    header = HEADER_TEMPLATE % case
    pol = policy.ParsePolicy(header + GOOD_TERM_1, self.naming)
    with self.assertRaises(newnftables.HeaderError):
      newnftables.NewNftables.__init__(
          newnftables.NewNftables.__new__(newnftables.NewNftables), pol,
          EXP_INFO)

  @parameterized.parameters((HEADER_NOVERBOSE, False), (HEADER_COMMENT, True))
  def testVerboseHeader(self, header_to_use, expected_output):
    pol = policy.ParsePolicy(header_to_use + GOOD_TERM_1, self.naming)
    data = newnftables.NewNftables(pol, EXP_INFO)
    for (_, _, _, _, _, verbose, _) in data.nftables_policies:
      result = verbose
    self.assertEqual(result, expected_output)

  def testGoodHeader(self):
    # TODO(gfm): Parameterize this test.
    newnftables.NewNftables(
        policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1, self.naming), EXP_INFO)
    nft = str(
        newnftables.NewNftables(
            policy.ParsePolicy(
                GOOD_HEADER_1 + GOOD_TERM_1 + GOOD_HEADER_2 + IPV6_TERM_2,
                self.naming), EXP_INFO))
    self.assertIn('type filter hook input', nft)

  def testOverridePolicyHeader(self):
    expected_output = 'accept'

    pol = policy.ParsePolicy(HEAD_OVERRIDE_DEFAULT_ACTION + GOOD_TERM_1,
                             self.naming)
    data = newnftables.NewNftables(pol, EXP_INFO)
    for (_, _, _, _, default_policy, _, _) in data.nftables_policies:
      result = default_policy
    self.assertEqual(result, expected_output)


if __name__ == '__main__':
  absltest.main()
