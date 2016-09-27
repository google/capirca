# Copyright 2008 Google Inc. All Rights Reserved.
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

import unittest

from lib import linters
from lib import naming
from lib import policy

class BaseLintTest(unittest.TestCase):

  """Base helper class for linters. Use self.linter to access a linter -
  and self.lint_errors to look at the errors produced."""

  LINTER_CLASS = None
  LINT_CONFIG = {}

  def setUp(self):
    errors = linters.LintErrors()
    self.linter = self.LINTER_CLASS(errors, self.LINT_CONFIG)

  @property
  def lint_errors(self):
    return self.linter.errors.errs

  def loadNaming(self, def_type, content, defs=None):

    """Load the given naming definition type and string blob"""

    defs = defs or naming.Naming(None)
    for lineno, line in enumerate(content.splitlines(), start=1):
      defs._ParseLine(line, def_type, lineno=lineno)
    return defs

  def loadPolicy(self, net_content, svc_content, policy_content,
                 filename='unittest'):

    """Load the provided string blobs into a tracked parsed policy"""

    defs = naming.Naming(None)
    self.loadNaming('networks', net_content, defs=defs)
    self.loadNaming('services', svc_content, defs=defs)
    p = policy.ParsePolicy(
      policy_content,
      defs,
      track=True,
      optimize=False,
      filename=filename,
    )
    return p

  def assertOneLintError(self):
    self.assertEquals(len(self.lint_errors), 1)

  def assertLintMessage(self, msg):
    self.assertEquals(self.lint_errors[0].message, msg)


NAMING_NETWORKS = """
NET_TEN_EIGHT = 10.0.0.0/8
NET_TWO_EIGHT = 2.0.0.0/8
"""

BAD_NAMING_NETWORKS = """
lowercase_network = 1.1.1.1/32
GARBAGE.DOT = 2.2.2.2/32
"""

NAMING_SVC = """
SSH = 22/tcp
"""

GOOD_POLICY = """
header {
}

term good-term-1 {
  action:: accept
}
"""

BAD_POLICY = """
header {
}
term BAD-TERM {
  action:: accept
}
"""

class NameEnforcerTest(BaseLintTest):
  LINTER_CLASS = linters.RegexNameEnforcer

  def test_good_naming(self):
    defs = self.loadNaming('networks', NAMING_NETWORKS)
    self.loadNaming('services', NAMING_SVC, defs=defs)
    self.linter.lint_naming(defs)
    self.assertEquals(self.linter.errors.errs, [])

  def test_bad_naming(self):
    defs = self.loadNaming('networks', BAD_NAMING_NETWORKS)
    self.loadNaming('services', NAMING_SVC, defs=defs)
    self.linter.lint_naming(defs)

    expected = set([
      'lowercase_network is not a valid network name',
      'GARBAGE.DOT is not a valid network name',
    ])
    found = set([x.message for x in self.lint_errors])
    self.assertEquals(expected, found)

  def test_good_policy(self):
    p = self.loadPolicy(NAMING_NETWORKS, NAMING_SVC, GOOD_POLICY)
    self.linter.lint_policy(p)
    self.assertEquals(self.lint_errors, [])

  def test_bad_policy(self):
    p = self.loadPolicy(NAMING_NETWORKS, NAMING_SVC, BAD_POLICY)
    self.linter.lint_policy(p)
    self.assertOneLintError()
    self.assertLintMessage('BAD-TERM is not a valid term name for all platforms')


SAMELINE_NET = """TWO_NETWORKS = 1.1.1.1/32 2.2.2.2/32"""
SAMELINE_SVC = """TCP_SSH = 22/tcp 22/udp"""

class SameLineEnforcerTest(BaseLintTest):
  LINTER_CLASS = linters.SameLineDefinitionsEnforcer

  def test_singleline_network(self):
    defs = self.loadNaming('networks', SAMELINE_NET)
    self.linter.lint_naming(defs)
    self.assertOneLintError()
    self.assertLintMessage('Networks on same line')

  def test_singleline_service(self):
    defs = self.loadNaming('services', SAMELINE_SVC)
    self.linter.lint_naming(defs)
    self.assertOneLintError()
    self.assertLintMessage('Services on same line')


LONG_NETWORK_NAMING = """THIS_IS_A_LONG_NETWORK = 1.1.1.1/32"""
LONG_SERVICE_NAMING = """THIS_IS_A_LONG_SERVICE = 22/tcp"""

class CharLengthEnforcerTest(BaseLintTest):
  LINTER_CLASS = linters.CharLengthEnforcer
  LINT_CONFIG = {
    'CharLengthEnforcer': {
      'MAX_NETWORK_LEN': 10,
      'MAX_SERVICE_LEN': 10,
    }
  }

  def test_long_network(self):
    defs = self.loadNaming('networks', LONG_NETWORK_NAMING)
    self.linter.lint_naming(defs)
    self.assertOneLintError()

  def test_long_service(self):
    defs = self.loadNaming('services', LONG_SERVICE_NAMING)
    self.linter.lint_naming(defs)
    self.assertOneLintError()

if __name__ == '__main__':
  unittest.main()
