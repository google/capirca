# Copyright 2010 Google Inc. All Rights Reserved.
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

"""Unittest for ACL rendering module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

from lib import aclgenerator
from lib import naming
from lib import policy
import mock


GOOD_HEADER_1 = """
header {
  comment:: "this is a test acl"
  target:: mock
}
"""


GOOD_TERM_1 = """
term good-term-1 {
  protocol:: icmp
  action:: accept
}
"""


STATEFUL_ONLY_TERM = """
term stateful-only {
  option:: established
  action:: accept
}
"""


ICMPV6_TERM = """
term icmpv6-term {
  protocol:: icmpv6
  action:: accept
}
"""

SHORT_TERM_NAME = """
term short-term-name {
  protocol:: tcp
  action:: accept
}
"""

GOOD_LONG_TERM_NAME = """
term google-experiment-abbreviations {
  protocol:: tcp
  action:: accept
}
"""

BAD_LONG_TERM_NAME = """
term this-term-name-is-really-far-too-long {
  protocol:: tcp
  action:: accept
}
"""

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class ACLMock(aclgenerator.ACLGenerator):
  _PLATFORM = 'mock'
  _TERM_MAX_LENGTH = 24

  def _TranslatePolicy(self, pol, exp_info):
    pass


class ACLGeneratorTest(unittest.TestCase):

  def setUp(self):
    self.naming = mock.create_autospec(naming.Naming)

  def testEstablishedNostate(self):
    # When using "nostate" filter and a term with "option:: established"
    # have any protocol other than TCP and/or UDP should raise error.
    pol = policy.ParsePolicy(GOOD_HEADER_1 + STATEFUL_ONLY_TERM, self.naming)
    acl = ACLMock(pol, EXP_INFO)
    for _, terms in pol.filters:
      for term in terms:
        self.assertRaises(aclgenerator.EstablishedError,
                          acl.FixHighPorts, term, 'inet', False)

  def testSupportedAF(self):
    # Unsupported address families should raise an error.
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1, self.naming)
    acl = ACLMock(pol, EXP_INFO)
    for _, terms in pol.filters:
      for term in terms:
        self.assertRaises(aclgenerator.UnsupportedAF,
                          acl.FixHighPorts, term, 'unsupported', False)

  def testTermNameBelowLimit(self):
    # Term name that is below specified limit should come out unchanged,
    # regardless of abbreviation and truncation settings.
    pol = policy.ParsePolicy(GOOD_HEADER_1 + SHORT_TERM_NAME, self.naming)
    acl = ACLMock(pol, EXP_INFO)
    for _, terms in pol.filters:
      for term in terms:
        result = acl.FixTermLength(term.name, True, True)
        self.assertEquals(term.name, result)
        result = acl.FixTermLength(term.name, True, False)
        self.assertEquals(term.name, result)
        result = acl.FixTermLength(term.name, False, True)
        self.assertEquals(term.name, result)
        result = acl.FixTermLength(term.name, False, False)
        self.assertEquals(term.name, result)

  def testLongTermAbbreviation(self):
    # Term name that is above specified limit should come out abbreviated
    # when abbreviation is enabled.
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_LONG_TERM_NAME, self.naming)
    acl = ACLMock(pol, EXP_INFO)
    for _, terms in pol.filters:
      for term in terms:
        result = acl.FixTermLength(term.name, True, False)
        self.failUnless('-abbreviations' in result,
                        'Our strings disappeared during abbreviation.')

  def testTermNameTruncation(self):
    # Term name that is above specified limit should come out truncated
    # when truncation is enabled.
    pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_LONG_TERM_NAME, self.naming)
    acl = ACLMock(pol, EXP_INFO)
    for _, terms in pol.filters:
      for term in terms:
        result = acl.FixTermLength(term.name, False, True)
        self.assertEquals('google-experiment-abbrev', result)

  def testLongTermName(self):
    # Term name that is above specified limit and is impossible to abbreviate
    # should raise an exception.
    pol = policy.ParsePolicy(GOOD_HEADER_1 + BAD_LONG_TERM_NAME, self.naming)
    acl = ACLMock(pol, EXP_INFO)
    for _, terms in pol.filters:
      for term in terms:
        self.assertRaises(aclgenerator.TermNameTooLongError,
                          acl.FixTermLength, term.name, True, False)

  def testProtocolNameToNumber(self):
    protoMap = {'icmp': 1,
                'ipip': 4,
                'tcp': 6,
                'gre': 47,
               }
    protoConvert = ['gre', 'tcp']

    protocolList = ['icmp', 'gre', 'tcp', 'ipip']
    expectedProtocolList = ['icmp', 47, 6, 'ipip']

    retProtocolList = aclgenerator.ProtocolNameToNumber(protocolList,
                                                        protoConvert,
                                                        protoMap)

    self.assertItemsEqual(expectedProtocolList, retProtocolList)

  def testAddRepositoryTags(self):
    # Format print the '$' into the RCS tags in order prevent the tags from
    # being interpolated here.

    # Include all tags.
    self.assertItemsEqual(
        ['%sId:%s' % ('$', '$'),
         '%sDate:%s' % ('$', '$'),
         '%sRevision:%s' % ('$', '$')], aclgenerator.AddRepositoryTags())
    # Remove the revision tag.
    self.assertItemsEqual(
        ['%sId:%s' % ('$', '$'),
         '%sDate:%s' % ('$', '$')],
        aclgenerator.AddRepositoryTags(revision=False))
    # Only include the Id: tag.
    self.assertItemsEqual(
        ['%sId:%s' % ('$', '$')],
        aclgenerator.AddRepositoryTags(date=False, revision=False))


if __name__ == '__main__':
  unittest.main()
