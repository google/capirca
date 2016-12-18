# Copyright 2016 Google Inc. All Rights Reserved.
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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

from lib import policy_simple
import logging


class FieldTest(unittest.TestCase):

  def setUp(self):
    logging.debug('======> %s <======', self.id())

  def testAppendAppends(self):
    f = policy_simple.Field('Testvalue')
    f.Append('TESTVALUE')
    self.assertEqual(f.value, 'TestvalueTESTVALUE')

  def testStr(self):
    f = policy_simple.Field('Testvalue')
    self.assertEqual('UNKNOWN::Testvalue', str(f))

  def testStrIndents(self):
    f = policy_simple.Field('Testvalue\nTestValue')
    self.assertEqual('UNKNOWN::Testvalue\n            TestValue', str(f))

  def testIntegerField(self):
    self.assertRaises(ValueError, policy_simple.IntegerField, '7.01')
    try:
      _ = policy_simple.IntegerField('7')
    except ValueError:
      self.fail("IntegerField should accept '7' as value.")

  def testNamingFieldRejectsBad(self):
    bads = (
        'corp_internal',
        'CORP+INTERNAL',
    )
    for bad in bads:
      logging.debug('Testing bad "%s".', bad)
      self.assertRaises(ValueError, policy_simple.NamingField, bad)

  def testNamingFieldAcceptsGood(self):
    goods = (
        'CORP_INTERNAL',
        'RFC1918',
        'FOO_BAR102.BAZ101',
    )
    for good in goods:
      try:
        logging.debug('Testing good "%s".', good)
        _ = policy_simple.NamingField(good)
      except ValueError:
        self.fail('Rejected good NamingField value "%s".' % good)

  def testNamingFieldAppendRejectsBad(self):
    f = policy_simple.NamingField('RFC1918')
    bads = (
        'corp_internal',
        'CORP+INTERNAL',
    )
    for bad in bads:
      logging.debug('Testing bad "%s".', bad)
      self.assertRaises(ValueError, f.Append, bad)

  def testNamingFieldAppendAcceptsGood(self):
    f = policy_simple.NamingField('RFC1918')
    goods = (
        'CORP_INTERNAL',
        'RFC1918',
        'FOO_BAR102.BAZ101',
    )
    for good in goods:
      try:
        logging.debug('Testing good "%s".', good)
        _ = f.Append(good)
      except ValueError:
        self.fail('Rejected good NamingField value "%s".' % good)

  def testNamingFieldDedupes(self):
    f = policy_simple.NamingField('RFC1918 CORP_INTERNAL RFC1918')
    f.Append('RFC1918')
    f.Append('CORP_INTERNAL RFC1918')
    self.assertEqual(set(['RFC1918', 'CORP_INTERNAL']), f.value)

  def testNamingFieldStr(self):
    f = policy_simple.NamingField(' '.join(str(x) for x in xrange(25)))
    expected_str = ('UNKNOWN:: 0 1 10 11 12 13 14 15 16 17 18 19 2 20 21'
                    ' 22 23 24 3 4 5 6 7\n            9')
    self.assertEqual(expected_str, str(f))


class BlockTest(unittest.TestCase):

  def setUp(self):
    logging.debug('======> %s <======', self.id())

  def testRejectsNonField(self):
    b = policy_simple.Block()
    for t in ('', 3, lambda x: x, policy_simple.Header(),
              policy_simple.Policy('test')):
      self.assertRaises(TypeError, b.AddField, t)

  def testFieldsWithType(self):
    b = policy_simple.Block()
    c1 = policy_simple.Comment('test1')
    c2 = policy_simple.Comment('test2')
    d = policy_simple.DestinationAddress('XYZ')
    s = policy_simple.SourceAddress('ABC')
    for field in (c1, d, c2, s):
      b.AddField(field)

    self.assertEqual([c1, d, c2, s], b.fields)
    self.assertEqual([c1, c2], b.FieldsWithType(policy_simple.Comment))

  def testIter(self):
    a = object()
    b = object()
    c = object()
    block = policy_simple.Block()
    block.fields = (a, b, c)

    self.assertEqual([a, b, c], list(block))


class PolicyTest(unittest.TestCase):

  def setUp(self):
    logging.debug('======> %s <======', self.id())

  def testAddMember(self):
    p = policy_simple.Policy('test')
    good = [policy_simple.Header(), policy_simple.Term('test'),
            policy_simple.BlankLine(), policy_simple.CommentLine('test'),
            policy_simple.Include('other_pol')]
    bad = ('', 3, lambda x: x, policy_simple.Field('test'))

    for member in good:
      try:
        p.AddMember(member)
      except TypeError:
        self.fail('Policy should accept member "%s"' % member)
    self.assertEqual(good, p.members)

    for member in bad:
      self.assertRaises(TypeError, p.AddMember, member)

  def testIter(self):
    a = object()
    b = object()
    c = object()
    pol = policy_simple.Policy(identifier=None)
    pol.members = (a, b, c)

    self.assertEqual([a, b, c], list(pol))


class PolicyParserTest(unittest.TestCase):

  def setUp(self):
    logging.debug('======> %s <======', self.id())

  def Parser(self, data):
    return policy_simple.PolicyParser(data=data, identifier='test')

  def testParseCommentLine(self):
    parser = self.Parser('# test-comment-value')
    expected = policy_simple.CommentLine('# test-comment-value')

    pol = parser.Parse()
    self.assertEqual([expected], pol.members)

  def testParseBlankLine(self):
    parser = self.Parser('')
    expected = policy_simple.BlankLine()

    pol = parser.Parse()
    self.assertEqual([expected], pol.members)

  def testParseInclude(self):
    parser = self.Parser('#include other/file #whatever')
    expected = policy_simple.Include('other/file')

    pol = parser.Parse()
    self.assertEqual([expected], pol.members)

  def testParseHeader(self):
    parser = self.Parser('header {\ntarget::Test\n}')
    expected = policy_simple.Header()
    expected.AddField(policy_simple.Target('Test'))

    pol = parser.Parse()
    self.assertEqual(expected, pol.members[0])

  def testParseTerm(self):
    parser = self.Parser('term testy {\ntarget::Test\n}')
    expected = policy_simple.Term('testy')
    expected.AddField(policy_simple.Target('Test'))

    pol = parser.Parse()
    self.assertEqual(expected, pol.members[0])

  def testParseTermBadField(self):
    parser = self.Parser('term testy {\nbad_field::Test\n}')
    self.assertRaises(ValueError, parser.Parse)

  def testUnfinishedBlock(self):
    parser = self.Parser('term testy {\ntarget::Test\n')
    self.assertRaises(ValueError, parser.Parse)


if __name__ == '__main__':
  unittest.main()
