# Lint as: python3
"""Unittest for GCP Firewall Generator module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import unittest

from absl.testing import parameterized

from capirca.lib import gcp


class HelperFunctionsTest(parameterized.TestCase):

  @parameterized.named_parameters(
      ('lowercase', 'project'),
      ('lowercase_w_hyphen', 'project-id'),
      ('lowercase_w_numbers', 'project123'),
      ('lowercase_w_numbers_hyphens', 'project-1-2-3'))
  def testIsProjectIDValidPasses(self, project):
    self.assertTrue(gcp.IsProjectIDValid(project))

  @parameterized.named_parameters(
      ('trailing_hyphen', 'project-'),
      ('start_w_number', '1project'),
      ('start_w_hyphen', '-project'),
      ('uppercase', 'Project'),
      ('too_short_by_one_char', 'proje'),
      ('too_long_by_one_char', 31 * 'a'))
  def testIsProjectIDValidFails(self, project):
    self.assertFalse(gcp.IsProjectIDValid(project))

  @parameterized.named_parameters(
      ('lowercase', 'vpc'),
      ('lowercase_w_hyphen', 'v-p-c'),
      ('lowercase_w_numbers', 'vpc123'),
      ('lowercase_w_numbers_hyphens', 'vpc-1-2-3'),
      ('one_letter', 'v'))
  def testIsVPCNameValidPasses(self, vpc):
    self.assertTrue(gcp.IsVPCNameValid(vpc))

  @parameterized.named_parameters(
      ('trailing_hyphen', 'vpc-'),
      ('start_w_number', '1vpc'),
      ('start_w_hyphen', '-vpc'),
      ('uppercase', 'Vpc'),
      ('too_short_by_one_char', ''),
      ('too_long_by_one_char', 64 * 'a'))
  def testIsVPCNameValidFails(self, vpc):
    self.assertFalse(gcp.IsVPCNameValid(vpc))


if __name__ == '__main__':
  unittest.main()
