"""Unittest for GCP Firewall Generator module."""

import unittest

from absl.testing import absltest

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
      ('trailing_hyphen', 'project-'), ('start_w_number', '1project'),
      ('start_w_hyphen', '-project'), ('uppercase', 'Project'),
      ('too_short_by_one_char', 'proje'), ('too_long_by_one_char', 31 * 'a'))
  def testIsProjectIDValidFails(self, project):
    self.assertFalse(gcp.IsProjectIDValid(project))

  @parameterized.named_parameters(
      ('lowercase', 'vpc'), ('lowercase_w_hyphen', 'v-p-c'),
      ('lowercase_w_numbers', 'vpc123'),
      ('lowercase_w_numbers_hyphens', 'vpc-1-2-3'), ('one_letter', 'v'))
  def testIsVPCNameValidPasses(self, vpc):
    self.assertTrue(gcp.IsVPCNameValid(vpc))

  @parameterized.named_parameters(
      ('trailing_hyphen', 'vpc-'), ('start_w_number', '1vpc'),
      ('start_w_hyphen', '-vpc'), ('uppercase', 'Vpc'),
      ('too_short_by_one_char', ''), ('too_long_by_one_char', 64 * 'a'))
  def testIsVPCNameValidFails(self, vpc):
    self.assertFalse(gcp.IsVPCNameValid(vpc))

  @parameterized.named_parameters(
      ('term', 'good-term', 'good-term-v6'),
      ('term_with_v6_suffix', 'good-term-v6', 'good-term-v6-v6'),
      ('one_letter', 'v', 'v-v6'))
  def testGetIpv6TermName(self, term_name, expected):
    self.assertEqual(expected, gcp.GetIpv6TermName(term_name))

  @parameterized.named_parameters(
      ('ipv4_mapped', ['::ffff:a02:301/128'], []),
      ('6to4', ['2002::/16'], []),
      ('ipv4_compatible', ['::0000:a02:301/128'], []),
      ('ipv4', ['10.2.3.4/32'], ['10.2.3.4/32']),
      ('ipv6', ['2001:4860:8000::5/128'], ['2001:4860:8000::5/128']),
      ('ipv4_wildcard', ['0.0.0.0/0'], ['0.0.0.0/0']),
      ('ipv6_wildcard', ['::/0'], ['::/0']))
  def testFilterIPv4InIPv6FormatAddrs(self, addrs, expected):
    self.assertEqual(expected, gcp.FilterIPv4InIPv6FormatAddrs(addrs))
    with self.assertRaises(ValueError):
      gcp.FilterIPv4InIPv6FormatAddrs(['dshjgsjfhgsd'])


if __name__ == '__main__':
  absltest.main()
