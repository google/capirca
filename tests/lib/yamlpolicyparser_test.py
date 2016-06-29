import unittest
import sys
import os
import inspect
# from cStringIO import StringIO

from lib import policy
from lib import yamlpolicyparser
from lib.yamlpolicyparser import YamlPolicyParser
from lib.yamlnaming import YamlNaming


class Target_Tests(unittest.TestCase):
  """
  These tests ensure that the Targets created through the YAML files
  have parity with the targets created through .pol files."""

  def test_ipv4_target_build(self):
    X = 'aclname'
    test_cases = [
      # Target only:
      ['cisco', ['cisco', X, 'extended']],
      ['juniper', ['juniper', X, 'inet']],
      ['nsxv', ['nsxv', 'inet']],
      ['demo', ['demo', X]],
      ['arista', ['arista', X]],
      ['brocade', ['brocade', X]],
      ['ciscoxr', ['ciscoxr', X]],
      ['packetfilter', ['packetfilter', X]],

      # Overrides specified in the target:
      ['cisco x y z', ['cisco', X, 'x', 'y', 'z']],
      ['juniper x y z', ['juniper', X, 'x', 'y', 'z']],
      ['nsxv section', ['nsxv', 'inet', 'section']],

      # Left as-is:
      ['gce some data', ['gce', 'some', 'data']],
      ['ipset some data', ['ipset', 'some', 'data']],
      ['speedway INPUT', ['speedway', 'INPUT']],
      ['ciscoasa asa_in', ['ciscoasa', 'asa_in']],
      ['srx some data', ['srx', 'some', 'data']],
    ]
    for raw_target, expected in test_cases:
      actual = YamlPolicyParser.build_Capirca_Target_ctor_array(raw_target, X, 'ipv4')
      self.assertEqual(actual, expected)

  def test_ipv6_target_build(self):
    X = 'aclname'
    test_cases = [
      # Target only:
      ['cisco', ['cisco', X, 'inet6']],
      ['juniper', ['juniper', X, 'inet6']],
      ['nsxv', ['nsxv', 'inet6']],
      ['demo', ['demo', X]],
      ['arista', ['arista', X]],
      ['brocade', ['brocade', X]],
      ['ciscoxr', ['ciscoxr', X]],

      # Overrides specified in the target.
      ['cisco x y z', ['cisco', X, 'x', 'y', 'z']],
      ['juniper x y z', ['juniper', X, 'x', 'y', 'z']],
      ['nsxv section', ['nsxv', 'inet6', 'section']],
    ]
    for raw_target, expected in test_cases:
      actual = YamlPolicyParser.build_Capirca_Target_ctor_array(raw_target, X, 'ipv6')
      self.assertEqual(actual, expected)

  def test_throws_for_unhandled_target(self):
    with self.assertRaises(ValueError):
      YamlPolicyParser.build_Capirca_Target_ctor_array('unknown_target', 'x', 'ipv4')

  def test_sanity_check(self):
    hsh = { 'name': 'X', 'address-family': 'ipv4', 'targets': ['cisco'] }
    actual = YamlPolicyParser.transform_targets_to_Capirca_style(hsh)
    expected = [['cisco', 'X', 'extended']]
    self.assertEqual(actual, expected)

class YamlParser_Test(unittest.TestCase):

  """Sanity check only to ensure parser runs.

  Uses data in characterization_data subfolder."""

  def setUp(self):
    curr_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
    self.base_dir = os.path.realpath(os.path.join(curr_dir, '..', 'yaml_policies'))
    yml = os.path.join(self.base_dir, 'policies', 'pol', 'sample_cisco_lab.yml')
    self.test_policy_filename = yml
    with open(yml, 'r') as f:
        self.test_policy = f.read()

    self.definitions = YamlNaming(os.path.join(self.base_dir, 'def'))

    self.parser = YamlPolicyParser(self.definitions, True)

  def test_sanity_check(self):
    p = self.parser.parse(self.test_policy)
    # If we reach here, assume OK.

  def test_header_settings(self):
    p = self.parser.parse(self.test_policy)
    self.assertEqual(p.headers[0].Name, 'allowtointernet')
    self.assertEqual(p.headers[0].FilterName('cisco'), 'allowtointernet')

  def test_target_set_correctly(self):
    p = self.parser.parse(self.test_policy)
    headers = p.headers
    self.assertEqual(1, len(headers))
    self.assertEqual(['cisco'], p.platforms)
    self.assertEqual(['allowtointernet', 'extended'], headers[0].target[0].options)

  def test_ParsePolicy(self):
    p = yamlpolicyparser.ParsePolicy(
      self.test_policy,
      self.definitions,
      os.path.join(self.base_dir, 'policies'),
      True)
    # Not doing real test.  Integration tests will catch further issues.
    self.assertTrue(p is not None)

  def test_ParseFile(self):
    """API should mimic the existing policyparser.py API."""
    p = yamlpolicyparser.ParseFile(
      self.test_policy_filename,
      self.definitions,
      True,
      True)
    # Not doing real test.  Integration tests will catch further issues.
    self.assertTrue(p is not None)

  # TODO fix/low: add term parsing tests for some directives.
  #
  # Marking as low pri as integration-level tests, stronger domain
  # model, and pykwalify yaml validation should take care of much of
  # this.


def main():
    unittest.main()

if __name__ == '__main__':
    main()

