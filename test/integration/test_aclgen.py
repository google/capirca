# Copyright 2015 The Capirca Project Authors All Rights Reserved.
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
import sys
import logging
import os
import inspect
import shutil
import tempfile
from cStringIO import StringIO
import filecmp

import aclgen
from lib import policy


class Test_AclGen_ensure_demo_files_work(unittest.TestCase):
  """Ensure Capirca demo runs successfully out-of-the-box."""

  def setUp(self):
    self.iobuff = StringIO()
    logger = logging.getLogger()
    logger.level = logging.DEBUG
    self.s = logging.StreamHandler(self.iobuff)
    self.s.level = logging.DEBUG
    logger.addHandler(self.s)

    # Capirca only writes if files have changed, so write out to a new
    # temp dir for each test run.
    self.output_dir = tempfile.mkdtemp()

    curr_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
    self.root_dir = os.path.realpath(os.path.join(curr_dir, '..', '..'))
    self.policies_dir = os.path.join(self.root_dir, 'policies')
    self.defs_dir = os.path.join(self.root_dir, 'def')

  def tearDown(self):
        # Remove the directory after the test
        shutil.rmtree(self.output_dir)

  def test_smoke_test_generates_successfully(self):
    args = [
      'program',  # Dummy value for gflags, which expects the program name to be the first entry.
      '--base_directory={0}'.format(self.policies_dir),
      '--definitions_directory={0}'.format(self.defs_dir),
      '--output_directory={0}'.format(self.output_dir)
    ]
    aclgen.main(args)

    expected_files = [
      'sample_cisco_lab.acl',
      'sample_gce.gce',
      'sample_ipset.ips',
      'sample_juniper_loopback.jcl',
      'sample_multitarget.acl',
      'sample_multitarget.asa',
      'sample_multitarget.bacl',
      'sample_multitarget.eacl',
      'sample_multitarget.ipt',
      'sample_multitarget.jcl',
      'sample_multitarget.xacl',
      'sample_nsxv.nsx',
      'sample_packetfilter.pf',
      'sample_speedway.ipt',
      'sample_srx.srx'
    ]
    def makeoutput(f):
      return 'writing file: {0}'.format(os.path.join(self.output_dir, f))

    actual_output = self.iobuff.getvalue().split("\n")
    for expected_output in map(makeoutput, expected_files):
      self.assertTrue(expected_output in actual_output)

    self.assertTrue('writing 15 files to disk...' in actual_output)


  def test_generate_single_policy(self):
    args = [
      'program',  # Dummy value for gflags, which expects the program name to be the first entry.
      '--policy_file={0}'.format(os.path.join(self.policies_dir, 'pol', 'sample_cisco_lab.pol')),
      '--definitions_directory={0}'.format(self.defs_dir),
      '--output_directory={0}'.format(self.output_dir)
    ]
    aclgen.main(args)

    actual_output = self.iobuff.getvalue()
    expected_outputs = [
      'rendering one file',
      os.path.join(self.output_dir, 'sample_cisco_lab.acl')
    ]
    for s in expected_outputs:
      self.assertTrue(s in actual_output)


# (Temporarily?) disabling.
#
# class AclGen_filter_name_scenarios(unittest.TestCase):
#   """Ensure the output directory structure mirrors the input correctly.

#   See aclgen.filter_name for notes."""

#   def test_file_in_base_directory_is_output_to_output_dir(self):
#     s = AclGen.filter_name('/policy', '/policy/x.txt', '.out', '/output')
#     self.assertEqual(s, '/output/x.out')

#   def test_file_in_subdirectory_is_output_to_subdirectory(self):
#     s = AclGen.filter_name('/policy', '/policy/subdir/x.txt', '.out', '/output')
#     self.assertEqual(s, '/output/subdir/x.out')

#   def test_file_in_nested_subdir(self):
#     s = AclGen.filter_name('/policy', '/policy/sub/dir/x.txt', '.out', '/output/here')
#     self.assertEqual(s, '/output/here/sub/dir/x.out')

#   def test_relative_directory_structure_mirrored(self):
#     s = AclGen.filter_name('../policy', '../policy/subdir/x.txt', '.out', '/output')
#     self.assertEqual(s, '/output/subdir/x.out')

#   def test_empty_source_dir_ok(self):
#     s = AclGen.filter_name('', 'subdir/x.txt', '.out', '/output')
#     self.assertEqual(s, '/output/subdir/x.out')

#   def test_base_dir_must_match_start_of_source_file(self):
#     self.assertRaises(ValueError, AclGen.filter_name, 'A', 'B/C', 'suff', 'O')


class AclGen_Characterization_Test_Base(unittest.TestCase):
  """Ensures base functionality works.  Uses data in
  characterization_data subfolder."""

  def setUp(self):
    # Ignore output during tests.
    logger = logging.getLogger()
    logger.level = logging.CRITICAL
    logger.addHandler(logging.NullHandler())

    curr_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
    self.test_dir = os.path.join(curr_dir, '..', 'characterization_data')
    self.output_dir = self.dirpath('filters_actual')
    if not os.path.exists(self.output_dir):
      os.makedirs(self.output_dir)
    self.empty_output_dir(self.output_dir)

  def dirpath(self, *args):
    return os.path.realpath(os.path.join(self.test_dir, *args))

  def empty_output_dir(self, d):
    entries = [ os.path.join(d, f) for f in os.listdir(d)]
    for f in [e for e in entries if os.path.isfile(e)]:
      os.remove(f)
    for d in [e for e in entries if os.path.isdir(e)]:
      shutil.rmtree(d)


class AclGen_Arguments_Tests(AclGen_Characterization_Test_Base):

  def test_missing_defs_folder_raises_error(self):
    def_dir, pol_dir, expected_dir = map(self.dirpath, ('def', 'policies', 'filters_expected'))
    with self.assertRaises(ValueError):
      aclgen.main(['-d', 'missing_dir', '--poldir', pol_dir, '-o', self.output_dir])


class AclGen_Characterization_Tests(AclGen_Characterization_Test_Base):

  def test_characterization(self):
    def_dir, pol_dir, expected_dir = map(self.dirpath, ('def', 'policies', 'filters_expected'))
    args = [
      'program',  # Dummy value for gflags, which expects the program name to be the first entry.
      '--base_directory={0}'.format(pol_dir),
      '--definitions_directory={0}'.format(def_dir),
      '--output_directory={0}'.format(self.output_dir)
    ]
    aclgen.main(args)
    dircmp = filecmp.dircmp(self.output_dir, expected_dir)
    self.assertEquals([], dircmp.left_only, 'missing {0} in filters_expected'.format(dircmp.left_only))
    self.assertEquals([], dircmp.right_only, 'missing {0} in filters_actual'.format(dircmp.right_only))
    self.assertEquals([], dircmp.diff_files)

  # Old tests, disabling.  Existing clients are perhaps using the wrapper as-is.
  #
  # def test_can_make_direct_API_call_to_load_and_render(self):
  #   """Existing clients may have been making calls directly
  #   to aclgen.load_and_render, double-checking it still works."""
  #   def_dir, pol_dir, expected_dir = map(self.testpath, ('def', 'policies', 'filters_expected'))
  #   aclgen.load_and_render(pol_dir, def_dir, False, 2, self.output_dir)

  #   dircmp = filecmp.dircmp(self.output_dir, expected_dir)
  #   self.assertEquals([], dircmp.left_only, 'missing {0} in filters_expected'.format(dircmp.left_only))
  #   self.assertEquals([], dircmp.right_only, 'missing {0} in filters_actual'.format(dircmp.right_only))
  #   self.assertEquals([], dircmp.diff_files)

  # def test_can_make_direct_API_call_to_render_filters(self):
  #   """Existing clients may have been making calls directly
  #   to aclgen.render_filters, double-checking it still works."""
  #   def_dir, pol_dir, expected_dir = map(self.testpath, ('def', 'policies', 'filters_expected'))
  #   src = os.path.join(pol_dir, 'sample_cisco_lab.pol')
  #   aclgen.render_filters(src, def_dir, False, 2, self.output_dir)
  #   # If we get here, assume all is OK.


# Old test, disabling.
# class AclGen_Create_filter_for_target(AclGen_Characterization_Test_Base):
#   """Given a policy, generate filter text for a particular target."""

#   def get_acl_gen(self):
#     return AclGen(policy_directory = self.testpath('policies'),
#                   definitions_directory = self.testpath('def'),
#                   output_directory = self.testpath('filters_expected'))

#   def test_can_generate_filter_from_policy_for_specified_platform(self):
#     src = self.testpath('policies', 'sample_cisco_lab.pol')
#     definitions = self.testpath('def')
#     a = self.get_acl_gen()
#     fw = a.create_filter_for_platform('cisco', src)
#     actual_filter = str(fw)
#     with open(self.testpath('filters_expected', 'sample_cisco_lab.acl'), 'r') as f:
#       expected_filter = f.read()

#     # If different, save for manual check.
#     if (actual_filter != expected_filter):
#       with open(self.testpath('filters_actual', 'sample_cisco_lab.acl'), 'w') as f:
#         f.write(actual_filter)
#     self.assertEqual(actual_filter, expected_filter)

#   def test_generating_filter_for_missing_platform_throws(self):
#     a = self.get_acl_gen()
#     with self.assertRaises(policy.PolicyTargetPlatformInvalidError):
#       a.create_filter_for_platform('missing', '')

#   def test_cannot_generate_filter_from_policy_for_platform_different_from_policy_header(self):
#     a = self.get_acl_gen()
#     src = self.testpath('policies', 'sample_cisco_lab.pol')
#     definitions = self.testpath('def')
#     with self.assertRaises(policy.PolicyTargetPlatformInvalidError):
#       a.create_filter_for_platform('juniper', src)


def main():
    unittest.main()

if __name__ == '__main__':
    main()

