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
import shutil
import tempfile
from cStringIO import StringIO
import filecmp

import aclgen
from lib import policy
from lib import naming


class Test_AclGen_ensure_demo_files_work(unittest.TestCase):
  """Ensure Capirca demo runs successfully out-of-the-box."""

  def setUp(self):
    if aclgen.FLAGS.IsParsed():
      aclgen.FLAGS.Reset()

    self.iobuff = StringIO()
    logger = logging.getLogger()
    logger.level = logging.DEBUG
    self.s = logging.StreamHandler(self.iobuff)
    self.s.level = logging.DEBUG
    logger.addHandler(self.s)

    # Capirca only writes if files have changed, so write out to a new
    # temp dir for each test run.
    self.output_dir = tempfile.mkdtemp()

    curr_dir = os.path.dirname(os.path.abspath(__file__))
    self.root_dir = os.path.realpath(os.path.join(curr_dir, '..', '..'))
    self.policies_dir = os.path.join(self.root_dir, 'policies')
    self.defs_dir = os.path.join(self.root_dir, 'def')

  def tearDown(self):
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


class AclGen_Characterization_Test_Base(unittest.TestCase):
  """Ensures base functionality works.  Uses data in
  characterization_data subfolder."""

  def setUp(self):
    if aclgen.FLAGS.IsParsed():
      aclgen.FLAGS.Reset()

    self.iobuff = StringIO()
    logger = logging.getLogger()
    logger.level = logging.DEBUG
    self.s = logging.StreamHandler(self.iobuff)
    self.s.level = logging.DEBUG
    logger.addHandler(self.s)

    curr_dir = os.path.dirname(os.path.abspath(__file__))
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
    args = [
      'program',  # Dummy value for gflags, which expects the program name to be the first entry.
      '--base_directory={0}'.format(pol_dir),
      '--definitions_directory=/some_missing_dir/',
      '--output_directory={0}'.format(self.output_dir)
    ]

    aclgen.main(args)

    # NOTE that the code still continues work, even if a bad directory
    # was passed in.
    # TODO: verify this behaviour.
    self.assertTrue('bad definitions directory' in self.iobuff.getvalue())



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

  def test_characterization_single_file(self):
    def_dir, pol_dir, expected_dir = map(self.dirpath, ('def', 'policies', 'filters_expected'))
    polfile = os.path.join(pol_dir, 'pol', 'sample_cisco_lab.pol')
    args = [
      'program',  # Dummy value for gflags, which expects the program name to be first.
      '--policy_file={0}'.format(polfile),
      '--base_directory={0}'.format(pol_dir),
      '--definitions_directory={0}'.format(def_dir),
      '--output_directory={0}'.format(self.output_dir)
    ]
    aclgen.main(args)

    def content(f):
      with open(f, 'r') as handle:
        return handle.read()

    actual_outfile = os.path.join(self.output_dir, 'sample_cisco_lab.acl')
    actual = content(actual_outfile)
    expected_outfile = os.path.join(expected_dir, 'sample_cisco_lab.acl')
    expected = content(expected_outfile)

    # Build nicer diff message for file content comparison:
    msg = ""
    first_diff = 0
    last_diff = -1  # Counting backwards from end
    if (actual != expected):
      actual = actual.split('\n')
      expected = expected.split('\n')
      while actual[first_diff] == expected[first_diff]:
        first_diff += 1  # may run off the end of one of the arrays
                         # ... not concerned, that's an error anyway.
      while actual[last_diff] == expected[last_diff]:
        print actual[last_diff]
        last_diff -= 1
      actual = '\n'.join(actual[first_diff:(len(actual) + last_diff + 1)])
      expected = '\n'.join(expected[first_diff:(len(expected) + last_diff + 1)])

      msg = """Files differ starting at line {0}:

Actual {1}:
---------------------
{2}
---------------------
Expected {3}:
---------------------
{4}
---------------------""".format(first_diff, actual_outfile, actual, expected_outfile, expected)

    if msg != "":
      self.assertEquals(1, 2, msg)


def main():
    unittest.main()

if __name__ == '__main__':
    main()

