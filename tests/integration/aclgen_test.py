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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from cStringIO import StringIO
import filecmp
import logging
import os
import shutil
import tempfile
import unittest

import aclgen


class TestAclGenDemo(unittest.TestCase):
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
        'program',
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
        'sample_srx.srx',
        'sample_paloalto.xml'
    ]
    def makeoutput(f):
      return 'writing file: {0}'.format(os.path.join(self.output_dir, f))

    actual_output = self.iobuff.getvalue().split('\n')
    for expected_output in map(makeoutput, expected_files):
      self.assertTrue(expected_output in actual_output)

    self.assertTrue('writing 16 files to disk...' in actual_output)

  def test_generate_single_policy(self):
    args = [
        'program',
        '--policy_file={0}'.format(os.path.join(self.policies_dir,
                                                'pol', 'sample_cisco_lab.pol')),
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


class AclGenCharacterizationTestBase(unittest.TestCase):
  """Ensures base functionality works."""

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
    entries = [os.path.join(d, f) for f in os.listdir(d)]
    for f in [e for e in entries if os.path.isfile(e)]:
      os.remove(f)
    for d in [e for e in entries if os.path.isdir(e)]:
      shutil.rmtree(d)


class AclGenArgumentsTests(AclGenCharacterizationTestBase):

  def test_missing_defs_folder_raises_error(self):
    unused_def_dir, pol_dir, unused_expected_dir = map(
        self.dirpath, ('def', 'policies', 'filters_expected'))
    args = [
        'program',
        '--base_directory={0}'.format(pol_dir),
        '--definitions_directory=/some_missing_dir/',
        '--output_directory={0}'.format(self.output_dir)
    ]

    aclgen.main(args)

    # NOTE that the code still continues work, even if a bad directory
    # was passed in.
    # TODO(jzohrab): verify this behaviour.
    self.assertTrue('bad definitions directory' in self.iobuff.getvalue())


class AclGenCharacterizationTests(AclGenCharacterizationTestBase):

  def test_characterization(self):
    def_dir, pol_dir, expected_dir = map(
        self.dirpath, ('def', 'policies', 'filters_expected'))
    args = [
        'program',
        '--base_directory={0}'.format(pol_dir),
        '--definitions_directory={0}'.format(def_dir),
        '--output_directory={0}'.format(self.output_dir)
    ]
    aclgen.main(args)
    dircmp = filecmp.dircmp(self.output_dir, expected_dir)
    self.assertEquals(
        [],
        dircmp.left_only,
        'missing {0} in filters_expected'.format(dircmp.left_only))
    self.assertEquals(
        [],
        dircmp.right_only,
        'missing {0} in filters_actual'.format(dircmp.right_only))
    self.assertEquals([], dircmp.diff_files)


def main():
  unittest.main()

if __name__ == '__main__':
  main()
