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

import os
import shutil
import tempfile

from absl import flags
from absl.testing import flagsaver
from capirca import aclgen
import mock
import unittest


FLAGS = flags.FLAGS


class TestAclGenDemo(unittest.TestCase):
  """Ensure Capirca demo runs successfully out-of-the-box."""

  def setUp(self):
    # Need to initialize flags since unittest doesn't do this for us.
    FLAGS(['aclgen_test.py'])
    self.saved_flag_values = flagsaver.save_flag_values()
    self.test_subdirectory = tempfile.mkdtemp()
    self.def_dir = os.path.join(self.test_subdirectory, 'def')
    self.pol_dir = os.path.join(self.test_subdirectory, 'policies')
    shutil.rmtree(self.test_subdirectory, ignore_errors=True)
    os.mkdir(self.test_subdirectory)
    shutil.copytree('def', self.def_dir)
    shutil.copytree('policies', self.pol_dir)
    FLAGS.base_directory = self.pol_dir
    FLAGS.definitions_directory = self.def_dir
    FLAGS.output_directory = self.test_subdirectory

  def tearDown(self):
    flagsaver.restore_flag_values(self.saved_flag_values)

  @mock.patch.object(aclgen, '_WriteFile', autospec=True)
  def test_smoke_test_generates_successfully(self, mock_writer):
    aclgen.main([])
    files = ['sample_cisco_lab.acl', 'sample_cloudarmor.gca', 'sample_gce.gce',
             'sample_ipset.ips', 'sample_juniper_loopback.jcl',
             'sample_multitarget.acl', 'sample_multitarget.asa',
             'sample_multitarget.bacl', 'sample_multitarget.eacl',
             'sample_multitarget.ipt', 'sample_multitarget.jcl',
             'sample_multitarget.xacl', 'sample_nsxv.nsx',
             'sample_packetfilter.pf', 'sample_speedway.ipt', 'sample_srx.srx',
             'sample_paloalto.xml']
    expected = [mock.call(
        os.path.join(self.test_subdirectory, f), mock.ANY) for f in files]
    mock_writer.assert_has_calls(expected, any_order=True)

  @mock.patch.object(aclgen, '_WriteFile', autospec=True)
  def test_generate_single_policy(self, mock_writer):
    FLAGS.policy_file = os.path.join(self.test_subdirectory,
                                     'policies/pol/sample_cisco_lab.pol')
    aclgen.main([])
    mock_writer.assert_called_with(
        os.path.join(self.test_subdirectory, 'sample_cisco_lab.acl'), mock.ANY)

if __name__ == '__main__':
  unittest.main()
