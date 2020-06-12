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
import sys
import shutil
import tempfile
import multiprocessing


from absl import app
from absl import flags
from capirca import aclgen
import mock
import unittest


FLAGS = flags.FLAGS
aclgen.SetupFlags()  # Ensure flags are set up only once
# Pass only the program name into absl so it uses the default flags
FLAGS(sys.argv[0:1])


class TestAclGenDemo(unittest.TestCase):
  """Ensure Capirca demo runs successfully out-of-the-box."""

  def setUp(self):
    self.test_subdirectory = tempfile.mkdtemp()
    self.def_dir = os.path.join(self.test_subdirectory, 'def')
    self.pol_dir = os.path.join(self.test_subdirectory, 'policies')
    shutil.rmtree(self.test_subdirectory, ignore_errors=True)
    os.mkdir(self.test_subdirectory)
    shutil.copytree('def', self.def_dir)
    shutil.copytree('policies', self.pol_dir)
    self.context = multiprocessing.get_context()


  @mock.patch.object(aclgen, '_WriteFile', autospec=True)
  def test_smoke_test_generates_successfully(self, mock_writer):
    aclgen.Run(self.pol_dir, self.def_dir, None, self.test_subdirectory,
               self.context)
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
    policy_file = os.path.join(self.test_subdirectory,
                               'policies/pol/sample_cisco_lab.pol')
    aclgen.Run(self.pol_dir, self.def_dir, policy_file,
               self.test_subdirectory, self.context)
    mock_writer.assert_called_with(
        os.path.join(self.test_subdirectory, 'sample_cisco_lab.acl'), mock.ANY)


  # Test to ensure the existence of the entry point function for installed script
  @mock.patch.object(aclgen, 'SetupFlags', autospec=True)
  @mock.patch.object(app, 'run', autospec=True)
  def test_entry_point(self, mock_run, mock_flags):
    aclgen.entry_point()
    mock_flags.assert_called_with()
    mock_run.assert_called_with(aclgen.main)

if __name__ == '__main__':
  unittest.main()
