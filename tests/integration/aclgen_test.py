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

import logging
import os

import aclgen
from lib import naming
import mock
from absl import flags
from absl import logging
import unittest


FLAGS = flags.FLAGS


class TestAclGenDemo(unittest.TestCase):
  """Ensure Capirca demo runs successfully out-of-the-box."""

  def setUp(self):
    if aclgen.FLAGS.is_parsed():
      aclgen.FLAGS.unparse_flags()
    self.output_dir = '.'

    curr_dir = os.path.dirname(os.path.abspath(__file__))
    self.root_dir = os.path.realpath(os.path.join(curr_dir, '..', '..'))
    self.policies_dir = os.path.join(self.root_dir, 'policies')
    self.defs_dir = os.path.join(self.root_dir, 'def')

  @mock.patch.object(aclgen, '_WriteFile', autospec=True)
  def test_smoke_test_generates_successfully(self, mock_writer):
    args = [
        'program',
        '--base_directory={0}'.format(self.policies_dir),
        '--definitions_directory={0}'.format(self.defs_dir),
        '--output_directory={0}'.format(self.output_dir)
    ]
    aclgen.main(args)
    expected = [
        mock.call('./sample_cisco_lab.acl', mock.ANY),
        mock.call('./sample_gce.gce', mock.ANY),
        mock.call('./sample_ipset.ips', mock.ANY),
        mock.call('./sample_juniper_loopback.jcl', mock.ANY),
        mock.call('./sample_multitarget.acl', mock.ANY),
        mock.call('./sample_multitarget.asa', mock.ANY),
        mock.call('./sample_multitarget.bacl', mock.ANY),
        mock.call('./sample_multitarget.eacl', mock.ANY),
        mock.call('./sample_multitarget.ipt', mock.ANY),
        mock.call('./sample_multitarget.jcl', mock.ANY),
        mock.call('./sample_multitarget.xacl', mock.ANY),
        mock.call('./sample_nsxv.nsx', mock.ANY),
        mock.call('./sample_packetfilter.pf', mock.ANY),
        mock.call('./sample_speedway.ipt', mock.ANY),
        mock.call('./sample_srx.srx', mock.ANY),
        mock.call('./sample_paloalto.xml', mock.ANY)
    ]
    mock_writer.assert_has_calls(expected, any_order=True)

  @mock.patch.object(aclgen, '_WriteFile', autospec=True)
  def test_generate_single_policy(self, mock_writer):
    args = [
        'program',
        '--policy_file={0}'.format(os.path.join(self.policies_dir,
                                                'pol', 'sample_cisco_lab.pol')),
        '--definitions_directory={0}'.format(self.defs_dir),
        '--output_directory={0}'.format(self.output_dir)
    ]
    aclgen.main(args)
    mock_writer.assert_called_with('./sample_cisco_lab.acl', mock.ANY)

  @mock.patch.object(logging, 'fatal')
  @mock.patch.object(naming, 'Naming', autospec=True)
  def test_missing_defs_folder_raises_error(self, mock_naming, mock_error):
    mock_naming.side_effect = naming.NoDefinitionsError()
    args = [
        'program',
        '--base_directory={0}'.format(self.policies_dir),
        '--definitions_directory=/some_missing_dir/',
        '--output_directory={0}'.format(self.output_dir)
    ]

    with self.assertRaises(SystemExit) as cm:
        aclgen.main(args)
    self.assertEqual(cm.exception.code, 1)
    self.assertTrue(mock_error.called)
    mock_error.assert_called_with(((u'bad definitions directory: %s',
                                    u'/some_missing_dir/')))

if __name__ == '__main__':
  unittest.main()
