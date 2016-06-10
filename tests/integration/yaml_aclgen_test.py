import unittest
import logging
import sys
import os
import inspect
import shutil
from cStringIO import StringIO
import filecmp

import aclgen
from lib import policy
import filediff

class YAML_AclGen_Characterization_Test_Base(unittest.TestCase):
  """Tests of aclgen.py, using the YAML parser."""

  def setUp(self):
    # Ignore output during tests.
    logger = logging.getLogger()
    logger.level = logging.CRITICAL
    logger.addHandler(logging.NullHandler())

    curr_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
    self.test_dir = os.path.realpath(os.path.join(curr_dir, '..', 'yaml_policies'))
    self.output_dir = self.get_testpath('filters_actual')
    if not os.path.exists(self.output_dir):
      os.makedirs(self.output_dir)
    self.empty_output_dir(self.output_dir)

  def get_testpath(self, *args):
    return os.path.abspath(os.path.join(self.test_dir, *args))

  def empty_output_dir(self, d):
    entries = [ os.path.join(d, f) for f in os.listdir(d)]
    for f in [e for e in entries if os.path.isfile(e)]:
      os.remove(f)
    for d in [e for e in entries if os.path.isdir(e)]:
      shutil.rmtree(d)


class YAML_AclGen_Tests(YAML_AclGen_Characterization_Test_Base):

  def test_characterization(self):
    def_dir, pol_dir, expected_dir = map(self.get_testpath, ('def', 'policies', 'filters_expected'))

    args = [
      'program',  # Dummy value for gflags, which expects the program name to be the first entry.
      '--base_directory={0}'.format(pol_dir),
      '--definitions_directory={0}'.format(def_dir),
      '--output_directory={0}'.format(self.output_dir),
      '--policy_format=yml'
    ]
    aclgen.main(args)

    dircmp = filecmp.dircmp(self.output_dir, expected_dir)
    self.assertEquals([], dircmp.left_only, 'missing {0} in filters_expected'.format(dircmp.left_only))
    self.assertEquals([], dircmp.right_only, 'missing {0} in filters_actual'.format(dircmp.right_only))

    if dircmp.diff_files != []:
      diffs = filediff.get_file_content_differences(
        self.output_dir, expected_dir, dircmp.diff_files)
      self.assertEquals(1, 2, '\n\n'.join(diffs))
      
    self.assertEquals([], dircmp.diff_files)


def main():
    unittest.main()

if __name__ == '__main__':
    main()

