import os
import unittest

def diff_long_strings(lhs, rhs):
  """Diff carriage-return delimited strings (i.e. text file content).

  Algorithm: search both files from the start until it finds the first
  line differences, then search backwards from end to the first line
  difference.  The diff is between those positions.

  Args:
    lhs: string 1
    rhs: string 2

  Returns:
    Tuple of three elements (pos, lhs_diff, rhs_diff):
    pos: line number where the strings start to diverge
    lhs_diff: fragment of the string that differs from the rhs
    rhs_diff: corresponding part of the rhs string

  """

  if lhs == rhs:
    return (-1, None, None)

  first_diff = 0
  lhs_tmp = lhs.split('\n')
  rhs_tmp = rhs.split('\n')
  while len(lhs_tmp) > 0 and len(rhs_tmp) > 0 and lhs_tmp[0] == rhs_tmp[0]:
    lhs_tmp.pop(0)
    rhs_tmp.pop(0)
    first_diff += 1
  while len(lhs_tmp) > 0 and len(rhs_tmp) > 0 and lhs_tmp[-1] == rhs_tmp[-1]:
    lhs_tmp.pop()
    rhs_tmp.pop()

  return (first_diff, '\n'.join(lhs_tmp), '\n'.join(rhs_tmp))


def get_file_content_differences(lhs_folder, rhs_folder, different_files):
  """Helper method to print differences for files to console.

  Python's filecmp.dircmp(lhs, rhs) has a 'diff_files' method
  that lists different files, but doesn't show the actual differences.
  This method prints the differences, useful when debugging tests."""

  def content(f):
    with open(f, 'r') as handle:
      return handle.read()

  def get_diff(filename):
    lhs_file = os.path.join(lhs_folder, filename)
    lhs_content = content(lhs_file)
    rhs_file = os.path.join(rhs_folder, filename)
    rhs_content = content(rhs_file)

    pos, ldiff, rdiff = diff_long_strings(lhs_content, rhs_content)
    if ldiff is None and rdiff is None:
      return ""

    msg = """Files differ starting at line {0}:

Actual {1}:
---------------------
{2}
---------------------
Expected {3}:
---------------------
{4}
---------------------"""
    return msg.format(pos, lhs_file, ldiff, rhs_file, rdiff)

  return map(get_diff, different_files)


####################
# Tests
#
# Not including these tests in the main project test suite.

class Test_Diff_Long_Strings(unittest.TestCase):
  """Tests for the utility method."""

  def assertLongDiffEquals(
      self, lhs, rhs,
      expected_pos, expected_diff_lhs, expected_diff_rhs):
    actual = diff_long_strings(lhs, rhs)
    expected = (expected_pos, expected_diff_lhs, expected_diff_rhs)
    self.assertEqual(actual, expected)

  def test_simple_diff(self):
    lhs = """hello
there
human"""
    rhs = """hello
funny
human"""
    self.assertLongDiffEquals(lhs, rhs, 1, 'there', 'funny')

  def test_identical_strings(self):
    self.assertLongDiffEquals('a', 'a', -1, None, None)

  def test_completely_different_strings(self):
    lhs = """and
now
for"""
    rhs = """something
completely
different"""
    self.assertLongDiffEquals(lhs, rhs, 0, lhs, rhs)
    
  def test_identical_one_string_longer_than_the_other(self):
    lhs = """hello
there
human"""
    rhs = """hello
there"""
    self.assertLongDiffEquals(lhs, rhs, 2, 'human', '')
    
if __name__ == '__main__':
  unittest.main()

