#!/usr/bin/python

# Splits policy.py into two separate files at tokens in policy.py:
# - policy.py (model objects)
# - policyparser.py (parser and model loader) 

# Read in each line of the file.  output to the files
# policy.py and policyparser.py.
# if line is "#oo", lines following should go to policy.py
# if "#pp", should go to policyparser.py
# if "#bb", should go to both

# After running this, fix the single compilation error in aclgen.py
# and then run the characterization tests: if all pass, all is good.


def get_line(lin):
  # Some lines have #REM in front of them - these lines should be
  # kept in the file post-split, and the comment removed.
  s = lin
  COMMENT = "#REM "
  if lin[0:len(COMMENT)] == COMMENT:
    s = lin[len(COMMENT):]
  return s + '\n'


with open('policy.py', 'r') as f:
  src = f.read()

curr_target = '#bb'

with open('policy.py', 'w') as policy_py:
  with open('policyparser.py', 'w') as policyparser_py:
    
    for lin in src.split('\n'):
      if lin in ('#pp', '#rr', '#bb'):
        curr_target = lin
      else:
        lin = get_line(lin)
        print 'print to target {0}'.format(curr_target)
        if curr_target == '#pp':
          policy_py.write(lin)
        elif curr_target == '#rr':
          policyparser_py.write(lin)
        else:
          policy_py.write(lin)
          policyparser_py.write(lin)
