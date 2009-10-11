#!/usr/bin/python
#
# Copyright 2009 Google Inc.
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
#

"""Generate output from policy files and naming definitions."""

__author__ = 'watson@google.com (Tony Watson)'

import sys
import getopt
import naming
import policy
import cisco
import juniper
import iptables

#
# Arguments:
# -s [path] : policy source directory
# -d [path] : output destination directory
# -n [path] : naming definitions directory
# -o        : disable optimizer
#

def usage():
  print '%s' % sys.argv[0]
  print 'Optional Arguments:'
  print '-s [path]: policy source directory'
  print '-d [path]: output destination directory'
  print '-n [path]: naming definitions directory'
  print '-o       : disable optimizations'
  print '-h       : help, display this message'

def main(_):
  try:
    opts, args = getopt.getopt(sys.argv[1:], 's:d:n:oh')
  except getopt.GetoptError, err:
    print str(err)
    usage()
    sys.exit(2)

  optimize = 'True'
  polsrc = '../policy'
  output = '../output'
  defs = '../def'

  for o, a in opts:
    if o == '-h':
      usage()
      sys.exit(0)
    if o == '-o':
      optimize = 'False'
    if o == '-s':
      polsrc = a
    if o == '-d':
      output = a
    if o == '-n':
      defs = a

  print 'Pol: %s ' % polsrc
  print 'Out: %s ' % output
  print 'Def: %s ' % defs
  print 'Opt: %s ' % optimize


if __name__ == "__main__":
  main()
