# Copyright 2011 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Simply util to grep through network definitions.
# Examples:
#   To find out which tokens contain "10.4.3.1" use
#   $ cgrep.py -i 10.4.3.1
#
#   To find out if token 'FOO' includes ip "1.2.3.4" use
#   $ cgrep.py -t FOO -i 1.2.3.4
#
#   To find the difference and union of tokens 'FOO' and 'BAR' use
#   $ cgrep.py -c FOO BAR
#
__author__ = "watson@google.com (Tony Watson)"

import sys
sys.path.append('../')
from lib import naming
from lib import nacaddr
from optparse import OptionParser

def main(argv):
  parser = OptionParser()

  parser.add_option("-d", "--def", dest="defs", action="store",
                    help="Network Definitions directory location",
                    default="../def")
  parser.add_option("-i", "--ip", dest="ip", action="store",
                    help="Return list of defintions containing this IP.  "
                         "Multiple IPs permitted.")

  parser.add_option("-t", "--token", dest="token", action="store",
                    help="See if an IP is contained within this token."
                         "Must be used in conjunction with --ip [addr].")

  parser.add_option("-c", "--cmp", dest="cmp", action="store_true",
                    help="Compare two network definition tokens")

  (options, args) = parser.parse_args()

  db = naming.Naming(options.defs)

  if options.ip is not None and options.token is None:
    for arg in sys.argv[2:]:
      print "%s: " % arg
      rval = db.GetIpParents(arg)
      print rval

  if options.token is not None and options.ip is None:
    print "You must specify and IP Address with --ip [addr] to check."
    sys.exit(0)

  if options.token is not None and options.ip is not None:
    token = options.token
    ip = options.ip
    rval = db.GetIpParents(ip)
    if token in rval:
      print '%s is in %s' % (ip, token)
    else:
      print '%s is not in %s' % (ip, token)

  if options.cmp is not None:
    t1 = argv[2]
    t2 = argv[3]
    d1 = db.GetNet(t1)
    d2 = db.GetNet(t2)
    union = list(set(d1 + d2))
    print 'Union of %s and %s:\n %s\n' % (t1, t2, union)
    print 'Diff of %s and %s:' % (t1, t2)
    for el in set(d1 + d2):
      el = nacaddr.IP(el)
      if el in d1 and el in d2:
        print '  %s' % el
      elif el in d1:
          print '+ %s' % el
      elif el in d2:
          print '- %s' % el

if __name__ == '__main__':
  main(sys.argv)
