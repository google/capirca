#!/usr/bin/env python
#
# Copyright 2009 Google Inc.
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
# This is an sample tool which will render policy
# files into usable iptables tables, cisco access lists or
# juniper firewall filters.

# system imports
import dircache
from optparse import OptionParser
import os
import stat

# compiler imports
from lib import naming
from lib import policy

# renderer imports
from lib import cisco
from lib import iptables
from lib import juniper

# TODO(pmoody): get rid of this global variable.
output_policy_dict = {}

parser = OptionParser()
parser.add_option('-d', '--def',
                  dest='definitions',
                  help='defintions directory',
                  default='./def')
parser.add_option('-o', '--output_directory',
                  dest='output_directory',
                  help='output directory',
                  default='./filters')
parser.add_option('-p', '--pol',
                  dest='policy',
                  help='policy file')
parser.add_option('', '--poldir',
                  dest='policy_directory',
                  help='policy directory',
                  default='./policies')
(FLAGS, args) = parser.parse_args()


def render_policy(pol, input_file, output_directory):
  """Store the string representation of the rendered policy."""
  input_file = input_file.lstrip('./')
  output_dir = '/'.join([output_directory] + input_file.split('/')[1:-1])
  fname = '%s%s' % (os.path.basename(input_file).split('.')[0], pol._SUFFIX)
  output_file = os.path.join(output_dir, fname)

  if output_file in output_policy_dict:
    output_policy_dict[output_file] += str(pol)
  else:
    output_policy_dict[output_file] = str(pol)

def output_policies():
  """Actually write the policies to disk overwriting existing files..

    If the output directory doesn't exist, create it.
  """
  for output_file in output_policy_dict:
    if not os.path.isdir(os.path.dirname(output_file)):
      os.mkdir(os.path.dirname(output_file))
    output = open(output_file, 'w')
    if output:
      print 'writing %s' % output_file
      output.write(output_policy_dict[output_file])

def load_policies(base_dir):
  """Recurssively load the polices in a given directory."""
  policies = []
  for dirfile in dircache.listdir(base_dir):
    fname = os.path.join(base_dir, dirfile)
    if os.path.isdir(fname):
      policies.extend(load_policies(fname))
    elif fname.endswith('.pol'):
      policies.append(fname)
  return policies

def parse_policies(policies, defs):
  """Parse and store the rendered policies."""
  jcl = False
  acl = False
  ipt = False
  for pol in policies:
    p = policy.ParsePolicy(open(pol).read(), defs)
    for header in p.headers:
      if 'juniper' in header.platforms:
        jcl = True
      if 'cisco' in header.platforms:
        acl = True
      if 'iptables' in header.platforms:
        ipt = True

    if jcl:
      render_policy(juniper.Juniper(p), pol, FLAGS.output_directory)
    if acl:
      render_policy(cisco.Cisco(p), pol, FLAGS.output_directory)
    if ipt:
      render_policy(iptables.Iptables(p), pol, FLAGS.output_directory)

    
def main():
  """the main entry point."""
  # first, load our naming
  if not FLAGS.definitions:
    parser.error('no definitions supplied')
  defs = naming.Naming(FLAGS.definitions)
  if not defs:
    print 'problem loading definitions'
    return

  policies_to_render = []
  if FLAGS.policy_directory:
    if FLAGS.policy and FLAGS.policy_directory != './policies':
      raise ValueError('policy and policy_directory are mutually exclusive')
    policies_to_render = load_policies(FLAGS.policy_directory)
  elif FLAGS.policy:
    policies_to_render.append(FLAGS.policy)

  parse_policies(policies_to_render, defs)
  output_policies()

if __name__ == '__main__':
  main()

