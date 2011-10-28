#!/usr/bin/env python
#
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
# This is an sample tool which will render policy
# files into usable iptables tables, cisco access lists or
# juniper firewall filters.


__author__ = 'watson@google.com (Tony Watson)'

# system imports
import copy
import dircache
from optparse import OptionParser
import os
import stat
import logging

# compiler imports
from lib import naming
from lib import policy

# renderers
from lib import cisco
from lib import ciscoasa
from lib import iptables
from lib import speedway
from lib import juniper
from lib import silverpeak
from lib import demo

_parser = OptionParser()
_parser.add_option('-d', '--def', dest='definitions',
                   help='definitions directory', default='./def')
_parser.add_option('-o', dest='output_directory', help='output directory',
                   default='./filters')
_parser.add_option('', '--poldir', dest='policy_directory',
                   help='policy directory (incompatible with -p)',
                   default='./policies')
_parser.add_option('-p', '--pol', help='policy file (incompatible with poldir)',
                   dest='policy')
_parser.add_option('--debug', help='enable debug-level logging', dest='debug')
(FLAGS, args) = _parser.parse_args()


def load_and_render(base_dir, defs):
  rendered = 0
  for dirfile in dircache.listdir(base_dir):
    fname = os.path.join(base_dir, dirfile)
    #logging.debug('load_and_render working with fname %s', fname)
    if os.path.isdir(fname):
      rendered += load_and_render(fname, defs)
    elif fname.endswith('.pol'):
      #logging.debug('attempting to render_filters on fname %s', fname)
      rendered += render_filters(fname, policy.ParsePolicy(open(fname).read(),
                                                           defs))
  return rendered

def filter_name(source, suffix):
  source = source.lstrip('./')
  o_dir = '/'.join([FLAGS.output_directory] + source.split('/')[1:-1])
  fname = '%s%s' % (".".join(os.path.basename(source).split('.')[0:-1]),
                    suffix)
  return os.path.join(o_dir, fname)

def do_output_filter(filter_text, filter_file):
  if not os.path.isdir(os.path.dirname(filter_file)):
    os.mkdir(os.path.dirname(output_file))
  output = open(filter_file, 'w')
  if output:
    print 'writing %s' % filter_file
    output.write(filter_text)


def render_filters(source_file, policy):
  count = 0
  [(jcl, acl, asa, ipt, spd, spk, dem)] = [(False, False, False, False, False,
                                       False, False)]

  for header in policy.headers:
    if 'juniper' in header.platforms:
      jcl = copy.deepcopy(policy)
    if 'cisco' in header.platforms:
      acl = copy.deepcopy(policy)
    if 'ciscoasa' in header.platforms:
      asa = copy.deepcopy(policy)
    if 'iptables' in header.platforms:
      ipt = copy.deepcopy(policy)
    if 'speedway' in header.platforms:
      spd = copy.deepcopy(policy)
    if 'silverpeak' in header.platforms:
      spk = copy.deepcopy(policy)
    if 'demo' in header.platforms:
      dem = copy.deepcopy(policy)
  if jcl:
    fw = juniper.Juniper(jcl)
    do_output_filter(str(fw), filter_name(source_file, fw._SUFFIX))
    count += 1
  if acl:
    fw = cisco.Cisco(acl)
    do_output_filter(str(fw), filter_name(source_file, fw._SUFFIX))
    count += 1
  if asa:
    fw = ciscoasa.CiscoASA(asa)
    do_output_filter(str(fw), filter_name(source_file, fw._SUFFIX))
    count += 1
  if ipt:
    fw = iptables.Iptables(ipt)
    do_output_filter(str(fw), filter_name(source_file, fw._SUFFIX))
    count += 1
  if spd:
    fw = speedway.Speedway(spd)
    do_output_filter(str(fw), filter_name(source_file, fw._SUFFIX))
    count += 1
  if dem:
    fw = demo.Demo(dem)
    do_output_filter(str(fw), filter_name(source_file, fw._SUFFIX))
    count += 1
  if spk:
    spk_obj = silverpeak.Silverpeak(spk, '')
    do_output_filter(spk_obj.GenerateACLString(),
                     filter_name(source_file, spk_obj._SUFFIX))
    do_output_filter(spk_obj.GenerateConfString(),
                     filter_name(source_file, spk_obj._CONF_SUFFIX))
    count += 1

  return count

def main():
  if not FLAGS.definitions:
    _parser.error('no definitions supplied')
  defs = naming.Naming(FLAGS.definitions)
  if not defs:
    print 'problem loading definitions'
    return

  count = 0
  if FLAGS.policy_directory:
    count = load_and_render(FLAGS.policy_directory, defs)

  elif FLAGS.policy:
    count = render_filters(policy.ParsePolicy(FLAGS.policy).read(), defs)

  print '%d filters rendered' % count


if __name__ == '__main__':
  # some sanity checking
  if FLAGS.policy_directory and FLAGS.policy:
    raise ValueError('policy and policy_directory are mutually exclusive')
  if not (FLAGS.policy_directory or FLAGS.policy):
    raise ValueError('must provide policy or policy_directive')

  # enable debugging
  if FLAGS.debug:
    logging.basicConfig(level=logging.DEBUG)

  # run run run run run away
  main()
