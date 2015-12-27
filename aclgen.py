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
import datetime
from optparse import OptionParser
import os
import logging

# compiler imports
from lib import naming
from lib import policy

# renderers
from lib import arista
from lib import aruba
from lib import brocade
from lib import cisco
from lib import ciscoasa
from lib import ciscoxr
from lib import gce
from lib import iptables
from lib import ipset
from lib import speedway
from lib import juniper
from lib import junipersrx
from lib import packetfilter
from lib import demo
from lib import nsxv


# pylint: disable=bad-indentation
_parser = OptionParser()
_parser.add_option('-d', '--def', dest='definitions',
                   help='definitions directory', default='./def')
_parser.add_option('-o', dest='output_directory', help='output directory',
                   default='./filters')
_parser.add_option('', '--poldir', dest='policy_directory',
                   help='policy directory (incompatible with -p)',
                   default='./policies')
_parser.add_option('-p', '--pol',
                   help='policy file (incompatible with poldir)',
                   dest='policy')
_parser.add_option('--debug', help='enable debug-level logging', dest='debug')
_parser.add_option('-s', '--shade_checking', help='Enable shade checking',
                   action="store_true", dest="shade_check", default=False)
_parser.add_option('-e', '--exp_info', type='int', action='store',
                   dest='exp_info', default=2,
                   help='Weeks in advance to notify that a term will expire')

(FLAGS, args) = _parser.parse_args()


def load_and_render(base_dir, defs, shade_check, exp_info):
  rendered = 0
  for dirfile in dircache.listdir(base_dir):
    fname = os.path.join(base_dir, dirfile)
    #logging.debug('load_and_render working with fname %s', fname)
    if os.path.isdir(fname):
      rendered += load_and_render(fname, defs, shade_check, exp_info)
    elif fname.endswith('.pol'):
      #logging.debug('attempting to render_filters on fname %s', fname)
      rendered += render_filters(fname, defs, shade_check, exp_info)
  return rendered


def filter_name(source, suffix):
  source = source.lstrip('./')
  o_dir = '/'.join([FLAGS.output_directory] + source.split('/')[1:-1])
  fname = '%s%s' % (".".join(os.path.basename(source).split('.')[0:-1]),
                    suffix)
  return os.path.join(o_dir, fname)


def do_output_filter(filter_text, filter_file):
  if not os.path.isdir(os.path.dirname(filter_file)):
    os.makedirs(os.path.dirname(filter_file))
  output = open(filter_file, 'w')
  if output:
    filter_text = revision_tag_handler(filter_file, filter_text)
    print 'writing %s' % filter_file
    output.write(filter_text)


def revision_tag_handler(fname, text):
  # replace $Id:$ and $Date:$ tags with filename and date
  timestamp = datetime.datetime.now().strftime('%Y/%m/%d')
  new_text = []
  for line in text.split('\n'):
    if '$Id:$' in line:
      line = line.replace('$Id:$', '$Id: %s $' % fname)
    if '$Date:$' in line:
      line = line.replace('$Date:$', '$Date: %s $' % timestamp)
    new_text.append(line)
  return '\n'.join(new_text)


def memoize(fn):
    """Memoization decorator for functions taking one or more args."""

    class memodict(dict):

        def __init__(self, fn):
            self.fn = fn

        def __call__(self, *args):
            return self[args]

        def __missing__(self, key):
            ret = self[key] = self.fn(*key)
            return ret

    return memodict(fn)


@memoize
def get_policy_obj(source_file, definitions_obj, optimize, shade_check):
    if optimize:
        return policy.ParsePolicy(open(source_file).read(), definitions_obj,
                                  shade_check=shade_check)
    else:
        return policy.ParsePolicy(open(source_file).read(), definitions_obj,
                                  optimize=False)


def render_filters(source_file, definitions_obj, shade_check, exp_info):
  count = 0

  supported_targets = {'arista': {'optimized': True,
                                  'renderer': arista.Arista},
                       'aruba': {'optimized': True, 'renderer': aruba.Aruba},
                       'brocade': {'optimized': True,
                                   'renderer': brocade.Brocade},
                       'juniper': {'optimized': True,
                                   'renderer': juniper.Juniper},
                       'junipersrx': {'optimized': False,
                                      'renderer': junipersrx.JuniperSRX},
                       'cisco': {'optimized': True, 'renderer': cisco.Cisco},
                       'ciscoasa': {'optimized': True,
                                    'renderer': ciscoasa.CiscoASA},
                       'ciscoxr': {'optimized': True,
                                   'renderer': ciscoxr.CiscoXR},
                       'gce': {'optimized': True, 'renderer': gce.GCE},
                       'iptables': {'optimized': True,
                                    'renderer': iptables.Iptables},
                       'ipset': {'optimized': True, 'renderer': ipset.Ipset},
                       'packetfilter': {'optimized': True,
                                        'renderer': packetfilter.PacketFilter},
                       'speedway': {'optimized': True,
                                    'renderer': speedway.Speedway},
                       'srx': {'optimized': False,
                               'renderer': junipersrx.JuniperSRX},
                       'demo': {'optimized': True, 'renderer': demo.Demo},
                       'nsxv': {'optimized': True, 'renderer': nsxv.Nsxv}, }

  pol = get_policy_obj(source_file, definitions_obj, True, shade_check)

  for header in pol.headers:
    for target_platform in header.platforms:
      # If header specifies an unsupported platform target then skip.
      if not supported_targets.get(target_platform):
        continue
      # Do output filter as per the policy.
      pol = copy.deepcopy(
        get_policy_obj(source_file, definitions_obj,
                       supported_targets[target_platform]['optimized'],
                       shade_check)
                      )
      fw = supported_targets[target_platform]['renderer'](pol, exp_info)
      do_output_filter(str(fw), filter_name(source_file, fw._SUFFIX))
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
    count = load_and_render(FLAGS.policy_directory, defs, FLAGS.shade_check,
                            FLAGS.exp_info)

  elif FLAGS.policy:
    count = render_filters(FLAGS.policy, defs, FLAGS.shade_check,
                           FLAGS.exp_info)

  print '%d filters rendered' % count


if __name__ == '__main__':
  # Do some sanity checking.
  if FLAGS.policy_directory and FLAGS.policy:
    # When parsing a single file, ignore default path of policy_directory.
    FLAGS.policy_directory = False
  if not (FLAGS.policy_directory or FLAGS.policy):
    raise ValueError('must provide policy or policy_directive')

  # Set log level to DEBUG if debug option is specified.
  if FLAGS.debug:
    logging.basicConfig(level=logging.DEBUG)

  # Start main program.
  main()
