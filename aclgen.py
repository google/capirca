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
import sys

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

def parse_args(command_line_args):
  """Populate flags from the command-line arguments."""
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

  flags, unused_args = _parser.parse_args(command_line_args)

  if flags.debug:
    logging.basicConfig(level=logging.DEBUG)

  # Checks:
  if flags.policy_directory and flags.policy:
    # When parsing a single file, ignore default path of policy_directory.
    flags.policy_directory = False
  if not (flags.policy_directory or flags.policy):
    raise ValueError('must provide policy or policy_directive')
  if not flags.definitions:
    raise ValueError('no definitions supplied')

  return flags


def load_and_render(base_dir, defs, shade_check, exp_info, output_dir):
  return _do_load_and_render(base_dir, base_dir, defs, shade_check, exp_info, output_dir)

def _do_load_and_render(base_dir, curr_dir, defs, shade_check, exp_info, output_dir):
  rendered = 0
  for dirfile in dircache.listdir(curr_dir):
    fname = os.path.join(curr_dir, dirfile)
    #logging.debug('load_and_render working with fname %s', fname)
    if os.path.isdir(fname):
      rendered += _do_load_and_render(base_dir, fname, defs, shade_check, exp_info, output_dir)
    elif fname.endswith('.pol'):
      #logging.debug('attempting to render_filters on fname %s', fname)
      rendered += _do_render_filters(base_dir, fname, defs, shade_check, exp_info, output_dir)
  return rendered


def filter_name(base_dir, source, suffix, output_directory):
  """Create an output filename for the filter.

  The output filename is such that the directory structure
  of `output_directory` matches the directory structure of
  the `source` relative to the `base_dir`.  For example,
  with the following:

  - `base_dir` = 'hi/there/'
  - source = 'hi/there/SOME/file.txt'
  - suffix = '.suff'
  - output_directory 'newlocation'

  the returned directory would be

    'newlocation/SOME/file.suff.'
  """
  abs_source = os.path.abspath(source)
  abs_base = os.path.abspath(base_dir) + '/'
  if not abs_source.startswith(abs_base):
    raise ValueError('{0} is not in base dir {1}'.format(abs_source, abs_base))
  rel_from_base = abs_source.replace(abs_base, '')
  reldir, fname = os.path.split(rel_from_base)
  fname = '%s%s' % ('.'.join(fname.split('.')[0:-1]), suffix)
  return os.path.join(output_directory, reldir, fname)


def do_output_filter(filter_text, filter_file):
  if not os.path.isdir(os.path.dirname(filter_file)):
    os.makedirs(os.path.dirname(filter_file))
  output = open(filter_file, 'w')
  if output:
    print 'writing %s' % filter_file
    output.write(filter_text)


def get_policy_obj(source_file, definitions_obj, optimize, shade_check):
  """Memoized call to parse policy by file name.

  Returns parsed policy object.
  """

  return policy.CacheParseFile(source_file, definitions_obj, optimize,
                               shade_check=shade_check)


def render_filters(source_file, definitions_obj, shade_check, exp_info, output_dir):
  base_dir = os.path.dirname(os.path.abspath(source_file))
  return _do_render_filters(base_dir, source_file, definitions_obj, shade_check, exp_info, output_dir)


def create_filter_for_platform(platform, source_file, definitions_obj, shade_check, exp_info):
  """Render platform specific filter for a policy.

  Use the platform's renderer to render its filter, using its
  own separate copy of the policy object and with optional, target
  specific attributes such as optimization."""

  supported_targets = {
    'arista': {'optimized': True, 'renderer': arista.Arista},
    'aruba': {'optimized': True, 'renderer': aruba.Aruba},
    'brocade': {'optimized': True, 'renderer': brocade.Brocade},
    'cisco': {'optimized': True, 'renderer': cisco.Cisco},
    'ciscoasa': {'optimized': True, 'renderer': ciscoasa.CiscoASA},
    'ciscoxr': {'optimized': True, 'renderer': ciscoxr.CiscoXR},
    'demo': {'optimized': True, 'renderer': demo.Demo},
    'gce': {'optimized': True, 'renderer': gce.GCE},
    'ipset': {'optimized': True, 'renderer': ipset.Ipset},
    'iptables': {'optimized': True, 'renderer': iptables.Iptables},
    'juniper': {'optimized': True, 'renderer': juniper.Juniper},
    'junipersrx': {'optimized': False, 'renderer': junipersrx.JuniperSRX},
    'nsxv': {'optimized': True, 'renderer': nsxv.Nsxv},
    'packetfilter': {'optimized': True, 'renderer': packetfilter.PacketFilter},
    'speedway': {'optimized': True, 'renderer': speedway.Speedway},
    'srx': {'optimized': False, 'renderer': junipersrx.JuniperSRX},
  }

  this_platform = supported_targets.get(platform)
  if this_platform is None:
    raise ValueError('unsupported platform {0}'.format(platform))

  optimized = this_platform['optimized']
  pol = copy.deepcopy(get_policy_obj(source_file, definitions_obj,
                                     optimized, shade_check))
  renderer = this_platform['renderer']
  return renderer(pol, exp_info)


def _do_render_filters(base_dir, source_file, definitions_obj, shade_check, exp_info, output_dir):
  """Render platform specfic filters for each target platform.

  For each target specified in each header of the policy, use that
  platforms renderer to render its platform specific filter, using its
  own separate copy of the policy object and with optional, target
  specific attributes such as optimization and expiration attributes.

  `base_dir` is the base dir of the policy file `source_file`.  It is
  required here to calculate relative path from the `base_dir` to the
  `source_file`.  This relative path is appended to the `output_dir`
  so that files are appropriately placed when written.

  Output the rendered filters for each target platform.
  Return the rendered filter count.
  """

  # Get a policy object from cache to determine headers within the policy file.
  pol = get_policy_obj(source_file, definitions_obj, True, shade_check)

  count = 0

  for header in pol.headers:
    for platform in header.platforms:

      fw = create_filter_for_platform(platform, source_file, definitions_obj, shade_check, exp_info)

      filter_file = filter_name(base_dir, source_file, fw._SUFFIX, output_dir)
      filter_text = str(fw)
      do_output_filter(filter_text, filter_file)
      count += 1

  return count


def main(args):
  FLAGS = parse_args(args)
  defs = naming.Naming(FLAGS.definitions)
  if not defs:
    print 'problem loading definitions'
    return

  count = 0
  if FLAGS.policy_directory:
    count = load_and_render(FLAGS.policy_directory, defs, FLAGS.shade_check,
                            FLAGS.exp_info, FLAGS.output_directory)

  elif FLAGS.policy:
    count = render_filters(FLAGS.policy, defs, FLAGS.shade_check,
                           FLAGS.exp_info, FLAGS.output_directory)

  print '%d filters rendered' % count


if __name__ == '__main__':

  # Start main program.
  # Pass in command-line args (except for first entry, which is the script name).
  # Note that OptionParser slices sys.argv in this way as well,
  # ref https://docs.python.org/2/library/optparse.html.
  main(sys.argv[1:])
