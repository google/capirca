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
from lib import policyparser

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


class AclGen(object):
  """ACL generation object.

  Given inputs, generates ACLs to output stream or filesystem.
  """

  def __init__(self,
               policy_directory,
               definitions_directory,
               output_directory,
               shade_check = False,
               expiry_info = 2):
    """Constructor.

    Args:
      policy_directory: string, path to the policies
      definitions_directory: string, path to the definitions
      output_directory: string, base directory for generated ACLs
      shade_check: True/False, whether or not to do a shade check
      expiry_info: int, expiry weeks.
    """

    self.policy_directory = policy_directory
    self.definitions_directory = definitions_directory
    self.output_directory = output_directory
    self.shade_check = shade_check
    self.expiry_info = expiry_info

    # A naming.Naming object created with self._create_defs()
    self.__memoized_defs = None

  def _create_defs(self):
    """Creates naming.Naming object using the contents of the supplied directory.

    The created defs object is memoized so that the public API of this module
    can be restricted to strings and ints, versus domain objects.  This promotes
    use of this module for other clients."""

    if self.__memoized_defs is not None:
      return self.__memoized_defs

    if not os.path.exists(self.definitions_directory):
      msg = 'missing defs directory {0}'.format(self.definitions_directory)
      raise ValueError(msg)
    self.__memoized_defs = naming.Naming(self.definitions_directory)
    if not self.__memoized_defs:
      raise ValueError('problem loading definitions')

    return self.__memoized_defs

  def load_and_render(self):
    return self._do_load_and_render(self.policy_directory, self.policy_directory)

  def _do_load_and_render(self, base_dir, curr_dir):
    rendered = 0
    for dirfile in dircache.listdir(curr_dir):
      fname = os.path.join(curr_dir, dirfile)
      #logging.debug('load_and_render working with fname %s', fname)
      if os.path.isdir(fname):
        rendered += self._do_load_and_render(base_dir, fname)
      elif fname.endswith('.pol'):
        #logging.debug('attempting to render_filters on fname %s', fname)
        rendered += self._do_render_filters(base_dir, fname)
    return rendered

  @staticmethod
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


  def do_output_filter(self, filter_text, filter_file):
    if not os.path.isdir(os.path.dirname(filter_file)):
      os.makedirs(os.path.dirname(filter_file))
    output = open(filter_file, 'w')
    if output:
      print 'writing %s' % filter_file
      output.write(filter_text)


  def get_policy_obj(self, source_file, optimize):
    """Memoized call to parse policy by file name.

    Returns parsed policy object.
    """
    definitions_obj = self._create_defs()
    return policyparser.CacheParseFile(source_file, definitions_obj, optimize, shade_check=self.shade_check)


  def render_filters(self, source_file):
    base_dir = os.path.dirname(os.path.abspath(source_file))
    return self._do_render_filters(base_dir, source_file)


  def create_filter_for_platform(self, platform, source_file):
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
      raise policy.PolicyTargetPlatformInvalidError('unsupported platform {0}'.format(platform))

    optimized = this_platform['optimized']
    pol = copy.deepcopy(self.get_policy_obj(source_file, optimized))

    if platform not in pol.platforms:
      msg = 'platform {0} not in policy targets {1}'.format(platform, pol.platforms)
      raise policy.PolicyTargetPlatformInvalidError(msg)

    renderer = this_platform['renderer']
    return renderer(pol, self.expiry_info)


  def _do_render_filters(self, base_dir, source_file):
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
    pol = self.get_policy_obj(source_file, True)

    count = 0

    for header in pol.headers:
      for platform in header.platforms:

        fw = self.create_filter_for_platform(platform, source_file)

        filter_file = AclGen.filter_name(base_dir, source_file, fw._SUFFIX, self.output_directory)
        filter_text = str(fw)
        self.do_output_filter(filter_text, filter_file)
        count += 1

    return count


########
# Backwards compatibility wrappers of AclGen methods.

def load_and_render(base_dir, defs_directory, shade_check, exp_info, output_dir):
  aclgen = AclGen(policy_directory = base_dir,
                  definitions_directory = defs_directory,
                  output_directory = output_dir,
                  shade_check = shade_check,
                  expiry_info = exp_info)
  return aclgen.load_and_render()

def filter_name(base_dir, source, suffix, output_directory):
  return AclGen.filter_name(base_dir, source, suffix, output_directory)

def render_filters(source_file, defs_directory, shade_check, exp_info, output_dir):
  p, f = os.path.split(source_file)
  aclgen = AclGen(policy_directory = p,
                  definitions_directory = defs_directory,
                  output_directory = output_dir,
                  shade_check = shade_check,
                  expiry_info = exp_info)
  return aclgen.render_filters(source_file)

def create_filter_for_platform(platform, source_file, defs_directory, shade_check, exp_info):
  p, f = os.path.split(source_file)
  aclgen = AclGen(policy_directory = p,
                  definitions_directory = defs_directory,
                  output_directory = None,
                  shade_check = shade_check,
                  expiry_info = exp_info)
  return aclgen.create_filter_for_platform(platform, source_file)


########
# Main

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


def main(args):
  FLAGS = parse_args(args)

  gen = AclGen(policy_directory = FLAGS.policy_directory,
               definitions_directory = FLAGS.definitions,
               output_directory = FLAGS.output_directory,
               shade_check = FLAGS.shade_check,
               expiry_info = FLAGS.exp_info)

  count = 0
  if FLAGS.policy_directory:
    count = gen.load_and_render()

  elif FLAGS.policy:
    count = gen.render_filters(FLAGS.policy)

  print '%d filters rendered' % count


if __name__ == '__main__':

  # Start main program.
  # Pass in command-line args (except for first entry, which is the script name).
  # Note that OptionParser slices sys.argv in this way as well,
  # ref https://docs.python.org/2/library/optparse.html.
  main(sys.argv[1:])
