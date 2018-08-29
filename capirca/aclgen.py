# Copyright 2011 Google Inc. All Rights Reserved.
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


"""Renders policy source files into actual Access Control Lists."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import copy
import multiprocessing
import os
import sys

from absl import app
from absl import flags
from absl import logging
from capirca.lib import aclgenerator
from capirca.lib import arista
from capirca.lib import aruba
from capirca.lib import brocade
from capirca.lib import cisco
from capirca.lib import ciscoasa
from capirca.lib import ciscoxr
from capirca.lib import gce
from capirca.lib import ipset
from capirca.lib import iptables
from capirca.lib import juniper
from capirca.lib import junipersrx
from capirca.lib import naming
from capirca.lib import nftables
from capirca.lib import nsxv
from capirca.lib import packetfilter
from capirca.lib import paloaltofw
from capirca.lib import pcap
from capirca.lib import policy
from capirca.lib import speedway
from capirca.lib import srxlo
from capirca.lib import windows_advfirewall


FLAGS = flags.FLAGS
flags.DEFINE_string(
    'base_directory',
    './policies',
    'The base directory to look for acls; '
    'typically where you\'d find ./corp and ./prod')
flags.DEFINE_string(
    'definitions_directory',
    './def',
    'Directory where the definitions can be found.')
flags.DEFINE_string(
    'policy_file',
    None,
    'Individual policy file to generate.')
flags.DEFINE_string(
    'output_directory',
    './',
    'Directory to output the rendered acls.')
flags.DEFINE_boolean(
    'optimize',
    False,
    'Turn on optimization.',
    short_name='o')
flags.DEFINE_boolean(
    'recursive',
    True,
    'Descend recursively from the base directory rendering acls')
flags.DEFINE_boolean(
    'debug',
    False,
    'Debug messages')
flags.DEFINE_boolean(
    'verbose',
    False,
    'Verbose messages')
flags.DEFINE_list(
    'ignore_directories',
    'DEPRECATED, def',
    "Don't descend into directories that look like this string")
flags.DEFINE_integer(
    'max_renderers',
    10,
    'Max number of rendering processes to use.')
flags.DEFINE_boolean(
    'shade_check',
    False,
    'Raise an error when a term is completely shaded by a prior term.')
flags.DEFINE_integer(
    'exp_info',
    2,
    'Print a info message when a term is set to expire in that many weeks.')


class Error(Exception):
  """Base Error class."""


class P4WriteFileError(Error):
  """Error when there are issues p4 editing the destination."""


class ACLGeneratorError(Error):
  """Raised when an ACL generator has errors."""


class ACLParserError(Error):
  """Raised when the ACL parser fails."""


def SkipLines(text, skip_line_func=False):
  """Difflib has problems with the junkline func. fix it.

  Args:
    text: list of the first text to scan
    skip_line_func: function to use to check if we should skip a line

  Returns:
    ret_text: text(list) minus the skipped lines
  """
  if not skip_line_func:
    return text
  return [x for x in text if not skip_line_func(x)]


def RenderFile(input_file, output_directory, definitions,
               exp_info, write_files):
  """Render a single file.

  Args:
    input_file: the name of the input policy file.
    output_directory: the directory in which we place the rendered file.
    definitions: the definitions from naming.Naming().
    exp_info: print a info message when a term is set to expire
              in that many weeks.
    write_files: a list of file tuples, (output_file, acl_text), to write
  """
  logging.debug('rendering file: %s into %s', input_file,
                output_directory)
  pol = None
  jcl = False
  acl = False
  asacl = False
  aacl = False
  bacl = False
  eacl = False
  gcefw = False
  ips = False
  ipt = False
  spd = False
  nsx = False
  pcap_accept = False
  pcap_deny = False
  pf = False
  srx = False
  jsl = False
  nft = False
  win_afw = False
  xacl = False
  paloalto = False

  try:
    conf = open(input_file).read()
    logging.debug('opened and read %s', input_file)
  except IOError as e:
    logging.warn('bad file: \n%s', e)
    raise

  try:
    pol = policy.ParsePolicy(
        conf, definitions, optimize=FLAGS.optimize,
        base_dir=FLAGS.base_directory, shade_check=FLAGS.shade_check)
  except policy.ShadingError as e:
    logging.warn('shading errors for %s:\n%s', input_file, e)
    return
  except (policy.Error, naming.Error):
    raise ACLParserError('Error parsing policy file %s:\n%s%s' % (
        input_file, sys.exc_info()[0], sys.exc_info()[1]))

  platforms = set()
  for header in pol.headers:
    platforms.update(header.platforms)

  if 'juniper' in platforms:
    jcl = copy.deepcopy(pol)
  if 'cisco' in platforms:
    acl = copy.deepcopy(pol)
  if 'ciscoasa' in platforms:
    asacl = copy.deepcopy(pol)
  if 'brocade' in platforms:
    bacl = copy.deepcopy(pol)
  if 'arista' in platforms:
    eacl = copy.deepcopy(pol)
  if 'aruba' in platforms:
    aacl = copy.deepcopy(pol)
  if 'ipset' in platforms:
    ips = copy.deepcopy(pol)
  if 'iptables' in platforms:
    ipt = copy.deepcopy(pol)
  if 'nsxv' in platforms:
    nsx = copy.deepcopy(pol)
  if 'packetfilter' in platforms:
    pf = copy.deepcopy(pol)
  if 'pcap' in platforms:
    pcap_accept = copy.deepcopy(pol)
    pcap_deny = copy.deepcopy(pol)
  if 'speedway' in platforms:
    spd = copy.deepcopy(pol)
  if 'srx' in platforms:
    srx = copy.deepcopy(pol)
  if 'srxlo' in platforms:
    jsl = copy.deepcopy(pol)
  if 'windows_advfirewall' in platforms:
    win_afw = copy.deepcopy(pol)
  if 'ciscoxr' in platforms:
    xacl = copy.deepcopy(pol)
  if 'nftables' in platforms:
    nft = copy.deepcopy(pol)
  if 'gce' in platforms:
    gcefw = copy.deepcopy(pol)
  if 'paloalto' in platforms:
    paloalto = copy.deepcopy(pol)

  if not output_directory.endswith('/'):
    output_directory += '/'

  try:
    if jcl:
      acl_obj = juniper.Juniper(jcl, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if srx:
      acl_obj = junipersrx.JuniperSRX(srx, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if acl:
      acl_obj = cisco.Cisco(acl, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if asacl:
      acl_obj = ciscoasa.CiscoASA(asacl, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if aacl:
      acl_obj = aruba.Aruba(aacl, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if bacl:
      acl_obj = brocade.Brocade(bacl, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if eacl:
      acl_obj = arista.Arista(eacl, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if ips:
      acl_obj = ipset.Ipset(ips, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if ipt:
      acl_obj = iptables.Iptables(ipt, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if nsx:
      acl_obj = nsxv.Nsxv(nsx, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if spd:
      acl_obj = speedway.Speedway(spd, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if pcap_accept:
      acl_obj = pcap.PcapFilter(pcap_accept, exp_info)
      RenderACL(str(acl_obj), '-accept' + acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if pcap_deny:
      acl_obj = pcap.PcapFilter(pcap_deny, exp_info, invert=True)
      RenderACL(str(acl_obj), '-deny' + acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if pf:
      acl_obj = packetfilter.PacketFilter(pf, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if win_afw:
      acl_obj = windows_advfirewall.WindowsAdvFirewall(win_afw, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if jsl:
      acl_obj = srxlo.SRXlo(jsl, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if xacl:
      acl_obj = ciscoxr.CiscoXR(xacl, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if nft:
      acl_obj = nftables.Nftables(nft, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if gcefw:
      acl_obj = gce.GCE(gcefw, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
    if paloalto:
      acl_obj = paloaltofw.PaloAltoFW(paloalto, exp_info)
      RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory,
                input_file, write_files)
  # TODO(robankeny) add additional errors.
  except (juniper.Error, junipersrx.Error, cisco.Error, ipset.Error,
          iptables.Error, speedway.Error, pcap.Error,
          aclgenerator.Error, aruba.Error, nftables.Error, gce.Error) as e:
    raise ACLGeneratorError(
        'Error generating target ACL for %s:\n%s' % (input_file, e))


def RenderACL(acl_text, acl_suffix, output_directory, input_file, write_files,
              binary=False):
  """Write the ACL string out to file if appropriate.

  Args:
    acl_text: Rendered output of an ACL Generator.
    acl_suffix: File suffix to append to output filename.
    output_directory: The directory to write the output file.
    input_file: The name of the policy file that was used to render ACL.
    write_files: A list of file tuples, (output_file, acl_text), to write.
    binary: Boolean if the rendered ACL is in binary format.
  """
  output_file = os.path.join(output_directory, '%s%s') % (
      os.path.splitext(os.path.basename(input_file))[0], acl_suffix)

  if FilesUpdated(output_file, acl_text, binary):
    logging.info('file changed: %s', output_file)
    write_files.append((output_file, acl_text))
  else:
    logging.debug('file not changed: %s', output_file)


def FilesUpdated(file_name, new_text, binary):
  """Diff the rendered acl with what's already on disk.

  Args:
    file_name: Name of file on disk to check against.
    new_text: Text of newly generated ACL.
    binary: True if file is a binary format.
  Returns:
    Boolean if config does not equal new text.
  """
  try:
    if binary:
      conf = open(file_name, 'rb').read()
    else:
      conf = open(file_name).read()
  except IOError:
    return True
  if not binary:
    p4_id = '$I d:'.replace(' ', '')
    p4_date = '$Da te:'.replace(' ', '')
    p4_revision = '$Rev ision:'.replace(' ', '')

    p4_tags = lambda x: p4_id in x or p4_date in x or p4_revision in x

    conf = SkipLines(conf.split('\n'), skip_line_func=p4_tags)
    new_text = SkipLines(new_text.split('\n'), skip_line_func=p4_tags)

  return conf != new_text


def DescendRecursively(input_dirname, output_dirname, definitions, depth=1):
  """Recursively descend from input_dirname looking for policy files to render.

  Args:
    input_dirname: the base directory.
    output_dirname: where to place the rendered files.
    definitions: naming.Naming object.
    depth: integer, for outputting '---> rendering prod/corp-backbone.jcl'.

  Returns:
    the files that were found
  """
  # p4 complains if you try to edit a file like ./corp//corp-isp.jcl
  input_dirname = input_dirname.rstrip('/')
  output_dirname = output_dirname.rstrip('/')

  files = []
  # calling all directories
  for curdir in [x for x in os.listdir(input_dirname) if
                 os.path.isdir(input_dirname + '/' + x)]:
    # be on the lookout for a policy directory
    if curdir == 'pol':
      for input_file in [x for x in os.listdir(input_dirname + '/pol')
                         if x.endswith('.pol')]:
        files.append({'in_file': os.path.join(input_dirname, 'pol', input_file),
                      'out_dir': output_dirname,
                      'defs': definitions})
    else:
      # so we don't have a policy directory, we should check if this new
      # directory has a policy directory
      if curdir in FLAGS.ignore_directories:
        continue
      logging.warn('-' * (2 * depth) + '> %s' % (
          input_dirname + '/' + curdir))
      files_found = DescendRecursively(input_dirname + '/' + curdir,
                                       output_dirname + '/' + curdir,
                                       definitions, depth + 1)
      logging.warn('-' * (2 * depth) + '> %s (%d pol files found)' % (
          input_dirname + '/' + curdir, len(files_found)))
      files.extend(files_found)

  return files


def WriteFiles(write_files):
  """Writes files to disk.

  Args:
    write_files: List of file names and strings.
  """
  if write_files:
    logging.info('writing %d files to disk...', len(write_files))
  else:
    logging.info('no files changed, not writing to disk')
  for output_file, file_string in write_files:
    _WriteFile(output_file, file_string)


def _WriteFile(output_file, file_string):
  try:
    with open(output_file, 'w') as output:
      logging.info('writing file: %s', output_file)
      output.write(file_string)
  except IOError:
    logging.warn('error while writing file: %s', output_file)
    raise


def main(unused_argv):
  if FLAGS.verbose:
    logging.basicConfig(level=logging.INFO)
  if FLAGS.debug:
    logging.basicConfig(level=logging.DEBUG)
  logging.debug('binary: %s\noptimize: %d\nbase_directory: %s\n'
                'policy_file: %s\nrendered_acl_directory: %s',
                str(sys.argv[0]),
                int(FLAGS.optimize),
                str(FLAGS.base_directory),
                str(FLAGS.policy_file),
                str(FLAGS.output_directory))

  definitions = None
  try:
    definitions = naming.Naming(FLAGS.definitions_directory)
  except naming.NoDefinitionsError:
    err_msg = 'bad definitions directory: %s' % FLAGS.definitions_directory
    logging.fatal(err_msg)

  # thead-safe list for storing files to write
  manager = multiprocessing.Manager()
  write_files = manager.list()

  with_errors = False
  if FLAGS.policy_file:
    # render just one file
    logging.info('rendering one file')
    RenderFile(FLAGS.policy_file, FLAGS.output_directory, definitions,
               FLAGS.exp_info, write_files)
  else:
    # render all files in parallel
    logging.info('finding policies...')
    pols = []
    pols.extend(DescendRecursively(FLAGS.base_directory, FLAGS.output_directory,
                                   definitions))

    pool = multiprocessing.Pool(processes=FLAGS.max_renderers)
    results = []
    for x in pols:
      results.append(pool.apply_async(RenderFile,
                                      args=(x.get('in_file'),
                                            x.get('out_dir'),
                                            definitions,
                                            FLAGS.exp_info,
                                            write_files)))
    pool.close()
    pool.join()

    for result in results:
      try:
        result.get()
      except (ACLParserError, ACLGeneratorError) as e:
        with_errors = True
        logging.warn('\n\nerror encountered in rendering process:\n%s\n\n', e)

  # actually write files to disk
  WriteFiles(write_files)

  if with_errors:
    logging.warn('done, with errors.')
    sys.exit(1)
  else:
    logging.info('done.')


def entry_point():
  app.run(main)

if __name__ == '__main__':
  entry_point()
