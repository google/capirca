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

import copy
import multiprocessing
import pathlib
import sys
from typing import Iterator, List, Tuple, cast

from absl import app
from absl import flags
from absl import logging
from capirca.lib import aclgenerator
from capirca.lib import arista
from capirca.lib import arista_tp
from capirca.lib import aruba
from capirca.lib import brocade
from capirca.lib import cisco
from capirca.lib import ciscoasa
from capirca.lib import cisconx
from capirca.lib import ciscoxr
from capirca.lib import cloudarmor
from capirca.lib import gce
from capirca.lib import gce_vpc_tf
from capirca.lib import gcp_hf
from capirca.lib import ipset
from capirca.lib import iptables
from capirca.lib import juniper
from capirca.lib import juniperevo
from capirca.lib import junipermsmpc
from capirca.lib import junipersrx
from capirca.lib import k8s
from capirca.lib import naming
from capirca.lib import nftables
from capirca.lib import nsxv
from capirca.lib import openconfig
from capirca.lib import packetfilter
from capirca.lib import paloaltofw
from capirca.lib import pcap
from capirca.lib import policy
from capirca.lib import sonic
from capirca.lib import speedway
from capirca.lib import srxlo
from capirca.lib import windows_advfirewall
from capirca.utils import config

FLAGS = flags.FLAGS
WriteList = List[Tuple[pathlib.Path, str]]


def SetupFlags():
  """Read in configuration from CLI flags."""
  flags.DEFINE_string(
      'base_directory', None, 'The base directory to look for acls; '
      'typically where you\'d find ./corp and ./prod\n(default: \'%s\')' %
      config.defaults['base_directory'])
  flags.DEFINE_string(
      'definitions_directory', None,
      'Directory where the definitions can be found.\n(default: \'%s\')' %
      config.defaults['definitions_directory'])
  flags.DEFINE_string('policy_file', None,
                      'Individual policy file to generate.')
  flags.DEFINE_string(
      'output_directory', None,
      'Directory to output the rendered acls.\n(default: \'%s\')' %
      config.defaults['output_directory'])
  flags.DEFINE_boolean(
      'optimize',
      None,
      'Turn on optimization.\n(default: \'%s\')' % config.defaults['optimize'],
      short_name='o')
  flags.DEFINE_boolean(
      'recursive', None,
      'Descend recursively from the base directory rendering acls\n(default: \'%s\')'
      % str(config.defaults['recursive']).lower())
  flags.DEFINE_boolean(
      'debug', None, 'Debug messages\n(default: \'%s\')' %
      str(config.defaults['debug']).lower())
  flags.DEFINE_boolean(
      'verbose', None, 'Verbose messages\n(default: \'%s\')' %
      str(config.defaults['verbose']).lower())
  flags.DEFINE_list(
      'ignore_directories', None,
      'Don\'t descend into directories that look like this string\n(default: \'%s\')'
      % ','.join(config.defaults['ignore_directories']))
  flags.DEFINE_integer(
      'max_renderers', None,
      'Max number of rendering processes to use.\n(default: \'%s\')' %
      config.defaults['max_renderers'])
  flags.DEFINE_boolean(
      'shade_check', None,
      'Raise an error when a term is completely shaded by a prior term.\n(default: \'%s\')'
      % str(config.defaults['shade_check']).lower())
  flags.DEFINE_integer(
      'exp_info', None,
      'Print a info message when a term is set to expire in that many weeks.\n(default: \'%s\')'
      % str(config.defaults['exp_info']))
  flags.DEFINE_multi_string(
      'config_file', None,
      'A yaml file with the configuration options for capirca')


class Error(Exception):
  """Base Error class."""


class P4WriteFileError(Error):
  """Error when there are issues p4 editing the destination."""


class ACLGeneratorError(Error):
  """Raised when an ACL generator has errors."""


class ACLParserError(Error):
  """Raised when the ACL parser fails."""


def SkipLines(text, skip_line_func=False):
  """Apply skip_line_func to the given text.

  Args:
    text: list of the first text to scan
    skip_line_func: function to use to check if we should skip a line

  Returns:
    ret_text: text(list) minus the skipped lines
  """
  if not skip_line_func:
    return text
  return [x for x in text if not skip_line_func(x)]


def RenderFile(base_directory: str, input_file: pathlib.Path,
               output_directory: pathlib.Path, definitions: naming.Naming,
               exp_info: int, optimize: bool, shade_check: bool,
               write_files: WriteList):
  """Render a single file.

  Args:
    base_directory: The base directory to look for acls.
    input_file: the name of the input policy file.
    output_directory: the directory in which we place the rendered file.
    definitions: the definitions from naming.Naming().
    exp_info: print a info message when a term is set to expire in that many
      weeks.
    optimize: a boolean indicating if we should turn on optimization or not.
    shade_check: should we raise an error if a term is completely shaded
    write_files: a list of file tuples, (output_file, acl_text), to write
  """
  output_relative = input_file.relative_to(base_directory).parent.parent
  output_directory = output_directory / output_relative

  logging.debug('rendering file: %s into %s', input_file, output_directory)

  pol = None
  jcl = False
  evojcl = False
  acl = False
  atp = False
  asacl = False
  aacl = False
  bacl = False
  eacl = False
  gca = False
  gcefw = False
  gcphf = False
  ips = False
  ipt = False
  msmpc = False
  spd = False
  nsx = False
  oc = False
  pcap_accept = False
  pcap_deny = False
  pf = False
  srx = False
  jsl = False
  nft = False
  win_afw = False
  nxacl = False
  xacl = False
  paloalto = False
  sonic_pol = False
  k8s_pol = False
  gce_vpc_tf_pol = False

  try:
    with open(input_file) as f:
      conf = f.read()
      logging.debug('opened and read %s', input_file)
  except IOError as e:
    logging.warning('bad file: \n%s', e)
    raise

  try:
    pol = policy.ParsePolicy(
        conf,
        definitions,
        optimize=optimize,
        base_dir=base_directory,
        shade_check=shade_check)
  except policy.ShadingError as e:
    logging.warning('shading errors for %s:\n%s', input_file, e)
    return
  except (policy.Error, naming.Error):
    raise ACLParserError('Error parsing policy file %s:\n%s%s' %
                         (input_file, sys.exc_info()[0], sys.exc_info()[1]))

  platforms = set()
  for header in pol.headers:
    platforms.update(header.platforms)

  if 'juniper' in platforms:
    jcl = copy.deepcopy(pol)
  if 'juniperevo' in platforms:
    evojcl = copy.deepcopy(pol)
  if 'cisco' in platforms:
    acl = copy.deepcopy(pol)
  if 'ciscoasa' in platforms:
    asacl = copy.deepcopy(pol)
  if 'brocade' in platforms:
    bacl = copy.deepcopy(pol)
  if 'arista' in platforms:
    eacl = copy.deepcopy(pol)
  if 'arista_tp' in platforms:
    atp = copy.deepcopy(pol)
  if 'aruba' in platforms:
    aacl = copy.deepcopy(pol)
  if 'ipset' in platforms:
    ips = copy.deepcopy(pol)
  if 'iptables' in platforms:
    ipt = copy.deepcopy(pol)
  if 'msmpc' in platforms:
    msmpc = copy.deepcopy(pol)
  if 'nsxv' in platforms:
    nsx = copy.deepcopy(pol)
  if 'openconfig' in platforms:
    oc = copy.deepcopy(pol)
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
  if 'cisconx' in platforms:
    nxacl = copy.deepcopy(pol)
  if 'ciscoxr' in platforms:
    xacl = copy.deepcopy(pol)
  if 'nftables' in platforms:
    nft = copy.deepcopy(pol)
  if 'gce' in platforms:
    gcefw = copy.deepcopy(pol)
  if 'gce_vpc_tf' in platforms:
    gce_vpc_tf_pol = copy.deepcopy(pol)
  if 'gcp_hf' in platforms:
    gcphf = copy.deepcopy(pol)
  if 'paloalto' in platforms:
    paloalto = copy.deepcopy(pol)
  if 'sonic' in platforms:
    sonic_pol = copy.deepcopy(pol)
  if 'cloudarmor' in platforms:
    gca = copy.deepcopy(pol)
  if 'k8s' in platforms:
    k8s_pol = copy.deepcopy(pol)

  acl_obj: aclgenerator.ACLGenerator

  try:
    if jcl:
      acl_obj = juniper.Juniper(jcl, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if evojcl:
      acl_obj = juniperevo.JuniperEvo(evojcl, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if msmpc:
      acl_obj = junipermsmpc.JuniperMSMPC(msmpc, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if srx:
      acl_obj = junipersrx.JuniperSRX(srx, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if acl:
      acl_obj = cisco.Cisco(acl, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if asacl:
      acl_obj = ciscoasa.CiscoASA(asacl, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if aacl:
      acl_obj = aruba.Aruba(aacl, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if bacl:
      acl_obj = brocade.Brocade(bacl, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if eacl:
      acl_obj = arista.Arista(eacl, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if atp:
      acl_obj = arista_tp.AristaTrafficPolicy(atp, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if ips:
      acl_obj = ipset.Ipset(ips, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if ipt:
      acl_obj = iptables.Iptables(ipt, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if nsx:
      acl_obj = nsxv.Nsxv(nsx, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if oc:
      acl_obj = openconfig.OpenConfig(oc, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if spd:
      acl_obj = speedway.Speedway(spd, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if pcap_accept:
      acl_obj = pcap.PcapFilter(pcap_accept, exp_info)
      RenderACL(
          str(acl_obj), '-accept' + acl_obj.SUFFIX, output_directory,
          input_file, write_files)
    if pcap_deny:
      acl_obj = pcap.PcapFilter(pcap_deny, exp_info, invert=True)
      RenderACL(
          str(acl_obj), '-deny' + acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if pf:
      acl_obj = packetfilter.PacketFilter(pf, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if win_afw:
      acl_obj = windows_advfirewall.WindowsAdvFirewall(win_afw, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if jsl:
      acl_obj = srxlo.SRXlo(jsl, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if nxacl:
      acl_obj = cisconx.CiscoNX(nxacl, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if xacl:
      acl_obj = ciscoxr.CiscoXR(xacl, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if nft:
      acl_obj = nftables.Nftables(nft, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if gcefw:
      acl_obj = gce.GCE(gcefw, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if gce_vpc_tf_pol:
      acl_obj = gce_vpc_tf.TerraformGCE(gce_vpc_tf_pol, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if gcphf:
      acl_obj = gcp_hf.HierarchicalFirewall(gcphf, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)

    if paloalto:
      acl_obj = paloaltofw.PaloAltoFW(paloalto, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)
    if sonic_pol:
      acl_obj = sonic.Sonic(sonic_pol, exp_info)
      RenderACL(
          str(acl_obj), '.json', output_directory, input_file, write_files,
          True)
    if gca:
      acl_obj = cloudarmor.CloudArmor(gca, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)

    if k8s_pol:
      acl_obj = k8s.K8s(k8s_pol, exp_info)
      RenderACL(
          str(acl_obj), acl_obj.SUFFIX, output_directory, input_file,
          write_files)

  # TODO(robankeny) add additional errors.
  except (
      juniper.Error,
      junipermsmpc.Error,
      junipersrx.Error,
      cisco.Error,
      ipset.Error,
      iptables.Error,
      speedway.Error,
      pcap.Error,
      sonic.Error,
      aclgenerator.Error,
      aruba.Error,
      nftables.Error,
      gce.Error,
      gce_vpc_tf.Error,
      cloudarmor.Error,
      k8s.Error) as e:
    raise ACLGeneratorError('Error generating target ACL for %s:\n%s' %
                            (input_file, e))


def RenderACL(acl_text: str,
              acl_suffix: str,
              output_directory: pathlib.Path,
              input_file: pathlib.Path,
              write_files: List[Tuple[pathlib.Path, str]],
              binary: bool = False):
  """Write the ACL string out to file if appropriate.

  Args:
    acl_text: Rendered output of an ACL Generator.
    acl_suffix: File suffix to append to output filename.
    output_directory: The directory to write the output file.
    input_file: The name of the policy file that was used to render ACL.
    write_files: A list of file tuples, (output_file, acl_text), to write.
    binary: Boolean if the rendered ACL is in binary format.
  """
  input_filename = input_file.with_suffix(acl_suffix).name
  output_file = output_directory / input_filename

  if FilesUpdated(output_file, acl_text, binary):
    logging.info('file changed: %s', output_file)
    write_files.append((output_file, acl_text))
  else:
    logging.debug('file not changed: %s', output_file)


def FilesUpdated(file_name: pathlib.Path, new_text: str, binary: bool) -> bool:
  """Diff the rendered acl with what's already on disk.

  Args:
    file_name: Name of file on disk to check against.
    new_text: Text of newly generated ACL.
    binary: True if file is a binary format.

  Returns:
    Boolean if config does not equal new text.
  """
  if binary:
    readmode = 'rb'
  else:
    readmode = 'r'
  try:
    with open(file_name, readmode) as f:
      conf: str = str(f.read())
  except IOError:
    return True
  if not binary:
    p4_id = '$I d:'.replace(' ', '')
    p4_date = '$Da te:'.replace(' ', '')
    p4_revision = '$Rev ision:'.replace(' ', '')

    def P4Tags(text: str) -> bool:
      return not (p4_id in text or p4_date in text or p4_revision in text)

    filtered_conf = filter(P4Tags, conf.split('\n'))
    filtered_text = filter(P4Tags, new_text.split('\n'))
    return list(filtered_conf) != list(filtered_text)
  return conf != new_text


def DescendDirectory(input_dirname: str,
                     ignore_directories: List[str]) -> List[pathlib.Path]:
  """Descend from input_dirname looking for policy files to render.

  Args:
    input_dirname: the base directory.
    ignore_directories: directories to ignore while traversing.

  Returns:
    a list of input file paths
  """
  input_dir = pathlib.Path(input_dirname)

  policy_files: List[pathlib.Path] = []
  policy_directories: Iterator[pathlib.Path] = filter(
      lambda path: path.is_dir(), input_dir.glob('**/pol'))
  for ignored_directory in ignore_directories:

    def Filtering(path, ignored=ignored_directory):
      return not path.match('%s/**/pol' % ignored) and not path.match(
          '%s/pol' % ignored)

    policy_directories = filter(Filtering, policy_directories)

  for directory in policy_directories:
    directory_policies = list(directory.glob('*.pol'))
    depth = len(directory.parents) - 1
    logging.warning('-' * (2 * depth) + '> %s (%d pol files found)' %
                    (directory, len(directory_policies)))
    policy_files.extend(filter(lambda path: path.is_file(), directory_policies))

  return policy_files


def WriteFiles(write_files: WriteList):
  """Writes files to disk.

  Args:
    write_files: List of file names and strings.
  """
  if write_files:
    logging.info('writing %d files to disk...', len(write_files))
  else:
    logging.info('no files changed, not writing to disk')
  for output_file, file_contents in write_files:
    _WriteFile(output_file, file_contents)


def _WriteFile(output_file: pathlib.Path, file_contents: str):
  """Inner file writing function.

  Args:
    output_file: Path to write to
    file_contents: Data to write
  """
  try:
    parent_path = pathlib.Path(output_file).parent
    if not parent_path.is_dir():
      parent_path.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as output:
      logging.info('writing file: %s', output_file)
      output.write(file_contents)
  except IOError:
    logging.warning('error while writing file: %s', output_file)
    raise


def Run(base_directory: str, definitions_directory: str, policy_file: str,
        output_directory: str, exp_info: int, max_renderers: int,
        ignore_directories: List[str], optimize: bool, shade_check: bool,
        context: multiprocessing.context.BaseContext):
  """Generate ACLs.

  Args:
    base_directory: directory containing policy files.
    definitions_directory: directory containing NETWORK and SERVICES definition
      files.
    policy_file: path to a single policy file to render.
    output_directory: directory in which rendered files are placed.
    exp_info: print a info message when a term is set to expire in that many
      weeks.
    max_renderers: the number of renderers to run in parallel.
    ignore_directories: directories to ignore when searching for policy files.
    optimize: a boolean indicating if we should turn on optimization or not.
    shade_check: should we raise an error if a term is completely shaded.
    context: multiprocessing context
  """
  definitions = None
  try:
    definitions = naming.Naming(definitions_directory)
  except naming.NoDefinitionsError:
    err_msg = 'bad definitions directory: %s' % definitions_directory
    logging.fatal(err_msg)
    return  # static type analyzer can't detect that logging.fatal exits program

  # thead-safe list for storing files to write
  manager: multiprocessing.managers.SyncManager = context.Manager()
  write_files: WriteList = cast(WriteList, manager.list())

  with_errors = False
  logging.info('finding policies...')
  if policy_file:
    # render just one file
    logging.info('rendering one file')
    RenderFile(base_directory, pathlib.Path(policy_file),
               pathlib.Path(output_directory), definitions, exp_info, optimize,
               shade_check, write_files)
  elif max_renderers == 1:
    # If only one process, run it sequentially
    policies = DescendDirectory(base_directory, ignore_directories)
    for pol in policies:
      RenderFile(base_directory, pol, pathlib.Path(output_directory),
                 definitions, exp_info, optimize, shade_check, write_files)
  else:
    # render all files in parallel
    policies = DescendDirectory(base_directory, ignore_directories)
    pool = context.Pool(processes=max_renderers)
    results: List[multiprocessing.pool.AsyncResult] = []
    for pol in policies:
      results.append(
          pool.apply_async(
              RenderFile,
              args=(base_directory, pol, output_directory, definitions,
                    exp_info, optimize, shade_check, write_files)))
    pool.close()
    pool.join()

    for result in results:
      try:
        result.get()
      except (ACLParserError, ACLGeneratorError) as e:
        with_errors = True
        logging.warning('\n\nerror encountered in rendering process:\n%s\n\n',
                        e)

  # actually write files to disk
  WriteFiles(write_files)

  if with_errors:
    logging.warning('done, with errors.')
    sys.exit(1)
  else:
    logging.info('done.')


def main(argv):
  del argv  # Unused.

  configs = config.generate_configs(FLAGS)

  if configs['verbose']:
    logging.set_verbosity(logging.INFO)
  if configs['debug']:
    logging.set_verbosity(logging.DEBUG)
  logging.debug(
      'binary: %s\noptimize: %d\nbase_directory: %s\n'
      'policy_file: %s\nrendered_acl_directory: %s', str(sys.argv[0]),
      int(configs['optimize']), str(configs['base_directory']),
      str(configs['policy_file']), str(configs['output_directory']))
  logging.debug('capirca configurations: %s', configs)

  context = multiprocessing.get_context()

  Run(configs['base_directory'], configs['definitions_directory'],
      configs['policy_file'], configs['output_directory'], configs['exp_info'],
      configs['max_renderers'], configs['ignore_directories'],
      configs['optimize'], configs['shade_check'], context)


def EntryPoint():
  """Read in flags and call main()."""
  SetupFlags()
  app.run(main)


if __name__ == '__main__':
  EntryPoint()
