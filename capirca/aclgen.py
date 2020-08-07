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
import pathlib
import sys

from absl import app
from absl import flags
from absl import logging
from capirca.parsing import naming
from capirca.parsing import policy
from capirca.utils.platutils import LoadExportedPlatforms


FLAGS = flags.FLAGS


def SetupFlags():
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
      'Don\'t descend into directories that look like this string')
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
  flags.DEFINE_boolean(
      'profile',
      False,
      'Run a thread to profile the execution. Implies \'--max_renderers 1\'')
  flags.DEFINE_integer(
      'profile_time',
      None,
      'The duration (seconds) that the profile thread should run for. '
      'Implies --profile.\n(default: 30)\n(an integer)')
  flags.DEFINE_string(
      'pprof_file',
      None,
      'The name of the output file for the profile thread. Implies --profile.\n'
      '(default:  \'profile.pprof\')')


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


def RenderFile(base_directory, input_file, output_directory, definitions,
               exp_info, write_files):
  """Render a single file.

  Args:
    base_directory: The base directory to look for acls.
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

  try:
    with open(input_file) as f:
      conf = f.read()
      logging.debug('opened and read %s', input_file)
  except IOError as e:
    logging.warning('bad file: \n%s', e)
    raise

  try:
    pol = policy.ParsePolicy(
        conf, definitions, optimize=FLAGS.optimize,
        base_dir=base_directory, shade_check=FLAGS.shade_check)
  except policy.ShadingError as e:
    logging.warning('shading errors for %s:\n%s', input_file, e)
    return
  except (policy.Error, naming.Error):
    raise ACLParserError('Error parsing policy file %s:\n%s%s' % (
        input_file, sys.exc_info()[0], sys.exc_info()[1]))

  header_platforms = set()
  for header in pol.headers:
    header_platforms.update(header.platforms)

  exported_platforms = LoadExportedPlatforms()

  if not output_directory.endswith('/'):
    output_directory += '/'

  try:
    for platform in exported_platforms:
      if platform.PLATFORM in header_platforms:
        policy_data = copy.deepcopy(pol)
        renderer = platform.RENDERER
        acl_obj = renderer(policy_data, exp_info)
        acl_suffix = acl_obj.SUFFIX

        RenderACL(str(acl_obj), acl_suffix, output_directory,
                  input_file, write_files)

  # TODO(robankeny) add additional errors.
  except (juniper.Error, junipersrx.Error, cisco.Error, ipset.Error,
          iptables.Error, speedway.Error, pcap.Error,
          aclgenerator.Error, aruba.Error, nftables.Error, gce.Error,
          cloudarmor.Error) as e:
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
      with open(file_name, 'rb') as f:
        conf = f.read()
    else:
      with open(file_name) as f:
        conf = f.read()
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
      logging.warning('-' * (2 * depth) + '> %s' % (
          input_dirname + '/' + curdir))
      files_found = DescendRecursively(input_dirname + '/' + curdir,
                                       output_dirname + '/' + curdir,
                                       definitions, depth + 1)
      logging.warning('-' * (2 * depth) + '> %s (%d pol files found)' % (
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
    parent_path = pathlib.Path(output_file).parent
    if not parent_path.is_dir():
      parent_path.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as output:
      logging.info('writing file: %s', output_file)
      output.write(file_string)
  except IOError:
    logging.warning('error while writing file: %s', output_file)
    raise


def DiscoverAllPolicies(base_directory, output_directory, definitions):
  logging.info('finding policies...')
  pols = []
  pols.extend(
      DescendRecursively(
          base_directory,
          output_directory,
          definitions
      )
  )
  return pols


def Run(base_directory, definitions_directory, policy_file, output_directory,
        context):
  definitions = None
  try:
    definitions = naming.Naming(definitions_directory)
  except naming.NoDefinitionsError:
    err_msg = 'bad definitions directory: %s' % definitions_directory
    logging.fatal(err_msg)

  # thead-safe list for storing files to write
  manager = context.Manager()
  write_files = manager.list()

  with_errors = False
  if policy_file:
    # render just one file
    logging.info('rendering one file')
    RenderFile(base_directory, policy_file, output_directory, definitions,
               FLAGS.exp_info, write_files)
  elif FLAGS.max_renderers == 1:
    # If only one process, run it sequentially
    policies = DiscoverAllPolicies(
        base_directory,
        output_directory,
        definitions
    )
    for pol in policies:
      RenderFile(
          base_directory,
          pol.get('in_file'),
          pol.get('out_dir'),
          definitions,
          FLAGS.exp_info,
          write_files
      )
  else:
    # render all files in parallel
    policies = DiscoverAllPolicies(
        base_directory,
        output_directory,
        definitions
    )
    pool = context.Pool(processes=FLAGS.max_renderers)
    results = []
    for pol in policies:
      results.append(
          pool.apply_async(
              RenderFile,
              args=(
                  base_directory,
                  pol.get('in_file'),
                  pol.get('out_dir'),
                  definitions,
                  FLAGS.exp_info,
                  write_files
              )
          )
      )
    pool.close()
    pool.join()

    for result in results:
      try:
        result.get()
      except (ACLParserError, ACLGeneratorError) as e:
        with_errors = True
        logging.warning('\n\nerror encountered in rendering '
                        'process:\n%s\n\n', e)

  # actually write files to disk
  WriteFiles(write_files)

  if with_errors:
    logging.warning('done, with errors.')
    sys.exit(1)
  else:
    logging.info('done.')


def main(argv):
  del argv  # Unused.

  if FLAGS.verbose:
    logging.set_verbosity(logging.INFO)
  if FLAGS.debug:
    logging.set_verbosity(logging.DEBUG)
  logging.debug('binary: %s\noptimize: %d\nbase_directory: %s\n'
                'policy_file: %s\nrendered_acl_directory: %s',
                str(sys.argv[0]),
                int(FLAGS.optimize),
                str(FLAGS.base_directory),
                str(FLAGS.policy_file),
                str(FLAGS.output_directory))

  context = multiprocessing.get_context()
  Run(FLAGS.base_directory, FLAGS.definitions_directory, FLAGS.policy_file,
      FLAGS.output_directory, context)


def entry_point():
  SetupFlags()
  app.run(main)


if __name__ == '__main__':
  entry_point()
