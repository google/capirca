#!/usr/bin/python
#
# Copyright 2013 Google Inc.
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
"""A JunOS device.

This module implements the device interface of base_device.py for
Juniper Networks' devices running the JunOS operating system.
These devices are typically routers, such as the T640 and MX960.
"""

import hashlib
import os
import re
import tempfile
import threading

import paramiko

import gflags
import logging

import base_device
import paramiko_device
import push_exceptions as exceptions


FLAGS = gflags.FLAGS

gflags.DEFINE_float('junos_timeout_response', None,
                    'JunOS device response timeout in seconds.')
gflags.DEFINE_float('junos_timeout_connect', None,
                    'JunOS device connect timeout in seconds.')
gflags.DEFINE_float('junos_timeout_idle', None,
                    'JunOS device idle timeout in seconds.')
gflags.DEFINE_float('junos_timeout_disconnect', None,
                    'JunOS device disconnect timeout in seconds.')
gflags.DEFINE_float('junos_timeout_act_user', None,
                    'JunOS device user activation timeout in seconds.')
gflags.DEFINE_boolean('paramiko_logging',
                     False,
                     'Log Paramiko output to STDERR found.')


class JunosDevice(paramiko_device.ParamikoDevice):
  """A device model suitable for Juniper JunOS devices.

  See the base_device.BaseDevice method docstrings.
  """
  # Used to protect the SetupParamikoLogging method, and state.
  _paramiko_logging_lock = threading.Lock()
  _paramiko_logging_initialized = False

  # Response strings that indicate an error during SetConfig().
  JUNOS_LOAD_ERRORS = ('error:',
                       ' errors',
                       'error recovery ignores input until this point:')

  # Response strings that do *not* indicate an error, and should be ignored
  # This currently matches that start with a "diff" character, or indicate a
  # failure to communicate with an RE.
  IGNORED_JUNOS_LINES = re.compile(
      r'^[+!-]|'   # Match diff characters at start of line.
      r'(?<!syntax )error: .*connect to re[0-9] :',  # Match missing RE errors.
      re.IGNORECASE)

  @staticmethod
  def _CleanupErrorLine(line):
    """Removes text from "line" which does not indicate an error.

    This is a helper function for _RaiseExceptionIfLoadError.

    If the line contains a single or double quote character, then it's assumed
    to start a quoted chunk of configuration from the client. Characters after
    the quote are ignored.
    If the (remaining part of the) line matches IGNORED_JUNOS_LINES, '' is
    returned.
    Otherwise, returns the characters before the first quote.

    This avoids problems where a user-entered interface description contains the
    word "error", for example.

    Args:
      line: A string, the string to clean up.

    Returns:
      The line, or a substring of the line (can be empty).
    """
    # Chop off anything after single or double quotes first.
    remaining = line.partition('\'')[0].partition('"')[0]
    if JunosDevice.IGNORED_JUNOS_LINES.match(remaining):
      return ''
    else:
      return remaining

  @staticmethod
  def _RaiseExceptionIfLoadError(result, expect_config_check=False,
                                 expect_commit=False):
    """Checks if a result string from a load configuration contains an error.

    Args:
      result: A string, the result of loading the configuration.
      expect_config_check: A boolean. If true, then the exception-raising code
        will raise a special "configuration check failed" exception if the
        string "configuration check succeeds" isn't found.
      expect_commit: A boolean. If True, then the function raises an exception
        if the string "commit complete" isn't found on a line by itself.

    Raises:
      An exception derived from exceptions.SetConfigError if the result
      indicates an error, else nothing.
    """
    # Remove output assumed to be part of diffs or quoted parts of the input.
    # Lines that are considered to be part of diffs start with + or - or !,
    # start and end with square brackets like "[edit ... ]", or immediately
    # follow a line that starts and ends with square brackets.
    lines = []
    last_line_started_diff = False
    for line in result.splitlines():
      if last_line_started_diff:
        last_line_started_diff = False
        # Ignore the line.
      elif line.startswith('[') and line.endswith(']'):
        last_line_started_diff = True
      else:
        lines.append(JunosDevice._CleanupErrorLine(line))

    for error in JunosDevice.JUNOS_LOAD_ERRORS:
      if any(error in line for line in lines):
        break
    else:
      # No special "error" string found, check for "commit complete". b/9750034
      # and Junos bug PR799925.
      if expect_commit and all(
          'commit complete' not in line for line in lines):
        raise exceptions.SetConfigError(
            '"commit complete" expected, but not found in output:\n%s' % result)
      return

    # Raise the right type of exception based on the error string found.
    if any('syntax error' in line for line in lines):
      raise exceptions.SetConfigSyntaxError(
          'Device reports a syntax error in the configuration.\n%s' %
          result)
    elif expect_config_check and all(
        'configuration check succeeds' not in line for line in lines):
      raise exceptions.SetConfigSyntaxError(
          'Configuration check failed.\n%s' % result)
    else:
      raise exceptions.SetConfigError(
          'Error occurred during config load.\n%s' % result)

  def __init__(self, **kwargs):
    self.vendor_name = 'junos'
    self.unsupported_non_file_destinations = ()
    super(JunosDevice, self).__init__(**kwargs)

    # Setup paramiko logging once only.
    if not JunosDevice._paramiko_logging_initialized:
      self._SetupParamikoLogging()

  def _SetupTimeouts(self):
    if FLAGS.junos_timeout_idle is None:
      self.timeout_idle = 1790.0

  def _SetupParamikoLogging(self):
    if not JunosDevice._paramiko_logging_initialized and FLAGS.paramiko_logging:
      # UN*X specific.
      log_dir_string = '/dev/fd/2'
      logging.info('Paramiko SSH2 logging to path: %r', log_dir_string)
      paramiko.util.log_to_file(log_dir_string)
      JunosDevice._paramiko_logging_initialized = True

  def _Cmd(self, command, mode=None):
    # Enforce that the 'ping' and 'monitor' commands have a count (else they
    # never complete).  JunOS allows these to be abbreviated to 'p' and 'mo'
    # since no other commands begin with those prefixes.
    if command.startswith('p') or command.startswith('mo'):
      if ' count ' not in command:
        # Use 5 pings by default (same as default for 'ping <host> rapid').
        command += ' count 5'
    # Enforce that traceroute and monitor have the stderr (header) and stdout
    # merged, in that order.
    if command.startswith('tr') or command.startswith('mo'):
      merge_stderr_first = True
    else:
      merge_stderr_first = False
    # Run the modified command.
    result = super(JunosDevice, self)._Cmd(
        command, mode=mode,
        merge_stderr_first=merge_stderr_first,
        require_low_chanid=True)
    # Report JunOS errors on stdout as CmdError.
    if result.startswith('\nerror: '):
      raise exceptions.CmdError(result[1:])  # Drop the leading \n.
    else:
      return result

  def _ChecksumsMatch(self, local_file_name, remote_file_name):
    """Compares the local and remote checksums for the named file.

    Args:
      local_file_name: A string, the filename on the local host.
      remote_file_name: A string, the file path and name of the remote file.

    Returns:
      A boolean. True iff the checksums match, else False.
    """
    remote_md5 = self._Cmd('file checksum md5 ' + remote_file_name)
    logging.debug('Remote checksum output: %s', remote_md5)
    local_md5 = hashlib.md5(open(local_file_name).read()).hexdigest()
    logging.debug('Local checksum: %s', local_md5)
    try:
      if local_md5 == remote_md5.split()[3]:
        logging.debug('PASS MD5 checksums match.')
        return True
      else:
        logging.error('FAIL MD5 checksums do not match.')
        return False
    except IndexError:
      logging.error('ERROR MD5 checksum parse error.')
      logging.error('ERROR local checksum: %r', local_md5)
      logging.error('ERROR remote checksum: %r', remote_md5)
      return False

  def _GetConfig(self, source_file):
    """Gets file or running configuration from the remote device.

    Args:
      source_file: A string, containing path to the file that should be
        retrieved from the remote device. It can also contain the defined
        reserved word self.CONFIG_RUNNING, in which case this method
        retrieves the running configuration from the remote device.

    Returns:
      response: A string, content of the retrieved file or running
        configuration.

    Raises:
      exceptions.GetConfigError: An error occured during the retrieval.
      exceptions.EmptyConfigError: Running configuration is empty.
    """
    response = ''

    if source_file == self.CONFIG_RUNNING:
      try:
        response = self._Cmd('show configuration')
      except exceptions.CmdError:
        msg = ('Could not retrieve system configuration from %s' %
               repr(self.host))
        logging.error(msg)
        raise exceptions.GetConfigError(msg)
      if not response:
        raise exceptions.EmptyConfigError(
            'Configuration of %s is empty' % repr(self.host))

    else:
      tempfile_ptr = tempfile.NamedTemporaryFile()
      try:
        self._GetFileViaSftp(local_filename=tempfile_ptr.name,
                             remote_filename=source_file)
      except (paramiko.SFTPError, IOError) as e:
        msg = ('Could not retrieve configuration file %r from %s, '
               'error: %s' % (source_file, self.host, e))
        logging.error(msg)
        raise exceptions.GetConfigError(msg)
      response = tempfile_ptr.read()

    return response

  def _JunosLoad(self, operation, filename, canary=False,
                 skip_show_compare=False, skip_commit_check=False,
                 rollback_patch=None):
    """Loads the configuration to the remote device using a given operation.

    Args:
      operation: A string, the load operation (e.g., 'replace', 'override').
      filename: A string, the remote temporary filename to stage configuration.
      canary: A boolean, if True, only canary check the configuration, don't
        apply it.
      skip_show_compare: A boolean, if True, "show | compare" will be skipped.
        This is a temporary flag due to a JunOS bug and may be removed in the
        future.
      skip_commit_check: A boolean, if True, "commit check" (running the commit
        scripts) will be skipped in canary mode.
      rollback_patch: None or a string, optional filename into which to
        record and return a patch to rollback the config change.

    Returns:
      A base_device.SetConfigResult, all responses from the router during the
      check/load operation, plus any optional extras.
    """

    show_compare = 'show | compare; '
    if skip_show_compare:
      show_compare = ''
    if canary:
      commit_check = 'commit check; '
      if skip_commit_check:
        commit_check = ''
      cmd = ('edit exclusive; load %s %s; %s%srollback 0; exit' %
             (operation, filename, show_compare, commit_check))
    else:
      save_rollback_patch = ''
      if rollback_patch:
        save_rollback_patch = ('rollback 1; show | compare | save %s; rollback;'
                               % rollback_patch)
      cmd = ('edit exclusive; load %s %s; %s'
             'commit comment "push: load %s %s";%s exit' %
             (operation, filename, show_compare, operation, filename,
              save_rollback_patch))
    result = base_device.SetConfigResult()
    result.transcript = self._Cmd(cmd)
    self._RaiseExceptionIfLoadError(
        result.transcript,
        expect_config_check=canary and not skip_commit_check,
        expect_commit=not canary)
    return result

  def _SetConfig(self, destination_file, data, canary, skip_show_compare=False,
                 skip_commit_check=False, get_rollback_patch=False):
    copied = False

    file_ptr = tempfile.NamedTemporaryFile()
    rollback_patch_ptr = tempfile.NamedTemporaryFile()
    rollback_patch = None
    # Setting the file name based upon if we are trying to copy a file or
    # we are trying to copy a config into the control plane.
    if destination_file in self.NON_FILE_DESTINATIONS:
      file_name = os.path.basename(file_ptr.name)
      if get_rollback_patch:
        rollback_patch = os.path.basename(rollback_patch_ptr.name)
    else:
      file_name = destination_file
      logging.info('Remote file path: %s', file_name)

    try:
      file_ptr.write(data)
      file_ptr.flush()
    except IOError:
      raise exceptions.SetConfigError('Could not open temporary file %r' %
                                      file_ptr.name)
    result = base_device.SetConfigResult()
    try:
      # Copy the file to the remote device.
      try:
        self._SendFileViaSftp(local_filename=file_ptr.name,
                              remote_filename=file_name)
        copied = True
      except (paramiko.SFTPError, IOError) as e:
        # _SendFileViaSftp puts the normalized destination path in e.args[1].
        msg = 'SFTP failed (filename %r to device %s(%s):%s): %s: %s' % (
            file_ptr.name, self.host, self.loopback_ipv4, e.args[1],
            e.__class__.__name__, e.args[0])
        raise exceptions.SetConfigError(msg)

      if not self._ChecksumsMatch(local_file_name=file_ptr.name,
                                  remote_file_name=file_name):
        raise exceptions.SetConfigError(
            'Local and remote file checksum mismatch.')

      if self.CONFIG_RUNNING == destination_file:
        operation = 'replace'
      elif self.CONFIG_STARTUP == destination_file:
        operation = 'override'
      elif self.CONFIG_PATCH == destination_file:
        operation = 'patch'
      else:
        result.transcript = 'SetConfig uploaded the file successfully.'
        print "### hi there"
        return result
      if canary:
        logging.debug('Canary syntax checking configuration file %r.',
                      file_name)
        result = self._JunosLoad(operation, file_name, canary=True,
                                 skip_show_compare=skip_show_compare,
                                 skip_commit_check=skip_commit_check)
      else:
        logging.debug('Setting destination %r with configuration file %r.',
                      destination_file, file_name)
        print "### LOADING CONFIGURATION"
        result = self._JunosLoad(operation, file_name,
                                 skip_show_compare=skip_show_compare,
                                 skip_commit_check=skip_commit_check,
                                 rollback_patch=rollback_patch)
        print "### ", result

        if rollback_patch:
          try:
            self._GetFileViaSftp(local_filename=rollback_patch_ptr.name,
                                 remote_filename=rollback_patch)
            result.rollback_patch = rollback_patch_ptr.read()
          except (paramiko.SFTPError, IOError) as e:
            # _GetFileViaSftp puts the normalized source path in e.args[1].
            result.transcript += (
                'SFTP rollback patch retrieval failed '
                '(filename %r from device %s(%s):%s): %s: %s' % (
                    rollback_patch_ptr.name, self.host, self.loopback_ipv4,
                    e.args[1], e.__class__.__name__, e.args[0]))

      # Return the diagnostic results as the (optional) result.
      return result

    finally:
      local_delete_exception = None
      # Unlink the original temporary file.
      try:
        logging.info('Deleting the file on the local machine: %s',
                     file_ptr.name)
        file_ptr.close()
      except IOError:
        local_delete_exception = exceptions.SetConfigError(
            'Could not close temporary file.')

      local_rollback_patch_delete_exception = None
      # Unlink the rollback patch temporary file.
      try:
        logging.info('Deleting the file on the local machine: %s',
                     rollback_patch_ptr.name)
        rollback_patch_ptr.close()
      except IOError:
        local_rollback_patch_delete_exception = exceptions.SetConfigError(
            'Could not close temporary rollback patch file.')

      # If we copied the file to the router and we were pushing a configuration,
      # delete the temporary file off the router.
      if copied and destination_file in self.NON_FILE_DESTINATIONS:
        logging.info('Deleting file on the router: %s', file_name)
        self.Cmd('file delete ' + file_name)

      # Delete any rollback patch file too.
      if rollback_patch:
        logging.info('Deleting patch on the router: %s', rollback_patch)
        self.Cmd('file delete ' + rollback_patch)

      # If we got an exception on the local file delete, but did not get a
      # (more important) exception on the remote delete, raise the local delete
      # exception.
      #
      # pylint is confused by the re-raising <http://b/5683453>
      # pylint: disable=raising-bad-type
      if local_delete_exception is not None:
        raise local_delete_exception
      if local_rollback_patch_delete_exception is not None:
        raise local_rollback_patch_delete_exception

  def _GetFileViaSftp(self, local_filename, remote_filename):
    """Gets the file named remote_filename from the remote device via SFTP.

    Args:
      local_filename: A string, the filename (must exist).
      remote_filename: A string, the path to the remote file location and
          filename.

    Raises:
      paramiko.SFTPError: An error occurred during the SFTP.
      IOError: There was an IOError accessing the named file.
    """
    sftp = self._ssh_client.open_sftp()
    try:
      sftp.get(remote_filename, local_filename)
    except (paramiko.SFTPError, IOError) as e:
      try:
        remote_filename = sftp.normalize(remote_filename)
      except (paramiko.SFTPError, IOError):
        pass
      raise e.__class__(e.args[0], remote_filename)
    finally:
      sftp.close()  # Request close from peer.

  def _SendFileViaSftp(self, local_filename, remote_filename):
    """Sends the file named filename to the remote device via SFTP.

    Args:
      local_filename: A string, the filename (must exist).
      remote_filename: A string, the path to the remote file location and
          filename.

    Returns:
      A tuple like stat() returns, the remote file's stat result.

    Raises:
      paramiko.SFTPError: An error occurred during the SFTP.
      IOError: There was an IOError accessing the named file.
    """
    sftp = self._ssh_client.open_sftp()
    try:
      sftp.put(local_filename, remote_filename)
    except (paramiko.SFTPError, IOError) as e:
      try:
        remote_filename = sftp.normalize(remote_filename)
      except (paramiko.SFTPError, IOError):
        pass
      raise e.__class__(e.args[0], remote_filename)
    finally:
      sftp.close()  # Request close from peer.
