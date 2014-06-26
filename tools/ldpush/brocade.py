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
"""Brocade device implementation.

This module implements the base device interface of base_device.py for
several Brocade models; MLX, TurboIron and FastIron.
"""

__author__ = 'weisu@google.com (Wei Su)'

import os
import re
import string
import time

import pexpect

import gflags
import logging

import base_device
import pexpect_connection
import push_exceptions as exceptions


FLAGS = gflags.FLAGS

gflags.DEFINE_float('brocademlx_timeout_response', None,
                   'Brocade device response timeout in seconds.')
gflags.DEFINE_float('brocademlx_timeout_connect', None,
                   'Brocade device connect timeout in seconds.')
gflags.DEFINE_float('brocademlx_timeout_idle', None,
                   'Brocade device idle timeout in seconds.')
gflags.DEFINE_float('brocademlx_timeout_disconnect', None,
                   'Brocade device disconnect timeout in seconds.')
gflags.DEFINE_float('brocademlx_timeout_act_user', None,
                   'Brocade device user activation timeout in seconds.')
gflags.DEFINE_float('brocadefi_timeout_response', None,
                   'Brocade FastIron device response timeout in seconds.')
gflags.DEFINE_float('brocadefi_timeout_connect', None,
                   'Brocade FastIron device connect timeout in seconds.')
gflags.DEFINE_float('brocadefi_timeout_idle', None,
                   'Brocade FastIron device idle timeout in seconds.')
gflags.DEFINE_float('brocadefi_timeout_disconnect', None,
                   'Brocade FastIron device disconnect timeout in seconds.')
gflags.DEFINE_float('brocadefi_timeout_act_user', None,
                   'Brocade FastIron device user activation timeout in'
                   'seconds.')
gflags.DEFINE_float('brocadeti_timeout_response', None,
                   'Brocade TurboIron device response timeout in seconds.')
gflags.DEFINE_float('brocadeti_timeout_connect', None,
                   'Brocade TurboIron device connect timeout in seconds.')
gflags.DEFINE_float('brocadeti_timeout_idle', None,
                   'Brocade TurboIron device idle timeout in seconds.')
gflags.DEFINE_float('brocadeti_timeout_disconnect', None,
                   'Brocade TurboIron device disconnect timeout in seconds.')
gflags.DEFINE_float('brocadeti_timeout_act_user', None,
                   'Brocade TurboIron device user activation timeout in'
                   'seconds.')

# Used in sleep statements for a minor pause.
MINOR_PAUSE = 0.05

RE_FILE_LISTING = re.compile(
    r'^[\d\/]+'  # Leading whitespace, then the file number.
    r'\s+'  # Whitespace.
    r'[\d\:]+'  # Hour:minute:seconds.
    r'\s+'
    r'([\d\,]+)'  # File size in bytes.
    r'\s+'
    r'(.*)')   # File name.

_BROCADE_TIFI_DISABLE_PAGER = 'skip-page-display\r'
_BROCADE_MLX_DISABLE_PAGER = 'terminal length 0\r'

class BrocadeDevice(base_device.BaseDevice):
  """A common superclass for Brocade devices."""

  verboten_commands = (
      'monitor ',
      'terminal length ',
      'terminal monitor',
      'page-display',
      'quit',
      'exit',
  )

  disable_pager_command = ''

  def __init__(self, **kwargs):
    self.ssh_client = kwargs.pop('ssh_client', None)
    super(BrocadeDevice, self).__init__(**kwargs)
    self._success = r'(?:^|\n)([A-Za-z0-9@\.\-]+[>#])'

  def _Connect(self, username=None, password=None, ssh_keys=None,
               enable_password=None, ssl_cert_set=None):
    _ = enable_password, ssl_cert_set
    self._connection = pexpect_connection.ParamikoSshConnection(
        self.loopback_ipv4, username, password, self._success,
        timeout=self.timeout_connect, find_prompt=True, ssh_keys=ssh_keys,
        # Brocade case 1101014 - \n\r\0 newlines in some 'tm voq' outputs.
        ssh_client=self.ssh_client, find_prompt_prefix=r'(?:^|\n|\n\r\0)')
    try:
      self._connection.Connect()
      self._DisablePager()
      self.connected = True
    except pexpect_connection.ConnectionError, e:
      self.connected = False
      raise exceptions.ConnectError(e)
    except pexpect_connection.TimeoutError, e:
      self.connected = False
      raise exceptions.ConnectError('Timed out connecting to %s(%s) after '
                                    '%s seconds.' %
                                    (self.host, self.loopback_ipv4, str(e)))

  def _Cmd(self, command, mode=None):

    def SendAndWait(command):
      """Sends a command and waits for a response."""
      self._connection.child.send(command+'\r')
      self._connection.child.expect('\r\n', timeout=self.timeout_response)
      self._connection.child.expect(self._connection.re_prompt,
                                    timeout=self.timeout_response,
                                    searchwindowsize=128)
      return self._connection.child.before.replace('\r\n', os.linesep)

    _ = mode
    command = command.replace('?', '')
    if next((command
             for prefix in self.verboten_commands
             if command.startswith(prefix)), False):
      raise exceptions.CmdError(
          'Command %s is not permitted on Brocade devices.' % command)
    result = ''
    try:
      result = SendAndWait(command)
    except pexpect.TIMEOUT, e:
      self.connected = False
      raise exceptions.CmdError('%s: %s' % (e.__class__, str(e)))
    except pexpect.EOF:
      # Retry once on EOF error, in case we have been idle disconnected.
      try:
        self.connected = False
        self._connection.Connect()
        self._DisablePager()
        self.connected = True
        result = SendAndWait(command)
      except pexpect.EOF:
        raise exceptions.CmdError('Failed with EOF error twice.')
      except pexpect_connection.ConnectionError, e:
        raise exceptions.CmdError('Auto-reconnect failed: %s' % e)
      except pexpect_connection.TimeoutError, e:
        raise exceptions.CmdError('Auto-reconnect timed out: %s' % e)

    # Fix trailing \r to \n (if \n of last \r\n is captured by prompt).
    if result and result[-1] == '\r':
      result = result[:-1] + '\n'

    if (result.startswith('Invalid input -> ') or
        result == 'Not authorized to execute this command.\n'):
      if result.endswith('\nType ? for a list\n'):
        result = result[:-19]
      elif result.endswith('\n'):
        result = result[:-1]
      raise exceptions.CmdError(result)
    return result

  def _GetConnected(self):
    """Returns the connected state."""
    if not (hasattr(self, '_connection') and
            hasattr(self._connection, 'child')):
      # The connection has disappeared.
      self.connected = False
    else:
      # Are we still connected?
      try:
        self.connected = not bool(self._connection.child.flag_eof)
      except (AttributeError, TypeError):
        # The connection has (just) disappeared.
        self.connected = False
    return self.connected

  def _Disconnect(self):
    if hasattr(self, '_connection'):
      try:
        self._connection.child.send('exit\r')
        # Loose prompt RE as prompt changes after first exit.
        self._connection.child.expect(self._success,
                                      timeout=self.timeout_act_user)
        self._connection.child.send('exit\r')
        self._connection.child.expect(self._connection.exit_list,
                                      timeout=self.timeout_act_user)
        self.connected = False
      except (pexpect.EOF, pexpect.TIMEOUT), e:
        self.connected = False
        raise exceptions.DisconnectError('%s: %s' % (e.__class__, str(e)))

  def _DisablePager(self):
    """Disables the pager."""
    try:
      self._connection.child.send(self.disable_pager_command)
      self._connection.child.expect(self._connection.re_prompt,
                                    timeout=self.timeout_connect,
                                    searchwindowsize=128)
    except (pexpect.EOF, pexpect.TIMEOUT), e:
      self.connected = False
      raise exceptions.CmdError('%s: %s' % (e.__class__, str(e)))


class BrocadeMlxDevice(BrocadeDevice):
  """A base device model suitable for Brocade MLX devices.

  See the base_device.BaseDevice method docstrings.
  """

  disable_pager_command = _BROCADE_MLX_DISABLE_PAGER

  def __init__(self, **kwargs):
    self.vendor_name = 'brocademlx'
    super(BrocadeMlxDevice, self).__init__(**kwargs)

  def _GetFileSize(self, file_name, data):
    """Gets the size of a file in Brocade 'dir' output.

    Args:
      file_name: A string, the file name.
      data: A string, the Brocade's "dir" output.

    Returns:
      An int, the file size, or None if the value could not be determined.
    """
    for line in data.splitlines():
      match = RE_FILE_LISTING.match(line)
      if match is not None:
        (file_size, fname) = match.groups()
        for char in string.punctuation:
          file_size = file_size.replace(char, '')
        if file_name.strip() == fname.strip():
          try:
            return int(file_size)
          except ValueError:
            continue
    return None

  def _SetConfig(self, destination_file, data, canary):
    # Canarying is not supported on BROCADE.
    if canary:
      raise exceptions.SetConfigCanaryingError('%s devices do not support '
                                               'configuration canarying.' %
                                               self.vendor_name)
    # The result object.
    result = base_device.SetConfigResult()
    # Check for a connection to the Brocade.
    if not self._GetConnected():
      raise exceptions.SetConfigError('Cannot use unless already '
                                      'connected to the device.')

    if destination_file in self.NON_FILE_DESTINATIONS:
      # Use a random remote file name
      file_name = 'push.%s' % os.urandom(8).encode('hex')
    else:
      # Okay, the user is just copying a file, not a configuraiton into either
      # startup-config or running-config, therefore we should use the entire
      # path.
      file_name = destination_file

    # Copy the file to the router using SCP.
    scp = pexpect_connection.ScpPutConnection(
        host=self.loopback_ipv4,
        username=self._username,
        password=self._password)

    # This is a workaround. Brocade case: 537017.
    # Brocade changed all the filename to lowercases after scp
    file_name = file_name.lower()
    try:
      scp.Copy(data, destination_file='slot1:' + file_name)
    except pexpect_connection.Error, e:
      raise exceptions.SetConfigError(
          'Failed to copy configuration to remote device. %s' % str(e))
    # Now that everything is OK locally and the file has been copied,
    # check the file and tell the device to set the new configuration.
    try:
      # Get the file size on the Brocade.
      try:
        cmd = 'dir /slot1/%s' % file_name
        dir_output = self._Cmd(cmd)
      except exceptions.CmdError, e:
        if 'Invalid input at' in str(e):
          raise exceptions.AuthenticationError(
              'Username/password for %s(%s) has insufficient privileges '
              'to set configuration.' %
              (self.host, self.loopback_ipv4))
        else:
          raise exceptions.SetConfigError('Could not traverse directory '
                                          'output.  Command was: %r. '
                                          'Error: %r' % (cmd, str(e)))
      destination_file_size = self._GetFileSize(file_name, dir_output)
      # We couldn't parse the output for some reason.
      if destination_file_size is None:
        raise exceptions.SetConfigError('Could not find or parse remote '
                                        'file size after copy to device.')

      # Verify file is the correct size on the Brocade.
      # This should use a checksum (e.g. MD5 or SHA1); Brocade case: 609719.
      if destination_file_size != len(data):
        raise exceptions.SetConfigError(
            'File transfer corrupted. Source file was: %d bytes, '
            'Destination file was: %d bytes.' %
            (len(data), destination_file_size))

      # Copy the file from flash to the
      # destination(running-config, startup-config)
      if destination_file == self.CONFIG_STARTUP:
        try:
          self._connection.child.send(
              'copy slot1 startup-config %s\r' % file_name)
          time.sleep(MINOR_PAUSE)
          pindex = self._connection.child.expect(
              ['Total bytes', self._connection.re_prompt, 'Error'],
              timeout=self.timeout_act_user)
          if pindex == 2:
            raise exceptions.SetConfigError('Could not copy temporary '
                                            'file to startup-config.')
        except (pexpect.EOF, pexpect.TIMEOUT), e:
          raise exceptions.SetConfigError(str(e))
      elif destination_file == self.CONFIG_RUNNING:
        try:
          # This is not working, unfortunately. Cannot copy a file to a running
          # config, raised support case RFE2901
          self._Cmd('copy slot1 running-config %s' % file_name)
        except exceptions.CmdError, e:
          raise exceptions.SetConfigError(str(e))
        # We need to 'write memory' if we are doing running-config.
        logging.vlog(3, 'Attempting to copy running-config to startup-config '
                     'on %s(%s)', self.host, self.loopback_ipv4)
        try:
          self._Cmd('wr mem')
        except exceptions.CmdError, e:
          raise exceptions.SetConfigError('Failed to write startup-config '
                                          'for %s(%s). Error was: %s' %
                                          (self.host, self.loopback_ipv4,
                                           str(e)))

    finally:
      # Now remove the remote temporary file.
      # If this fails, we may have already copied the file, so log warnings
      # regarding this and return this information to the user in the
      # RPC response, so that they can delete the files.
      if destination_file in self.NON_FILE_DESTINATIONS:
        try:
          self._connection.child.send('delete /slot1/%s\r' % file_name)
          pindex = self._connection.child.expect(
              ['/slot1/%s removed' % file_name,
               'Remove file /slot1/%s failed - File not found' % file_name,
               r'Error: .*'],
              timeout=self.timeout_act_user)
          if pindex == 0:
            self._connection.child.expect(self._connection.re_prompt,
                                          timeout=self.timeout_act_user,
                                          searchwindowsize=128)
          elif pindex == 1:
            result.transcript = ('Could not delete temporary file %r '
                                 '(file does not exist). ' % file_name)
            logging.warn(result.transcript)
          else:
            result.transcript = ('Unable to delete temporary file %r. Error: %s'
                                 % (file_name, str(self._connection.child)))
            logging.warn(result.transcript)
        except (pexpect.EOF, pexpect.TIMEOUT), e:
          result.transcript = ('Unable to delete temporary file %r. Error: %s'
                               % (file_name, str(self._connection.child)))
          logging.warn(result.transcript)

      else:
        result.transcript = 'SetConfig uploaded the file successfully.'

    return result

  def _GetConfig(self, source):
    try:
      if source == 'running-config':
        result = self._Cmd('show %s' % source)
      elif source == 'startup-config':
        result = self._Cmd('show configuration')
      else:
        raise exceptions.GetConfigError('source argument must be '
                                        '"running-config" or '
                                        '"startup-config".')
      if not result:
        return exceptions.EmptyConfigError('%s has an empty configuration.'
                                           % self.host)
      else:
        return result
    except exceptions.Error, e:
      raise exceptions.GetConfigError('Could not fetch config from %s. %s.'
                                      % (self.host, str(e)))


class BrocadeFiDevice(BrocadeDevice):
  """A base device model suitable for Brocade FastIron devices."""

  disable_pager_command = _BROCADE_TIFI_DISABLE_PAGER

  def __init__(self, **kwargs):
    self.vendor_name = 'brocadefi'
    super(BrocadeFiDevice, self).__init__(**kwargs)


class BrocadeTiDevice(BrocadeDevice):
  """A base device model suitable for Brocade TurboIron devices."""

  disable_pager_command = _BROCADE_TIFI_DISABLE_PAGER

  def __init__(self, **kwargs):
    self.vendor_name = 'brocadeti'
    super(BrocadeTiDevice, self).__init__(**kwargs)
