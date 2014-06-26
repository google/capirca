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
"""A Cisco IOS devicemodel.

This module implements a device interface of base_device.py for
most of the herd of variants of Cisco IOS devices.
"""

import hashlib
import os
import re
import time

import pexpect

import gflags
import logging

import base_device
import pexpect_connection
import push_exceptions as exceptions

FLAGS = gflags.FLAGS

gflags.DEFINE_float('ios_timeout_response', None,
                   'IOS device response timeout in seconds.')
gflags.DEFINE_float('ios_timeout_connect', None,
                   'IOS device connect timeout in seconds.')
gflags.DEFINE_float('ios_timeout_idle', None,
                   'IOS device idle timeout in seconds.')
gflags.DEFINE_float('ios_timeout_disconnect', None,
                   'IOS device disconnect timeout in seconds.')
gflags.DEFINE_float('ios_timeout_act_user', None,
                   'IOS device user activation timeout in seconds.')

MD5_RE = re.compile(r'verify /md5 \(\S+\)\s+=\s+([A-Fa-f0-9]+)')
# Used in sleep statements for a minor pause.
MINOR_PAUSE = 0.05

# Some Cisco ways of saying 'access denied' and/or 'invalid command'.
# Due to the way Cisco privilege levels work and since unknown commands
# may be looked up in DNS, any of these could be a response which really
# means 'access denied', or they could mean what they say.
INVALID_1 = "% Invalid input detected at '^' marker.\n\n"
INVALID_2 = ('% Unknown command or computer name, or unable to find computer '
             'address\n')
INVALID_3 = 'Command authorization failed.\n\n'
INVALID_4 = '% Authorization failed.\n\n'
INVALID_5 = '% Incomplete command.\n\n'
INVALID_6_PREFIX = '% Ambiguous command:'


class DeleteFileError(Exception):
  """A file was not successfully deleted."""


class IosDevice(base_device.BaseDevice):
  """A device model for devices with IOS-like interfaces."""

  def __init__(self, **kwargs):
    self.vendor_name = 'ios'
    super(IosDevice, self).__init__(**kwargs)

    # The response regexp indicating connection success.
    self._success = r'(?:^|\n)([]A-Za-z0-9\.\-[]+[>#])'

  def _Connect(self, username, password=None, ssh_keys=None,
               enable_password=None, ssl_cert_set=None):
    _ = enable_password, ssl_cert_set
    self._connection = pexpect_connection.ParamikoSshConnection(
        self.loopback_ipv4, username, password, self._success,
        timeout=self.timeout_connect, find_prompt=True, ssh_keys=ssh_keys)
    try:
      self._connection.Connect()
      self._DisablePager()
      self.connected = True
    except pexpect_connection.ConnectionError as e:
      self.connected = False
      raise exceptions.ConnectError(e)
    except pexpect_connection.TimeoutError as e:
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

    # Quieten pylint.
    _ = mode
    # We strip question-marks ('?') from the input as they upset the
    # buffering for minimal gain (they work only on IOS and not on FTOS).
    command = command.replace('?', '')
    result = ''
    try:
      result = SendAndWait(command)
    except pexpect.TIMEOUT as e:
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
      except pexpect_connection.ConnectionError as e:
        raise exceptions.CmdError('Auto-reconnect failed: %s' % e)
      except pexpect_connection.TimeoutError as e:
        raise exceptions.CmdError('Auto-reconnect timed out: %s' % e)

    # Fix trailing \r to \n (if \n of last \r\n is captured by prompt).
    if result and result[-1] == '\r':
      result = result[:-1] + '\n'

    if (result.endswith(INVALID_1) or result.endswith(INVALID_2) or
        result.endswith(INVALID_3) or result.endswith(INVALID_4) or
        result.endswith(INVALID_5) or (
            result.endswith('\n') and
            result[result[:-1].rfind('\n') + 1:].startswith(
                INVALID_6_PREFIX))):
      raise exceptions.CmdError('Command failed: %s' % result)

    return result

  def _SetConfig(self, destination_file, data, canary):
    # Canarying is not supported on IOS.
    if canary:
      raise exceptions.SetConfigCanaryingError('%s devices do not support '
                                               'configuration canarying.' %
                                               self.vendor_name)
    # We only support copying to 'running-config' or 'startup-config' on IOS.
    if destination_file not in ('running-config', 'startup-config'):
      raise exceptions.SetConfigError('destination_file argument must be '
                                      '"running-config" or "startup-config" '
                                      'for %s devices.' % self.vendor_name)
    # Result object.
    result = base_device.SetConfigResult()

    # Get the MD5 sum of the file.
    local_digest = hashlib.md5(data).hexdigest()

    try:
      # Get the working path from the remote device
#      remote_path = self._Cmd('pwd')
      remote_path = 'nvram:/'
    except exceptions.CmdError as e:
      msg = 'Error obtaining working directory: %s' % e
      logging.error(msg)
      raise exceptions.SetConfigError(msg)

    # Use a random remote file name
    remote_tmpfile = '%s/push.%s' % (
        remote_path.rstrip(), os.urandom(8).encode('hex'))

    # Upload the file to the device.
    scp = pexpect_connection.ScpPutConnection(
        self.loopback_ipv4,
        username=self._username,
        password=self._password)
    try:
      scp.Copy(data, remote_tmpfile)
    except pexpect_connection.Error as e:
      raise exceptions.SetConfigError(
          'Failed to copy configuration to remote device. %s' % str(e))

    # Get the file size on the router.
    try:
      # Get the MD5 hexdigest of the file on the remote device.
      try:
        verify_output = self._Cmd('verify /md5 %s' % remote_tmpfile)
        match = MD5_RE.search(verify_output)
        if match is not None:
          remote_digest = match.group(1)
        else:
          raise exceptions.SetConfigError(
              'The "verify /md5 <filename>" command did not produce '
              'expected results. It returned: %r' % verify_output)
      except exceptions.CmdError as e:
        raise exceptions.SetConfigError(
            'The MD5 hash command on the router did not succed. '
            'The device may not support: "verify /md5 <filename>"')
      # Verify the local_digest and remote_digest are the same.
      if local_digest != remote_digest:
        raise exceptions.SetConfigError(
            'File transfer to remote host corrupted. Local digest: %r, '
            'Remote digest: %r' % (local_digest, remote_digest))

      # Copy the file from flash to the
      # destination(running-config, startup-config).
      # Catch errors that may occur during application, and report
      # these to the user.
      try:
        self._connection.child.send(
            'copy %s %s\r' % (remote_tmpfile, destination_file))
        pindex = self._connection.child.expect(
            [r'Destination filename \[%s\]\?' % destination_file,
             r'%\s*\S*.*',
             r'%Error.*',
             self._connection.re_prompt],
            timeout=self.timeout_act_user)
        if pindex == 0:
          self._connection.child.send('\r')
          try:
            pindex = self._connection.child.expect(
                [r'Invalid input detected',
                 self._connection.re_prompt,
                 r'%Warning:There is a file already existing.*'
                 'Do you want to over write\? \[confirm\]'],
                timeout=self.timeout_act_user)
            if pindex == 0:
              # Search again using findall to get all bad lines.
              bad_lines = re.findall(
                  r'^(.*)$[\s\^]+% Invalid input',
                  self._connection.child.match.string,
                  re.MULTILINE)
              raise exceptions.SetConfigSyntaxError(
                  'Configuration loaded, but with bad lines:\n%s' %
                  '\n'.join(bad_lines))
            if pindex == 2:
              # Don't over-write.
              self._connection.child.send('n')
              raise exceptions.SetConfigError(
                  'Destination file %r already exists, cannot overwrite.'
                  % destination_file)
          except (pexpect.EOF, pexpect.TIMEOUT) as e:
            raise exceptions.SetConfigError(
                'Copied file to device, but did not '
                'receive prompt afterwards. %s %s' %
                (self._connection.child.before, self._connection.child.after))

        elif pindex == 2:
          print "MATCHED 2"
          # The expect does a re.search, search again using findall to get all
          raise exceptions.SetConfigError('Could not copy temporary '
                                          'file to %s.' % destination_file)
      except (pexpect.EOF, pexpect.TIMEOUT) as e:
        raise exceptions.SetConfigError(
            'Attempted to copy to bootflash, but a timeout occurred.')

      # We need to 'write memory' if we are doing running-config.
      if destination_file == 'running-config':
        logging.debug('Attempting to copy running-config to startup-config '
                     'on %s(%s)', self.host, self.loopback_ipv4)
        try:
          self._Cmd('wr mem')
        except exceptions.CmdError as e:
          raise exceptions.SetConfigError('Failed to write startup-config '
                                          'for %s(%s). Changes applied. '
                                          'Error was: %s' %
                                          (self.host, self.loopback_ipv4,
                                           str(e)))
    finally:
      try:
        self._DeleteFile(remote_tmpfile)
      except DeleteFileError as e:
        result.transcript = 'SetConfig warning: %s' % str(e)
        logging.warn(result.transcript)

    # And finally, return the result text.
    return result

  def _DeleteFile(self, file_name):
    """Delete a file.

    Args:
      file_name: A string, the file name.

    Raises:
      DeleteFileError, if the deletion failed.
    """
    try:
      self._connection.child.send('\r')
      self._connection.child.expect('\r\n', timeout=self.timeout_act_user)
      self._connection.child.expect(self._connection.re_prompt,
                                    timeout=self.timeout_act_user,
                                    searchwindowsize=128)
      self._connection.child.send('delete %s\r' % file_name)
    except pexpect.ExceptionPexpect:
      raise DeleteFileError('DeleteFile operation failed. %s' %
                            self._connection.child)

    try:
      pindex = self._connection.child.expect(
          [r'Delete filename \[.*\]\?',
           r'%.*Error.*'],
          timeout=self.timeout_act_user)
      if pindex == 0:
        self._connection.child.send('\r')
        logging.debug('DeleteFile: answering first confirmation.')
        self._connection.child.expect([r'Delete .*\[confirm\]'],
                                      timeout=self.timeout_act_user)
        logging.debug('DeleteFile: answering second confirmation.')
        self._connection.child.send('\r')
      elif pindex == 1:
        raise DeleteFileError('DeleteFile operation failed. %s' %
                              self._connection.child.match)

      pindex = self._connection.child.expect([self._connection.re_prompt,
                                              r'%.*Error.*'],
                                             timeout=self.timeout_act_user)
      if pindex == 1:
        raise DeleteFileError('DeleteFile operation failed. %s' %
                              self._connection.child.match)
      logging.debug('DeleteFile: success.')
    except pexpect.ExceptionPexpect:
      raise DeleteFileError('DeleteFile operation failed. %s' %
                            self._connection.child)

  def _GetConfig(self, source):
    try:
      if source in ('running-config', 'startup-config'):
        result = self._Cmd('show %s' % source)
      else:
        raise exceptions.GetConfigError('source argument must be '
                                        '"running-config" or '
                                        '"startup-config".')
      if not result:
        return exceptions.EmptyConfigError('%s has an empty configuration.' %
                                           self.host)
      else:
        return result
    except exceptions.Error as e:
      raise exceptions.GetConfigError('Could not fetch config from %s. %s.' %
                                      (self.host, str(e)))

  def _Disconnect(self):
    if hasattr(self, '_connection'):
      try:
        self._connection.child.send('exit\r')
        self._connection.child.expect(self._connection.exit_list,
                                      timeout=self.timeout_act_user)
        self.connected = False
      except (pexpect.EOF, pexpect.TIMEOUT) as e:
        self.connected = False
        raise exceptions.DisconnectError('%s: %s' % (e.__class__, str(e)))

  def _DisablePager(self):
    """Disables the pager."""
    try:
      self._connection.child.send('\r')
      self._connection.child.expect(r'\r\n',
                                    timeout=self.timeout_connect)
      self._connection.child.expect(self._connection.re_prompt,
                                    timeout=self.timeout_connect,
                                    searchwindowsize=128)
      self._connection.child.send('terminal length 0\r')
      pindex = self._connection.child.expect(
          [self._connection.re_prompt, r'Command authorization failed\.'],
          timeout=self.timeout_connect)
      if pindex == 1:
        self.connected = False
        raise exceptions.ConnectError('terminal length 0 command denied.')
      # Pause momentarily to avoid a TAC+ packet drop. See b/1890881.
      time.sleep(0.5)
    except (pexpect.EOF, pexpect.TIMEOUT) as e:
      self.connected = False
      raise exceptions.ConnectError('%s: %s' % (e.__class__, str(e)))
    logging.debug('terminal length set to 0')
