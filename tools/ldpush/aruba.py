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

"""An Aruba device .

This module implements the base device interface of base_device.py for
Aruba devices.
"""
import os

import pexpect

import gflags
import logging

import base_device
import pexpect_connection
import push_exceptions as exceptions

FLAGS = gflags.FLAGS

gflags.DEFINE_float('aruba_timeout_response', None,
                   'Aruba device response timeout in seconds.')
gflags.DEFINE_float('aruba_timeout_connect', None,
                   'Aruba device connect timeout in seconds.')
gflags.DEFINE_float('aruba_timeout_idle', None,
                   'Aruba device idle timeout in seconds.')
gflags.DEFINE_float('aruba_timeout_disconnect', None,
                   'Aruba device disconnect timeout in seconds.')
gflags.DEFINE_float('aruba_timeout_act_user', None,
                   'Aruba device user activation timeout in seconds.')

# Error message format while executing an invalid command eg:.
# (sydpirwmc1) #asdfasd.
#               ^
# % Invalid input detected at '^' marker.
INVALID_OUT1 = "% Invalid input detected at '^' marker.\n\n"
# eg: (sydpirwmc1) #traceroute a.
# Incorrect Input !use traceroute <ipaddr>.
INVALID_OUT2 = 'Incorrect Input'


class ArubaDevice(base_device.BaseDevice):
  """A base device model suitable for Aruba devices.

  See the base_device.BaseDevice method docstrings.
  """

  def __init__(self, **kwargs):
    self.vendor_name = 'aruba'
    super(ArubaDevice, self).__init__(**kwargs)
    # Aruba prompt sample = '(sydpirwmc1) #'.
    self._success = r'(?:^|\n)(\([A-Za-z0-9\.\-]+\)\s[#>])'

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

    _ = mode
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

    if result.endswith(INVALID_OUT1) or result.startswith(INVALID_OUT2):
      raise exceptions.CmdError('Command failed: %s' % result)

    return result

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
      except (pexpect.EOF, pexpect.TIMEOUT) as e:
        self.connected = False
        raise exceptions.DisconnectError('%s: %s' % (e.__class__, str(e)))

  def _DisablePager(self):
    """Disables the paging."""
    try:
      self._connection.child.send('no paging\r')
      self._connection.child.expect(self._connection.re_prompt,
                                    timeout=self.timeout_connect,
                                    searchwindowsize=128)
    except (pexpect.EOF, pexpect.TIMEOUT) as e:
      self.connected = False
      raise exceptions.ConnectError('%s: %s' % (e.__class__, str(e)))
    logging.debug('Disabled paging on aruba device')
