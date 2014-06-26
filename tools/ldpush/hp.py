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
"""An HP ProCurve switch device .

This module implements the base device interface of base_device.py for
Hewlett-Packard ProCurve Ethernet switches.
"""

__author__ = 'afort@google.com (Andreux Fort)'

import os
import re

import pexpect

import gflags
import logging

import base_device
import pexpect_connection
import push_exceptions as exceptions


FLAGS = gflags.FLAGS


gflags.DEFINE_float('hp_timeout_response', None,
                   'HP device response timeout in seconds.')
gflags.DEFINE_float('hp_timeout_connect', 22.0,
                   'HP device connect timeout in seconds.')
gflags.DEFINE_float('hp_timeout_idle', None,
                   'HP device idle timeout in seconds.')
gflags.DEFINE_float('hp_timeout_disconnect', None,
                   'HP device disconnect timeout in seconds.')
gflags.DEFINE_float('hp_timeout_act_user', None,
                   'HP device user activation timeout in seconds.')


class HpProCurveDevice(base_device.BaseDevice):
  """A base device model for Hewlett-Packard ProCurve switches."""

  RE_INVALID = re.compile(r'^(Invalid|Ambiguous) input:', re.I | re.M)
  RE_PAGER = re.compile(r'-- MORE --, next page: Space, next line: Enter, '
                        'quit: Control-C')

  def __init__(self, **kwargs):
    self.vendor_name = 'hp'
    super(HpProCurveDevice, self).__init__(**kwargs)

    # The response regexp indicating connection success.
    self._success = r'ProCurve .*[Ss]witch'

  def _Connect(self, username, password=None, ssh_keys=None,
               enable_password=None, ssl_cert_set=None):
    # Quieten pylint.
    _ = ssl_cert_set
    self._connection = pexpect_connection.HpSshFilterConnection(
        self.loopback_ipv4, username, password, success=self._success,
        timeout=self.timeout_connect, find_prompt=True, ssh_keys=ssh_keys,
        enable_password=enable_password)
    try:
      self._connection.Connect()
      self._DisablePager()
    except pexpect_connection.ConnectionError, e:
      self.connected = False
      raise exceptions.ConnectError(e)
    except pexpect_connection.TimeoutError, e:
      self.connected = False
      raise exceptions.ConnectError('Timed out connecting to %s(%s) after '
                                    '%s seconds.' %
                                    (self.host, self.loopback_ipv4, str(e)))

  def _Cmd(self, command, mode=None, called_already=False):
    _ = mode
    # Strip question marks and short-circuit if we have nothing more.
    command = command.replace('?', '')
    if not command:
      return ''

    try:
      self._connection.child.send(command+'\r')
      self._connection.child.expect(command+'\n')
      result = ''
      while True:
        i = self._connection.child.expect([self._connection.re_prompt,
                                           self.RE_PAGER],
                                          timeout=self.timeout_response,
                                          searchwindowsize=128)
        # HP prefers \n\r to \r\n.
        result += self._connection.child.before.replace('\n\r', os.linesep)
        if i == 1:
          self._connection.child.send(' ')
        else:
          break
      # Check if the device told us our command was not recognized.
      if self.RE_INVALID.search(result) is not None:
        raise exceptions.CmdError('Command %r invalid on %s(%s)' %
                                  (command, self.host, self.loopback_ipv4))
      return result
    except pexpect.TIMEOUT, e:
      self.connected = False
      raise exceptions.CmdError('%s: %s' % (e.__class__, str(e)))
    except pexpect.EOF, e:
      if not called_already:
        return self._Cmd(command, mode=mode, called_already=True)
      else:
        self.connected = False
        raise exceptions.CmdError('%s: %s' % (e.__class__, str(e)))

  def _DisablePager(self):
    """Enables and logs in so the pager can be disabled."""
    # Maximum terminal size on sw version M.08.74 (8095) is 1920x1000.
    try:
      self._connection.child.send('terminal length 1000\r')
      self._connection.child.expect(self._connection.re_prompt,
                                    timeout=self.timeout_act_user,
                                    searchwindowsize=128)
      self._connection.child.send('terminal width 1920\r')
      self._connection.child.expect(self._connection.re_prompt,
                                    timeout=self.timeout_act_user,
                                    searchwindowsize=128)
    except (pexpect.EOF, pexpect.TIMEOUT), e:
      self.connected = False
      raise exceptions.CmdError('%s: %s' % (e.__class__, str(e)))

  def _Disconnect(self):
    """Disconnects from the device."""
    if hasattr(self, '_connection'):
      try:
        try:
          self._connection.child.send('exit\r')
          while True:
            i = self._connection.child.expect([r'\S(?:#|>) ',
                                               r'Do you want to log out',
                                               r'Do you want to save'],
                                              timeout=self.timeout_act_user)
            if i == 0:
              self._connection.child.send('exit\r')
              continue
            elif i == 1:
              self._connection.child.send('y')
              return
            elif i == 2:
              self._connection.child.send('n')
              logging.warn('Uncomitted config on %s(%s). Not saving.',
                           self.host, self.loopback_ipv4)
              return
        except pexpect.TIMEOUT, e:
          raise exceptions.DisconnectError('%s: %s' % (e.__class__, str(e)))
        except pexpect.EOF, e:
          # An EOF now means nothing more than a disconnect.
          pass
      finally:
        self.connected = False
