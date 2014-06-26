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
"""Tests for paramiko_device."""

import cStringIO as StringIO
import push_exceptions as exceptions
import gflags
import mox
import paramiko_device
import time
import unittest

FLAGS = gflags.FLAGS


def FakeSshLibrary(stderr='', expected_command=''):
  """Creates a simple fake SSH connection."""
  # pylint:disable=g-bad-name

  class FakeSshClient(object):

    def __init__(self, *unused_args, **unused_kwargs):
      self._channels = {}

    def close(self):
      self._closed = True

    def get_transport(self):
      return self

    def open_session(self):
      return self

    def settimeout(self, unused_timeout):
      pass

    def exec_command(self, command):
      assert command == expected_command, (
          'exec_command(%r) expected, got exec_command(%r)' % (
              expected_command, command))

    def makefile(self, unused_mode, unused_arg):
      return StringIO.StringIO()

    def makefile_stderr(self, unused_mode, unused_arg):
      return StringIO.StringIO(stderr)

  return FakeSshClient()


class ParamikoDeviceTest(unittest.TestCase):

  def setUp(self):
    self._mox = mox.Mox()
    self._mox.StubOutWithMock(time, 'sleep')
    self.user = 'joe'
    self.pw = 'pass'

  def tearDown(self):
    self._mox.UnsetStubs()
    self._mox.VerifyAll()

  def testCommandSuccess(self):
    self._mox.StubOutWithMock(paramiko_device.sshclient, 'Connect')
    device = paramiko_device.ParamikoDevice()
    device.host = '127.0.0.1'
    device.loopback_ipv4 = '127.0.0.1'
    paramiko_device.sshclient.Connect(
        hostname=device.host, password=self.pw, port=22, ssh_keys=(),
        username=self.user).AndReturn(
            FakeSshLibrary(stderr='', expected_command='show version'))
    self._mox.ReplayAll()

    device.Connect(username=self.user, password=self.pw)
    device.Cmd('show version')

  def testCommandError(self):
    self._mox.StubOutWithMock(paramiko_device.sshclient, 'Connect')
    device = paramiko_device.ParamikoDevice()
    device.host = '128.0.0.1'
    device.loopback_ipv4 = '127.0.0.1'
    paramiko_device.sshclient.Connect(
        hostname=device.host, password=self.pw, port=22, ssh_keys=(),
        username=self.user).AndReturn(
            FakeSshLibrary(stderr='failboat', expected_command='show version'))
    self._mox.ReplayAll()

    device.Connect(username=self.user, password=self.pw)
    self.assertRaises(exceptions.CmdError, device.Cmd, 'show version')


if __name__ == '__main__':
  unittest.main()
